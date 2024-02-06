# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import time
import threading
import hashlib
import logging

logging.basicConfig(
    format="%(asctime)-15s [%(levelname)s] %(threadName)s in %(funcName)s:\n\t%(message)s",
    level=logging.INFO,
)
logger = logging.getLogger()
logger.disabled = True

ack_timeout = 0.25
send_empty_timeout = 0.1
hash_size = 4 # number of bytes
packet_size = 1472
packet_header_format_wo_hash = f"!IIc" # 3-byte md5 hash, 4-byte sequence number
packet_header_size = hash_size + struct.calcsize(packet_header_format_wo_hash)
payload_size = packet_size - packet_header_size
assert(payload_size > 0)

# big-endian byte-ordering
# 32-bit sequence number, packet type ('D', 'A', or 'F')

def create_packet(seq_num: int, ack_num: int, packet_type: bytes, payload: bytes) -> bytes:
    packet_header_wo_hash = struct.pack(packet_header_format_wo_hash, seq_num, ack_num, packet_type)
    packet_wo_hash = packet_header_wo_hash + payload
    hash = shake(packet_wo_hash, hash_size)
    packet = hash + packet_wo_hash
    return packet

def dissect_packet(packet: bytes):
    """Given a packet, returns a pair consisting of the headers tuple and the
    payload or None if the hash doesn't match."""
    expected_hash = packet[:hash_size]
    packet_wo_hash = packet[hash_size:]
    actual_hash = shake(packet_wo_hash, hash_size)
    if expected_hash != actual_hash:
        return None
    seq_num, ack_num, packet_type = struct.unpack_from(packet_header_format_wo_hash, packet_wo_hash)
    payload = packet[packet_header_size:]
    return (seq_num, ack_num, packet_type), payload

def get_slice(buffer, begin, end):
    mod = len(buffer)
    i = begin % mod
    j = end % mod
    if i < j or begin == end:
        return buffer[i:j]
    else:
        return buffer[i:] + buffer[:j]

class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Receive buffer:
        # This buffer is used to hold all the bytes received but not yet read
        # by the application. This allows out-of-order bytes to be stored.
        # Semantically, it is a sliding window that starts at self.recv_seq_start
        # with the given size. self.recv_buff_valid determines which bytes
        # have been received.
        self.recv_buff_condition = threading.Condition()
        self.recv_buff_size = 128
        self.recv_buff_bytes = bytearray(self.recv_buff_size) # stores the received bytes
        self.recv_buff_valid = [False] * self.recv_buff_size # stores which bytes are valid
        self.recv_seq_start = 0 # the sequence number of the next byte to be sent to the application
        # self.recv_seq_end = 0 # the sequence number of the first invalid byte
        self.received_fin = threading.Event()
        # TODO make sure dropped fins get resent

        # Send buffer:
        # This buffer is used to hold all the bytes that are awaiting ACKs or
        # waiting to be sent.
        # Semantically, it is a sliding window that starts at self.send_seq_unacked
        # and ends at self.send_seq_unused
        # An element not between those pointers has no meaning.
        self.send_buff_condition = threading.Condition()
        self.send_buff_size = 64
        self.send_buff = bytearray(self.send_buff_size)
        self.send_seq_unacked = 0 # the sequence number of next byte that is awaiting acknowledgement
        self.send_seq_unsent = 0 # the sequence number of the next byte to be sent
        self.send_seq_unused = 0 # the sequence number of the next byte to be used by the application

        self.closed = False

        executor = ThreadPoolExecutor(max_workers=3)
        executor.submit(self.listener)
        executor.submit(self.transmitter)
        executor.submit(self.retransmitter)

    # TODO doesn't need to be a method
    def chunketize(self, data_bytes: bytes):
        """Given a byte-array, iteratively returns the array transformed into packets."""

        for start in range(0, len(data_bytes), payload_size):
            yield data_bytes[start:(start+payload_size)]

    def calc_ack_num(self):
        """Returns the ack num to be send with all outgoing packets from this streamer."""
        with self.recv_buff_condition:
            ack_num = self.recv_seq_start
            while self.recv_buff_valid[ack_num % self.recv_buff_size]:
                # TODO what if every element is not None?
                ack_num += 1
        return ack_num

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet.
        Writes data_bytes to send buffer"""

        def send_buffer_has_space():
            return self.send_buff_size > (self.send_seq_unused - self.send_seq_unacked)

        with self.send_buff_condition:
            i = 0
            while i < len(data_bytes):
                # logging.info("waiting for there to be room in the buffer")
                self.send_buff_condition.wait_for(send_buffer_has_space)
                # logging.info("space in the buffer found!")
                while i < len(data_bytes) and send_buffer_has_space():
                    self.send_buff[self.send_seq_unused % self.send_buff_size] = data_bytes[i]
                    self.send_seq_unused += 1
                    i += 1
                self.send_buff_condition.notify_all()

                # amt_to_send = min(len(data_bytes) - i, remaining_room)
                # begin = self.send_seq_unsent % self.send_buff_size
                # end = (self.send_seq_unsent + amt_to_send) % self.send_buff_size

                # if begin <= end:
                #     # no wraparound
                #     self.send_buff[begin:end] = data_bytes[i:(i + amt_to_send)]
                # else:
                #     # wraparound
                #     cutoff = i + self.send_buff_size - begin
                #     self.send_buff[begin:] = data_bytes[i:cutoff]
                #     self.send_buff[0:end] = data_bytes[cutoff:(i + amt_to_send)]
                # i += amt_to_send

        # for packet in self.packetize(data_bytes):
        #     self.send_packet(packet)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""

        result = b''
        with self.recv_buff_condition:
            # wait for the next packet to come
            logging.info(f"waiting for #{self.recv_seq_start} to come")
            self.recv_buff_condition.wait_for(lambda: self.recv_buff_valid[self.recv_seq_start % self.recv_buff_size])
            logging.info(f"got #{self.recv_seq_start}; retreiving for application")

            while self.recv_buff_valid[(i := self.recv_seq_start % self.recv_buff_size)]:
                self.recv_seq_start += 1
                result += self.recv_buff_bytes[i:(i + 1)]
                self.recv_buff_valid[i] = False

            self.recv_buff_condition.notify_all()
        return result

    def send_packet(self, send_seq_start, send_seq_end, packet_type):
        """creates and sends a packet where the payload is the contents of the send buffer between send_seq_start and send_seq_end"""
        # with self.send_buff_condition:
        ack_num = self.calc_ack_num()
        logging.info(f"sending #{send_seq_start}-{send_seq_end} with ACK #{ack_num}")
        payload = get_slice(self.send_buff, send_seq_start, send_seq_end)
        logging.info(payload)
        packet = create_packet(send_seq_start, ack_num, packet_type, payload)
        self.socket.sendto(packet, (self.dst_ip, self.dst_port))

    def transmitter(self):
        try:
            with self.send_buff_condition:
                while True:
                    logging.info("waiting for packets to send")
                    self.send_buff_condition.wait_for(
                        lambda: self.closed or self.send_seq_unused >= self.send_seq_unsent + payload_size or
                            (self.send_seq_unsent < self.send_seq_unused and self.send_seq_unacked == self.send_seq_unsent)
                    )
                    if self.closed: break

                    # send one packet and then enter the loop
                    end_seq = min(self.send_seq_unused, self.send_seq_unsent + payload_size)
                    logging.info(f"initial send for #{self.send_seq_unsent}-{end_seq}")
                    self.send_packet(self.send_seq_unsent, end_seq, b'D')
                    self.send_seq_unsent = end_seq
                self.send_buff_condition.notify_all()
        except Exception as e:
            print("transmitter died!")
            print(e)
        finally:
            logging.info("good night.")

    def handle_received_data(self, seq_num, ack_num, data: bytes):
        logging.info(f"handling incoming #{seq_num}-{seq_num + len(data)} with ack #{ack_num}")
        with self.send_buff_condition:
            logging.info("a")
            if ack_num > self.send_seq_unacked:
                logging.info(f"got ACK {ack_num}")
                self.send_seq_unacked = ack_num
                self.send_buff_condition.notify_all() # TODO this might be why we're not seeing ACKs
        logging.info("b")
        with self.recv_buff_condition:
            logging.info("c")
            if seq_num < self.recv_seq_start + self.recv_buff_size:
                # the received packet won't overflow the buffer

                if self.recv_seq_start <= seq_num:
                    # the received packet won't underflow the buffer; store it
                    logging.info("storing data packet into buffer")
                    for i in range(len(data)):
                        s = seq_num + i
                        self.recv_buff_bytes[s % self.recv_buff_size] = data[i]
                        self.recv_buff_valid[s % self.recv_buff_size] = True
                    self.recv_buff_condition.notify_all()
                else:
                    logging.info("data packet is old; dropping")

                # make a cumulative acknowledgement
                # ack_num = self.recv_seq_start
                # while self.recv_buff_bytes[ack_num % self.recv_buff_size] is not None:
                #     # TODO what if every element is not None?
                #     ack_num += 1
                # # acknowledge packet even if we already received it (maybe our ACK got lost)
                # logging.info(f"sending ACK for #{ack_num}")
                # ack = create_packet(ack_num, b'A', b'')
                # self.socket.sendto(ack, (self.dst_ip, self.dst_port))
            else:
                logging.info("data packet won't fit in the buffer; dropped")
            # if the received packet can't fit or was already transmitted to the application, then drop it

    def listener(self):
        try:
            while not self.closed:
                # get a good packet from the socket
                packet, addr = self.socket.recvfrom()
                if len(packet) == 0:
                    # the socket died
                    break
                assert(len(packet) <= packet_size) # pretty sure self.socket.recvfrom() returns only one packet
                maybe_dissected_packet = dissect_packet(packet)
                if maybe_dissected_packet is None:
                    logging.info("got corrupted packet; ignoring")
                    continue

                # act on the received packet
                (seq_num, ack_num, packet_type), data = maybe_dissected_packet
                if packet_type == b'D': # includes pure ACKs
                    self.handle_received_data(seq_num, ack_num, data)
                elif packet_type == b'F':
                    self.received_fin.set()
                    self.handle_received_data(seq_num, ack_num, data)
                else:
                    raise Exception(f"unknown packet type: {packet_type}")
        except Exception as e:
            print("listener died!")
            print(e)
        finally:
            logging.info("good night.")

    def retransmitter(self):
        try:
            with self.send_buff_condition:
                while True:
                    # wait for a packet to be sent
                    logging.info("waiting for a packet to be in flight")
                    packet_in_flight = self.send_buff_condition.wait_for(lambda: self.send_seq_unacked < self.send_seq_unsent or self.closed, timeout=send_empty_timeout)
                    if self.closed: break
                    if not packet_in_flight:
                        logging.info("no outgoing packets, sending an empty ACK")
                        # send an empty packet just to ACK
                        self.send_packet(self.send_seq_unsent, self.send_seq_unsent, b'D')
                        continue

                    logging.info(f"packet in flight detected! starting timer for #{self.send_seq_unacked}")
                    # wait for an ACK, but impatiently
                    old_ack_num = self.send_seq_unacked # TODO: see if prayer (byte seq nums) fixed this
                    got_ack = self.send_buff_condition.wait_for(lambda: self.send_seq_unacked > old_ack_num or self.closed, timeout=ack_timeout)
                    if self.closed: break

                    if got_ack:
                        logging.info(f"ACK received up to #{self.send_seq_unacked}; restarting timer")
                    else:
                        logging.info(f"no ACK received, retransmitting #{self.send_seq_unacked}")
                        # timeout occurred, resend the oldest unACK'ed bytes
                        end_seq = min(self.send_seq_unsent, self.send_seq_unacked + payload_size)
                        self.send_packet(self.send_seq_unacked, end_seq, b'D')
        except Exception as e:
            print("retransmitter died!")
            print(e)
        finally:
            logging.info("good night.")

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        with self.send_buff_condition:
            # wait for every previous message to be acknowledged
            logging.info("waiting for all packets to be acknowledged before sending FIN")
            self.send_buff_condition.wait_for(lambda: self.send_seq_unacked == self.send_seq_unsent)
            logging.info(f"all packets acknowledged, sending FIN as #{self.send_seq_unsent}")
            # Send a FIN packet.
            fin = create_packet(self.send_seq_unsent, b'F', b'')
            self.send_packet(fin)
            # Wait for an ACK of the FIN packet. Go back to Step 2 if a timer expires.
            logging.info("waiting for ACK of FIN")
            self.send_buff_condition.wait_for(lambda: self.send_seq_unacked == self.send_seq_unsent)
            logging.info("ACK of FIN received")
            # Wait until the listener records that a FIN packet was received from the other side.
            logging.info("waiting for FIN from the other side")
            self.received_fin.wait() # blocks forever until a FIN comes TODO can we not???
            logging.info("FIN received; starting grace period")
            # Wait two seconds.
            time.sleep(2.0)
            logging.info("grace period over. good night.")
            # Stop the other threads
            self.closed = True
            self.send_buff_condition.notify_all()
            # no need to notify those waiting on the recv_buff_condition; no one waits on it anyway
            self.socket.stoprecv()
            # Finally, return from Streamer#close
        return

def shake(data: bytes, length=hash_size):
    m = hashlib.shake_128()
    m.update(data)
    return m.digest(length)
