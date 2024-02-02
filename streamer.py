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
hash_size = 4 # number of bytes
packet_size = 1472
packet_header_format_wo_hash = f"!Ic" # 3-byte md5 hash
packet_header_size = hash_size + struct.calcsize(packet_header_format_wo_hash)
payload_size = packet_size - packet_header_size
assert(payload_size > 0)

# big-endian byte-ordering
# 32-bit sequence number, packet type ('D', 'A', or 'F')

def create_packet(seq_num: int, packet_type: bytes, payload: bytes) -> bytes:
    packet_header_wo_hash = struct.pack(packet_header_format_wo_hash, seq_num, packet_type)
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
    seq_num, packet_type = struct.unpack_from(packet_header_format_wo_hash, packet_wo_hash)
    payload = packet[packet_header_size:]
    return (seq_num, packet_type), payload

class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Receive buffer:
        # This buffer is used to hold all the packets received but not yet read
        # by the application. This allows out-of-order packets to be stored.
        # Semantically, it is a sliding window that starts at self.recv_seq_num
        # with the given size. A given element is None if its corresponding
        # packet has not yet been received.
        self.recv_buff_condition = threading.Condition()
        self.recv_buff_size = 128
        self.recv_buff = [None for _ in range(self.recv_buff_size)]
        self.recv_seq_num = 0 # the sequence number of the next packet to be sent to the application
        self.received_fin = threading.Event()

        # Send buffer:
        # This buffer is used to hold all the packets that are awaiting ACKs.
        # Semantically, it is a sliding window that starts at self.send_ack_num
        # and ends at self.send_seq_num
        # Every element between those two pointers is an in-flight packet.
        # An element not between those pointers has no meaning.
        self.send_buff_condition = threading.Condition()
        self.send_buff_size = 64
        self.send_buff = [None for _ in range(self.send_buff_size)]
        self.send_seq_num = 0 # the sequence number of the next packet to be sent
        self.send_ack_num = 0 # the sequence number of next packet that is awaiting acknowledgement

        self.closed = False

        executor = ThreadPoolExecutor(max_workers=2)
        executor.submit(self.listener)
        executor.submit(self.retransmitter)

    def packetize(self, data_bytes: bytes):
        """Given a byte-array, iteratively returns the array transformed into packets."""

        for start in range(0, len(data_bytes), payload_size):
            payload = data_bytes[start:(start+payload_size)]
            yield create_packet(self.send_seq_num, b'D', payload)

    def send_packet(self, packet: bytes) -> None:
        with self.send_buff_condition:
            # wait until we have enough buffer space to send the packet
            logging.info(f"waiting for send buffer space for #{self.send_seq_num}")
            self.send_buff_condition.wait_for(lambda: self.send_seq_num - self.send_ack_num < self.send_buff_size)
            logging.info(f"buffer space exists, sending #{self.send_seq_num}")

            self.send_buff[self.send_seq_num % self.send_buff_size] = packet
            self.send_seq_num += 1
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

            self.send_buff_condition.notify_all()

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        for packet in self.packetize(data_bytes):
            self.send_packet(packet)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""

        result = b''
        with self.recv_buff_condition:
            # wait for the next packet to come
            logging.info(f"waiting for #{self.recv_seq_num} to come")
            self.recv_buff_condition.wait_for(lambda: self.recv_buff[self.recv_seq_num % self.recv_buff_size] is not None)
            logging.info(f"got #{self.recv_seq_num}; retreiving for application")

            while self.recv_buff[(i := self.recv_seq_num % self.recv_buff_size)] is not None:
                self.recv_seq_num += 1
                result += self.recv_buff[i]
                self.recv_buff[i] = None

            self.recv_buff_condition.notify_all()
        return result

    def handle_received_data(self, seq_num, data: bytes):
        logging.info(f"handling incoming #{seq_num}")
        with self.recv_buff_condition:
            if seq_num < self.recv_seq_num + self.recv_buff_size:
                # the received packet won't overflow the buffer

                if self.recv_seq_num <= seq_num:
                    # the received packet won't underflow the buffer; store it
                    logging.info("storing data packet into buffer")
                    self.recv_buff[seq_num % self.recv_buff_size] = data
                    self.recv_buff_condition.notify_all()
                else:
                    logging.info("data packet is old; dropping")

                # make a cumulative acknowledgement
                ack_num = self.recv_seq_num
                while self.recv_buff[ack_num % self.recv_buff_size] is not None:
                    # TODO what if every element is not None?
                    ack_num += 1
                # acknowledge packet even if we already received it (maybe our ACK got lost)
                logging.info(f"sending ACK for #{ack_num}")
                ack = create_packet(ack_num, b'A', b'')
                self.socket.sendto(ack, (self.dst_ip, self.dst_port))
            else:
                logging.info("data packet won't fit in the buffer; dropped")
            # if the received packet can't fit or was already transmitted to the application, then drop it

    def handle_received_ack(self, ack_num):
        with self.send_buff_condition:
            if ack_num > self.send_ack_num:
                logging.info(f"got ACK {ack_num}")
                self.send_ack_num = ack_num
                self.send_buff_condition.notify_all()

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
                (seq_num, packet_type), data = maybe_dissected_packet
                if packet_type == b'D':
                    self.handle_received_data(seq_num, data)
                elif packet_type == b'A':
                    self.handle_received_ack(seq_num)
                elif packet_type == b'F':
                    self.received_fin.set()
                    self.handle_received_data(seq_num, data)
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
                    self.send_buff_condition.wait_for(lambda: self.send_ack_num < self.send_seq_num or self.closed)
                    if self.closed: break
                    logging.info(f"packet in flight detected! starting timer for #{self.send_ack_num}")

                    # wait for an ACK, but impatiently
                    old_ack_num = self.send_ack_num
                    got_ack = self.send_buff_condition.wait_for(lambda: self.send_ack_num > old_ack_num or self.closed, timeout=ack_timeout)
                    if self.closed: break

                    if got_ack:
                        logging.info(f"ACK received up to #{self.send_ack_num}; restarting timer")
                    else:
                        logging.info(f"no ACK received, retransmitting #{self.send_ack_num}")
                        # timeout occurred, resend the oldest unACK'ed packet
                        self.socket.sendto(self.send_buff[self.send_ack_num % self.send_buff_size], (self.dst_ip, self.dst_port))
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
            self.send_buff_condition.wait_for(lambda: self.send_ack_num == self.send_seq_num)
            logging.info(f"all packets acknowledged, sending FIN as #{self.send_seq_num}")
            # Send a FIN packet.
            fin = create_packet(self.send_seq_num, b'F', b'')
            self.send_packet(fin)
            # Wait for an ACK of the FIN packet. Go back to Step 2 if a timer expires.
            logging.info("waiting for ACK of FIN")
            self.send_buff_condition.wait_for(lambda: self.send_ack_num == self.send_seq_num)
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