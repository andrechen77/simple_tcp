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

patient_ack_timeout = 0.25
impatient_ack_timeout = 0.1
send_empty_timeout = 0.1
hash_size = 4 # number of bytes
packet_size = 1472
packet_header_format_wo_hash = f"!IIc" # 4-byte sequence number, 4-byte ACK number
packet_header_size = hash_size + struct.calcsize(packet_header_format_wo_hash)
payload_size = packet_size - packet_header_size
assert(payload_size > 0)

# big-endian byte-ordering
# 32-bit sequence number, packet type ('D', 'A', or 'F')

def create_packet(seq_num: int, ack_num: int, packet_type: bytes, payload: bytes) -> bytes:
    """Given the components of a packet, assembles a bytes object representing
    the the bytes to be sent over the network."""
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
    """Given a circular buffer, returns a copy of the slice between the two
    indices, pretending that the indices will wrap around."""
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

        # TODO ensure that it's correctly documented what gets guarded
        # by the conditions

        # Receive buffer:
        # This buffer is used to hold all the bytes received but not yet read
        # by the application. This allows out-of-order bytes to be stored.
        # Semantically, it is a sliding window that starts at self.recv_seq_start
        # with the given size. self.recv_buff_valid determines which bytes
        # have been received.
        self.recv_buff_condition = threading.Condition() # guards access to all variables in this group
        self.recv_buff_size = 2048
        self.recv_buff_bytes = bytearray(self.recv_buff_size) # stores the received bytes
        self.recv_buff_valid = [False] * self.recv_buff_size # stores which bytes are valid
        self.recv_seq_start = 0 # the sequence number of the next byte to be sent to the application

        self.received_fin = threading.Event()
        self.received_data = threading.Event() # for pure ACKer

        # Send buffer:
        # This buffer is used to hold all the bytes that are awaiting ACKs or
        # waiting to be sent.
        # Semantically, it is a sliding window that starts at self.send_seq_unacked
        # and ends at self.send_seq_unused
        # An element not between those pointers has no meaning.
        self.send_buff_condition = threading.Condition() # guards access to all variables in this group
        self.send_buff_size = 2048
        self.send_buff = bytearray(self.send_buff_size)
        self.send_seq_unacked = 0 # the sequence number of next byte that is awaiting acknowledgement
        self.send_seq_unsent = 0 # the sequence number of the next byte to be sent
        self.send_seq_unused = 0 # the sequence number of the next byte to be used by the application
        self.send_finished = False # is there a fin packet in flight

        self.sent_anything = threading.Event() # for pure ack'er

        self.closed = False

        # TODO make this just start separate threads without an executor
        executor = ThreadPoolExecutor(max_workers=4)
        executor.submit(self.listener)
        executor.submit(self.transmitter)
        executor.submit(self.retransmitter)
        executor.submit(self.pure_acker)

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
        self.add_to_send_buff(data_bytes)

    def add_to_send_buff(self, data_bytes: bytes) -> None:
        """Writes the given data into the send buffer. Blocks until all the data
        has fit into the buffer."""

        def send_buffer_has_space():
            return self.send_buff_size > (self.send_seq_unused - self.send_seq_unacked)

        with self.send_buff_condition:
            i = 0
            while i < len(data_bytes):
                logging.info("waiting for send_buffer space")
                self.send_buff_condition.wait_for(send_buffer_has_space)
                logging.info("found send_buffer space!")
                while i < len(data_bytes) and send_buffer_has_space():
                    self.send_buff[self.send_seq_unused % self.send_buff_size] = data_bytes[i]
                    self.send_seq_unused += 1
                    i += 1
                self.send_buff_condition.notify_all()

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""

        result = b''
        with self.recv_buff_condition:
            # wait for the next packet to come
            logging.info(f"waiting for #{self.recv_seq_start}")
            self.recv_buff_condition.wait_for(lambda: self.recv_buff_valid[self.recv_seq_start % self.recv_buff_size])
            logging.info(f"found #{self.recv_seq_start}; retreiving for application")

            while self.recv_buff_valid[(i := self.recv_seq_start % self.recv_buff_size)]:
                self.recv_seq_start += 1
                result += self.recv_buff_bytes[i:(i + 1)]
                self.recv_buff_valid[i] = False

            self.recv_buff_condition.notify_all()
        return result

    def send_packet(self, send_seq_start: int, send_seq_end: int, packet_type: bytes):
        """creates and sends a packet where the payload is the contents of the send buffer between send_seq_start and send_seq_end"""
        with self.send_buff_condition:
            # all sent packets include the current ACK number, which implements piggy-backing
            ack_num = self.calc_ack_num()
            payload = get_slice(self.send_buff, send_seq_start, send_seq_end)
            packet = create_packet(send_seq_start, ack_num, packet_type, payload)
        logging.info(f"sending #{send_seq_start}-{send_seq_end} with ACK #{ack_num} and type {packet_type}: {payload}")
        self.socket.sendto(packet, (self.dst_ip, self.dst_port))
        self.sent_anything.set()
        self.sent_anything.clear()

    def transmitter(self):
        try:
            with self.send_buff_condition:
                while True:
                    logging.info("waiting for packets to send")
                    # use Nagle's algorithm to combine small packets
                    self.send_buff_condition.wait_for(
                        lambda: self.closed or self.send_seq_unused >= self.send_seq_unsent + payload_size or # max payload size is filled
                            (self.send_seq_unsent < self.send_seq_unused and self.send_seq_unacked == self.send_seq_unsent) # we have data to send and are not waiting for ACKs on our own data
                    )
                    if self.closed: break

                    # send one packet and then enter the loop
                    end_seq = min(self.send_seq_unused, self.send_seq_unsent + payload_size)
                    logging.info(f"initial send for #{self.send_seq_unsent}-{end_seq}")
                    packet_type = b'F' if self.send_finished else b'D'
                    self.send_packet(self.send_seq_unsent, end_seq, packet_type)
                    self.send_seq_unsent = end_seq
                    self.send_buff_condition.notify_all()
        except Exception as e:
            print("transmitter died!")
            print(e)
        finally:
            logging.info("good night.")

    def handle_received_data(self, seq_num: int, ack_num: int, data: bytes):
        logging.info(f"handling incoming #{seq_num}-{seq_num + len(data)} with ack #{ack_num}")

        if len(data) > 0:
            self.received_data.set()
            self.received_data.clear()
        with self.send_buff_condition:
            if ack_num > self.send_seq_unacked:
                self.send_seq_unacked = ack_num
                self.send_buff_condition.notify_all()
        with self.recv_buff_condition:
            if seq_num < self.recv_seq_start + self.recv_buff_size:
                # the received packet won't overflow the buffer

                if self.recv_seq_start <= seq_num:
                    # the received packet won't underflow the buffer; store it
                    # logging.info("storing data packet into buffer")
                    for i in range(len(data)):
                        s = seq_num + i
                        self.recv_buff_bytes[s % self.recv_buff_size] = data[i]
                        self.recv_buff_valid[s % self.recv_buff_size] = True
                    self.recv_buff_condition.notify_all()
                else:
                    logging.info("data packet is old; dropping")
            else:
                logging.info("data packet won't fit in the buffer; dropped")

            # fast ack a received fin
            if self.received_fin.is_set():
                logging.info("fast-acking a received FIN")
                self.send_packet(self.send_seq_unsent, self.send_seq_unsent, b'D')

    def listener(self):
        try:
            while not self.closed:
                # get a good packet from the socket
                logging.info("abt to ask socket for stuff")
                packet, addr = self.socket.recvfrom()
                logging.info("got literally any packet")
                if len(packet) == 0:
                    # the socket died
                    logging.info("aight imma head out")
                    break
                assert(len(packet) <= packet_size) # pretty sure self.socket.recvfrom() returns only one packet
                logging.info("sdfjlsdjf")
                maybe_dissected_packet = dissect_packet(packet)
                if maybe_dissected_packet is None:
                    logging.info("got corrupted packet; ignoring")
                    continue

                # act on the received packet
                (seq_num, ack_num, packet_type), data = maybe_dissected_packet
                if packet_type == b'D': # includes pure ACKs
                    self.handle_received_data(seq_num, ack_num, data)
                elif packet_type == b'F':
                    logging.info("i see your fin")
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
                    self.send_buff_condition.wait_for(lambda: self.send_seq_unacked < self.send_seq_unsent or self.closed)
                    if self.closed: break

                    logging.info(f"packet in flight detected! starting timer for #{self.send_seq_unacked}")
                    # wait for an ACK, but impatiently
                    old_ack_num = self.send_seq_unacked
                    acktual_timeout = impatient_ack_timeout if self.send_finished else patient_ack_timeout
                    got_ack = self.send_buff_condition.wait_for(lambda: self.send_seq_unacked > old_ack_num or self.closed, timeout=acktual_timeout)
                    if self.closed: break

                    if got_ack:
                        logging.info(f"ACK received up to #{self.send_seq_unacked}; restarting timer")
                    else:
                        logging.info(f"no ACK received, retransmitting #{self.send_seq_unacked}")
                        # timeout occurred, resend the oldest unACK'ed bytes
                        end_seq = min(self.send_seq_unsent, self.send_seq_unacked + payload_size)
                        packet_type = b'F' if self.send_finished else b'D'
                        self.send_packet(self.send_seq_unacked, end_seq, packet_type)
        except Exception as e:
            print("retransmitter died!")
            print(e)
        finally:
            logging.info("good night.")

    def pure_acker(self) -> None:
        try:
            while True:
                # wait for data to be received
                # logging.info("waiting for data to be received")
                self.received_data.wait()
                if self.closed: break

                # wait for EITHER: timeout occurs OR another thread has sent data
                # logging.info("looks like we got data. waiting for either timeout or another thread to send")
                other_thread_has_sent = self.sent_anything.wait(timeout=send_empty_timeout)
                if self.closed: break

                if not other_thread_has_sent and not self.received_fin.is_set():
                    # send pure ACK
                    logging.info("sending an empty ACK")
                    with self.send_buff_condition:
                        self.send_packet(self.send_seq_unsent, self.send_seq_unsent, b'D')
                else:
                    logging.info("someone has ACKed for us; do nothing")
        except Exception as e:
            print("pure_acker died")
            print(e)
        finally:
            logging.info("good night.")

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        with self.send_buff_condition:
            # wait for every previous message to be acknowledged
            logging.info("waiting for all packets to be acknowledged before sending FIN")
            self.send_buff_condition.wait_for(lambda: self.send_seq_unacked == self.send_seq_unused)
            logging.info(f"all packets acknowledged, sending FIN as #{self.send_seq_unused}")
            # Send a FIN packet.
            self.send_finished = True
            self.add_to_send_buff(b'\0')
            # transmitter takes care of sending a fin with an empty byte (from send buffer) as the payload
            # Wait for an ACK of the FIN packet. Go back to Step 2 if a timer expires.
            logging.info("waiting for ACK of FIN")
            self.send_buff_condition.wait_for(lambda: self.send_seq_unacked == self.send_seq_unused)
            logging.info("ACK of FIN received")
        # Wait until the listener records that a FIN packet was received from the other side.
        logging.info("waiting for FIN from the other side")
        self.received_fin.wait() # blocks forever until a FIN comes
        logging.info("FIN received; starting grace period")
        # Wait two seconds.
        time.sleep(2.0)
        logging.info("grace period over. good night.")
        # Stop the other threads
        self.closed = True
        with self.send_buff_condition:
            self.send_buff_condition.notify_all()
        # no need to notify those waiting on the recv_buff_condition; no one waits on it anyway
        self.received_data.set() # to kill waiting threads
        self.sent_anything.set() # to kill waiting threads
        self.socket.stoprecv()
            # Finally, return from Streamer#close
        return

def shake(data: bytes, length=hash_size):
    m = hashlib.shake_128()
    m.update(data)
    return m.digest(length)
