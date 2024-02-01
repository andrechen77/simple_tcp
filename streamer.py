# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import time
import threading
import hashlib

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
    # print(f"creating packet with hash {packet}")
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
        self.recv_buff_size = 128
        self.recv_buff = [None for _ in range(self.recv_buff_size)]
        self.recv_seq_num = 0 # the sequence number of the next packet expected by the receiver
        self.send_seq_num = 0 # the sequence number of the next packet to be sent
        self.send_ack_num = 0 # the sequence number of next packet that is awaiting acknowledgement
        self.send_got_ack = threading.Event()
        self.got_fin = threading.Event()
        self.closed = False

        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.listener)

    def packetize(self, data_bytes: bytes):
        """Given a byte-array, iteratively returns the array transformed into packets."""

        for start in range(0, len(data_bytes), payload_size):
            payload = data_bytes[start:(start+payload_size)]
            yield create_packet(self.send_seq_num, b'D', payload)
            self.send_seq_num += 1

    def send_packet(self, packet: bytes) -> None:
        """blocks until the packet is ACK'ed"""
        # self.socket.sendto(packet, (self.dst_ip, self.dst_port))
        # print("attempt made at packet", packet)
        # t = threading.Timer(ack_timeout, lambda: self.send_packet(packet))
        # t.start()
        # while self.send_seq_num > self.send_ack_num:
        #     time.sleep(0.01)
        # t.cancel()
        while True:
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            if self.send_got_ack.wait(timeout=ack_timeout):
                # packet was succesfully acknowledged
                self.send_got_ack.clear()
                break
            else:
                # timeout occurred, resend
                pass

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        for packet in self.packetize(data_bytes):
            self.send_packet(packet)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""

        result = b''
        while self.recv_buff[(i := self.recv_seq_num % self.recv_buff_size)] is not None or not result:
            if self.recv_buff[i] is None:
                time.sleep(0.01)
                continue
            self.recv_seq_num += 1 # this happens before we modify recv_buff so that the listener thread never replaces a packet that's being removed
            result += self.recv_buff[i]
            self.recv_buff[i] = None
        return result

    def listener(self):
        while not self.closed: # a later hint will explain self.closed
            try:
                packet, addr = self.socket.recvfrom()
                if len(packet) == 0:
                    # the socket died
                    break
                assert(len(packet) <= packet_size) # pretty sure self.socket.recvfrom() returns only one packet
                maybe_dissected_packet = dissect_packet(packet)
                if maybe_dissected_packet is None:
                    print("this data sucks")
                    continue
                (seq_num, packet_type), data = maybe_dissected_packet
                if packet_type == b'D':
                    if seq_num < self.recv_seq_num + self.recv_buff_size:
                        if self.recv_seq_num <= seq_num:
                            # the received packet can fit within the next recv_buff_size packets
                            self.recv_buff[seq_num % self.recv_buff_size] = data
                        # acknowledge packet even if we already received it (maybe our ACK got lost)
                        ack = create_packet(seq_num + 1, b'A', b'')
                        self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                    # if the received packet can't fit or was already transmitted to the application, then drop it
                elif packet_type == b'A':
                    if seq_num > self.send_ack_num:
                        self.send_got_ack.set()
                        self.send_ack_num = seq_num
                elif packet_type == b'F':
                    self.got_fin.set()
                    # acknowledge packet even if we already received it (maybe our ACK got lost)
                    ack = create_packet(seq_num + 1, b'A', b'')
                    self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                    print("got fin")
                else:
                    raise Exception(f"unknown packet type: {packet_type}")
            except Exception as e:
                print("listener died!")
                print(e)


    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # TODO at part 5 [Wait for any sent data packets to be ACKed. Actually, if you're doing stop-and-wait then you know all of your sent data has been ACKed. However, in Part 5 you'll add code to maybe wait here.]
        # Send a FIN packet.
        fin = create_packet(self.send_seq_num, b'F', b'')
        # Wait for an ACK of the FIN packet. Go back to Step 2 if a timer expires.
        # print("starting to send fin")
        self.send_packet(fin) # blocks until ACK'ed
        # print("finished fin")
        # Wait until the listener records that a FIN packet was received from the other side.
        self.got_fin.wait() # blocks forever until a FIN comes TODO can we not???
        # Wait two seconds.
        time.sleep(2.0)
        # Stop the listener thread with self.closed = True and self.socket.stoprecv()
        self.closed = True
        self.socket.stoprecv()
        # Finally, return from Streamer#close
        return

def shake(data: bytes, length=hash_size):
    m = hashlib.shake_128()
    m.update(data)
    return m.digest(length)