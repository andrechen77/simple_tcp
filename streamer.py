# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import time

packet_size = 1472
packet_header_format = "!Ic"
packet_header_size = struct.calcsize(packet_header_format)
payload_size = packet_size - packet_header_size
assert(payload_size > 0)
# big-endian byte-ordering
# 32-bit sequence number, packet type ('D', 'A', or 'F')

class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.recv_buff_size = 128
        self.recv_buff = [None for _ in range(self.recv_buff_size)]
        self.recv_seq_num = 0
        self.send_seq_num = 0 # the sequence number of the next packet to be sent
        self.send_ack_num = 0 # the sequence number of next packet that is awaiting acknowledgement
        self.closed = False

        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.listener)

    def packetize(self, data_bytes):
        """Given a byte-array, iteratively returns the array transformed into packets."""

        for start in range(0, len(data_bytes), payload_size):
            payload = data_bytes[start:(start+payload_size)]
            packet_header = struct.pack(packet_header_format, self.send_seq_num, b'D')
            self.send_seq_num += 1
            yield packet_header + payload

    def unpacketize(self, packet):
        """Given a packet, returns a pair consisting of the headers tuple and the payload."""

        seq_num, packet_type = struct.unpack_from(packet_header_format, packet)
        payload = packet[packet_header_size:]
        return (seq_num, packet_type), payload

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        for packet in self.packetize(data_bytes):
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            while self.send_seq_num > self.send_ack_num:
                time.sleep(0.01)

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
                headers, data = self.unpacketize(packet)
                seq_num, packet_type = headers
                if packet_type == b'D':
                    if self.recv_seq_num <= seq_num and seq_num < self.recv_seq_num + self.recv_buff_size:
                        # the received packet can fit within the next recv_buff_size packets
                        self.recv_buff[seq_num % self.recv_buff_size] = data
                        ack = struct.pack(packet_header_format, seq_num, b'A') # no payload
                        self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                    # if the received packet can't fit or was already transmitted to the application, then drop it
                elif packet_type == b'A':
                    if seq_num >= self.send_ack_num:
                        # TODO what about the previous packets? can we guarantee if they ACK packet 8 that packet 7 was received?
                        self.send_ack_num = seq_num + 1
                elif packet_type == b'F':
                    pass
                else:
                    pass
            except Exception as e:
                print("listener died!")
                print(e)


    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        self.closed = True
        self.socket.stoprecv()