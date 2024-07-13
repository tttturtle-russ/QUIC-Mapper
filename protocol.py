# import asyncio
import select
import socket

from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *

class QUICClientProtocol:
    def __init__(self, dst_addr, local_addr, handle):
        self.transport = None
        self.handle = handle
        # self._handshake_confirm = False
        # self.handshake_done = asyncio.Event()
        self.dst_addr = dst_addr
        self.local_addr = local_addr
        # self._packet_receive_event = asyncio.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.sock.bind(local_addr)
        # self.sock.setblocking(False)
        # self.handle.connect()

    def initial_ack_packet(self):
        print('initial ack\n')
        addr = self.dst_addr
        for datagram in self.handle.send_initial_ack_packet():
            self.transmit(datagram, addr)
            # self.wait_for_packet()

    def handshake_packet(self):
        print('handshake packet\n')
        addr = self.dst_addr
        for datagram in self.handle.send_handshake_packet():
            self.transmit(datagram, addr)

    def datagram_received(self) -> Optional[str]:
        readable, writeable, errored = select.select([self.sock], [], [],1)
        if self.sock not in readable:
            return "Timeout"
        data, addr = self.sock.recvfrom(2048)
        self.handle.receive_datagram(data, addr, now=0.0)
        return None


    def connect(self):
        print('connect\n')
        addr = self.dst_addr
        for datagram in self.handle.connect(addr):
            self.transmit(datagram, addr)
    def transmit(self, data, addr):
        self.sock.sendto(data, addr)

    def path_challenge(self):
        print('path challenge\n')
        for data in self.handle.send_path_challenge():
            self.transmit(data, self.dst_addr)

    def path_response(self):
        for data in self.handle.send_path_response():
            self.transmit(data, self.dst_addr)

    def initial_close(self):
        for data in self.handle.send_initial_close():
            self.transmit(data, self.dst_addr)

    def handshake_close(self):
        for data in self.handle.send_handshake_close():
            self.transmit(data, self.dst_addr)

    def onertt_ack(self):
        for data in self.handle.send_1rrt_ack():
            self.transmit(data, self.dst_addr)

    def onertt_close(self):
        for data in self.handle.send_1rtt_close():
            self.transmit(data, self.dst_addr)

    def new_connection_id(self):
        for data in self.handle.send_new_connectionid():
            self.transmit(data, self.dst_addr)

    def end_trace(self):
        self.handle.end_trace_file()

    def reset(self):
        self.handle.reset(self.dst_addr)



