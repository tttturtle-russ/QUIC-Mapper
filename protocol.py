import asyncio
from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *



class QUICClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, addr, handle):
        self.transport = None
        self.handle = handle
        self._handshake_confirm = False
        self.handshake_done = asyncio.Event()
        self._addr = addr
        # self.handle.connect()

    def connection_made(self, transport):
        self.transport = transport

    def initial_ack_packet(self):
        addr = self._addr
        for datagram in self.handle.initial_ack_packet():
            self.transmit(datagram, addr)

    def handshake_packet(self):
        addr = self._addr
        for datagram in self.handle.handshake_packet():
            self.transmit(datagram, addr)

    def datagram_received(self, data, addr):
        # 使用你已有的 datagram_received 函数
        # data_pre = data
        self.handle.receive_datagram(data, addr, now=0.0)
        # print("data received")
        buf = Buffer(data=data)
        header = pull_quic_header(buf, 8)
        if self.handle.handshake_confirmed is True:
            self.handshake_done.set()
        # if header.packet_type == PACKET_TYPE_INITIAL:
        #     self.send_initial_ack_packet()
        # if header.packet_type == PACKET_TYPE_HANDSHAKE:
        #     self.send_handshake_packet()
        # self.end_trace()

    def connect(self):
        addr = self._addr
        for datagram in self.handle.connect(addr):
            self.transport.sendto(datagram, addr)

    def transmit(self, data, addr):
        self.transport.sendto(data, addr)

    def path_challenge(self):
        for data in self.handle.send_path_challenge():
            self.transmit(data, self._addr)

    def path_response(self):
        for data in self.handle.send_path_response():
            self.transmit(data, self._addr)

    def initial_close(self):
        for data in self.handle.send_initial_close():
            self.transmit(data, self._addr)

    def handshake_close(self):
        for data in self.handle.send_handshake_close():
            self.transmit(data, self._addr)

    def onertt_ack(self):
        for data in self.handle.send_1rrt_ack():
            self.transmit(data, self._addr)

    def onertt_close(self):
        for data in self.handle.send_1rtt_close():
            self.transmit(data, self._addr)

    def new_connection_id(self):
        for data in self.handle.send_new_connectionid():
            self.transmit(data, self._addr)

    def end_trace(self):
        self.handle.end_trace_file()



