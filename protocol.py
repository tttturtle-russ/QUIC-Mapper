# import asyncio
import select
import socket
import time

from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *

class QUICClientProtocol:
    def __init__(self, dst_addr, local_addr, handle, local_port=10086):
        self.transport = None
        self.handle = handle
        # self._handshake_confirm = False
        # self.handshake_done = asyncio.Event()
        self.dst_addr = dst_addr
        self.local = local_addr
        self.port = local_port
        self.origin_port = local_port
        self.local_addr = (local_addr, local_port)

        # self._packet_receive_event = asyncio.Event()

        # self.sock.bind(local_addr)
        # self.sock.setblocking(False)
        # self.handle.connect()

    def initial_ack_packet(self):
        #print('initial ack\n')
        self._flush_receive_buffer()
        addr = self.dst_addr
        for datagram in self.handle.send_initial_ack_packet():
            self.transmit(datagram, addr)
            # self.wait_for_packet()

    def handshake_packet(self):
        #print('handshake packet\n')
        self._flush_receive_buffer()
        addr = self.dst_addr
        for datagram in self.handle.send_handshake_packet():
            self.transmit(datagram, addr)

    def datagram_received(self, timeout=0.2) -> Optional[str]:
        readable, writeable, errored = select.select([self.sock], [], [],timeout)
        if self.sock not in readable:
            return None
        data, addr = self.sock.recvfrom(2048)
        return self.handle.receive_datagram(data, addr, now=0.0)

    def connect(self):
        #print('connect\n')
        addr = self.dst_addr
        self._flush_receive_buffer()
        for datagram in self.handle.connect(addr):
            self.transmit(datagram, addr)

    def transmit(self, data, addr):
        self.sock.sendto(data, addr)

    def path_challenge(self):
        #print('path challenge\n')
        self._flush_receive_buffer()
        for data in self.handle.send_path_challenge():
            self.transmit(data, self.dst_addr)

    def path_response(self):
        self._flush_receive_buffer()
        for data in self.handle.send_path_response():
            self.transmit(data, self.dst_addr)

    def initial_close(self):
        self._flush_receive_buffer()
        for data in self.handle.send_initial_close():
            self.transmit(data, self.dst_addr)

    def handshake_close(self):
        self._flush_receive_buffer()
        for data in self.handle.send_handshake_close():
            self.transmit(data, self.dst_addr)

    def onertt_ack(self):
        self._flush_receive_buffer()
        for data in self.handle.send_1rrt_ack():
            self.transmit(data, self.dst_addr)

    def onertt_close(self):
        self._flush_receive_buffer()
        for data in self.handle.send_1rtt_close():
            self.transmit(data, self.dst_addr)

    def new_connection_id(self):
        self._flush_receive_buffer()
        for data in self.handle.send_new_connectionid():
            self.transmit(data, self.dst_addr)

    def end_trace(self):
        self.handle.end_trace_file()
        # self.handle.end_trace()

    def reset(self):
        # self.handle.end_trace()
        self.handle.reset(self.dst_addr)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port += 1
        self.port = (self.port - self.origin_port) % 1000 + self.origin_port
        self.local_addr = (self.local, self.port)
        self.sock.bind(self.local_addr)

    def close_sock(self):
        self.sock.close()

    def _flush_receive_buffer(self, timeout=0.01):
        """ 清空接收缓冲区 """
        # readable, _, _ = select.select([self.sock], [], [], timeout)
        # if self.sock in readable:
        #     data, addr = self.sock.recvfrom(2048)
        pass
            # print(f"接收并丢弃缓冲区数据: {data} 来自 {addr}")
