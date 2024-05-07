import asyncio
from receive_data import *


class MyServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.handle = Handle(configuration=QuicConfiguration())
        # self.handle.connect()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # 使用你已有的 datagram_received 函数
        self.handle.receive_datagram(data, addr,now=0.0)
        # self.end_trace()

    def connect(self,addr):
        for datagram in self.handle.connect():
            self.transport.sendto(datagram, addr)

    def transmit(self, data, addr):
        self.transport.sendto(data, addr)

    def handshake_packet(self):
        return self.handle.send_handshake_packet()

    def end_trace(self):
        self.handle.end_trace_file()

async def main():
    loop = asyncio.get_running_loop()
    addr = ("127.0.0.1", 34986)
    # 创建一个 UDP 端点
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MyServerProtocol(),
        local_addr=("127.0.0.1", 10019))

    try:
        protocol.connect(addr)
        # while True:
        await asyncio.sleep(1)
        for data in protocol.handle.send_handshake_packet():
            protocol.transmit(data,addr)
        # protocol.transmit(protocol.handshake_packet(),addr)
# 每秒检查一次
    finally:
        transport.close()

asyncio.run(main())