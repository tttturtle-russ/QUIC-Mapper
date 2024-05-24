import asyncio
from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *

SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "pycacert.pem")

class MyServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        configuration = QuicConfiguration()
        configuration.supported_versions = [QuicProtocolVersion.DRAFT_32]
        configuration.load_verify_locations(cadata=None,cafile=SERVER_CACERTFILE)
        self.handle = Handle(configuration=configuration)
        self._handshake_confirm = False
        self._handshake_done = False
        # self.handle.connect()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # 使用你已有的 datagram_received 函数
        # data_pre = data
        self.handle.receive_datagram(data, addr, now=0.0)
        # print("data received")
        buf = Buffer(data=data)
        header = pull_quic_header(buf,8)
        if header.packet_type == PACKET_TYPE_INITIAL and self._handshake_confirm is False:
            self._handshake_confirm = True
            for datagram in self.handle.send_initial_ack_packet():
                self.transmit(datagram, addr)
        if header.packet_type == PACKET_TYPE_HANDSHAKE and self._handshake_done is False:
            # self._handshake_done = True
            for datagram in (self.handle.send_handshake_packet() or []):
                self.transmit(datagram, addr)

        # self.end_trace()

    def connect(self,addr):
        for datagram in self.handle.connect(addr):
            self.transport.sendto(datagram, addr)

    def transmit(self, data, addr):
        self.transport.sendto(data, addr)

    def handshake_packet(self):
        return self.handle.send_handshake_packet()

    def path_challenge(self):
        return self.handle.send_path_challenge()

    def path_response(self):
        return self.handle.send_path_response()

    def initial_close(self):
        return self.handle.send_initial_packet()

    def handshake_close(self):
        return self.handle.send_handshake_close()

    def onertt_close(self):
        return self.handle.send_1rtt_close()

    def new_connection_id(self):
        return self.handle.send_new_connectionid()

    def end_trace(self):
        self.handle.end_trace_file()

async def main():
    loop = asyncio.get_running_loop()
    addr = ("127.0.0.1", 10086)
    # 创建一个 UDP 端点
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MyServerProtocol(),
        local_addr=("127.0.0.1", 10023))

    try:
        protocol.connect(addr)
        # while True:
        # await asyncio.sleep(1)
        # for data in protocol.handle.send_handshake_packet():
        #     protocol.transmit(data,addr)
        # while True:
        await asyncio.sleep(2)
        # protocol.handle.request_key_update()
        for data in protocol.path_challenge():
            protocol.transmit(data, addr)
        #
        for data in protocol.path_response():
            protocol.transmit(data, addr)
        #
        for data in protocol.new_connection_id():
            protocol.transmit(data, addr)

        for data in protocol.onertt_close():
            protocol.transmit(data, addr)
        print('send close')

        await asyncio.sleep(1)
        protocol.end_trace()
        # protocol.transmit(protocol.handshake_packet(),addr)
# 每秒检查一次
    finally:
        transport.close()

asyncio.run(main())