import asyncio
from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *
from protocol import *
from aioquic.quic.configuration import QuicConfiguration


async def main():
    loop = asyncio.get_running_loop()
    addr = ("127.0.0.1", 10086)
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.DRAFT_32]
    configuration.load_verify_locations(cadata=None, cafile=SERVER_CACERTFILE)
    quic_logger = QuicFileLogger(os.getcwd())
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    # 创建一个 UDP 端点
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MyServerProtocol(addr, handle),
        local_addr=("127.0.0.1", 10035))

    try:
        protocol.connect()
        await protocol.handshake_done.wait()
        protocol.path_challenge()
        #
        protocol.path_response()
        #
        protocol.new_connection_id()

        # protocol.onertt_ack()
        # print('send 1rtt ack')

        # print('send close')

        await asyncio.sleep(1)
        # protocol.end_trace()
        # protocol.transmit(protocol.handshake_packet(),addr)
# 每秒检查一次
    finally:
        transport.close()

    transport_new, protocol = await loop.create_datagram_endpoint(
        lambda: MyServerProtocol(addr, handle),
        local_addr=("127.0.0.2", 10011))

    try:
        protocol.path_challenge()
    finally:
        transport_new.close()

asyncio.run(main())