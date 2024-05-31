import asyncio
from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *
from protocol import *
from aioquic.quic.configuration import QuicConfiguration

QUANT_SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "dummy.ca.crt")

async def start_quic_client(destination_addr, local_addr, handle):
    loop = asyncio.get_running_loop()
    # configuration = QuicConfiguration()
    # configuration.supported_versions = [QuicProtocolVersion.VERSION_1]
    # configuration.load_verify_locations(cadata=None, cafile=server_ca_certfile)
    # quic_logger = QuicFileLogger(quic_logger_path)
    # configuration.quic_logger = quic_logger
    # handle = Handle(configuration=configuration)

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QUICClientProtocol(destination_addr, handle),
        local_addr=local_addr)
    return transport, protocol


async def main():
    # loop = asyncio.get_running_loop()
    addr = ("127.0.0.1", 4433)
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1] # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=QUANT_SERVER_CACERTFILE) # CA certificate can be changed
    quic_logger = QuicFileLogger(os.getcwd())
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    # 创建一个 UDP 端点
    local_addr = ("127.0.0.2", 10011)
    transport, protocol = await start_quic_client(addr, local_addr, handle)
    # above is necessary

    try:
        protocol.connect()
        await asyncio.sleep(0.1)
        protocol.initial_ack_packet()
        protocol.initial_close()
        protocol.handshake_packet()

        await asyncio.sleep(0.1)
        # protocol.send_handshake_packet()
        # protocol.end_trace()
        # await protocol.handshake_done.wait()
        # protocol.path_challenge()
        # #
        # protocol.path_response()
        # #
        # protocol.new_connection_id()
        protocol.end_trace()

        # protocol.onertt_ack()
        # print('send 1rtt ack')

        # print('send close')

        await asyncio.sleep(1)
        # protocol.end_trace()
        # protocol.transmit(protocol.handshake_packet(),addr)
# 每秒检查一次
    finally:
        transport.close()

    # transport_new, protocol = await loop.create_datagram_endpoint(
    #     lambda: MyServerProtocol(addr, handle),
    #     local_addr=("172.17.0.2", 10011))
    #
    # try:
    #     # protocol.onertt_ack()
    #     protocol.path_challenge()
    # finally:
    #     transport_new.close()

asyncio.run(main())