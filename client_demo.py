import asyncio
from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *
from protocol import *
from aioquic.quic.configuration import QuicConfiguration

QUANT_SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "dummy.ca.crt")


# async def start_quic_client(destination_addr, local_addr, handle):
#     loop = asyncio.get_running_loop()
#     transport, protocol = await loop.create_datagram_endpoint(
#         lambda: QUICClientProtocol(destination_addr, handle),
#         local_addr=local_addr)
#     return transport, protocol
#
#
# async def new_connection(old_transport, destination_addr, new_local_addr, handle):
#     old_transport.close()
#     loop = asyncio.get_running_loop()
#     transport, protocol = await loop.create_datagram_endpoint(
#         lambda: QUICClientProtocol(destination_addr, handle),
#         local_addr=new_local_addr)
#
#     return transport, protocol


def main():
    # loop = asyncio.get_running_loop()
    addr = ("172.17.0.2", 4433)
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=QUANT_SERVER_CACERTFILE)  # CA certificate can be changed
    quic_logger = QuicFileLogger(os.getcwd())
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    # 创建一个 UDP 端点
    local_addr = ("172.17.0.1", 10011)
    # transport, protocol = await start_quic_client(addr, local_addr, handle)
    # above is necessary
    protocol = QUICClientProtocol(addr, local_addr, handle)
    # try:
    protocol.reset()
    protocol.connect()
    protocol.datagram_received()
    # await asyncio.sleep(0.1)
    protocol.initial_ack_packet()
    protocol.datagram_received()
    # protocol.initial_close()
    protocol.handshake_packet()
    protocol.datagram_received()
    # protocol.connect()
    # protocol.datagram_received()
    # protocol.onertt_ack()
    # protocol.initial_ack_packet()
    # protocol.datagram_received()
    # await asyncio.sleep(0.1)
    # protocol.send_handshake_packet()
    # protocol.end_trace()
    # await protocol.handshake_done.wait()
    # protocol.path_challenge()
    # handle.reset(configuration)
    # print('reset\n')
    # protocol.connect()
    # protocol.datagram_received()
    # protocol.onertt_close()
    protocol.path_response()
    protocol.datagram_received()
    # #
    # protocol.path_response()
    # #
    # protocol.new_connection_id()
    protocol.end_trace()

    # protocol.onertt_ack()
    # print('send 1rtt ack')

    # print('send close')
    # protocol.end_trace()
    # protocol.transmit(protocol.handshake_packet(),addr)


# 每秒检查一次
#     finally:
# transport.close()
# transport_new, protocol = await loop.create_datagram_endpoint(
#     lambda: MyServerProtocol(addr, handle),
#     local_addr=("172.17.0.2", 10011))
#
# try:
#     # protocol.onertt_ack()
#     protocol.path_challenge()
# finally:
#     transport_new.close()
main()