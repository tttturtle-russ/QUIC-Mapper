import asyncio
import time

from aioquic.quic.packet import *
from aioquic.buffer import *
from receive_data import *
from protocol import *
from aioquic.quic.configuration import QuicConfiguration

QUANT_SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "server.crt")
AIOQUIC_SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "pycacert.pem")
QUICHE_SERVER_CACERTFILE = os.path.join(os.getcwd(), "vertify", "cert.key")


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

def _get_datagrams(file_path):
    datagrams = []
    with open(file_path, "rb") as f:
        while True:
            length_bytes = f.read(4)
            if not length_bytes:
                break
            length = int.from_bytes(length_bytes, 'big')
            datagram = f.read(length)
            if not datagram:
                break
            datagrams.append(datagram)
    return datagrams





def main():
    # loop = asyncio.get_running_loop()
    dst_addr = ("172.17.0.6", 4433)
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=None)  # CA certificate can be changed
    quic_logger = QuicFileLogger(os.getcwd())
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    # 创建一个 UDP 端点
    local_addr = '172.17.0.1'
    local_port = 20000
    # transport, protocol = await start_quic_client(addr, local_addr, handle)
    # above is necessary
    protocol = QUICClientProtocol(dst_addr, local_addr, handle, local_port=local_port)

    def receive():
        msg = protocol.datagram_received()

        if msg is None:
            # print('no data')
            return None
        # print('data yes')

        return msg

    def re():
        time_now = time.time()
        while 1:
            tmp = receive()
            print(tmp)
            if not tmp:
                break
        print('-' * 20)

    i = 0
    while 1:
        print('='*20 + 'reset' + '='*20)
        protocol.reset()
        # protocol.handshake_close()
        time_now = time.time()
        # re()

        protocol.connect()
        # time_now = time.time()
        re()

        # protocol.initial_ack_packet()
        # time_now = time.time()
        # re()

        # protocol.path_challenge()
        # re()

        # protocol.connect()
        # re()

        protocol.connect()
        re()

        protocol.handshake_packet()
        re()

        protocol.path_challenge()
        re()
        # time_now = time.time()
        # while 1:
        #     tmp = receive()
        #     print(tmp)
        #     end_time = time.time()
        #     if end_time - time_now > 20:
        #         break
        # protocol.end_trace()
    return
    # try:
    while 1:
        protocol.reset()
        protocol.connect()
        # time.sleep(1)
        start_time = time.time()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)
        # datagrams = _get_datagrams('bin/onertt_close.bin')
        # tmp = protocol.handle.receive_datagram(datagrams[0], dst_addr, now=0.0)
        # print(tmp)
        protocol.initial_ack_packet()
        # start_time = time.time()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)
        protocol.initial_ack_packet()
        start_time = time.time()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)

        protocol.initial_ack_packet()
        start_time = time.time()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)

        protocol.initial_ack_packet()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)

        protocol.connect()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)

        protocol.initial_ack_packet()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)

        protocol.initial_ack_packet()
        while 1:
            # end_time = time.time()
            tmp = receive()
            if not tmp:
                break
            print(tmp)

        print('-' * 10 + 'end' + '-' * 10)
        protocol.close_sock()
        print('-'*10 + 'END' + '-'*10)
        print('-'*30)
        i += 1
        if i == 10:
            break
    # time.sleep(1)
    # while protocol.datagram_received() is None:
    #     pass
    # # protocol.handshake_close()
    # # protocol.initial_close()
    # while 1:
    #     tmp = protocol.datagram_received()
    #     if tmp is not None:
    #         print(tmp)
    #     else:
    #         break
    # protocol.end_trace()

    # await asyncio.sleep(0.1)
    # protocol.reset()
    # protocol.connect()
    # protocol.initial_ack_packet()
    # protocol.datagram_received()
    # protocol.end_trace()
    # protocol.close_sock()
    # protocol.reset()
    # protocol.connect()
    # protocol.datagram_received()
    # protocol.end_trace()
    # protocol.initial_close()
    # protocol.handshake_packet()
    # protocol.datagram_received()

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
    # protocol.path_response()
    # protocol.datagram_received()
    # #
    # protocol.path_response()
    # #
    # protocol.new_connection_id()
    # protocol.end_trace()

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
