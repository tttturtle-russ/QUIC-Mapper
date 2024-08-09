import ssl
import time

from protocol import *
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN


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
    # ip_address = socket.gethostbyname("http3-test.litespeedtech.com")
    dst_addr = ("www.taobao.com", 443) # server address
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=None) # CA certificate can be changed
    configuration.verify_mode = ssl.CERT_NONE # important for client disable CA verification
    quic_logger = QuicFileLogger(os.getcwd())
    configuration.quic_logger = quic_logger
    configuration.alpn_protocols = H3_ALPN  # Application Layer Protocol Negotiation
    handle = Handle(configuration=configuration)
    # 创建一个 UDP 端点
    local_addr = '0.0.0.0'
    local_port = 30000
    protocol = QUICClientProtocol(dst_addr, local_addr, handle, local_port=local_port)

    def receive():
        msg = protocol.datagram_received(timeout=1)

        if msg is None:
            # print('no data')
            return None
        # print('data yes')

        return msg

    def re():
        time_now = time.time()
        ping = False
        while 1:
            tmp = receive()
            print(tmp)

            if not tmp or ping:
                break
            if 'ping' in tmp:
                ping = True
            if time.time() - time_now > 1:
                break
        print('-' * 20)

    i = 0
    while 1:
        print('='*20 + 'reset' + '='*20)
        protocol.reset()

        # protocol.initial_close()
        # re()

        protocol.connect()
        re()
        protocol.initial_ack_packet()
        re()
        # protocol.path_challenge()
        # re()
        # protocol.path_challenge()
        # re()
        print('='*10 + 'handshake' + '=' * 10)
        protocol.handshake_packet()
        re()
        # protocol.initial_ack_packet()
        # re()
        time_now = time.time()
        while 1:
            re()
            if time.time() - time_now > 10:
                break

        # protocol.initial_ack_packet()
        # re()
        # protocol.handshake_packet()
        # re()
        # protocol.connect()
        # re()

        i = 0
        # while 1:
        #     protocol.path_challenge()
        #     re()
        #     i += 1
        #     if i > 1000:
        #         break

        # protocol.handshake_packet()
        # re()
        # while 1:
        #     re()
        # protocol.end_trace()
        break


main()