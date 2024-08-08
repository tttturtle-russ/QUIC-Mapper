import ssl
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion

from client_concretization import *
from logger import QuicLogger
from receive_data import Handle


class QUIC_Client:
    def __init__(self, configuration, dst_addr, local_addr, local_port, handle, timeout):
        self.configuration = configuration
        self.dst_addr = dst_addr
        self.local_addr = local_addr
        self.tool = QUICClientInferTool(configuration, dst_addr, local_addr, local_port, handle)
        # self.options = options
        self.learned = False
        self.CC = False
        self.timeout_set = timeout
        self.timeout_real = self.timeout_set
        self.pre_msg = None
        self.handshake_done = False


    def send_and_receive(self, symbols):
        if self.CC is True:
            return "CC"
        if self.handshake_done is True:
            return 'Done'
        try:
            self.tool.concretize_client_messages(symbols)
        except BrokenPipeError:
            return "EOF"
        except ConnectionResetError:
            return "EOF"
        # pylint: disable=broad-except
        except Exception as e:
            if str(e) == 'Encryption key is not available':
                pass
            else:
                print(e)
                return "INTERNAL ERROR DURING EMISSION"

        response = self.receive()
        if not response:
            return 'TIMEOUT'

        if response == 'ping':
            response = ''

        start_time = time.time()
        while 1:
            next_msg = self.receive()
            if next_msg == 'ping':
                # print('ping')
                next_msg = self.receive()
            if next_msg and next_msg != '' and next_msg != 'ping':
                if response != '':
                    response += ':' + next_msg
                else:
                    response = next_msg
            time_now = time.time()
            if time_now - start_time > self.timeout_set:
                next_msg = self.receive()
                if next_msg == 'ping':
                    # print('ping')
                    next_msg = self.receive()
                if next_msg and next_msg != '' and next_msg != 'ping':
                    if response != '':
                        response += ':' + next_msg
                    else:
                        response = next_msg
                break
            # self.pre_msg = next_msg

        if not response or response == '':
            return 'TIMEOUT'
        if 'handshake_done' in response:
            self.handshake_done = True
        return response

    def reset(self):
        # handle = Handle(configuration=self.configuration)
        # self.tool = QUICClientInferTool(self.configuration, self.dst_addr, self.local_addr, handle)
        self.tool.reset()
        self.CC = False
        self.handshake_done = False
        print('-' * 20)
        print('-'*10 + ' reset '+'-'*10)

    def receive(self):
        msg = self.tool.protocol.datagram_received(timeout=self.timeout_set)

        if msg is None:
            # print('no data')
            return None
        # print('data yes')
        if 'CC' in msg:
            self.CC = True

        return msg

    def close(self):
        self.tool.close()

def create_client(local_ip, local_port, dst_addr, timeout):
    # args = tls_args.parse_args(client_inference=False)
    configuration = QuicConfiguration()
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]  # QUIC version can be changed
    configuration.load_verify_locations(cadata=None, cafile=None)  # CA certificate can be changed
    configuration.verify_mode = ssl.CERT_NONE  # important for client disable CA verification

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    handle = Handle(configuration=configuration)
    configuration.alpn_protocols = ['h3']

    # dst_addr = (dst_ip, dst_port)
    client = QUIC_Client(configuration, dst_addr, local_ip, local_port, handle, timeout)
    return client
