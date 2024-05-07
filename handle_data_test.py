from receive_data import *
from initial_packet import *
from handshake_packet import *
from aioquic.quic.packet import *
from aioquic.quic.packet_builder import *

from utils import *
from cryptography.hazmat.primitives import serialization


SERVER_CACERTFILE = os.path.join(os.path.dirname(__file__), "pycacert.pem")

# def test_handle_data(data=b''):
#     # print(handle._cryptos.keys())
#     # print(handle._cryptos[tls.Epoch.ONE_RTT])
#     if data is None:
#         return
#     handle.receive_datagram(data, ('1.2.3.4',1234),now=0.0)

class SimpleClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, addr):
        self.message = message
        self.addr = addr

    def connection_made(self, transport):
        transport.sendto(self.message, self.addr)

def send_datagrams(datagrams, addr):
    loop = asyncio.get_event_loop()
    for datagram in datagrams:
        connect = loop.create_datagram_endpoint(
            lambda: SimpleClientProtocol(datagram, addr),
            remote_addr=addr)
        transport, protocol = loop.run_until_complete(connect)
        transport.close()
    loop.close()



packet = InitialPacket(
    host_cid=b'\x11'*8,
    peer_cid=b'\x22'*8,
    is_client=True,
    version=QuicProtocolVersion.VERSION_1,
    peer_token=b'',
    packet_number=0
)
# packet = HandshakePacket()
data = [("uint64", 123)]
# This is the packet 0
packet.new_packet()
packet.push_frame(QuicFrameType.CRYPTO, data)
packet.push_frame(QuicFrameType.ACK, [("uint16", 222)])
# Packet 0 has 2 frames now

# This is the packet 1
# packet.new_packet()
# packet.push_frame(QuicFrameType.PADDING, data)

# Build all the packet and get the datagrams and packets
# datagrams, packets = packet.build()

certificate, private_key = generate_rsa_certificate(
    alternative_names=["localhost", "127.0.0.1"], common_name="localhost"
)


configuration = QuicConfiguration(is_client=True)
configuration.load_verify_locations(cadata=certificate.public_bytes(serialization.Encoding.PEM), cafile=SERVER_CACERTFILE)
configuration.server_name = '127.0.0.1'
handle = Handle(configuration=configuration)
datagrams = handle.connect()

# handle.initialize(b'\x11'*8)

# for datagram in datagrams:
#     test_handle_data(data=datagram)
#
addr = ('127.0.0.1', 43023)
# handle.receive_datagram(datagrams[0], addr, now=0.0)
send_datagrams(datagrams, addr)

# for data,add in handle.datagrams_to_send(0.0):
#     print(data)
#     send_datagrams(data, addr)

# builder = QuicPacketBuilder(
#     host_cid=b'12345678',
#     is_client=True,
#     packet_number=0,
#     peer_cid=b'87654321',
#     peer_token=b'',
#     version=QuicProtocolVersion.VERSION_1,
# )


# handle.end_trace_file()