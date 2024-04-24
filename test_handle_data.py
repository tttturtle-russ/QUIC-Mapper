from receive_data import *
from initial_packet import *
from aioquic.quic.packet import *
from aioquic.quic.packet_builder import *


def test_handle_data(data=Optional[bytes]):
    handle = Handle(configuration=QuicConfiguration())
    handle.initialize(b'')
    handle.receive_datagram(data, ('1.2.3.4',1234),now=0.0)


packet = InitialPacket()
data = [("uint64", 123)]
# This is the packet 0
packet.new_packet()
packet.push_frame(QuicFrameType.PING, data)
packet.push_frame(QuicFrameType.ACK, [("uint16", 222)])
# Packet 0 has 2 frames now

# This is the packet 1
packet.new_packet()
packet.push_frame(QuicFrameType.PADDING, data)

# Build all the packet and get the datagrams and packets
datagrams, packets = packet.build()

# def create_builder(is_client=False):
#     return QuicPacketBuilder(
#         host_cid=bytes(8),
#         is_client=is_client,
#         max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
#         packet_number=0,
#         peer_cid=bytes(8),
#         peer_token=b"",
#         spin_bit=False,
#         version=QuicProtocolVersion.VERSION_1,
#     )
#
#
# def create_crypto():
#     crypto = CryptoPair()
#     crypto.setup_initial(
#         bytes(8), is_client=True, version=QuicProtocolVersion.VERSION_1
#     )
#     return crypto
#
#
# builder = create_builder(is_client=True)
# crypto = create_crypto()
#
# # INITIAL, fully padded
# builder.start_packet(PACKET_TYPE_INITIAL, crypto)
#
# buf = builder.start_frame(QuicFrameType.CRYPTO)
# buf.push_bytes(bytes(100))
# datagrams, packets = builder.flush()

for datagram in datagrams:
    test_handle_data(data=datagram)