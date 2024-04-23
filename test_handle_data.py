from receive_data import *
from initial_packet import *
from aioquic.quic.packet import *
from aioquic.quic.packet_builder import *


def test_handle_data(data=Optional[bytes]):
    handle = Handle(configuration=QuicConfiguration())

    handle.receive_datagram(data, ('1.2.3.4',1234),now=0.0)


p = InitialPacket()
p.new_packet()
p.push_frame(QuicFrameType.CRYPTO, {"bytes": b"hello"})
p.new_packet()
p.push_frame(QuicFrameType.CRYPTO, {"bytes": b"world"})
datagrams, packets = p.build()

for datagram in datagrams:
    test_handle_data(data=datagram)