from aioquic.quic.packet import PACKET_TYPE_INITIAL, QuicFrameType
from aioquic.quic.packet_builder import  QuicPacketBuilderStop, QuicSentPacket
from aioquic.asyncio.protocol import *
from aioquic.quic.configuration import *

from packet import BasePacket, TYPE_MAP_TO_FUNCTION


class InitialPacket(BasePacket):
    """
    Here is an example of how to use this class:
    ```
        packet = InitialPacket(args...)
        data = [("uint64", 123)]
        # This is the packet 0
        packet.new_packet()
        packet.push_frame(QuicFrameType.CRYPTO, data)
        packet.push_frame(QuicFrameType.ACK, [("uint16", 222)])
        # Packet 0 has 2 frames now

        # This is the packet 1
        packet.new_packet()
        packet.push_frame(QuicFrameType.CRYPTO, data)

        # Build all the packet and get the datagrams and packets
        datagrams, packets = packet.build()

        # datagrams is a list of bytes
        # packets is a list of QuicSentPacket
    ```
    """

    def __init__(
            self,
            host_cid: Optional[bytes] = bytes(8),
            peer_cid: Optional[bytes] = bytes(8),
            is_client: Optional[bool] = False,
            version: Optional[QuicProtocolVersion] = QuicProtocolVersion.VERSION_1,
            peer_token: Optional[bytes] = b"",
            packet_number: Optional[int] = 0,
    ):
        super().__init__(version=version,
                         host_cid=host_cid,
                         peer_cid=peer_cid,
                         is_client=is_client,
                         peer_token=peer_token,
                         packet_number=packet_number)
        self.packet_type = PACKET_TYPE_INITIAL


