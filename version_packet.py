from typing import Optional, Dict, Union, Tuple, List

from aioquic.quic.packet import QuicProtocolVersion, QuicFrameType
from aioquic.quic.packet_builder import QuicPacketBuilderStop, QuicSentPacket

from packet import BasePacket, TYPE_MAP_TO_FUNCTION


class VersionNegotiationPacket(BasePacket):
    def __init__(self,
                 host_cid: Optional[bytes] = bytes(8),
                 peer_cid: Optional[bytes] = bytes(8),
                 is_client: Optional[bool] = False,
                 version: Optional[QuicProtocolVersion] = QuicProtocolVersion.NEGOTIATION,
                 peer_token: Optional[bytes] = b"",
                 packet_number: Optional[int] = 0
                 ):
        assert version == QuicProtocolVersion.NEGOTIATION
        super().__init__(version=version,
                         host_cid=host_cid,
                         peer_cid=peer_cid,
                         is_client=is_client,
                         peer_token=peer_token,
                         packet_number=packet_number)
        # TODO:can't found corresponding packet type in aioquic
        self.packet_type = None


