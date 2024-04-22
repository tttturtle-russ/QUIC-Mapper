from packet import BasePacket
from aioquic.quic.packet import QuicProtocolVersion, PACKET_TYPE_ZERO_RTT
from typing import Optional


class ZeroRTTPacket(BasePacket):
    def __init__(self,
                 host_cid: Optional[bytes] = bytes(8),
                 peer_cid: Optional[bytes] = bytes(8),
                 is_client: Optional[bool] = False,
                 version: Optional[QuicProtocolVersion] = QuicProtocolVersion.VERSION_1,
                 peer_token: Optional[bytes] = b"",
                 packet_number: Optional[int] = 0
                 ):
        super().__init__(version=version,
                         host_cid=host_cid,
                         peer_cid=peer_cid,
                         is_client=is_client,
                         peer_token=peer_token,
                         packet_number=packet_number)
        self.packet_type = PACKET_TYPE_ZERO_RTT
