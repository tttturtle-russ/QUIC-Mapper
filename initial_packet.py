from aioquic.quic.packet import PACKET_TYPE_INITIAL, QuicFrameType
from aioquic.quic.packet_builder import  QuicPacketBuilderStop, QuicSentPacket
from aioquic.asyncio.protocol import *
from aioquic.quic.configuration import *

from packet import BasePacket, TYPE_MAP_TO_FUNCTION


class InitialPacket(BasePacket):
    """
    Initial Packet is structured as follows:
    +-+-+-+-+-+-+-+-+
    |1|  Type (7)   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Version (32)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | DCIL (4) | SCIL (4) |                                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Destination Connection ID (0/32..144)           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Source Connection ID (0/32..144)              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Token Length (i)                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Token (*)                          ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Length (i)                          ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Packet Number (8/16/32)                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Payload (*)                          ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Here is an example of how to use this class:
    ```
        packet = InitialPacket(args...)
        data = {
            "int": "1",
            "bytes": b"hello"
        }
        # This is the packet 0
        packet.new_packet()
        packet.push_frame(QuicFrameType.CRYPTO, data)
        packet.push_frame(QuicFrameType.ACK, {"int", "0"})
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
        self.frames = []
        self.packet_type = PACKET_TYPE_INITIAL

    def push_frame(self, frame_type: QuicFrameType, data: Dict[str, Union[int, bytes]]):
        try:
            buffer = self.builder.start_frame(frame_type=frame_type)
            for _type, value in data.items():
                if _type not in TYPE_MAP_TO_FUNCTION:
                    raise ValueError(f"Type {_type} is not supported")
                TYPE_MAP_TO_FUNCTION[_type](buffer, value)
        except QuicPacketBuilderStop:
            raise ValueError("Packet is full")

    def build(self) -> Tuple[List[bytes], List[QuicSentPacket]]:
        return self.builder.flush()
