from typing import Optional, Tuple, List, Dict, Union

from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicProtocolVersion, QuicFrameType
from aioquic.quic.packet_builder import QuicPacketBuilder, QuicSentPacket, QuicPacketBuilderStop


def push_bytes(buffer, data: bytes):
    buffer.push_bytes(data)


def push_uint8(buffer, data: int):
    buffer.push_uint8(data)


def push_uint16(buffer, data: int):
    buffer.push_uint16(data)


def push_uint32(buffer, data: int):
    buffer.push_uint32(data)


def push_uint64(buffer, data: int):
    buffer.push_uint64(data)


def push_varint(buffer, data: int):
    buffer.push_uint_var(data)


TYPE_MAP_TO_FUNCTION = {
    "bytes": push_bytes,
    "uint8": push_uint8,
    "uint16": push_uint16,
    "uint32": push_uint32,
    "uint64": push_uint64,
    "varint": push_varint
}


class BasePacket:
    """
    This is the base packet model for all the packets
    Any packet should inherit from this class and implement the push_frame and build methods
    """
    def __init__(self,
                 host_cid: Optional[bytes] = bytes(8),
                 peer_cid: Optional[bytes] = bytes(8),
                 is_client: Optional[bool] = False,
                 version: Optional[QuicProtocolVersion] = QuicProtocolVersion.VERSION_1,
                 peer_token: Optional[bytes] = b"",
                 packet_number: Optional[int] = 0
                 ):
        self.version = version
        self.peer = peer_cid
        self.host = host_cid
        self.peer_token = peer_token
        self.packet_number = packet_number
        self.is_client = is_client
        self.packet_type = None
        self._builder = QuicPacketBuilder(
            host_cid=self.host,
            peer_cid=self.peer,
            is_client=self.is_client,
            max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
            packet_number=self.packet_number,
            peer_token=self.peer_token,
            spin_bit=False,
            version=self.version,
        )
        self._crypto = self._create_crypto()

    def _create_crypto(self) -> CryptoPair:
        crypto = CryptoPair()
        if self.is_client:
            cid = self.host
        else:
            cid = self.peer
        crypto.setup_initial(
            cid, is_client=self.is_client, version=self.version
        )
        return crypto

    def new_packet(self):
        if self.packet_type is None:
            raise ValueError("Packet type is not set")
        self._builder.start_packet(packet_type=self.packet_type, crypto=self._crypto)

    def push_frame(self, frame_type: QuicFrameType, data: List[Tuple[str, Union[int, bytes]]]):
        """
        Push a frame to the packet
        """
        try:
            buffer = self._builder.start_frame(frame_type=frame_type)
            for _type, value in data:
                if _type not in TYPE_MAP_TO_FUNCTION:
                    raise ValueError(f"Unknown type {_type}")
                TYPE_MAP_TO_FUNCTION[_type](buffer, value)
        except QuicPacketBuilderStop:
            raise ValueError("Not enough space to push frame")
        except Exception as e:
            raise RuntimeError(f"Error when pushing frame: {e}")

    def build(self) -> Tuple[List[bytes], List[QuicSentPacket]]:
        """
        Build the packet
        """
        return self._builder.flush()
