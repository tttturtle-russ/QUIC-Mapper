import binascii
import logging
import os
from collections import deque
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from aioquic import tls
from aioquic.buffer import (
    UINT_VAR_MAX,
    UINT_VAR_MAX_SIZE,
    Buffer,
    BufferReadError,
    size_uint_var,
)
from aioquic.quic import events
from aioquic.quic.configuration import (SMALLEST_MAX_DATAGRAM_SIZE, QuicConfiguration)
from aioquic.quic.congestion.base import K_GRANULARITY
from aioquic.quic.crypto import CryptoError, CryptoPair, KeyUnavailableError
from aioquic.quic.logger import QuicLoggerTrace
from aioquic.quic.packet import (
    CONNECTION_ID_MAX_SIZE,
    NON_ACK_ELICITING_FRAME_TYPES,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ONE_RTT,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ZERO_RTT,
    PROBING_FRAME_TYPES,
    RETRY_INTEGRITY_TAG_SIZE,
    STATELESS_RESET_TOKEN_SIZE,
    QuicErrorCode,
    QuicFrameType,
    QuicProtocolVersion,
    QuicStreamFrame,
    QuicTransportParameters,
    get_retry_integrity_tag,
    get_spin_bit,
    is_draft_version,
    is_long_header,
    pull_ack_frame,
    pull_quic_header,
    pull_quic_transport_parameters,
    push_ack_frame,
    push_quic_transport_parameters,
)
from aioquic.quic.packet_builder import (
    QuicDeliveryState,
    QuicPacketBuilder,
    QuicPacketBuilderStop,
)
from aioquic.quic.recovery import QuicPacketRecovery, QuicPacketSpace
from aioquic.quic.stream import FinalSizeError, QuicStream, StreamFinishedError

NetworkAddress = Any
CRYPTO_BUFFER_SIZE = 16384
MAX_EARLY_DATA = 0xFFFFFFFF
STREAM_FLAGS = 0x07
STREAM_COUNT_MAX = 0x1000000000000000
UDP_HEADER_SIZE = 8
MAX_PENDING_RETIRES = 100

EPOCH_SHORTCUTS = {
    "I": tls.Epoch.INITIAL,
    "H": tls.Epoch.HANDSHAKE,
    "0": tls.Epoch.ZERO_RTT,
    "1": tls.Epoch.ONE_RTT,
}

class QuicConnectionError(Exception):
    def __init__(self, error_code: int, frame_type: int, reason_phrase: str):
        self.error_code = error_code
        self.frame_type = frame_type
        self.reason_phrase = reason_phrase

    def __str__(self) -> str:
        s = "Error: %d, reason: %s" % (self.error_code, self.reason_phrase)
        if self.frame_type is not None:
            s += ", frame_type: %s" % self.frame_type
        return s

class Limit:
    def __init__(self, frame_type: int, name: str, value: int):
        self.frame_type = frame_type
        self.name = name
        self.sent = value
        self.used = 0
        self.value = value

@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: int
    stateless_reset_token: bytes = b""
    was_sent: bool = False

@dataclass
class QuicReceiveContext:
    epoch: tls.Epoch
    host_cid: bytes
    # network_path: QuicNetworkPath
    quic_logger_frames: Optional[List[Any]]
    time: float

def EPOCHS(shortcut: str) -> FrozenSet[tls.Epoch]:
    return frozenset(EPOCH_SHORTCUTS[i] for i in shortcut)


def dump_cid(cid: bytes) -> str:
    return binascii.hexlify(cid).decode("ascii")


def get_epoch(packet_type: int) -> tls.Epoch:
    if packet_type == PACKET_TYPE_INITIAL:
        return tls.Epoch.INITIAL
    elif packet_type == PACKET_TYPE_ZERO_RTT:
        return tls.Epoch.ZERO_RTT
    elif packet_type == PACKET_TYPE_HANDSHAKE:
        return tls.Epoch.HANDSHAKE
    else:
        return tls.Epoch.ONE_RTT


QuicTokenHandler = Callable[[bytes], None]

# END_STATES = frozenset(
#     [
#         QuicConnectionState.CLOSING,
#         QuicConnectionState.DRAINING,
#         QuicConnectionState.TERMINATED,
#     ]
# )

def get_transport_parameters_extension(version: int) -> tls.ExtensionType:
    if is_draft_version(version):
        return tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS_DRAFT
    else:
        return tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS

class Handle:
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: Optional[bytes] = None,
        retry_source_connection_id: Optional[bytes] = None,
        session_ticket_fetcher: Optional[tls.SessionTicketFetcher] = None,
        session_ticket_handler: Optional[tls.SessionTicketHandler] = None,
        token_handler: Optional[QuicTokenHandler] = None,
    ) -> None:
        assert configuration.max_datagram_size >= SMALLEST_MAX_DATAGRAM_SIZE, (
            "The smallest allowed maximum datagram size is "
            f"{SMALLEST_MAX_DATAGRAM_SIZE} bytes"
        )
        if configuration.is_client:
            assert (
                original_destination_connection_id is None
            ), "Cannot set original_destination_connection_id for a client"
            assert (
                retry_source_connection_id is None
            ), "Cannot set retry_source_connection_id for a client"

        # configuration
        self._configuration = configuration
        self._is_client = True
        #
        # self._ack_delay = K_GRANULARITY
        # self._close_at: Optional[float] = None
        # self._close_event: Optional[events.ConnectionTerminated] = None
        # self._connect_called = False
        self._cryptos: Dict[tls.Epoch, CryptoPair] = {}
        self._crypto_buffers: Dict[tls.Epoch, Buffer] = {}
        self._crypto_retransmitted = False
        self._crypto_streams: Dict[tls.Epoch, QuicStream] = {}
        # self._events: Deque[events.QuicEvent] = deque()
        # self._handshake_complete = False
        # self._handshake_confirmed = False

        self._host_cids = [
            QuicConnectionId(
                cid=os.urandom(configuration.connection_id_length),
                sequence_number=0,
                stateless_reset_token=os.urandom(16) if not self._is_client else None,
                was_sent=True,
            )
        ]
        self.host_cid = self._host_cids[0].cid
        self._host_cid_seq = 1
        self._local_ack_delay_exponent = 3
        self._local_active_connection_id_limit = 8
        self._local_initial_source_connection_id = self._host_cids[0].cid
        self._local_max_data = Limit(
            frame_type=QuicFrameType.MAX_DATA,
            name="max_data",
            value=configuration.max_data,
        )
        self._local_max_stream_data_bidi_local = configuration.max_stream_data
        self._local_max_stream_data_bidi_remote = configuration.max_stream_data
        self._local_max_stream_data_uni = configuration.max_stream_data
        self._local_max_streams_bidi = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_BIDI,
            name="max_streams_bidi",
            value=128,
        )
        self._local_max_streams_uni = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_UNI, name="max_streams_uni", value=128
        )
        self._local_next_stream_id_bidi = 0 if self._is_client else 1
        self._local_next_stream_id_uni = 2 if self._is_client else 3
        self._loss_at: Optional[float] = None
        self._max_datagram_size = configuration.max_datagram_size
        # self._network_paths: List[QuicNetworkPath] = []
        self._pacing_at: Optional[float] = None
        self._packet_number = 0
        self._parameters_received = False
        self._peer_cid = QuicConnectionId(
            cid=os.urandom(configuration.connection_id_length), sequence_number=None
        )
        self._peer_cid_available: List[QuicConnectionId] = []
        self._peer_cid_sequence_numbers: Set[int] = set([0])
        self._peer_retire_prior_to = 0
        self._peer_token = configuration.token
        self._quic_logger: Optional[QuicLoggerTrace] = None
        # self._remote_ack_delay_exponent = 3
        # self._remote_active_connection_id_limit = 2
        # self._remote_initial_source_connection_id: Optional[bytes] = None
        # self._remote_max_idle_timeout: Optional[float] = None  # seconds
        # self._remote_max_data = 0
        # self._remote_max_data_used = 0
        # self._remote_max_datagram_frame_size: Optional[int] = None
        # self._remote_max_stream_data_bidi_local = 0
        # self._remote_max_stream_data_bidi_remote = 0
        # self._remote_max_stream_data_uni = 0
        # self._remote_max_streams_bidi = 0
        # self._remote_max_streams_uni = 0
        self._retry_count = 0
        self._retry_source_connection_id = retry_source_connection_id
        self._spaces: Dict[tls.Epoch, QuicPacketSpace] = {}
        self._spin_bit = False
        self._spin_highest_pn = 0
        # self._state = QuicConnectionState.FIRSTFLIGHT
        # self._streams: Dict[int, QuicStream] = {}
        # self._streams_queue: List[QuicStream] = []
        # self._streams_blocked_bidi: List[QuicStream] = []
        # self._streams_blocked_uni: List[QuicStream] = []
        # self._streams_finished: Set[int] = set()
        self._version: Optional[int] = None
        self._version_negotiation_count = 0

        if self._is_client:
            self._original_destination_connection_id = self._peer_cid.cid

        # logging
        # self._logger = QuicConnectionAdapter(
        #     logger, {"id": dump_cid(self._original_destination_connection_id)}
        # )
        # if configuration.quic_logger:
        #     self._quic_logger = configuration.quic_logger.start_trace(
        #         is_client=configuration.is_client,
        #         odcid=self._original_destination_connection_id,
        #     )

        # loss recovery
        # self._loss = QuicPacketRecovery(
        #     congestion_control_algorithm=configuration.congestion_control_algorithm,
        #     initial_rtt=configuration.initial_rtt,
        #     max_datagram_size=self._max_datagram_size,
        #     peer_completed_address_validation=not self._is_client,
        #     quic_logger=self._quic_logger,
        #     send_probe=self._send_probe,
        #     logger=self._logger,
        # )

        # things to send
        # self._close_pending = False
        # self._datagrams_pending: Deque[bytes] = deque()
        # self._handshake_done_pending = False
        # self._ping_pending: List[int] = []
        # self._probe_pending = False
        # self._retire_connection_ids: List[int] = []
        # self._streams_blocked_pending = False
        #
        # # callbacks
        # self._session_ticket_fetcher = session_ticket_fetcher
        # self._session_ticket_handler = session_ticket_handler
        # self._token_handler = token_handler

        # frame handlers
        self.__frame_handlers = {
            0x00: (self._handle_padding_frame, EPOCHS("IH01")),
            0x01: (self._handle_ping_frame, EPOCHS("IH01")),
            0x02: (self._handle_ack_frame, EPOCHS("IH1")),
            0x03: (self._handle_ack_frame, EPOCHS("IH1")),
            0x04: (self._handle_reset_stream_frame, EPOCHS("01")),
            0x05: (self._handle_stop_sending_frame, EPOCHS("01")),
            0x06: (self._handle_crypto_frame, EPOCHS("IH1")),
            0x07: (self._handle_new_token_frame, EPOCHS("1")),
            0x08: (self._handle_stream_frame, EPOCHS("01")),
            0x09: (self._handle_stream_frame, EPOCHS("01")),
            0x0A: (self._handle_stream_frame, EPOCHS("01")),
            0x0B: (self._handle_stream_frame, EPOCHS("01")),
            0x0C: (self._handle_stream_frame, EPOCHS("01")),
            0x0D: (self._handle_stream_frame, EPOCHS("01")),
            0x0E: (self._handle_stream_frame, EPOCHS("01")),
            0x0F: (self._handle_stream_frame, EPOCHS("01")),
            0x10: (self._handle_max_data_frame, EPOCHS("01")),
            0x11: (self._handle_max_stream_data_frame, EPOCHS("01")),
            0x12: (self._handle_max_streams_bidi_frame, EPOCHS("01")),
            0x13: (self._handle_max_streams_uni_frame, EPOCHS("01")),
            0x14: (self._handle_data_blocked_frame, EPOCHS("01")),
            0x15: (self._handle_stream_data_blocked_frame, EPOCHS("01")),
            0x16: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x17: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x18: (self._handle_new_connection_id_frame, EPOCHS("01")),
            0x19: (self._handle_retire_connection_id_frame, EPOCHS("01")),
            0x1A: (self._handle_path_challenge_frame, EPOCHS("01")),
            0x1B: (self._handle_path_response_frame, EPOCHS("01")),
            0x1C: (self._handle_connection_close_frame, EPOCHS("IH01")),
            0x1D: (self._handle_connection_close_frame, EPOCHS("01")),
            0x1E: (self._handle_handshake_done_frame, EPOCHS("1")),
            0x30: (self._handle_datagram_frame, EPOCHS("01")),
            0x31: (self._handle_datagram_frame, EPOCHS("01")),
        }

    def receive_datagram(self, data: bytes, addr: NetworkAddress, now: float) -> None:
        """
        Handle an incoming datagram.

        .. aioquic_transmit::

        :param data: The datagram which was received.
        :param addr: The network address from which the datagram was received.
        :param now: The current time.
        """

        # log datagram
        # if self._quic_logger is not None:
        #     payload_length = len(data)
        #     self._quic_logger.log_event(
        #         category="transport",
        #         event="datagrams_received",
        #         data={
        #             "count": 1,
        #             "raw": [
        #                 {
        #                     "length": UDP_HEADER_SIZE + payload_length,
        #                     "payload_length": payload_length,
        #                 }
        #             ],
        #         },
        #     )

        # for servers, arm the idle timeout on the first datagram
        # if self._close_at is None:
        #     self._close_at = now + self._idle_timeout()

        buf = Buffer(data=data)
        while not buf.eof():
            start_off = buf.tell()
            try:
                header = pull_quic_header(
                    buf, host_cid_length=self._configuration.connection_id_length
                )
            except ValueError:
                # if self._quic_logger is not None:
                #     self._quic_logger.log_event(
                #         category="transport",
                #         event="packet_dropped",
                #         data={
                #             "trigger": "header_parse_error",
                #             "raw": {"length": buf.capacity - start_off},
                #         },
                #     )
                return

            # RFC 9000 section 14.1 requires servers to drop all initial packets
            # # contained in a datagram smaller than 1200 bytes.
            # if (
            #         not self._is_client
            #         and header.packet_type == PACKET_TYPE_INITIAL
            #         and len(data) < SMALLEST_MAX_DATAGRAM_SIZE
            # ):
            #     if self._quic_logger is not None:
            #         self._quic_logger.log_event(
            #             category="transport",
            #             event="packet_dropped",
            #             data={
            #                 "trigger": "initial_packet_datagram_too_small",
            #                 "raw": {"length": buf.capacity - start_off},
            #             },
            #         )
            #     return

            # check destination CID matches
            # destination_cid_seq: Optional[int] = None
            # for connection_id in self._host_cids:
            #     if header.destination_cid == connection_id.cid:
            #         destination_cid_seq = connection_id.sequence_number
            #         break
            # if (
            #         self._is_client or header.packet_type == PACKET_TYPE_HANDSHAKE
            # ) and destination_cid_seq is None:
            #     if self._quic_logger is not None:
            #         self._quic_logger.log_event(
            #             category="transport",
            #             event="packet_dropped",
            #             data={"trigger": "unknown_connection_id"},
            #         )
                # return

            # # check protocol version
            # if (
            #         self._is_client
            #         and self._state == QuicConnectionState.FIRSTFLIGHT
            #         and header.version == QuicProtocolVersion.NEGOTIATION
            #         and not self._version_negotiation_count
            # ):
            #     # version negotiation
            #     versions = []
            #     while not buf.eof():
            #         versions.append(buf.pull_uint32())
            #     if self._quic_logger is not None:
            #         self._quic_logger.log_event(
            #             category="transport",
            #             event="packet_received",
            #             data={
            #                 "frames": [],
            #                 "header": {
            #                     "packet_type": "version_negotiation",
            #                     "scid": dump_cid(header.source_cid),
            #                     "dcid": dump_cid(header.destination_cid),
            #                 },
            #                 "raw": {"length": buf.tell() - start_off},
            #             },
            #         )
            #     if self._version in versions:
            #         self._logger.warning(
            #             "Version negotiation packet contains %s" % self._version
            #         )
            #         return
            #     common = [
            #         x for x in self._configuration.supported_versions if x in versions
            #     ]
            #     chosen_version = common[0] if common else None
            #     if self._quic_logger is not None:
            #         self._quic_logger.log_event(
            #             category="transport",
            #             event="version_information",
            #             data={
            #                 "server_versions": versions,
            #                 "client_versions": self._configuration.supported_versions,
            #                 "chosen_version": chosen_version,
            #             },
            #         )
            #     if chosen_version is None:
            #         self._logger.error("Could not find a common protocol version")
            #         self._close_event = events.ConnectionTerminated(
            #             error_code=QuicErrorCode.INTERNAL_ERROR,
            #             frame_type=QuicFrameType.PADDING,
            #             reason_phrase="Could not find a common protocol version",
            #         )
            #         self._close_end()
            #         return
            #     self._packet_number = 0
            #     self._version = QuicProtocolVersion(chosen_version)
            #     self._version_negotiation_count += 1
            #     self._logger.info("Retrying with %s", self._version)
            #     self._connect(now=now)
            #     return
            # elif (
            #         header.version is not None
            #         and header.version not in self._configuration.supported_versions
            # ):
            #     # unsupported version
            #     if self._quic_logger is not None:
            #         self._quic_logger.log_event(
            #             category="transport",
            #             event="packet_dropped",
            #             data={"trigger": "unsupported_version"},
            #         )
            #     return

            # handle retry packet
            # if header.packet_type == PACKET_TYPE_RETRY:
            #     if (
            #             self._is_client
            #             and not self._retry_count
            #             and header.destination_cid == self.host_cid
            #             and header.integrity_tag
            #             == get_retry_integrity_tag(
            #         buf.data_slice(
            #             start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
            #         ),
            #         self._peer_cid.cid,
            #         version=header.version,
            #     )
            #     ):
            #         if self._quic_logger is not None:
            #             self._quic_logger.log_event(
            #                 category="transport",
            #                 event="packet_received",
            #                 data={
            #                     "frames": [],
            #                     "header": {
            #                         "packet_type": "retry",
            #                         "scid": dump_cid(header.source_cid),
            #                         "dcid": dump_cid(header.destination_cid),
            #                     },
            #                     "raw": {"length": buf.tell() - start_off},
            #                 },
            #             )
            #
            #         self._peer_cid.cid = header.source_cid
            #         self._peer_token = header.token
            #         self._retry_count += 1
            #         self._retry_source_connection_id = header.source_cid
            #         self._logger.info(
            #             "Retrying with token (%d bytes)" % len(header.token)
            #         )
            #         self._connect(now=now)
            #     else:
            #         # unexpected or invalid retry packet
            #         if self._quic_logger is not None:
            #             self._quic_logger.log_event(
            #                 category="transport",
            #                 event="packet_dropped",
            #                 data={"trigger": "unexpected_packet"},
            #             )
            #     return

            crypto_frame_required = False
            # network_path = self._find_network_path(addr)

            # determine crypto and packet space
            epoch = get_epoch(header.packet_type)
            crypto = self._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self._spaces[epoch]

            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = buf.tell() + header.rest_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                    data[start_off:end_off], encrypted_off, space.expected_packet_number
                )
            except KeyUnavailableError as exc:
                # self._logger.debug(exc)
                # if self._quic_logger is not None:
                #     self._quic_logger.log_event(
                #         category="transport",
                #         event="packet_dropped",
                #         data={"trigger": "key_unavailable"},
                #     )
                print("key_unavailable\n")

            # check reserved bits
            if header.is_long_header:
                reserved_mask = 0x0C
            else:
                reserved_mask = 0x18
            if plain_header[0] & reserved_mask:
                # self.close(
                #     error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                #     frame_type=QuicFrameType.PADDING,
                #     reason_phrase="Reserved bits must be zero",
                # )
                print("Reserved bits must be zero\n")
                return

            # log packet
            quic_logger_frames: Optional[List[Dict]] = None
            if self._quic_logger is not None:
                quic_logger_frames = []
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_received",
                    data={
                        "frames": quic_logger_frames,
                        "header": {
                            "packet_number": packet_number,
                            "packet_type": self._quic_logger.packet_type(
                                header.packet_type
                            ),
                            "dcid": dump_cid(header.destination_cid),
                            "scid": dump_cid(header.source_cid),
                        },
                        "raw": {"length": end_off - start_off},
                    },
                )

            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # discard initial keys and packet space
            # if not self._is_client and epoch == tls.Epoch.HANDSHAKE:
            #     self._discard_epoch(tls.Epoch.INITIAL)

            # update spin bit
            if not header.is_long_header and packet_number > self._spin_highest_pn:
                spin_bit = get_spin_bit(plain_header[0])
                if self._is_client:
                    self._spin_bit = not spin_bit
                else:
                    self._spin_bit = spin_bit
                self._spin_highest_pn = packet_number

                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="connectivity",
                        event="spin_bit_updated",
                        data={"state": self._spin_bit},
                    )

            # handle payload
            context = QuicReceiveContext(
                epoch=epoch,
                host_cid=header.destination_cid,
                # network_path=network_path,
                quic_logger_frames=quic_logger_frames,
                time=now,
            )
            try:
                is_ack_eliciting, is_probing = self._payload_received(
                    context, plain_payload, crypto_frame_required=crypto_frame_required
                )
            except QuicConnectionError as exc:
                # self._logger.warning(exc)
                # self.close(
                #     error_code=exc.error_code,
                #     frame_type=exc.frame_type,
                #     reason_phrase=exc.reason_phrase,
                # )
                print("connection error\n")
            # if self._state in END_STATES or self._close_pending:
            #     return

            # update idle timeout
            # self._close_at = now + self._idle_timeout()

            # # handle migration
            # if (
            #         not self._is_client
            #         and context.host_cid != self.host_cid
            #         and epoch == tls.Epoch.ONE_RTT
            # ):
            #     self._logger.debug(
            #         "Peer switching to CID %s (%d)",
            #         dump_cid(context.host_cid),
            #         destination_cid_seq,
            #     )
            #     self.host_cid = context.host_cid
            #     self.change_connection_id()
            #
            # # update network path
            # if not network_path.is_validated and epoch == tls.Epoch.HANDSHAKE:
            #     self._logger.debug(
            #         "Network path %s validated by handshake", network_path.addr
            #     )
            #     network_path.is_validated = True
            # network_path.bytes_received += end_off - start_off
            # if network_path not in self._network_paths:
            #     self._network_paths.append(network_path)
            # idx = self._network_paths.index(network_path)
            # if idx and not is_probing and packet_number > space.largest_received_packet:
            #     self._logger.debug("Network path %s promoted", network_path.addr)
            #     self._network_paths.pop(idx)
            #     self._network_paths.insert(0, network_path)
            #
            # # record packet as received
            # if not space.discarded:
            #     if packet_number > space.largest_received_packet:
            #         space.largest_received_packet = packet_number
            #         space.largest_received_time = now
            #     space.ack_queue.add(packet_number)
            #     if is_ack_eliciting and space.ack_at is None:
            #         space.ack_at = now + self._ack_delay

    def _payload_received(
            self,
            context: QuicReceiveContext,
            plain: bytes,
            crypto_frame_required: bool = False,
    ) -> Tuple[bool, bool]:
        """
        Handle a QUIC packet payload.
        """
        buf = Buffer(data=plain)

        crypto_frame_found = False
        frame_found = False
        is_ack_eliciting = False
        is_probing = None
        while not buf.eof():
            # get frame type
            try:
                frame_type = buf.pull_uint_var()
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=None,
                    reason_phrase="Malformed frame type",
                )

            # check frame type is known
            try:
                frame_handler, frame_epochs = self.__frame_handlers[frame_type]
            except KeyError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Unknown frame type",
                )

            # check frame type is allowed for the epoch
            if context.epoch not in frame_epochs:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unexpected frame type",
                )

            # handle the frame
            try:
                frame_handler(context, frame_type, buf)
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Failed to parse frame",
                )
            except StreamFinishedError:
                # we lack the state for the stream, ignore the frame
                pass

            # update ACK only / probing flags
            frame_found = True

            if frame_type == QuicFrameType.CRYPTO:
                crypto_frame_found = True

            if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                is_ack_eliciting = True

            if frame_type not in PROBING_FRAME_TYPES:
                is_probing = False
            elif is_probing is None:
                is_probing = True

        if not frame_found:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.PADDING,
                reason_phrase="Packet contains no frames",
            )

        # RFC 9000 - 17.2.2. Initial Packet
        # The first packet sent by a client always includes a CRYPTO frame.
        if crypto_frame_required and not crypto_frame_found:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.PADDING,
                reason_phrase="Packet contains no CRYPTO frame",
            )

        return is_ack_eliciting, bool(is_probing)

    def _initialize(self, peer_cid: bytes) -> None:
        # TLS
        self.tls = tls.Context(
            alpn_protocols=self._configuration.alpn_protocols,
            cadata=self._configuration.cadata,
            cafile=self._configuration.cafile,
            capath=self._configuration.capath,
            cipher_suites=self.configuration.cipher_suites,
            is_client=self._is_client,
            logger=self._logger,
            max_early_data=None if self._is_client else MAX_EARLY_DATA,
            server_name=self._configuration.server_name,
            verify_mode=self._configuration.verify_mode,
        )
        self.tls.certificate = self._configuration.certificate
        self.tls.certificate_chain = self._configuration.certificate_chain
        self.tls.certificate_private_key = self._configuration.private_key
        self.tls.handshake_extensions = [
            (
                get_transport_parameters_extension(self._version),
                self._serialize_transport_parameters(),
            )
        ]

        # TLS session resumption
        session_ticket = self._configuration.session_ticket
        if (
                self._is_client
                and session_ticket is not None
                and session_ticket.is_valid
                and session_ticket.server_name == self._configuration.server_name
        ):
            self.tls.session_ticket = self._configuration.session_ticket

            # parse saved QUIC transport parameters - for 0-RTT
            if session_ticket.max_early_data_size == MAX_EARLY_DATA:
                for ext_type, ext_data in session_ticket.other_extensions:
                    if ext_type == get_transport_parameters_extension(self._version):
                        self._parse_transport_parameters(
                            ext_data, from_session_ticket=True
                        )
                        break

        # TLS callbacks
        self.tls.alpn_cb = self._alpn_handler
        if self._session_ticket_fetcher is not None:
            self.tls.get_session_ticket_cb = self._session_ticket_fetcher
        if self._session_ticket_handler is not None:
            self.tls.new_session_ticket_cb = self._handle_session_ticket
        self.tls.update_traffic_key_cb = self._update_traffic_key

        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            secret_names = [
                "server_%s_secret" % epoch_name,
                "client_%s_secret" % epoch_name,
            ]
            recv_secret_name = secret_names[not self._is_client]
            send_secret_name = secret_names[self._is_client]
            return CryptoPair(
                recv_setup_cb=partial(self._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self._log_key_retired, send_secret_name),
            )

        self._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.INITIAL,
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self._spaces = {
            tls.Epoch.INITIAL: QuicPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicPacketSpace(),
            tls.Epoch.ONE_RTT: QuicPacketSpace(),
        }

        self._cryptos[tls.Epoch.INITIAL].setup_initial(
            cid=peer_cid, is_client=self._is_client, version=self._version
        )

        self._loss.spaces = list(self._spaces.values())


    def _handle_ack_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ACK frame.
        """
        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._remote_ack_delay_exponent) / 1000000

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_ack_frame(ack_rangeset, ack_delay)
            )

        # check whether peer completed address validation
        if not self._loss.peer_completed_address_validation and context.epoch in (
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
        ):
            self._loss.peer_completed_address_validation = True

        self._loss.on_ack_received(
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
            space=self._spaces[context.epoch],
        )


    def _handle_connection_close_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CONNECTION_CLOSE frame.
        """
        error_code = buf.pull_uint_var()
        if frame_type == QuicFrameType.TRANSPORT_CLOSE:
            frame_type = buf.pull_uint_var()
        else:
            frame_type = None
        reason_length = buf.pull_uint_var()
        try:
            reason_phrase = buf.pull_bytes(reason_length).decode("utf8")
        except UnicodeDecodeError:
            reason_phrase = ""

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_close_frame(
                    error_code=error_code,
                    frame_type=frame_type,
                    reason_phrase=reason_phrase,
                )
            )

        self._logger.info(
            "Connection close received (code 0x%X, reason %s)",
            error_code,
            reason_phrase,
        )
        if self._close_event is None:
            self._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._close_begin(is_initiator=False, now=context.time)


    def _handle_crypto_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CRYPTO frame.
        """
        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(offset=offset, data=buf.pull_bytes(length))

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_crypto_frame(frame)
            )

        stream = self._crypto_streams[context.epoch]
        event = stream.receiver.handle_frame(frame)
        if event is not None:
            # pass data to TLS layer
            try:
                self.tls.handle_message(event.data, self._crypto_buffers)
                self._push_crypto_data()
            except tls.Alert as exc:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.CRYPTO_ERROR + int(exc.description),
                    frame_type=frame_type,
                    reason_phrase=str(exc),
                )

            # parse transport parameters
            if (
                    not self._parameters_received
                    and self.tls.received_extensions is not None
            ):
                for ext_type, ext_data in self.tls.received_extensions:
                    if ext_type == get_transport_parameters_extension(self._version):
                        self._parse_transport_parameters(ext_data)
                        self._parameters_received = True
                        break
                if not self._parameters_received:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.CRYPTO_ERROR
                                   + tls.AlertDescription.missing_extension,
                        frame_type=frame_type,
                        reason_phrase="No QUIC transport parameters received",
                    )

            # update current epoch
            if not self._handshake_complete and self.tls.state in [
                tls.State.CLIENT_POST_HANDSHAKE,
                tls.State.SERVER_POST_HANDSHAKE,
            ]:
                self._handshake_complete = True

                # for servers, the handshake is now confirmed
                if not self._is_client:
                    self._discard_epoch(tls.Epoch.HANDSHAKE)
                    self._handshake_confirmed = True
                    self._handshake_done_pending = True

                self._replenish_connection_ids()
                self._events.append(
                    events.HandshakeCompleted(
                        alpn_protocol=self.tls.alpn_negotiated,
                        early_data_accepted=self.tls.early_data_accepted,
                        session_resumed=self.tls.session_resumed,
                    )
                )
                self._unblock_streams(is_unidirectional=False)
                self._unblock_streams(is_unidirectional=True)
                self._logger.info(
                    "ALPN negotiated protocol %s", self.tls.alpn_negotiated
                )
        else:
            self._logger.info(
                "Duplicate CRYPTO data received for epoch %s", context.epoch
            )

            # if a server receives duplicate CRYPTO in an INITIAL packet,
            # it can assume the client did not receive the server's CRYPTO
            if (
                    not self._is_client
                    and context.epoch == tls.Epoch.INITIAL
                    and not self._crypto_retransmitted
            ):
                self._loss.reschedule_data(now=context.time)
                self._crypto_retransmitted = True


    def _handle_data_blocked_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATA_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_data_blocked_frame(limit=limit)
            )


    def _handle_datagram_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATAGRAM frame.
        """
        start = buf.tell()
        if frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - start
        data = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_datagram_frame(length=length)
            )

        # check frame is allowed
        if (
                self._configuration.max_datagram_frame_size is None
                or buf.tell() - start >= self._configuration.max_datagram_frame_size
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Unexpected DATAGRAM frame",
            )

        self._events.append(events.DatagramFrameReceived(data=data))


    def _handle_handshake_done_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a HANDSHAKE_DONE frame.
        """
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_handshake_done_frame()
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send HANDSHAKE_DONE frames",
            )

        # for clients, the handshake is now confirmed
        if not self._handshake_confirmed:
            self._discard_epoch(tls.Epoch.HANDSHAKE)
            self._handshake_confirmed = True
            self._loss.peer_completed_address_validation = True


    def _handle_max_data_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_DATA frame.

        This adjusts the total amount of we can send to the peer.
        """
        max_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_data
                )
            )

        if max_data > self._remote_max_data:
            self._logger.debug("Remote max_data raised to %d", max_data)
            self._remote_max_data = max_data


    def _handle_max_stream_data_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAM_DATA frame.

        This adjusts the amount of data we can send on a specific stream.
        """
        stream_id = buf.pull_uint_var()
        max_stream_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_max_stream_data_frame(
                    maximum=max_stream_data, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        stream = self._get_or_create_stream(frame_type, stream_id)
        if max_stream_data > stream.max_stream_data_remote:
            self._logger.debug(
                "Stream %d remote max_stream_data raised to %d",
                stream_id,
                max_stream_data,
            )
            stream.max_stream_data_remote = max_stream_data


    def _handle_max_streams_bidi_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_BIDI frame.

        This raises number of bidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_bidi:
            self._logger.debug("Remote max_streams_bidi raised to %d", max_streams)
            self._remote_max_streams_bidi = max_streams
            self._unblock_streams(is_unidirectional=False)


    def _handle_max_streams_uni_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_UNI frame.

        This raises number of unidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_uni:
            self._logger.debug("Remote max_streams_uni raised to %d", max_streams)
            self._remote_max_streams_uni = max_streams
            self._unblock_streams(is_unidirectional=True)


    def _handle_new_connection_id_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(STATELESS_RESET_TOKEN_SIZE)
        if not connection_id or len(connection_id) > CONNECTION_ID_MAX_SIZE:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Length must be greater than 0 and less than 20",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_connection_id_frame(
                    connection_id=connection_id,
                    retire_prior_to=retire_prior_to,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )

        # sanity check
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Retire Prior To is greater than Sequence Number",
            )

        # only accept retire_prior_to if it is bigger than the one we know
        self._peer_retire_prior_to = max(retire_prior_to, self._peer_retire_prior_to)

        # determine which CIDs to retire
        change_cid = False
        retire = [
            cid
            for cid in self._peer_cid_available
            if cid.sequence_number < self._peer_retire_prior_to
        ]
        if self._peer_cid.sequence_number < self._peer_retire_prior_to:
            change_cid = True
            retire.insert(0, self._peer_cid)

        # update available CIDs
        self._peer_cid_available = [
            cid
            for cid in self._peer_cid_available
            if cid.sequence_number >= self._peer_retire_prior_to
        ]
        if (
                sequence_number >= self._peer_retire_prior_to
                and sequence_number not in self._peer_cid_sequence_numbers
        ):
            self._peer_cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            self._peer_cid_sequence_numbers.add(sequence_number)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._retire_peer_cid(quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._consume_peer_cid()

        # check number of active connection IDs, including the selected one
        if 1 + len(self._peer_cid_available) > self._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many active connection IDs",
            )

        # Check the number of retired connection IDs pending, though with a safer limit
        # than the 2x recommended in section 5.1.2 of the RFC.  Note that we are doing
        # the check here and not in _retire_peer_cid() because we know the frame type to
        # use here, and because it is the new connection id path that is potentially
        # dangerous.  We may transiently go a bit over the limit due to unacked frames
        # getting added back to the list, but that's ok as it is bounded.
        if len(self._retire_connection_ids) > min(
                self._local_active_connection_id_limit * 4, MAX_PENDING_RETIRES
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many pending retired connection IDs",
            )


    def _handle_new_token_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_TOKEN frame.
        """
        length = buf.pull_uint_var()
        token = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_token_frame(token=token)
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send NEW_TOKEN frames",
            )

        if self._token_handler is not None:
            self._token_handler(token)


    def _handle_padding_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_padding_frame())


    def _handle_path_challenge_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_CHALLENGE frame.
        """
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_challenge_frame(data=data)
            )

        context.network_path.remote_challenge = data


    def _handle_path_response_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_RESPONSE frame.
        """
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_response_frame(data=data)
            )

        if data != context.network_path.local_challenge:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Response does not match challenge",
            )
        self._logger.debug(
            "Network path %s validated by challenge", context.network_path.addr
        )
        context.network_path.is_validated = True


    def _handle_ping_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PING frame.
        """
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_ping_frame())


    def _handle_reset_stream_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RESET_STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()
        final_size = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_reset_stream_frame(
                    error_code=error_code, final_size=final_size, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if final_size > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, final_size - stream.receiver.highest_offset)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process reset
        self._logger.info(
            "Stream %d reset by peer (error code %d, final size %d)",
            stream_id,
            error_code,
            final_size,
        )
        try:
            event = stream.receiver.handle_reset(
                error_code=error_code, final_size=final_size
            )
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received


    def _handle_retire_connection_id_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RETIRE_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_retire_connection_id_frame(sequence_number)
            )

        if sequence_number >= self._host_cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        for index, connection_id in enumerate(self._host_cids):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Cannot retire current connection ID",
                    )
                self._logger.debug(
                    "Peer retiring CID %s (%d)",
                    dump_cid(connection_id.cid),
                    connection_id.sequence_number,
                )
                del self._host_cids[index]
                self._events.append(
                    events.ConnectionIdRetired(connection_id=connection_id.cid)
                )
                break

        # issue a new connection ID
        self._replenish_connection_ids()


    def _handle_stop_sending_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STOP_SENDING frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()  # application error code

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stop_sending_frame(
                    error_code=error_code, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        # reset the stream
        stream = self._get_or_create_stream(frame_type, stream_id)
        stream.sender.reset(error_code=QuicErrorCode.NO_ERROR)

        self._events.append(
            events.StopSendingReceived(error_code=error_code, stream_id=stream_id)
        )


    def _handle_stream_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        if frame_type & 4:
            offset = buf.pull_uint_var()
        else:
            offset = 0
        if frame_type & 2:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - buf.tell()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(
            offset=offset, data=buf.pull_bytes(length), fin=bool(frame_type & 1)
        )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_frame(frame, stream_id=stream_id)
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if offset + length > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, offset + length - stream.receiver.highest_offset)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process data
        try:
            event = stream.receiver.handle_frame(frame)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received


    def _handle_stream_data_blocked_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM_DATA_BLOCKED frame.
        """
        stream_id = buf.pull_uint_var()
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_data_blocked_frame(
                    limit=limit, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        self._get_or_create_stream(frame_type, stream_id)


    def _handle_streams_blocked_frame(
            self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAMS_BLOCKED frame.
        """
        limit = buf.pull_uint_var()
        if limit > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_streams_blocked_frame(
                    is_unidirectional=frame_type == QuicFrameType.STREAMS_BLOCKED_UNI,
                    limit=limit,
                )
            )