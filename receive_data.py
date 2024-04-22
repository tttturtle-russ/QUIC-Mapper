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
from aioquic.quic.connection import dump_cid, END_STATES, UDP_HEADER_SIZE, NetworkAddress
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


def receive_datagram(self, data: bytes, addr: NetworkAddress, now: float) -> None:
    """
    Handle an incoming datagram.

    .. aioquic_transmit::

    :param data: The datagram which was received.
    :param addr: The network address from which the datagram was received.
    :param now: The current time.
    """
    # stop handling packets when closing
    if self._state in END_STATES:
        return

    # log datagram
    if self._quic_logger is not None:
        payload_length = len(data)
        self._quic_logger.log_event(
            category="transport",
            event="datagrams_received",
            data={
                "count": 1,
                "raw": [
                    {
                        "length": UDP_HEADER_SIZE + payload_length,
                        "payload_length": payload_length,
                    }
                ],
            },
        )

    # for servers, arm the idle timeout on the first datagram
    if self._close_at is None:
        self._close_at = now + self._idle_timeout()

    buf = Buffer(data=data)
    while not buf.eof():
        start_off = buf.tell()
        try:
            header = pull_quic_header(
                buf, host_cid_length=self._configuration.connection_id_length
            )
        except ValueError:
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={
                        "trigger": "header_parse_error",
                        "raw": {"length": buf.capacity - start_off},
                    },
                )
            return

        # RFC 9000 section 14.1 requires servers to drop all initial packets
        # contained in a datagram smaller than 1200 bytes.
        if (
                not self._is_client
                and header.packet_type == PACKET_TYPE_INITIAL
                and len(data) < SMALLEST_MAX_DATAGRAM_SIZE
        ):
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={
                        "trigger": "initial_packet_datagram_too_small",
                        "raw": {"length": buf.capacity - start_off},
                    },
                )
            return

        # check destination CID matches
        destination_cid_seq: Optional[int] = None
        for connection_id in self._host_cids:
            if header.destination_cid == connection_id.cid:
                destination_cid_seq = connection_id.sequence_number
                break
        if (
                self._is_client or header.packet_type == PACKET_TYPE_HANDSHAKE
        ) and destination_cid_seq is None:
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={"trigger": "unknown_connection_id"},
                )
            # return

        # check protocol version
        if (
                self._is_client
                and self._state == QuicConnectionState.FIRSTFLIGHT
                and header.version == QuicProtocolVersion.NEGOTIATION
                and not self._version_negotiation_count
        ):
            # version negotiation
            versions = []
            while not buf.eof():
                versions.append(buf.pull_uint32())
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_received",
                    data={
                        "frames": [],
                        "header": {
                            "packet_type": "version_negotiation",
                            "scid": dump_cid(header.source_cid),
                            "dcid": dump_cid(header.destination_cid),
                        },
                        "raw": {"length": buf.tell() - start_off},
                    },
                )
            if self._version in versions:
                self._logger.warning(
                    "Version negotiation packet contains %s" % self._version
                )
                return
            common = [
                x for x in self._configuration.supported_versions if x in versions
            ]
            chosen_version = common[0] if common else None
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="version_information",
                    data={
                        "server_versions": versions,
                        "client_versions": self._configuration.supported_versions,
                        "chosen_version": chosen_version,
                    },
                )
            if chosen_version is None:
                self._logger.error("Could not find a common protocol version")
                self._close_event = events.ConnectionTerminated(
                    error_code=QuicErrorCode.INTERNAL_ERROR,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Could not find a common protocol version",
                )
                self._close_end()
                return
            self._packet_number = 0
            self._version = QuicProtocolVersion(chosen_version)
            self._version_negotiation_count += 1
            self._logger.info("Retrying with %s", self._version)
            self._connect(now=now)
            return
        elif (
                header.version is not None
                and header.version not in self._configuration.supported_versions
        ):
            # unsupported version
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={"trigger": "unsupported_version"},
                )
            return

        # handle retry packet
        if header.packet_type == PACKET_TYPE_RETRY:
            if (
                    self._is_client
                    and not self._retry_count
                    and header.destination_cid == self.host_cid
                    and header.integrity_tag
                    == get_retry_integrity_tag(
                buf.data_slice(
                    start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                ),
                self._peer_cid.cid,
                version=header.version,
            )
            ):
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_received",
                        data={
                            "frames": [],
                            "header": {
                                "packet_type": "retry",
                                "scid": dump_cid(header.source_cid),
                                "dcid": dump_cid(header.destination_cid),
                            },
                            "raw": {"length": buf.tell() - start_off},
                        },
                    )

                self._peer_cid.cid = header.source_cid
                self._peer_token = header.token
                self._retry_count += 1
                self._retry_source_connection_id = header.source_cid
                self._logger.info(
                    "Retrying with token (%d bytes)" % len(header.token)
                )
                self._connect(now=now)
            else:
                # unexpected or invalid retry packet
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "unexpected_packet"},
                    )
            return

        crypto_frame_required = False
        network_path = self._find_network_path(addr)

        # server initialization
        if not self._is_client and self._state == QuicConnectionState.FIRSTFLIGHT:
            assert (
                    header.packet_type == PACKET_TYPE_INITIAL
            ), "first packet must be INITIAL"
            crypto_frame_required = True
            self._network_paths = [network_path]
            self._version = QuicProtocolVersion(header.version)
            self._initialize(header.destination_cid)

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
            self._logger.debug(exc)
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={"trigger": "key_unavailable"},
                )

            # If a client receives HANDSHAKE or 1-RTT packets before it has
            # handshake keys, it can assume that the server's INITIAL was lost.
            if (
                    self._is_client
                    and epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
                    and not self._crypto_retransmitted
            ):
                self._loss.reschedule_data(now=now)
                self._crypto_retransmitted = True
            continue
        except CryptoError as exc:
            self._logger.debug(exc)
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_dropped",
                    data={"trigger": "payload_decrypt_error"},
                )
            continue

        # check reserved bits
        if header.is_long_header:
            reserved_mask = 0x0C
        else:
            reserved_mask = 0x18
        if plain_header[0] & reserved_mask:
            self.close(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.PADDING,
                reason_phrase="Reserved bits must be zero",
            )
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
        if not self._is_client and epoch == tls.Epoch.HANDSHAKE:
            self._discard_epoch(tls.Epoch.INITIAL)

        # update state
        if self._peer_cid.sequence_number is None:
            self._peer_cid.cid = header.source_cid
            self._peer_cid.sequence_number = 0

        if self._state == QuicConnectionState.FIRSTFLIGHT:
            self._remote_initial_source_connection_id = header.source_cid
            self._set_state(QuicConnectionState.CONNECTED)

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
            network_path=network_path,
            quic_logger_frames=quic_logger_frames,
            time=now,
        )
        try:
            is_ack_eliciting, is_probing = self._payload_received(
                context, plain_payload, crypto_frame_required=crypto_frame_required
            )
        except QuicConnectionError as exc:
            self._logger.warning(exc)
            self.close(
                error_code=exc.error_code,
                frame_type=exc.frame_type,
                reason_phrase=exc.reason_phrase,
            )
        if self._state in END_STATES or self._close_pending:
            return

        # update idle timeout
        self._close_at = now + self._idle_timeout()

        # handle migration
        if (
                not self._is_client
                and context.host_cid != self.host_cid
                and epoch == tls.Epoch.ONE_RTT
        ):
            self._logger.debug(
                "Peer switching to CID %s (%d)",
                dump_cid(context.host_cid),
                destination_cid_seq,
            )
            self.host_cid = context.host_cid
            self.change_connection_id()

        # update network path
        if not network_path.is_validated and epoch == tls.Epoch.HANDSHAKE:
            self._logger.debug(
                "Network path %s validated by handshake", network_path.addr
            )
            network_path.is_validated = True
        network_path.bytes_received += end_off - start_off
        if network_path not in self._network_paths:
            self._network_paths.append(network_path)
        idx = self._network_paths.index(network_path)
        if idx and not is_probing and packet_number > space.largest_received_packet:
            self._logger.debug("Network path %s promoted", network_path.addr)
            self._network_paths.pop(idx)
            self._network_paths.insert(0, network_path)

        # record packet as received
        if not space.discarded:
            if packet_number > space.largest_received_packet:
                space.largest_received_packet = packet_number
                space.largest_received_time = now
            space.ack_queue.add(packet_number)
            if is_ack_eliciting and space.ack_at is None:
                space.ack_at = now + self._ack_delay
