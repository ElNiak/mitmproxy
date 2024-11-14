"""
This module contains a very terrible QUIC client hello parser.

Nothing is more permanent than a temporary solution!
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from aioquic.buffer import Buffer as QuicBuffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.connection import QuicConnectionError
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import PACKET_TYPE_INITIAL
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import HandshakeType
from aioquic.quic.connection import *

from mitmproxy.tls import ClientHello


@dataclass
class QuicClientHello(Exception):
    """Helper error only used in `quic_parse_client_hello_from_datagrams`."""

    data: bytes

def new_receive_datagram(self, data: bytes, addr:NetworkAddress, now: float) -> None:
        """
        Handle an incoming datagram.

        .. aioquic_transmit::

        :param data: The datagram which was received.
        :param addr: The network address from which the datagram was received.
        :param now: The current time.
        """
        print("new_receive_datagram")
        payload_length = len(data)

        # stop handling packets when closing
        if self._state in END_STATES:
            return

        # log datagram
        if self._quic_logger is not None:
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

        # For anti-amplification purposes, servers need to keep track of the
        # amount of data received on unvalidated network paths. We must count the
        # entire datagram size regardless of whether packets are processed or
        # dropped.
        #
        # This is particularly important when talking to clients who pad
        # datagrams containing INITIAL packets by appending bytes after the
        # long-header packets, which is legitimate behaviour.
        #
        # https://datatracker.ietf.org/doc/html/rfc9000#section-8.1
        network_path = self._find_network_path(addr)
        if not network_path.is_validated:
            network_path.bytes_received += payload_length

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
                and header.packet_type == QuicPacketType.INITIAL
                and payload_length < SMALLEST_MAX_DATAGRAM_SIZE
            ):
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={
                            "trigger": "initial_packet_datagram_too_small",
                            "raw": {"length": header.packet_length},
                        },
                    )
                return

            # Check destination CID matches.
            destination_cid_seq: Optional[int] = None
            for connection_id in self._host_cids:
                if header.destination_cid == connection_id.cid:
                    destination_cid_seq = connection_id.sequence_number
                    break
            if (
                self._is_client or header.packet_type == QuicPacketType.HANDSHAKE
            ) and destination_cid_seq is None:
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={
                            "trigger": "unknown_connection_id",
                            "raw": {"length": header.packet_length},
                        },
                    )
                return

            # Handle version negotiation packet.
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self._receive_version_negotiation_packet(header=header, now=now)
                return

            # Check long header packet protocol version.
            if (
                header.version is not None
                and header.version not in self._configuration.supported_versions
            ):
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={
                            "trigger": "unsupported_version",
                            "raw": {"length": header.packet_length},
                        },
                    )
                return

            # Handle retry packet.
            if header.packet_type == QuicPacketType.RETRY:
                self._receive_retry_packet(
                    header=header,
                    packet_without_tag=buf.data_slice(
                        start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                    ),
                    now=now,
                )
                return

            crypto_frame_required = False

            # Server initialization.
            if not self._is_client and self._state == QuicConnectionState.FIRSTFLIGHT:
                assert (
                    header.packet_type == QuicPacketType.INITIAL
                ), "first packet must be INITIAL"
                crypto_frame_required = True
                self._network_paths = [network_path]
                self._version = header.version
                self._initialize(header.destination_cid)

            # Determine crypto and packet space.
            epoch = get_epoch(header.packet_type)
            if epoch == tls.Epoch.INITIAL:
                crypto = self._cryptos_initial[header.version]
            else:
                crypto = self._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self._spaces[epoch]

            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = start_off + header.packet_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                    data[start_off:end_off], encrypted_off, space.expected_packet_number
                )
                print("Decrypted packet:")
                print("Header bytes:" + plain_header.hex())
                print("Payload bytes:" + plain_payload.hex())
            except KeyUnavailableError as exc:
                self._logger.debug(exc)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={
                            "trigger": "key_unavailable",
                            "raw": {"length": header.packet_length},
                        },
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
                        data={
                            "trigger": "payload_decrypt_error",
                            "raw": {"length": header.packet_length},
                        },
                    )
                continue

            # check reserved bits
            if header.packet_type == QuicPacketType.ONE_RTT:
                reserved_mask = 0x18
            else:
                reserved_mask = 0x0C
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
                        "raw": {"length": header.packet_length},
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
            if (
                header.packet_type == QuicPacketType.ONE_RTT
                and packet_number > self._spin_highest_pn
            ):
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
                version=header.version,
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



def quic_parse_client_hello_from_datagrams(
    datagrams: list[bytes],
) -> Optional[ClientHello]:
    """
    Check if the supplied bytes contain a full ClientHello message,
    and if so, parse it.

    Args:
        - msgs: list of ClientHello fragments received from client

    Returns:
        - A ClientHello object on success
        - None, if the QUIC record is incomplete

    Raises:
        - A ValueError, if the passed ClientHello is invalid
    """

    # ensure the first packet is indeed the initial one
    buffer = QuicBuffer(data=datagrams[0])
    header = pull_quic_header(buffer, 8)
    if header.packet_type != PACKET_TYPE_INITIAL:
        raise ValueError("Packet is not initial one.")
    
    QuicConnection.receive_datagram = new_receive_datagram

    # patch aioquic to intercept the client hello
    quic = QuicConnection(
        configuration=QuicConfiguration(
            is_client=False,
            certificate="",
            private_key="",
            quic_logger=QuicLogger(),
        ),
        original_destination_connection_id=header.destination_cid,
    )
    _initialize = quic._initialize

    def server_handle_hello_replacement(
        input_buf: QuicBuffer,
        initial_buf: QuicBuffer,
        handshake_buf: QuicBuffer,
        onertt_buf: QuicBuffer,
    ) -> None:
        assert input_buf.pull_uint8() == HandshakeType.CLIENT_HELLO
        length = 0
        for b in input_buf.pull_bytes(3):
            length = (length << 8) | b
        offset = input_buf.tell()
        raise QuicClientHello(input_buf.data_slice(offset, offset + length))

    def initialize_replacement(peer_cid: bytes) -> None:
        try:
            return _initialize(peer_cid)
        finally:
            quic.tls._server_handle_hello = server_handle_hello_replacement  # type: ignore

    quic._initialize = initialize_replacement  # type: ignore
    try:
        for dgm in datagrams:
            print(dgm.hex())
            quic.receive_datagram(dgm, ("0.0.0.0", 0), now=time.time())
    except QuicClientHello as hello:
        try:
            return ClientHello(hello.data)
        except EOFError as e:
            raise ValueError("Invalid ClientHello data.") from e
    except QuicConnectionError as e:
        raise ValueError(e.reason_phrase) from e

    quic_logger = quic._configuration.quic_logger
    assert isinstance(quic_logger, QuicLogger)
    traces = quic_logger.to_dict().get("traces")
    assert isinstance(traces, list)
    for trace in traces:
        quic_events = trace.get("events")
        for event in quic_events:
            if event["name"] == "transport:packet_dropped":
                raise ValueError(
                    f"Invalid ClientHello packet: {event['data']['trigger']}"
                )

    return None  # pragma: no cover  # FIXME: this should have test coverage
