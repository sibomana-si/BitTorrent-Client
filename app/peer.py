"""The peer wire protocol over a single TCP connection.

:class:`PeerConnection` owns one socket and speaks the handshake, the metadata
extension (BEP 9) and piece requests. It is a context manager, so the socket is
always closed - including on error, which the original recursive/return-based
code did not guarantee.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import time
from collections.abc import Sequence
from typing import cast

import bencodepy

from app.constants import (
    BLOCK_SIZE,
    CONNECT_TIMEOUT,
    MAGNET_RESERVED,
    MAX_METADATA_BYTES,
    MSG_CHOKE,
    MSG_EXTENSION,
    MSG_INTERESTED,
    MSG_PIECE,
    MSG_REQUEST,
    MSG_UNCHOKE,
    PEER_ID,
    PIPELINE_DEPTH,
    PROTOCOL_NAME,
    RECV_TIMEOUT
)
from app.errors import PeerProtocolError
from app.models import Peer, TorrentMetadata
from app.reporting import NullReporter, ProgressReporter


_HANDSHAKE_LEN = 68

# A piece message is a 4-byte length, 1-byte id, 4-byte index, 4-byte begin,
# then the block payload - 13 bytes of framing before the data.
_PIECE_HEADER_LEN = 13

# Upper bound on a single message body.
_MAX_MESSAGE_LEN = 2**20

logger = logging.getLogger(__name__)


class PeerConnection:
    """A live connection to one peer."""

    def __init__(self, peer_id: bytes = PEER_ID, reporter: ProgressReporter | None = None) -> None:
        self.peer_id = peer_id
        self._reporter = reporter or NullReporter()
        self._sock: socket.socket | None = None
        self.remote_peer_id: str | None = None
        self.reserved_bytes = b""
        self.metadata_extension_id: int | None = None

    def __enter__(self) -> "PeerConnection":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    @property
    def _socket(self) -> socket.socket:
        if self._sock is None:
            raise RuntimeError("Not connected to a peer")
        return self._sock

    def connect(self, peers: Sequence[Peer]) -> None:
        """Connect to the first reachable peer, trying each in turn."""

        last_error: Exception | None = None
        for peer in peers:
            started = time.perf_counter()
            logger.debug("peer connect attempt", extra={"ctx": {"peer": str(peer)}})
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle
            sock.settimeout(CONNECT_TIMEOUT)
            try:
                sock.connect((peer.ip, peer.port))
            except OSError as error:  # includes socket.timeout
                sock.close()
                last_error = error
                logger.debug(
                    "peer connect failed",
                    extra={"ctx": {"peer": str(peer), "error": str(error)}}
                )
                continue
            # Switch to the longer per-message deadline for the live connection.
            sock.settimeout(RECV_TIMEOUT)
            self._sock = sock
            logger.debug(
                "peer connected",
                extra={
                    "ctx": {
                        "peer": str(peer),
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)
                    }
                }
            )
            self._reporter.report(f"connected to {peer.ip}:{peer.port}")
            return

        logger.debug("all peers unreachable", extra={"ctx": {"peers_tried": len(peers)}})
        self._reporter.report("failed to connect to all peers!")
        raise PeerProtocolError("failed to connect to all peers") from last_error

    def handshake(self, info_hash: bytes, *, magnet: bool = False) -> None:
        """Send the BitTorrent handshake and record the peer's response."""

        started = time.perf_counter()
        reserved = MAGNET_RESERVED if magnet else bytes(8)
        message = (
            len(PROTOCOL_NAME).to_bytes(1, "big")
            + PROTOCOL_NAME
            + reserved
            + info_hash
            + self.peer_id
        )
        self._socket.sendall(message)
        response = self._recv_exact(_HANDSHAKE_LEN)
        # confirm the response is the protocol we expect and the info hash received matches the one we sent
        if response[1:20] != PROTOCOL_NAME:
            raise PeerProtocolError("Peer sent an unexpected handshake protocol")
        if response[28:48] != info_hash:
            raise PeerProtocolError(
                f"Peer handshake info hash mismatch: "
                f"{response[28:48].hex()} != {info_hash.hex()}"
            )
        self.reserved_bytes = response[20:28]
        self.remote_peer_id = response[-20:].hex()
        logger.debug(
            "handshake ok",
            extra={
                "ctx": {
                    "info_hash": info_hash.hex()[:8],
                    "peer_id": self.remote_peer_id[:16],
                    "magnet": magnet,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)
                }
            }
        )

    def recv_message(self) -> bytes:
        """Receive one length-prefixed message (header included)."""

        header = self._recv_exact(4)
        length = int.from_bytes(header, "big")
        if length > _MAX_MESSAGE_LEN:
            logger.warning(
                "peer message rejected by the size cap",
                extra={"ctx": {"bytes": length, "cap": _MAX_MESSAGE_LEN}}
            )
            raise PeerProtocolError(f"Peer announced an oversized message: {length} bytes")
        # Receive the body straight into the message buffer behind the header,
        # rather than concatenating two separately assembled byte strings.
        message = bytearray(4 + length)
        message[:4] = header
        if length:
            self._recv_into(memoryview(message)[4:])
        return bytes(message)

    def _recv_until(self, wanted_id: int) -> bytes:
        """Read frames until one with id ``wanted_id`` arrives (header included).

        Peers freely interleave keep-alives (length-0 frames) and informational
        messages (``have``, ``bitfield``, repeated ``unchoke``) with the reply we
        are waiting for; the old "read exactly one frame" code would misread
        those as the awaited message. We consume and ignore anything unrelated,
        and treat a ``choke`` while waiting as a protocol failure.
        """

        while True:
            message = self.recv_message()
            length = int.from_bytes(message[:4], "big")
            if length == 0:
                logger.debug("keep-alive received")
                continue # keep-alive: no id, nothing to do
            msg_id = message[4]
            if msg_id == wanted_id:
                return message
            if msg_id == MSG_CHOKE:
                logger.debug(
                    "peer chocked the connection",
                    extra={"ctx": {"waiting_for": wanted_id}}
                )
                raise PeerProtocolError("Peer choked the connection")
            logger.debug(
                "skipping informational frame",
                extra={"ctx": {"msg_id": msg_id, "waiting_for": wanted_id}}
            )

    def send_interested(self) -> None:
        """Announce interest and wait for the peer to unchoke us."""

        message = (1).to_bytes(4, "big") + MSG_INTERESTED.to_bytes(1, "big")
        self._socket.sendall(message)
        self._recv_until(MSG_UNCHOKE)
        logger.debug("peer unchoked us")

    def _recv_exact(self, count: int) -> bytes:
        """Receive exactly ``count`` bytes, looping over short reads."""

        buffer = bytearray(count)
        self._recv_into(memoryview(buffer))
        return bytes(buffer)

    def _recv_into(self, view: memoryview) -> None:
        """Fill ``view`` completely from the socket, looping over short reads.

        ``recv_into`` writes each chunk at its final offset, so reassembly
        needs no per-chunk allocations and no joining copy.
        """

        filled = 0
        while filled < len(view):
            try:
                read = self._socket.recv_into(view[filled:])
            except OSError as exc:
                raise PeerProtocolError(f"Peer read failed: {exc}") from exc
            if not read:
                raise PeerProtocolError("Peer closed the connection")
            filled += read

    def extension_handshake(self) -> int:
        """Negotiate the metadata extension; return the peer's ut_metadata id."""

        if not any(self.reserved_bytes):
            raise PeerProtocolError("Peer does not support the metadata extension")

        started = time.perf_counter()
        payload = bencodepy.encode({"m": {"ut_metadata": 1}})
        self._send_extension(extension_id=0, payload=payload)

        response = self._recv_until(MSG_EXTENSION)
        handshake = cast(dict, cast(object, bencodepy.decode(response[6:])))
        if b"m" not in handshake or b"ut_metadata" not in handshake[b"m"]:
            raise PeerProtocolError(f"Invalid extension handshake response: {handshake}")
        self.metadata_extension_id = handshake[b"m"][b"ut_metadata"]
        logger.debug(
            "extension handshake ok",
            extra={
                "ctx": {
                    "ut_metadata": self.metadata_extension_id,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)
                }
            }
        )
        return self.metadata_extension_id

    def fetch_metadata(self, extension_id: int) -> bytes:
        """Request piece 0 of the metadata and return the raw info dictionary."""

        payload = bencodepy.encode({"msg_type": 0, "piece": 0})
        self._send_extension(extension_id, payload)

        response = self._recv_until(MSG_EXTENSION)
        header = _decode_leading(response[6:])
        total_size = header.get(b"total_size")
        # total_size is peer-supplied: reject anything that isn't a sane positive
        # length bounded by both our cap and the bytes actually received, so a
        # negative/huge/missing value can't yield a garbage slice or OOM.
        available = len(response) - 6
        if (not isinstance(total_size, int) or not 0 < total_size <= available or total_size > MAX_METADATA_BYTES):
            logger.warning(
                "peer metadata rejected by the size guard",
                extra={
                    "ctx": {
                        "total_size": total_size,
                        "available": available
                    }
                }
            )
            raise PeerProtocolError(f"Peer advertised an invalid metadata size: {total_size!r}")
        return response[-total_size:]

    def _send_extension(self, extension_id: int, payload: bytes) -> None:
        message = (
            (2 + len(payload)).to_bytes(4, "big")
            + MSG_EXTENSION.to_bytes(1, "big")
            + extension_id.to_bytes(1, "big")
            + payload
        )
        self._socket.sendall(message)

    def download_piece(
            self,
            meta: TorrentMetadata,
            piece_index: int,
            reporter: ProgressReporter | None = None
    ) -> bytearray:
        """Download one piece, verify its SHA-1, and return its bytes.

        ``reporter`` overrides the connection's reporter for this piece's
        progress lines (the concurrent downloader passes a per-piece buffer so
        the lines can be released in piece-index order); it defaults to the
        connection's own reporter for the single-connection paths.
        """

        if reporter is None:
            reporter = self._reporter
        reporter.report(f"downloading piece_index: {piece_index} ...")
        started = time.perf_counter()
        blocks = self._block_requests(meta, piece_index)

        # Slot returned blocks into a preallocated buffer at their offset so
        # out-of-order responses are reassembled correctly (and without holding
        # a second copy of the piece, as a per-block dict + join would), and
        # reject any block that does not match a request we actually made
        # (wrong piece, unexpected offset/length).
        wanted = {begin: length for _index, begin, length in blocks}
        piece = bytearray(sum(wanted.values()))
        received: set[int] = set()
        # Sliding window: keep PIPELINE_DEPTH requests in flight, sending the next pending request as each block arrives.
        sent = min(PIPELINE_DEPTH, len(blocks))
        self._socket.sendall(b"".join(self._request_message(block) for block in blocks[:sent]))
        for _ in blocks:
            message = self._recv_until(MSG_PIECE)
            index = int.from_bytes(message[5:9], "big")
            begin = int.from_bytes(message[9:13], "big")
            block_data = message[_PIECE_HEADER_LEN:]
            if index != piece_index or begin not in wanted:
                raise PeerProtocolError(f"Peer returned an unexpected block: index={index} begin={begin}")
            if len(block_data) != wanted[begin]:
                raise PeerProtocolError(
                    f"Peer returned a short block at begin={begin}: "
                    f"{len(block_data)} != {wanted[begin]}"
                )
            piece[begin : begin + len(block_data)] = block_data
            received.add(begin)
            if logger.isEnabledFor(logging.DEBUG):
                # Marked ``sampled`` so the CLI's sampling filter thins these
                # high-frequency events; guarded so the silent path builds nothing.
                logger.debug(
                    "block received",
                    extra={
                        "ctx": {"piece_index": piece_index, "begin": begin, "len": len(block_data)},
                        "sampled": True
                    }
                )
            if sent < len(blocks):
                self._socket.sendall(self._request_message(blocks[sent]))
                sent += 1
        if received != wanted.keys():
            raise PeerProtocolError("Peer did not return every requested block")
        expected = meta.piece_hashes[piece_index]
        actual = hashlib.sha1(piece).digest()
        if actual != expected:
            raise PeerProtocolError(f"Invalid piece hash: {actual.hex()} | {expected.hex()}")
        logger.debug(
            "piece downloaded",
            extra={
                "ctx": {
                    "piece_index": piece_index,
                    "blocks": len(blocks),
                    "bytes": len(piece),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)
                }
            }
        )
        reporter.report(f"valid piece hash: {actual.hex()} | {expected.hex()}")
        return piece

    @staticmethod
    def _block_requests(meta: TorrentMetadata, piece_index: int) -> list[tuple[int, int, int]]:
        """Split a piece into (index, begin, length) block requests."""

        last_index = len(meta.piece_hashes) - 1
        remainder = meta.length % meta.piece_length
        if piece_index == last_index and remainder:
            piece_size = remainder
        else:
            piece_size = meta.piece_length

        requests = []
        begin = 0
        while begin < piece_size:
            length = min(BLOCK_SIZE, piece_size - begin)
            requests.append((piece_index, begin, length))
            begin += length
        return requests

    @staticmethod
    def _request_message(block: tuple[int, int, int]) -> bytes:
        index, begin, length = block
        return (
                (_PIECE_HEADER_LEN).to_bytes(4, "big")
                + MSG_REQUEST.to_bytes(1, "big")
                + index.to_bytes(4, "big")
                + begin.to_bytes(4, "big")
                + length.to_bytes(4, "big")
        )


def _decode_leading(buf: bytes) -> dict:
    """Decode just the leading bencoded dict, ignoring any trailing bytes.

    ``bencodepy.decode`` rejects data after a complete value, but a metadata
    "data" message (BEP 9) is a dict immediately followed by the raw info
    bytes. The per-type decoders return ``(value, consumed)`` and stop at the
    end of the first value, so we use one directly.
    """

    decoder = bencodepy.BencodeDecoder()
    value, _consumed = decoder.decode_func[buf[:1]](buf, 0)
    return cast(dict, cast(object, value))
