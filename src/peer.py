"""The peer wire protocol over a single TCP connection.

:class:`PeerConnection` owns one socket and speaks the handshake, the metadata
extension (BEP 9) and piece requests. It is a context manager, so the socket is
always closed - including on error, which the original recursive/return-based
code did not guarantee.
"""

from __future__ import annotations

import hashlib
import socket
from collections.abc import Iterator, Sequence

import bencodepy

from src.constants import (
    BLOCK_SIZE,
    CONNECT_TIMEOUT,
    MAGNET_RESERVED,
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
from src.errors import PeerProtocolError
from src.models import Peer, TorrentMetadata
from src.reporting import NullReporter, ProgressReporter


_HANDSHAKE_LEN = 68

# A piece message is a 4-byte length, 1-byte id, 4-byte index, 4-byte begin,
# then the block payload - 13 bytes of framing before the data.
_PIECE_HEADER_LEN = 13

# Upper bound on a single message body.
_MAX_MESSAGE_LEN = 2**20


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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            try:
                sock.connect((peer.ip, peer.port))
            except OSError as error:  # includes socket.timeout
                sock.close()
                last_error = error
                continue
            # Switch to the longer per-message deadline for the live connection.
            sock.settimeout(RECV_TIMEOUT)
            self._sock = sock
            self._reporter.report(f"connected to {peer.ip}:{peer.port}")
            return

        self._reporter.report("failed to connect to all peers!")
        raise PeerProtocolError("failed to connect to all peers") from last_error

    def handshake(self, info_hash: bytes, *, magnet: bool = False) -> None:
        """Send the BitTorrent handshake and record the peer's response."""

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
        self.reserved_bytes = response[20:28]
        self.remote_peer_id = response[-20:].hex()

    def recv_message(self) -> bytes:
        """Receive one length-prefixed message (header included)."""

        header = self._recv_exact(4)
        length = int.from_bytes(header, "big")
        if length > _MAX_MESSAGE_LEN:
            raise PeerProtocolError(f"Peer announced an oversized message: {length} bytes")
        return header + self._recv_exact(length)

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
                continue # keep-alive: no id, nothing to do
            msg_id = message[4]
            if msg_id == wanted_id:
                return message
            if msg_id == MSG_CHOKE:
                raise PeerProtocolError("Peer choked the connection")

    def send_interested(self) -> None:
        """Announce interest and wait for the peer to unchoke us."""

        message = (1).to_bytes(4, "big") + MSG_INTERESTED.to_bytes(1, "big")
        self._socket.sendall(message)
        self.recv_message() # unchoke

    def _recv_exact(self, count: int) -> bytes:
        """Receive exactly ``count`` bytes, looping over short reads."""

        chunks = []
        remaining = count
        while remaining:
            try:
                chunk = self._socket.recv(remaining)
            except OSError as exc: # includes socket.timeout and resets
                raise PeerProtocolError(f"Peer read failed: {exc}") from exc
            if not chunk:
                raise PeerProtocolError("Peer closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def extension_handshake(self) -> int:
        """Negotiate the metadata extension; return the peer's ut_metadata id."""

        if not any(self.reserved_bytes):
            raise PeerProtocolError("Peer does not support the metadata extension")

        payload = bencodepy.encode({"m": {"ut_metadata": 1}})
        self._send_extension(extension_id=0, payload=payload)

        response = self._recv_until(MSG_EXTENSION)
        handshake = bencodepy.decode(response[6:])
        if b"m" not in handshake or b"ut_metadata" not in handshake[b"m"]:
            raise PeerProtocolError(f"Invalid extension handshake response: {handshake}")
        self.metadata_extension_id = handshake[b"m"][b"ut_metadata"]
        return self.metadata_extension_id

    def fetch_metadata(self, extension_id: int) -> bytes:
        """Request piece 0 of the metadata and return the raw info dictionary."""

        payload = bencodepy.encode({"msg_type": 0, "piece": 0})
        self._send_extension(extension_id, payload)

        response = self._recv_until(MSG_EXTENSION)
        header = _decode_leading(response[6:])
        total_size = header[b"total_size"]
        return response[-total_size:]

    def _send_extension(self, extension_id: int, payload: bytes) -> None:
        message = (
            (2 + len(payload)).to_bytes(4, "big")
            + MSG_EXTENSION.to_bytes(1, "big")
            + extension_id.to_bytes(1, "big")
            + payload
        )
        self._socket.sendall(message)

    def download_piece(self, meta: TorrentMetadata, piece_index: int) -> bytes:
        """Download one piece, verify its SHA-1, and return its bytes."""

        self._reporter.report(f"downloading piece_index: {piece_index} ...")
        blocks = self._block_requests(meta, piece_index)

        payloads: list[bytes] = []
        for batch in _batched(blocks, PIPELINE_DEPTH):
            for block in batch:
                self._socket.sendall(self._request_message(block))
            for _ in batch:
                payloads.append(self._recv_until(MSG_PIECE)[_PIECE_HEADER_LEN:])

        piece = b"".join(payloads)
        expected = meta.piece_hashes_hex[piece_index]
        actual = hashlib.sha1(piece).hexdigest()
        if actual != expected:
            raise PeerProtocolError(f"Invalid piece hash: {actual} | {expected}")
        self._reporter.report(f"valid piece hash: {actual} | {expected}")
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


def _batched(items: Sequence, size: int) -> Iterator[Sequence]:
    """Yield successive ``size``-length slices of ``items``."""

    for start in range(0, len(items), size):
        yield items[start : start + size]


def _decode_leading(buf: bytes) -> dict:
    """Decode just the leading bencoded dict, ignoring any trailing bytes.

    ``bencodepy.decode`` rejects data after a complete value, but a metadata
    "data" message (BEP 9) is a dict immediately followed by the raw info
    bytes. The per-type decoders return ``(value, consumed)`` and stop at the
    end of the first value, so we use one directly.
    """

    decoder = bencodepy.BencodeDecoder()
    value, _consumed = decoder.decode_func[buf[:1]](buf, 0)
    return value

