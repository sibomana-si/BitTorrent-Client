"""Build :class:`TorrentMetadata` from a ``.torrent`` file or a metadata blob.

Two sources produce the same entity:

- a local ``.torrent`` file, where the info hash is the SHA-1 of the re-encoded ``info`` dictionary;
- a raw ``info`` dictionary fetched from a peer over the metadata extension
    (magnet links), where the info hash is the SHA-1 of the bytes as received.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import bencodepy

from app.constants import MAX_PIECE_LENGTH
from app.errors import InvalidTorrentError, PeerProtocolError
from app.models import TorrentMetadata


_PIECE_HASH_LEN = 20

logger = logging.getLogger(__name__)


def load_torrent_file(path: str) -> TorrentMetadata:
    """Read and parse a ``.torrent`` file into metadata."""

    if not path.endswith(".torrent"):
        raise InvalidTorrentError(f"Invalid file extension: {path}")

    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise InvalidTorrentError(f"Cannot read torrent file: {path}") from exc

    try:
        decoded = bencodepy.decode(raw)
        info = decoded[b"info"]
    except (bencodepy.BencodeDecodeError, KeyError) as exc:
        raise InvalidTorrentError(f"Malformed torrent file: {path}") from exc
    info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
    return _build(decoded[b"announce"].decode(), info, info_hash)


def metadata_from_raw_info(tracker_url: str, raw_info: bytes, expected_hash: bytes | None = None) -> TorrentMetadata:
    """Build metadata from a raw ``info`` dictionary received from a peer.

    When ``expected_hash`` is given (the magnet's info hash), the received bytes
    are verified against it before being trusted, so a peer cannot substitute
    forged metadata for the torrent we asked for.
    """

    info_hash = hashlib.sha1(raw_info).digest()
    if expected_hash is not None and info_hash != expected_hash:
        raise PeerProtocolError(f"Metadata info hash mismatch: {info_hash.hex()} != {expected_hash.hex()}")
    try:
        info = bencodepy.decode(raw_info)
        return _build(tracker_url, info, info_hash)
    except (bencodepy.BencodeDecodeError, KeyError, TypeError) as exc:
        raise InvalidTorrentError(f"Malformed metadata received from peer: {exc}") from exc


def _build(tracker_url: str, info: dict, info_hash: bytes) -> TorrentMetadata:
    length = info[b"length"]
    piece_length = info[b"piece length"]
    pieces = info[b"pieces"]

    if not isinstance(length, int) or length <= 0:
        raise InvalidTorrentError(f"Invalid torrent length: {length!r}")
    if not isinstance(piece_length, int) or not 0 < piece_length <= MAX_PIECE_LENGTH:
        raise InvalidTorrentError(f"Invalid piece length: {piece_length!r}")
    if not isinstance(pieces, bytes) or len(pieces) % _PIECE_HASH_LEN != 0:
        raise InvalidTorrentError("Piece hashes are missing or misaligned")
    expected_count = -(-length // piece_length)
    if len(pieces) // _PIECE_HASH_LEN != expected_count:
        raise InvalidTorrentError("Piece count is inconsistent with the torrent length")

    piece_hashes = [ pieces[i : i + _PIECE_HASH_LEN] for i in range(0, len(pieces), _PIECE_HASH_LEN) ]
    logger.debug(
        "metadata built",
        extra={
            "ctx": {
                "info_hash": info_hash.hex()[:8],
                "length": length,
                "pieces": len(piece_hashes),
                "piece_length": piece_length
            }
        }
    )

    return TorrentMetadata(
        tracker_url=tracker_url,
        length=length,
        info_hash=info_hash,
        piece_length=piece_length,
        piece_hashes=piece_hashes
    )
