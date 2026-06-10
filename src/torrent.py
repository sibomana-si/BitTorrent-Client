"""Build :class:`TorrentMetadata` from a ``.torrent`` file or a metadata blob.

Two sources produce the same entity:

- a local ``.torrent`` file, where the info hash is the SHA-1 of the re-encoded ``info`` dictionary;
- a raw ``info`` dictionary fetched from a peer over the metadata extension
    (magnet links), where the info hash is the SHA-1 of the bytes as received.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import bencodepy

from src.errors import InvalidTorrentError
from src.models import TorrentMetadata


_PIECE_HASH_LEN = 20


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


def metadata_from_raw_info(tracker_url: str, raw_info: bytes) -> TorrentMetadata:
    """Build metadata from a raw ``info`` dictionary received from a peer."""

    info_hash = hashlib.sha1(raw_info).digest()
    try:
        info = bencodepy.decode(raw_info)
        return _build(tracker_url, info, info_hash)
    except (bencodepy.BencodeDecodeError, KeyError, TypeError) as exc:
        raise InvalidTorrentError(f"Malformed metadata received from peer: {exc}") from exc


def _build(tracker_url: str, info: dict, info_hash: bytes) -> TorrentMetadata:
    pieces = info[b"pieces"]
    piece_hashes = [ pieces[i : i + _PIECE_HASH_LEN] for i in range(0, len(pieces), _PIECE_HASH_LEN) ]
    return TorrentMetadata(
        tracker_url=tracker_url,
        length=info[b"length"],
        info_hash=info_hash,
        piece_length=info[b"piece length"],
        piece_hashes=piece_hashes
    )
