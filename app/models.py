"""Immutable domain entities. No I/O, no protocol logic - just data.

The info hash is stored once, as raw 20 bytes, with a ``*_hex`` helper for
display. This is deliberate: the previous design kept it as a mix of hash
objects, hex strings, and bytes, forcing ``type(...)`` checks at every call site.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Peer:
    """A peer address advertised by a tracker."""

    ip: str
    port: int

    @classmethod
    def from_address(cls, address: str) -> "Peer":
        """Parse an ``ip:port`` address (as passed to the handshake command)."""
        ip, port = address.rsplit(":", 1)
        return cls(ip, int(port))

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class MagnetLink:
    """The pieces of a magnet URI we care about."""

    info_hash: bytes
    tracker_url: str
    trackers: tuple[str, ...] = ()

    @property
    def info_hash_hex(self) -> str:
        return self.info_hash.hex()

    @property
    def announce_urls(self) -> list[str]:
        """Trackers to try in order; the primary ``tracker_url`` when none extra."""

        return list(self.trackers) or [self.tracker_url]


@dataclass(frozen=True)
class TorrentMetadata:
    """Everything needed to fetch a torrent, whether from a file or a magnet."""

    tracker_url: str
    length: int
    info_hash: bytes
    piece_length: int
    piece_hashes: list[bytes]
    trackers: tuple[str, ...] = ()

    @property
    def info_hash_hex(self) -> str:
        return self.info_hash.hex()

    @property
    def piece_hashes_hex(self) -> list[str]:
        return [piece_hash.hex() for piece_hash in self.piece_hashes]

    @property
    def announce_urls(self) -> list[str]:
        """Trackers to try in order; the primary ``tracker_url`` when none extra."""

        return list(self.trackers) or [self.tracker_url]
