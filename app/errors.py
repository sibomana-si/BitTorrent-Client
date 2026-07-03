"""The client's error contract.

Every expected operational failure is a :class:`BitTorrentError`. The CLI
boundary (:func:`app.cli.main`) catches this base class, reports it cleanly, and
exits non-zero; anything else propagates as a traceback, so genuine bugs stay
loud. Each infrastructure boundary translates the low-level exception it sees
(``OSError``, ``requests.RequestException``, ``BencodeDecodeError``) into the
matching error below.
"""

from __future__ import annotations


class BitTorrentError(Exception):
    """Base for expected, operational errors raised by this client."""


class BencodeError(BitTorrentError):
    """A bencoded value could not be decoded."""


class InvalidTorrentError(BitTorrentError):
    """A ``.torrent`` file is missing, has the wrong extension, or is malformed."""


class InvalidMagnetError(BitTorrentError):
    """A magnet URI is malformed or missing required fields."""


class TrackerError(BitTorrentError):
    """The tracker request failed or returned an unusable response."""


class PeerProtocolError(BitTorrentError):
    """A peer connection failed or violated the wire protocol."""
