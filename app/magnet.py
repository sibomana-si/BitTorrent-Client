"""Parsing of magnet URIs into a :class:`MagnetLink`."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlparse

from app.errors import InvalidMagnetError
from app.models import MagnetLink


_BTIH_PREFIX = "urn:btih:"
_INFO_HASH_HEX_LEN = 40

logger = logging.getLogger(__name__)


def parse_magnet_link(uri: str) -> MagnetLink:
    """Extract the info hash and tracker URL from a magnet URI.

    Parsed structurally with ``urlparse``/``parse_qs`` rather than by substring
    search, so field order, percent-encoding, and extra/duplicate parameters
    cannot be used to smuggle a different value past the parser. Only the subset
    this client uses is honoured: the ``xt=urn:btih:`` info hash and the
    ``tr=`` tracker announce URLs - the first is the primary ``tracker_url``
    (shown by ``magnet_parse``), and all of them, de-duplicated in order, are
    kept in ``trackers`` for failover.
    """

    parsed = urlparse(uri)
    if parsed.scheme != "magnet":
        raise InvalidMagnetError(f"Invalid magnet link: {uri}")

    params = parse_qs(parsed.query)
    xt_values = params.get("xt", [])
    tr_values = params.get("tr", [])
    if not xt_values or not tr_values:
        raise InvalidMagnetError(f"Missing info hash or tracker URL: {uri}")

    xt = xt_values[0]
    if not xt.startswith(_BTIH_PREFIX):
        raise InvalidMagnetError(f"Invalid info hash in magnet link: {uri}")
    info_hash_hex = xt[len(_BTIH_PREFIX) :]
    if len(info_hash_hex) != _INFO_HASH_HEX_LEN:
        raise InvalidMagnetError(f"Invalid info hash in magnet link: {uri}")

    try:
        info_hash = bytes.fromhex(info_hash_hex)
    except ValueError as exc:
        raise InvalidMagnetError(f"Invalid info hash in magnet link: {uri}") from exc

    trackers = tuple(dict.fromkeys(tr_values))
    logger.debug("magnet link parsed", extra={"ctx": {"info_hash": info_hash.hex()[:8], "tracker": tr_values[0], "trackers": len(trackers)}})
    return MagnetLink(info_hash=info_hash, tracker_url=tr_values[0], trackers=trackers)
