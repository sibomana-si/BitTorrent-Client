"""Parsing of magnet URIs into a :class:`MagnetLink`."""

from __future__ import annotations

from urllib.parse import unquote_plus

from src.errors import InvalidMagnetError
from src.models import MagnetLink


_XT_PREFIX = "xt=urn:btih:"
_INFO_HASH_HEX_LEN = 40


def parse_magnet_link(uri: str) -> MagnetLink:
    """Extract the info hash and tracker URL from a magnet URI.

    Only the subset used by this client is parsed: the ``xt=urn:btih:`` info
    hash and the ``tr=`` tracker announce URL.
    """

    if not uri.startswith("magnet:?xt="):
        raise InvalidMagnetError(f"Invalid magnet link: {uri}")

    xt_index = uri.find(_XT_PREFIX)
    tracker_index = uri.find("tr=")
    if xt_index == -1 or tracker_index == -1:
        raise InvalidMagnetError(f"Missing info hash or tracker URL: {uri}")

    hash_start = xt_index + len(_XT_PREFIX)
    info_hash_hex = uri[hash_start : hash_start + _INFO_HASH_HEX_LEN]
    tracker_url = unquote_plus(uri[tracker_index + len("tr=") :])

    try:
        info_hash = bytes.fromhex(info_hash_hex)
    except ValueError as exc:
        raise InvalidMagnetError(f"Invalid info hash in magnet link: {uri}") from exc

    return MagnetLink(info_hash=info_hash, tracker_url=tracker_url)
