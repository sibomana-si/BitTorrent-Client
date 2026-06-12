"""HTTP tracker client: announce to a tracker and parse the peer list."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import quote_plus, urlencode, urljoin, urlsplit

import bencodepy
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.constants import (
    ALLOWED_SCHEMES,
    MAX_REDIRECTS,
    MAX_TRACKER_RESPONSE_BYTES,
    PEER_ID,
    TRACKER_PORT
)
from app.errors import TrackerError
from app.models import Peer


_PEER_RECORD_LEN = 6 # 4 bytes IPv4 + 2 bytes port
_HTTP_TIMEOUT = (5, 15) # (connect, read) timeout in seconds


def _is_blocked_ip(ip: str) -> bool:
    """True if ``ip`` is one we must never let a tracker URL point us at.

    Loopback, private, link-local (including the cloud-metadata address
    ``169.254.169.254``), reserved, multicast, and unspecified addresses are all
    internal/non-routable targets an SSRF payload would aim for.
    """
    address = ipaddress.ip_address(ip)
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _validate_tracker_url(url: str) -> None:
    """Reject tracker URLs that could be used for SSRF.

    The announce URL is attacker-controlled (it comes from the .torrent/magnet),
    so only ``http``/``https`` are honoured - ``file://``, ``gopher://`` and the
    like are refused before any request is made. The host is then resolved, and
    every resolved address is checked: a URL that points at an internal,
    loopback, or cloud-metadata address is refused before we connect.
    """

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TrackerError(f"Unsupported tracker URL scheme: {scheme or '(none)'}")

    host = parts.hostname
    if not host:
        raise TrackerError(f"Tracker URL has no host: {url}")

    try:
        resolved = socket.getaddrinfo(host, parts.port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise TrackerError(f"Cannot resolve tracker host {host!r}: {exc}") from exc

    for info in resolved:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise TrackerError(f"Tracker host {host!r} resolves to a blocked address: {ip}")


def _build_session() -> requests.Session:
    """A session that pools the tracker connection and retries transient faults.

    GET is idempotent, so urllib3 retries it on connection errors and on the
    usual transient 5xx responses, with exponential backoff between attempts.
    """
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504),
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# One shared session: reuses the TCP connection across announces in a download.
_SESSION = _build_session()


def _get_validated(url: str) -> requests.Response:
    """GET ``url``, following redirects manually with the SSRF guard on each hop.

    Automatic redirects are disabled: a tracker that passes the guard could
    otherwise ``302`` us to an internal address. Each ``Location`` is resolved,
    re-validated by :func:`_validate_tracker_url`, and followed up to
    ``MAX_REDIRECTS`` times before giving up.
    """

    for _ in range(MAX_REDIRECTS + 1):
        response = _SESSION.get(url, timeout=_HTTP_TIMEOUT, allow_redirects=False, stream=True)
        if not (response.is_redirect or response.is_permanent_redirect):
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            return response
        url = urljoin(url, location)
        _validate_tracker_url(url)
    raise TrackerError("Too many tracker redirects")


def _read_capped(response: requests.Response) -> bytes:
    """Read the response body, refusing to buffer more than the size limit."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(8192):
        total += len(chunk)
        if total > MAX_TRACKER_RESPONSE_BYTES:
            response.close()
            raise TrackerError("Tracker response exceeded the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


class TrackerClient:
    """Announces to a tracker and returns the peers it reports."""

    def __init__(self, peer_id: bytes = PEER_ID, port: int = TRACKER_PORT) -> None:
        self.peer_id = peer_id
        self.port = port

    def get_peers(self, tracker_url: str, info_hash: bytes, left: int) -> list[Peer]:
        """Request peers for ``info_hash`` from ``tracker_url`` (compact mode)."""

        _validate_tracker_url(tracker_url)
        params = {
            "info_hash": info_hash,
            "peer_id": self.peer_id,
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": left,
            "compact": 1,
        }
        url = f"{tracker_url}?{urlencode(params, quote_via=quote_plus)}"
        try:
            response = _get_validated(url)
            response.raise_for_status()
            body = _read_capped(response)
        except requests.RequestException as exc:
            raise TrackerError(f"Tracker request failed: {exc}") from exc

        try:
            decoded = bencodepy.decode(body)
            peers = decoded[b"peers"]
        except (bencodepy.BencodeDecodeError, KeyError, TypeError) as exc:
            raise TrackerError(f"Unexpected tracker response: {exc}") from exc

        return self._parse_peers(peers)

    @staticmethod
    def _parse_peers(blob: bytes) -> list[Peer]:
        # The compact list is a sequence of 6-byte records;
        # reject any length that isn't a non-zero multiple of 6.
        if not isinstance(blob, bytes) or not blob or len(blob) % _PEER_RECORD_LEN:
            raise TrackerError("Tracker returned a malformed peer list")

        peers = []
        for offset in range(0, len(blob), _PEER_RECORD_LEN):
            record = blob[offset : offset + _PEER_RECORD_LEN]
            ip = ".".join(str(byte) for byte in record[:4])
            port = int.from_bytes(record[4:6], "big")
            peers.append(Peer(ip, port))
        return peers
