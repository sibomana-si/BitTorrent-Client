"""HTTP tracker client: announce to a tracker and parse the peer list."""

from __future__ import annotations

from urllib.parse import quote_plus, urlencode, urlsplit

import bencodepy
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.constants import ALLOWED_SCHEMES, PEER_ID, TRACKER_PORT
from src.errors import TrackerError
from src.models import Peer


_PEER_RECORD_LEN = 6 # 4 bytes IPv4 + 2 bytes port
_HTTP_TIMEOUT = (5, 15) # (connect, read) timeout in seconds


def _validate_tracker_url(url: str) -> None:
    """Reject tracker URLs that could be used for SSRF.

    The announce URL is attacker-controlled (it comes from the .torrent/magnet),
    so only ``http``/``https`` are honoured - ``file://``, ``gopher://`` and the
    like are refused before any request is made.
    """

    scheme = urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TrackerError(f"Unsupported tracker URL scheme: {scheme or '(none)'}")


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
            response = _SESSION.get(url, timeout=_HTTP_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise TrackerError(f"Tracker request failed: {exc}") from exc

        try:
            decoded = bencodepy.decode(response.content)
            peers = decoded[b"peers"]
        except (bencodepy.BencodeDecodeError, KeyError, TypeError) as exc:
            raise TrackerError(f"Unexpected tracker response: {exc}") from exc

        return self._parse_peers(peers)

    @staticmethod
    def _parse_peers(blob: bytes) -> list[Peer]:
        peers = []
        for offset in range(0, len(blob), _PEER_RECORD_LEN):
            record = blob[offset : offset + _PEER_RECORD_LEN]
            ip = ".".join(str(byte) for byte in record[:4])
            port = int.from_bytes(record[4:6], "big")
            peers.append(Peer(ip, port))
        return peers
