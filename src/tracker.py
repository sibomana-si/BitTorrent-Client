"""HTTP tracker client: announce to a tracker and parse the peer list."""

from __future__ import annotations

from urllib.parse import quote_plus, urlencode

import bencodepy
import requests

from src.constants import PEER_ID, TRACKER_PORT
from src.errors import TrackerError
from src.models import Peer


_PEER_RECORD_LEN = 6 # 4 bytes IPv4 + 2 bytes port


class TrackerClient:
    """Announces to a tracker and returns the peers it reports."""

    def __init__(self, peer_id: bytes = PEER_ID, port: int = TRACKER_PORT) -> None:
        self.peer_id = peer_id
        self.port = port

    def get_peers(self, tracker_url: str, info_hash: bytes, left: int) -> list[Peer]:
        """Request peers for ``info_hash`` from ``tracker_url`` (compact mode)."""

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
            response = requests.get(url)
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
