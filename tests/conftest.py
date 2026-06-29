"""Shared fixtures and protocol fakes for the test suite.

Nothing here touches the real network:

- ``FakePeer`` is a real TCP server bound to ``127.0.0.1`` (peer connections are not SSRF-guarded,
    so the client may connect to it directly);
- tracker HTTP is stubbed by monkeypatching ``app.tracker._SESSION.get`` and
  ``app.tracker.socket.getaddrinfo`` (the SSRF guard blocks loopback, so a real local HTTP tracker
    can never pass validation).
"""

from __future__ import annotations

import hashlib
import socket as socket_mod
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote

import bencodepy
import pytest
import requests

from app.constants import ALLOW_PRIVATE_PEERS_ENV_VAR, MAGNET_RESERVED, PROTOCOL_NAME
from app.models import Peer, TorrentMetadata

TRACKER_HOST = "tracker.example.test"
TRACKER_URL = f"http://{TRACKER_HOST}/announce"
# What the stubbed resolver returns for any host without an explicit mapping.
PUBLIC_IP = "93.184.216.34"

CLIENT_PEER_ID = b"TESTCLIENT0123456789"  # 20 bytes


# -- low-level wire helpers ---------------------------------------------------


def frame(msg_id: int | None = None, payload: bytes = b"") -> bytes:
    """Build one length-prefixed peer message; ``msg_id=None`` is a keep-alive."""
    if msg_id is None:
        return (0).to_bytes(4, "big")
    body = bytes([msg_id]) + payload
    return len(body).to_bytes(4, "big") + body


def handshake_bytes(info_hash: bytes, peer_id: bytes, *, protocol: bytes = PROTOCOL_NAME, reserved: bytes = bytes(8)) -> bytes:
    """Build a 68-byte BitTorrent handshake."""
    return bytes([len(protocol)]) + protocol + reserved + info_hash + peer_id


class ScriptedSocket:
    """A fake socket: ``recv`` serves a preloaded script, ``sendall`` records.

    ``chunk`` forces short reads so ``_recv_exact``'s reassembly loop is exercised;
    ``recv_error`` makes the next ``recv`` raise.
    """

    def __init__(self, script: bytes = b"", *, chunk: int | None = None, recv_error: Exception | None = None) -> None:
        self._script = script
        self._chunk = chunk
        self._recv_error = recv_error
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, count: int) -> bytes:
        if self._recv_error is not None:
            raise self._recv_error
        if not self._script:
            return b""  # peer closed
        take = min(count, len(self._script))
        if self._chunk is not None:
            take = min(take, self._chunk)
        out, self._script = self._script[:take], self._script[take:]
        return out

    def recv_into(self, buffer) -> int:
        data = self.recv(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def settimeout(self, _timeout: float) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class ListReporter:
    """A ProgressReporter that collects messages for assertions."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def report(self, message: str) -> None:
        self.lines.append(message)


# -- torrent factory ----------------------------------------------------------


@dataclass
class TorrentFixture:
    """A generated torrent: the file on disk plus every fact tests assert on."""

    path: str
    content: bytes
    tracker_url: str
    length: int
    piece_length: int
    piece_hashes: list[bytes]
    raw_info: bytes
    info_hash: bytes

    @property
    def magnet_link(self) -> str:
        return f"magnet:?xt=urn:btih:{self.info_hash.hex()}&tr={quote(self.tracker_url, safe='')}"

    def piece(self, index: int) -> bytes:
        start = index * self.piece_length
        return self.content[start : start + self.piece_length]

    @property
    def metadata(self) -> TorrentMetadata:
        return TorrentMetadata(
            tracker_url=self.tracker_url,
            length=self.length,
            info_hash=self.info_hash,
            piece_length=self.piece_length,
            piece_hashes=self.piece_hashes,
        )


def build_metadata(content: bytes, piece_length: int) -> TorrentMetadata:
    """An in-memory TorrentMetadata for unit tests that never touch a file."""
    hashes = [
        hashlib.sha1(content[i : i + piece_length]).digest()
        for i in range(0, len(content), piece_length)
    ]
    return TorrentMetadata(
        tracker_url=TRACKER_URL,
        length=len(content),
        info_hash=hashlib.sha1(b"unit-test-info").digest(),
        piece_length=piece_length,
        piece_hashes=hashes,
    )


@pytest.fixture
def make_torrent(tmp_path):
    """Factory: write a valid single-file ``.torrent`` and return its facts."""

    def _make(
        *,
        length: int = 40,
        piece_length: int = 16,
        name: str = "sample",
        tracker_url: str = TRACKER_URL,
        content: bytes | None = None,
        announce_list: list[str] | None = None,
    ) -> TorrentFixture:
        if content is None:
            # Deterministic, non-repeating bytes (defaults to a short last piece).
            content = bytes((i * 37 + 11) % 256 for i in range(length))
        length = len(content)
        hashes = [
            hashlib.sha1(content[i : i + piece_length]).digest()
            for i in range(0, length, piece_length)
        ]
        info = {
            "length": length,
            "name": name,
            "piece length": piece_length,
            "pieces": b"".join(hashes),
        }
        raw_info = bencodepy.encode(info)
        path = tmp_path / f"{name}.torrent"
        torrent_dict = {"announce": tracker_url, "info": info}
        if announce_list is not None:
            # BEP 12: a list of tiers, each a list of tracker URLs.
            torrent_dict["announce-list"] = [[url] for url in announce_list]
        path.write_bytes(bencodepy.encode(torrent_dict))
        return TorrentFixture(
            path=str(path),
            content=content,
            tracker_url=tracker_url,
            length=length,
            piece_length=piece_length,
            piece_hashes=hashes,
            raw_info=raw_info,
            info_hash=hashlib.sha1(raw_info).digest(),
        )

    return _make


# -- fake peer ----------------------------------------------------------------


class FakePeer:
    """A minimal BitTorrent peer served over real TCP on 127.0.0.1.

    Speaks just enough of the wire protocol for the client under test:
    handshake echo, an interleaved keep-alive/have/bitfield burst (to exercise
    the client's frame skipping), interested -> unchoke, request -> piece, and
    the BEP 9 extension handshake + metadata "data" message. Knobs corrupt
    individual behaviors for error-path tests; ``block_delays`` maps a piece
    index to seconds slept before its block is served, so a test can force a
    given piece to finish last (exercising the concurrent ordered-output gate).
    Serves any number of sequential connections (failover tests reconnect).
    """

    def __init__(
        self,
        info_hash: bytes,
        *,
        content: bytes = b"",
        piece_length: int = 1,
        raw_info: bytes = b"",
        peer_id: bytes = b"-FAKEPEER-0123456789",
        extension: bool = False,
        protocol: bytes = PROTOCOL_NAME,
        echo_info_hash: bytes | None = None,
        corrupt_data: bool = False,
        total_size: int | None = None,
        ut_metadata_id: int = 42,
        block_delays: dict[int, float] | None = None,
    ) -> None:
        self.info_hash = info_hash
        self.content = content
        self.piece_length = piece_length
        self.raw_info = raw_info
        self.peer_id = peer_id
        self.extension = extension
        self.protocol = protocol
        self.echo_info_hash = echo_info_hash
        self.corrupt_data = corrupt_data
        self.total_size = total_size
        self.ut_metadata_id = ut_metadata_id
        self.block_delays = block_delays or {}
        self.connections = 0

        self._server = socket_mod.socket(socket_mod.AF_INET, socket_mod.SOCK_STREAM)
        self._server.setsockopt(socket_mod.SOL_SOCKET, socket_mod.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(5)
        self._server.settimeout(0.2)
        self.ip, self.port = self._server.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)

    @classmethod
    def for_torrent(cls, torrent: TorrentFixture, **kwargs) -> "FakePeer":
        return cls(
            torrent.info_hash,
            content=torrent.content,
            piece_length=torrent.piece_length,
            raw_info=torrent.raw_info,
            **kwargs,
        )

    @property
    def peer(self) -> Peer:
        return Peer(self.ip, self.port)

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    def __enter__(self) -> "FakePeer":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._server.close()

    def _serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except socket_mod.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            # One thread per connection: the concurrent download path holds
            # several connections open at once.
            threading.Thread(target=self._serve_connection, args=(conn,), daemon=True).start()

    def _serve_connection(self, conn: socket_mod.socket) -> None:
        try:
            self._serve(conn)
        except OSError:
            pass  # client went away mid-conversation; keep accepting
        finally:
            conn.close()

    @staticmethod
    def _recv_exact(conn: socket_mod.socket, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = conn.recv(count - len(data))
            if not chunk:
                raise OSError("client closed the connection")
            data += chunk
        return data

    def _serve(self, conn: socket_mod.socket) -> None:
        # Real peers disable Nagle; without this the *fake's* piece messages
        # stall behind delayed ACKs and benchmarks measure the fake, not the app.
        conn.setsockopt(socket_mod.IPPROTO_TCP, socket_mod.TCP_NODELAY, 1)
        conn.settimeout(5)
        received = self._recv_exact(conn, 68)
        reserved = MAGNET_RESERVED if self.extension else bytes(8)
        echo = self.echo_info_hash if self.echo_info_hash is not None else received[28:48]
        conn.sendall(handshake_bytes(echo, self.peer_id, protocol=self.protocol, reserved=reserved))
        # Interleave informational frames the client must skip over.
        conn.sendall(frame(None) + frame(4, (0).to_bytes(4, "big")) + frame(5, b"\xff"))

        while True:
            try:
                header = self._recv_exact(conn, 4)
            except OSError:
                return
            length = int.from_bytes(header, "big")
            if length == 0:
                continue
            body = self._recv_exact(conn, length)
            msg_id = body[0]
            if msg_id == 2:  # interested -> unchoke
                conn.sendall(frame(1))
            elif msg_id == 6:  # request -> piece
                index = int.from_bytes(body[1:5], "big")
                begin = int.from_bytes(body[5:9], "big")
                wanted = int.from_bytes(body[9:13], "big")
                start = index * self.piece_length + begin
                block = self.content[start : start + wanted]
                if self.corrupt_data:
                    block = bytes(byte ^ 0xFF for byte in block)
                if index in self.block_delays:
                    time.sleep(self.block_delays[index])
                conn.sendall(
                    frame(7, index.to_bytes(4, "big") + begin.to_bytes(4, "big") + block)
                )
            elif msg_id == 20:  # extension protocol
                ext_id = body[1]
                if ext_id == 0:  # extension handshake
                    payload = bencodepy.encode({"m": {"ut_metadata": self.ut_metadata_id}})
                    conn.sendall(frame(20, bytes([0]) + payload))
                else:  # metadata request -> data message (dict + raw info bytes)
                    total = self.total_size if self.total_size is not None else len(self.raw_info)
                    head = bencodepy.encode({"msg_type": 1, "piece": 0, "total_size": total})
                    conn.sendall(frame(20, bytes([1]) + head + self.raw_info))


# -- tracker stub -------------------------------------------------------------


class StubResponse:
    """The small slice of ``requests.Response`` that ``app.tracker`` uses."""

    def __init__(self, body: bytes = b"", status: int = 200, headers: dict | None = None):
        self.body = body
        self.status_code = status
        self.headers = headers or {}

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_permanent_redirect(self) -> bool:
        return False

    def iter_content(self, chunk_size: int):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)

    def close(self) -> None:
        pass


def compact_peers_blob(peers: list[tuple[str, int]]) -> bytes:
    """Encode ``(ip, port)`` pairs as a compact tracker peer list."""
    return b"".join(socket_mod.inet_aton(ip) + port.to_bytes(2, "big") for ip, port in peers)


class TrackerStub:
    """Programmable stand-in for the tracker HTTP session and DNS resolution.

    ``queue`` holds one-shot responses (or exceptions to raise); when empty,
    ``default`` is returned for every request. ``resolve`` maps a hostname to
    an IP string (or an exception) for the patched ``getaddrinfo``; unmapped
    hosts resolve to ``PUBLIC_IP`` so they pass the SSRF guard.
    """

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.queue: list[StubResponse | Exception] = []
        self.default: StubResponse | None = None
        self.resolve: dict[str, str | Exception] = {}

    def get(self, url: str, **_kwargs) -> StubResponse:
        self.urls.append(url)
        item = self.queue.pop(0) if self.queue else self.default
        if isinstance(item, Exception):
            raise item
        assert item is not None, f"TrackerStub got an unexpected request: {url}"
        return item

    def getaddrinfo(self, host: str, port, **_kwargs):
        target = self.resolve.get(host, PUBLIC_IP)
        if isinstance(target, Exception):
            raise target
        return [
            (
                socket_mod.AF_INET,
                socket_mod.SOCK_STREAM,
                socket_mod.IPPROTO_TCP,
                "",
                (target, port or 80),
            )
        ]

    def set_peers(self, peers: list[tuple[str, int]]) -> None:
        """Make every announce return this compact peer list."""
        body = bencodepy.encode({"interval": 60, "peers": compact_peers_blob(peers)})
        self.default = StubResponse(body)


@pytest.fixture
def stub_tracker(monkeypatch) -> TrackerStub:
    import app.tracker as tracker_mod

    stub = TrackerStub()
    monkeypatch.setattr(tracker_mod._SESSION, "get", stub.get)
    monkeypatch.setattr(tracker_mod.socket, "getaddrinfo", stub.getaddrinfo)
    return stub


# -- misc ---------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _allow_loopback_peers(monkeypatch) -> None:
    """Let the suite connect to FakePeer (127.0.0.1) through the SSRF peer guard.

    The peer-IP guard added for SEC1 blocks loopback/private addresses by
    default; the test harness legitimately runs peers on loopback, so opt out
    here. Tests that exercise the guard itself delete this env var.
    """
    monkeypatch.setenv(ALLOW_PRIVATE_PEERS_ENV_VAR, "1")


@pytest.fixture
def no_sleep(monkeypatch) -> list[float]:
    """Disable real sleeping in retry backoff; returns the recorded delays."""
    delays: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: delays.append(seconds))
    return delays
