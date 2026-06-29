"""Unit tests for the application layer in app/client.py.

PeerConnection is replaced with an in-memory stub for the failover tests, so
these exercise the orchestration logic alone; the real wire protocol is covered
in tests/unit/test_peer.py and tests/integration/.
"""

import io

import pytest
from typing import cast

import app.client as client_mod
from app.client import _PIECE_RETRIES, TorrentClient, PeerConnection
from app.constants import CONNECT_RETRIES, MAX_TORRENT_LENGTH
from app.errors import BencodeError, InvalidTorrentError, PeerProtocolError
from app.models import Peer

from tests.conftest import ListReporter, build_metadata

PEERS = [Peer("1.1.1.1", 1111), Peer("2.2.2.2", 2222), Peer("3.3.3.3", 3333)]


class TestDecode:
    def test_decodes_bencode(self):
        assert TorrentClient().decode("d3:foo3:bare") == {b"foo": b"bar"}
        assert TorrentClient().decode("li1ei2ee") == [1, 2]

    def test_invalid_value_raises_bencode_error(self):
        with pytest.raises(BencodeError, match="Invalid bencoded value"):
            TorrentClient().decode("i12")  # unterminated integer


class TestSizeCeiling:
    def test_length_at_the_ceiling_is_allowed(self):
        TorrentClient._enforce_size_ceiling(MAX_TORRENT_LENGTH)  # must not raise

    def test_length_over_the_ceiling_is_refused(self):
        with pytest.raises(InvalidTorrentError, match="Refusing to download"):
            TorrentClient._enforce_size_ceiling(MAX_TORRENT_LENGTH + 1)


class TestAtomicWrites:
    def test_atomic_write_lands_the_content(self, tmp_path):
        path = tmp_path / "out.bin"
        TorrentClient()._atomic_write(str(path), b"payload")
        assert path.read_bytes() == b"payload"

    def test_atomic_write_leaves_no_temp_files(self, tmp_path):
        path = tmp_path / "out.bin"
        TorrentClient()._atomic_write(str(path), b"payload")
        assert [entry.name for entry in tmp_path.iterdir()] == ["out.bin"]

    def test_failure_leaves_no_output_and_no_temp_file(self, tmp_path):
        path = tmp_path / "out.bin"
        with pytest.raises(RuntimeError):
            with TorrentClient._atomic_output(str(path)) as output_file:
                output_file.write(b"half written")
                raise RuntimeError("simulated crash mid-download")

    def test_overwrites_an_existing_file_atomically(self, tmp_path):
        path = tmp_path / "out.bin"
        path.write_bytes(b"old")
        TorrentClient()._atomic_write(str(path), b"new")
        assert path.read_bytes() == b"new"

    def test_failure_preserves_an_existing_file(self, tmp_path):
        path = tmp_path / "out.bin"
        path.write_bytes(b"precious")
        with pytest.raises(RuntimeError):
            with TorrentClient._atomic_output(str(path)) as output_file:
                output_file.write(b"garbage")
                raise RuntimeError("boom")


class _FlakyConn:
    """connect() fails a configured number of times, then succeeds."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0

    def connect(self, peers) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise PeerProtocolError("transient connect failure")


class TestConnectWithRetry:
    def test_first_try_success_does_not_sleep(self, no_sleep):
        conn = _FlakyConn(failures=0)
        TorrentClient()._connect_with_retry(cast(PeerConnection, conn), PEERS)
        assert conn.calls == 1
        assert no_sleep == []

    def test_recovers_after_transient_failures(self, no_sleep):
        conn = _FlakyConn(failures=CONNECT_RETRIES - 1)
        TorrentClient()._connect_with_retry(cast(PeerConnection, conn), PEERS)
        assert conn.calls == CONNECT_RETRIES
        assert len(no_sleep) == CONNECT_RETRIES - 1

    def test_backoff_delays_grow(self, no_sleep):
        conn = _FlakyConn(failures=CONNECT_RETRIES - 1)
        TorrentClient()._connect_with_retry(cast(PeerConnection, conn), PEERS)
        # Each delay is base*2^n plus jitter in [0, base*2^n).
        assert no_sleep == sorted(no_sleep)

    def test_exhausted_retries_raise(self, no_sleep):
        conn = _FlakyConn(failures=CONNECT_RETRIES)
        with pytest.raises(PeerProtocolError):
            TorrentClient()._connect_with_retry(cast(PeerConnection, conn), PEERS)
        assert conn.calls == CONNECT_RETRIES
        assert len(no_sleep) == CONNECT_RETRIES - 1


class _StubConn:
    """Stands in for PeerConnection inside _download_with_failover.

    ``piece_results`` is a shared queue of behaviors consumed per
    ``download_piece`` call: a bytes value is returned, an exception is raised.
    """

    instances: list["_StubConn"] = []
    piece_results: list = []

    def __init__(self, peer_id, reporter=None) -> None:
        self.closed = False
        self.connect_order: list[Peer] = []
        type(self).instances.append(self)

    def connect(self, peers) -> None:
        self.connect_order = list(peers)

    def handshake(self, info_hash, *, magnet=False) -> None:
        self.magnet = magnet

    def send_interested(self) -> None:
        pass

    def download_piece(self, meta, piece_index: int, reporter=None) -> bytes:
        result = type(self).piece_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def stub_conn_cls(monkeypatch):
    _StubConn.instances = []
    _StubConn.piece_results = []
    monkeypatch.setattr(client_mod, "PeerConnection", _StubConn)
    return _StubConn


class TestDownloadWithFailover:
    CONTENT = bytes((i * 13 + 5) % 256 for i in range(40))  # pieces: 16, 16, 8

    def _run(self, reporter=None, initial_conn=None):
        meta = build_metadata(self.CONTENT, piece_length=16)
        buffer = io.BytesIO()
        client = TorrentClient(reporter=reporter or ListReporter())
        client._download_with_failover(
            meta, buffer, "out.bin", PEERS, meta.info_hash,
            magnet=False, initial_conn=initial_conn,
        )
        return buffer.getvalue()

    def test_happy_path_writes_every_piece_at_its_offset(self, stub_conn_cls):
        stub_conn_cls.piece_results = [self.CONTENT[0:16], self.CONTENT[16:32], self.CONTENT[32:40]]
        assert self._run() == self.CONTENT
        assert len(stub_conn_cls.instances) == 1

    def test_happy_path_reports_progress(self, stub_conn_cls):
        stub_conn_cls.piece_results = [self.CONTENT[0:16], self.CONTENT[16:32], self.CONTENT[32:40]]
        reporter = ListReporter()
        self._run(reporter=reporter)
        assert reporter.lines == [
            "downloading to out.bin ...",
            "pieces to download: 3",
            "piece_0 | 16 downloaded.",
            "piece_1 | 16 downloaded.",
            "piece_2 | 8 downloaded.",
        ]

    def test_piece_failure_fails_over_to_the_next_peer(self, stub_conn_cls):
        stub_conn_cls.piece_results = [
            self.CONTENT[0:16],
            PeerProtocolError("flaky peer"),     # piece 1, attempt 1
            self.CONTENT[16:32],                  # piece 1, attempt 2 (new conn)
            self.CONTENT[32:40],
        ]
        assert self._run() == self.CONTENT
        first, second = stub_conn_cls.instances
        assert first.closed is True               # dropped after the failure
        # The replacement starts from the next peer in the rotation.
        assert second.connect_order[0] == PEERS[1]

    def test_retries_exhausted_raises_and_closes_everything(self, stub_conn_cls):
        stub_conn_cls.piece_results = [PeerProtocolError("bad") for _ in range(_PIECE_RETRIES)]
        with pytest.raises(PeerProtocolError):
            self._run()
        assert len(stub_conn_cls.instances) == _PIECE_RETRIES
        assert all(conn.closed for conn in stub_conn_cls.instances)

    def test_initial_conn_is_reused_and_never_closed_here(self, stub_conn_cls):
        initial = _StubConn(b"x")
        stub_conn_cls.instances = []  # the caller-owned conn is not "opened" here
        stub_conn_cls.piece_results = [
            PeerProtocolError("initial conn fails piece 0"),
            self.CONTENT[0:16], self.CONTENT[16:32], self.CONTENT[32:40],
        ]
        assert self._run(initial_conn=initial) == self.CONTENT
        assert initial.closed is False             # owned by the caller
        (replacement,) = stub_conn_cls.instances
        assert replacement.closed is True          # owned (and closed) here
