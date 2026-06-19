"""Application use cases: orchestrate tracker, peer, and metadata steps.

This layer wires the infrastructure together for each high-level action and
owns the connection lifecycle. The CLI calls these methods and handles all
formatting; the protocol details live in :mod:`app.peer` and :mod:`app.tracker`.
"""

from __future__ import annotations

import logging
import os
import random
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import bencodepy

from app.constants import (
    CONNECT_RETRIES,
    MAGNET_STUB_LENGTH,
    MAX_PEERS_ENV_VAR,
    MAX_TORRENT_LENGTH,
    PEER_ID,
    RETRY_BASE_DELAY
)
from app.errors import BencodeError, InvalidTorrentError, PeerProtocolError, TrackerError
from app.magnet import parse_magnet_link
from app.models import MagnetLink, Peer, TorrentMetadata
from app.peer import PeerConnection
from app.reporting import NullReporter, ProgressReporter
from app.torrent import load_torrent_file, metadata_from_raw_info

if TYPE_CHECKING:
    from app.tracker import TrackerClient


# How many peers to try for a single piece before giving the whole piece up.
_PIECE_RETRIES = 3

logger = logging.getLogger(__name__)


def _max_peer_connections() -> int:
    """Worker-connection count for full downloads (from the environment).

    Unset, unparseable or < 1 all mean 1: the sequential single-connection
    path, whose output the test suite asserts byte-for-byte.
    """

    try:
        value = int(os.environ.get(MAX_PEERS_ENV_VAR, ""))
    except ValueError:
        return 1
    return max(value, 1)


class _BufferReporter:
    """Collects one piece's progress lines for ordered release."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def report(self, message: str) -> None:
        self.lines.append(message)


class _OrderedProgress:
    """Releases buffered per-piece progress lines in piece-index order.

    Concurrent workers finish pieces out of order, but the progress output
    lists pieces strictly by index, so each piece's buffer is held until every
    earlier piece has delivered its own.
    """

    def __init__(self, reporter: ProgressReporter) -> None:
        self._reporter = reporter
        self._lock = threading.Lock()
        self._next = 0
        self._held: dict[int, list[str]] = {}

    def deliver(self, piece_index: int, lines: list[str]) -> None:
        with self._lock:
            self._held[piece_index] = lines
            while self._next in self._held:
                for line in self._held.pop(self._next):
                    self._reporter.report(line)
                self._next += 1


class _DownloadSession:
    """Shared state and per-worker operations for one full download.

    Owns the peer rotation, the replacement connections opened here, and the run
    stats, so the sequential and concurrent download paths drive the same
    connect/handshake and per-piece failover logic. ``initial_conn`` (a magnet
    metadata socket) is owned by the caller and is never closed here.
    """

    def __init__(
            self,
            client: "TorrentClient",
            meta: TorrentMetadata,
            peers: list[Peer],
            info_hash: bytes,
            *,
            magnet: bool,
            initial_conn: PeerConnection | None
    ) -> None:
        self._client = client
        self._meta = meta
        self._peers = peers
        self._info_hash = info_hash
        self._magnet = magnet
        self._initial_conn = initial_conn
        self.stats = {"bytes": 0, "piece_failures": 0, "failovers": 0}
        self.stats_lock = threading.Lock()
        self.opened: list[PeerConnection] = []
        self._rotation = 0
        self._rotation_lock = threading.Lock()

    def open_ready(self, reporter: ProgressReporter) -> PeerConnection:
        """Open, connect, handshake, and unchoke a fresh worker connection."""

        conn = PeerConnection(self._client.peer_id, reporter=reporter)
        with self._rotation_lock:
            self.opened.append(conn)
            count = len(self._peers) or 1
            start = self._rotation % count
            self._rotation = start + 1
        ordered = list(self._peers[start:]) + list(self._peers[:start])
        self._client._connect_with_retry(conn, ordered)
        conn.handshake(self._info_hash, magnet=self._magnet)
        conn.send_interested()
        return conn

    def download_one(
            self,
            conn: PeerConnection,
            piece_index: int,
            reporter: ProgressReporter
    ) -> tuple[PeerConnection, bytearray]:
        """One piece with per-piece failover; returns the live connection."""

        for attempt in range(1, _PIECE_RETRIES + 1):
            try:
                return conn, conn.download_piece(self._meta, piece_index, reporter)
            except PeerProtocolError as error:
                with self.stats_lock:
                    self.stats["piece_failures"] += 1
                logger.debug(
                    "piece failed",
                    extra={
                        "ctx": {
                            "piece_index": piece_index,
                            "attempt": attempt,
                            "error": str(error)
                        }
                    }
                )
                if conn is not self._initial_conn:
                    conn.close()
                if attempt == _PIECE_RETRIES:
                    raise
                with self.stats_lock:
                    self.stats["failovers"] += 1
                logger.debug(
                    "failing over to the next peer",
                    extra={"ctx": {"piece_index": piece_index}}
                )
                conn = self.open_ready(reporter)
        raise AssertionError("unreachable: the retry loop returns or raises")

    @property
    def connection_count(self) -> int:
        """How many connections this download used (for the completion log)."""

        return len(self.opened) + (1 if self._initial_conn else 0)

    def close_all(self) -> None:
        """Close every replacement connection; ``initial_conn`` is the caller's."""

        for conn in self.opened:
            conn.close()


class TorrentClient:
    """High-level operations over a torrent or a magnet link."""

    def __init__(self, peer_id: bytes = PEER_ID, reporter: ProgressReporter | None = None) -> None:
        self.peer_id = peer_id
        self._reporter = reporter or NullReporter()
        self._tracker: TrackerClient | None = None

    @property
    def tracker(self) -> TrackerClient:
        """The tracker client, created on first use.

        Importing :mod:`app.tracker` pulls in ``requests``/``urllib3`` - the
        bulk of CLI cold start - yet commands like ``decode``, ``info`` and
        ``magnet_parse`` never announce, so the import is deferred until a
        command actually needs the tracker.
        """

        if self._tracker is None:
            from app.tracker import TrackerClient

            self._tracker = TrackerClient(self.peer_id)
        return self._tracker

    def read_metadata(self, path: str) -> TorrentMetadata:
        """Load and parse a ``.torrent`` file into metadata."""
        return load_torrent_file(path)

    def parse_magnet(self, link: str) -> MagnetLink:
        """Parse a magnet URI into its tracker URL and info hash."""
        return parse_magnet_link(link)

    def decode(self, value: str):
        """Decode a bencoded string into native Python objects."""
        try:
            return bencodepy.decode(value.encode())
        except bencodepy.BencodeDecodeError as exc:
            raise BencodeError(f"Invalid bencoded value: {value!r}") from exc

    def get_peers(self, meta: TorrentMetadata) -> list[Peer]:
        return self._announce(meta.announce_urls, meta.info_hash, meta.length)

    def _announce(self, trackers: list[str], info_hash: bytes, left: int) -> list[Peer]:
        """Announce to each tracker in order, returning the first peer list.

        A tracker that errors - a ``failure reason`` response, an empty or
        malformed peer list, or an HTTP/network fault (all raised as
        ``TrackerError``) - is skipped in favour of the next, so a single dead
        or unhappy tracker no longer fails the command. If every tracker fails,
        the last error propagates. ``trackers`` is never empty (it falls back to
        the primary announce URL).
        """

        last_error: TrackerError | None = None
        for index, url in enumerate(trackers):
            try:
                return self.tracker.get_peers(url, info_hash, left)
            except TrackerError as error:
                last_error = error
                logger.debug(
                    "tracker announce failed; trying the next",
                    extra={"ctx": {"tracker": index + 1, "of": len(trackers), "error": str(error)}}
                )
        assert last_error is not None
        raise last_error

    def handshake(self, meta: TorrentMetadata, peer: Peer | None = None) -> str:
        """Connect and handshake; return the peer's id (hex).

        Connects to ``peer`` when given (the handshake command takes a specific
        ``ip:port``), otherwise falls back to the tracker's peer list.
        """

        peers = [peer] if peer is not None else self.get_peers(meta)
        with PeerConnection(self.peer_id, reporter=self._reporter) as conn:
            self._connect_with_retry(conn, peers)
            conn.handshake(meta.info_hash)
            if conn.remote_peer_id is None:
                raise PeerProtocolError("Handshake did not yield a peer id")
            return conn.remote_peer_id

    def download_piece_to_file(self, meta: TorrentMetadata, piece_index: int, output_path: str) -> None:
        with self._ready_connection(meta) as conn:
            piece = conn.download_piece(meta, piece_index)
        self._atomic_write(output_path, piece)

    def download_to_file(self, meta: TorrentMetadata, output_path: str) -> None:
        self._enforce_size_ceiling(meta.length)
        peers = self.get_peers(meta)
        with self._atomic_output(output_path) as output_file:
            self._download_with_failover(meta, output_file, output_path, peers, meta.info_hash, magnet=False)

    @contextmanager
    def _ready_connection(self, meta: TorrentMetadata) -> Iterator[PeerConnection]:
        """A connection that has handshaked, read the bitfield, and unchocked."""
        with PeerConnection(self.peer_id, reporter=self._reporter) as conn:
            self._connect_with_retry(conn, self.get_peers(meta))
            conn.handshake(meta.info_hash)
            conn.send_interested()
            yield conn

    def magnet_handshake(self, magnet: MagnetLink) -> tuple[str, int]:
        """Return the peer id (hex) and the negotiated ut_metadata id."""

        with self._magnet_connection(magnet) as (conn, ext_id):
            if conn.remote_peer_id is None:
                raise PeerProtocolError("Handshake did not yield a peer id")
            return conn.remote_peer_id, ext_id

    def magnet_metadata(self, magnet: MagnetLink) -> TorrentMetadata:
        with self._magnet_connection(magnet) as (conn, ext_id):
            raw_info = conn.fetch_metadata(ext_id)
        return metadata_from_raw_info(magnet.tracker_url, raw_info, magnet.info_hash)

    def magnet_download_piece_to_file(self, magnet: MagnetLink, piece_index: int, output_path: str) -> None:
        with self._magnet_connection(magnet) as (conn, ext_id):
            meta = metadata_from_raw_info(magnet.tracker_url, conn.fetch_metadata(ext_id), magnet.info_hash)
            conn.send_interested()
            piece = conn.download_piece(meta, piece_index)
        self._atomic_write(output_path, piece)

    def magnet_download_to_file(self, magnet: MagnetLink, output_path: str) -> None:
        peers = self._announce(magnet.announce_urls, magnet.info_hash, MAGNET_STUB_LENGTH)
        with self._atomic_output(output_path) as output_file:
            with self._magnet_connection(magnet, peers) as (conn, ext_id):
                meta = metadata_from_raw_info(magnet.tracker_url, conn.fetch_metadata(ext_id), magnet.info_hash)
                self._enforce_size_ceiling(meta.length)
                conn.send_interested()
                self._download_with_failover(
                    meta,
                    output_file,
                    output_path,
                    peers,
                    magnet.info_hash,
                    magnet=True,
                    initial_conn=conn
                )

    @contextmanager
    def _magnet_connection(self, magnet: MagnetLink, peers: list[Peer] | None = None) -> Iterator[tuple[PeerConnection, int]]:
        """A connection that has completed the extension handshake.

        The same socket is kept open afterwards so metadata and pieces can be
        fetched without reconnecting. ``peers`` may be supplied to reuse an
        already-fetched peer list (e.g. so a download can fail over within it).
        """

        if peers is None:
            peers = self._announce(magnet.announce_urls, magnet.info_hash, MAGNET_STUB_LENGTH)
        with PeerConnection(self.peer_id, reporter=self._reporter) as conn:
            self._connect_with_retry(conn, peers)
            conn.handshake(magnet.info_hash, magnet=True)
            ext_id = conn.extension_handshake()
            yield conn, ext_id

    @staticmethod
    def _enforce_size_ceiling(length: int) -> None:
        """Refuse a download whose declared size exceeds the safety ceiling.

        The length comes from an untrusted torrent/magnet; a crafted one must not
        be able to request a disk-filling write.
        """
        if length > MAX_TORRENT_LENGTH:
            raise InvalidTorrentError(f"Refusing to download {length} bytes (over the {MAX_TORRENT_LENGTH}-byte limit)")

    def _connect_with_retry(self, conn: PeerConnection, peers) -> None:
        """Connect ``conn`` to the peer set, retrying transient failures.

        ``PeerConnection.connect`` already tries each peer once; this wraps the
        whole attempt in a bounded exponential backoff (with jitter) so a
        momentary network blip or a peer set that is briefly all-unreachable is
        retried rather than failing the command outright. The happy path
        connects on the first try with no delay.
        """

        delay = RETRY_BASE_DELAY
        for attempt in range(1, CONNECT_RETRIES + 1):
            try:
                conn.connect(peers)
                return
            except PeerProtocolError:
                if attempt == CONNECT_RETRIES:
                    raise
                logger.debug(
                    "retrying peer connect",
                    extra={"ctx": {"attempt": attempt, "delay_s": round(delay, 2)}}
                )
                time.sleep(delay + random.uniform(0, delay))
                delay *= 2

    @staticmethod
    @contextmanager
    def _atomic_output(output_path: str) -> Iterator[BinaryIO]:
        """Yield a writable file that lands at ``output_path`` only on success.

        A crash or interrupt mid-write must not leave a half-written file at the
        final path: callers write to the yielded temp file (in the same
        directory), and on clean exit it is flushed+fsynced and renamed into
        place (atomic on the same filesystem). If the body raises, the temp file
        is removed and the final path is left untouched.
        """

        path = Path(output_path)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent or "."), prefix=f".{path.name}.", suffix=".part")

        try:
            with os.fdopen(fd, "wb") as tmp:
                yield tmp
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _atomic_write(self, output_path: str, data: bytes | bytearray) -> None:
        """Atomically write a single in-memory blob (used for single pieces)."""

        with self._atomic_output(output_path) as output_file:
            output_file.write(data)

    def _download_with_failover(
            self,
            meta: TorrentMetadata,
            output_file: BinaryIO,
            output_path: str,
            peers: list[Peer],
            info_hash: bytes,
            *,
            magnet: bool,
            initial_conn: PeerConnection | None = None
    ) -> None:
        """Download every piece, streaming each to disk, failing over on error.

        Each verified piece is written at its absolute offset (so peak memory
        stays O(piece)). If a piece fails - peer choke, timeout, reset, or hash
        mismatch - the connection is dropped and the piece is retried on the next
        peer in the list, up to ``_PIECE_RETRIES`` times, so a single flaky peer
        no longer dooms the whole download. ``initial_conn`` is an
        already-prepared connection (the magnet metadata socket) owned by the
        caller; replacement connections are owned and closed here.

        ``BITTORRENT_MAX_PEERS`` above 1 stripes pieces across that many peer
        connections; piece progress lines are still released strictly in
        piece-index order.
        """

        session = _DownloadSession(self, meta, peers, info_hash, magnet=magnet, initial_conn=initial_conn)
        workers = min(_max_peer_connections(), len(meta.piece_hashes))
        # Open every connection (for torrent) before announcing progress so the
        # "connected to ..." line(s) keep a deterministic position in the output.
        conns = [] if initial_conn is None else [initial_conn]
        conns += [session.open_ready(self._reporter) for _ in range(workers - len(conns))]
        self._reporter.report(f"downloading to {output_path} ...")
        self._reporter.report(f"pieces to download: {len(meta.piece_hashes)}")
        started = time.perf_counter()
        try:
            if workers <= 1:
                self._download_sequentially(meta, output_file, conns[0], session)
            else:
                self._download_concurrently(meta, output_file, conns, session)

            elapsed = time.perf_counter() - started
            logger.info(
                "download complete",
                extra={
                    "ctx": {
                        "info_hash": info_hash.hex()[:8],
                        "bytes": session.stats["bytes"],
                        "pieces": len(meta.piece_hashes),
                        "elapsed_ms": round(elapsed * 1000, 1),
                        "throughput_bps": round(session.stats["bytes"] / elapsed) if elapsed else 0,
                        "piece_failures": session.stats["piece_failures"],
                        "failovers": session.stats["failovers"],
                        "connections": session.connection_count
                    }
                }
            )
        finally:
            session.close_all()

    def _download_sequentially(
            self,
            meta: TorrentMetadata,
            output_file: BinaryIO,
            conn: PeerConnection,
            session: _DownloadSession
    ) -> None:
        """Download every piece over a single connection, in index order."""

        for piece_index in range(len(meta.piece_hashes)):
            conn, piece = session.download_one(conn, piece_index, self._reporter)
            output_file.seek(piece_index * meta.piece_length)
            output_file.write(piece)
            with session.stats_lock:
                session.stats["bytes"] += len(piece)
            self._reporter.report(f"piece_{piece_index} | {len(piece)} downloaded.")

    def _download_concurrently(
            self,
            meta: TorrentMetadata,
            output_file: BinaryIO,
            conns: list[PeerConnection],
            session: _DownloadSession
    ) -> None:
        """Stripe the pieces across the worker connections.

        Each worker claims the next undone piece, buffers that piece's progress
        lines, and writes the verified bytes with ``os.pwrite`` at the absolute
        offset (positional writes need no shared seek pointer). Buffers are
        released through :class:`_OrderedProgress` so the output lists pieces
        strictly by index. A failed piece (retries exhausted) stops the other
        workers at their next claim and propagates from here.
        """

        output_file.flush()
        fd = output_file.fileno()
        ordered = _OrderedProgress(self._reporter)
        remaining = deque(range(len(meta.piece_hashes)))
        abort = threading.Event()

        def run(conn: PeerConnection) -> None:
            while not abort.is_set():
                try:
                    piece_index = remaining.popleft()
                except IndexError:
                    return
                buffer = _BufferReporter()
                try:
                    conn, piece = session.download_one(conn, piece_index, buffer)
                except Exception:
                    abort.set()
                    ordered.deliver(piece_index, buffer.lines)
                    raise
                os.pwrite(fd, piece, piece_index * meta.piece_length)
                with session.stats_lock:
                    session.stats["bytes"] += len(piece)
                buffer.report(f"piece_{piece_index} | {len(piece)} downloaded.")
                ordered.deliver(piece_index, buffer.lines)

        with ThreadPoolExecutor(max_workers=len(conns)) as pool:
            futures = [pool.submit(run, conn) for conn in conns]
        for future in futures:
            future.result()
