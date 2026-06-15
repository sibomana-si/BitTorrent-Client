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
import time
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import bencodepy

from app.constants import (
    CONNECT_RETRIES,
    MAGNET_STUB_LENGTH,
    MAX_TORRENT_LENGTH,
    PEER_ID,
    RETRY_BASE_DELAY
)
from app.errors import BencodeError, InvalidTorrentError, PeerProtocolError
from app.magnet import parse_magnet_link
from app.models import MagnetLink, Peer, TorrentMetadata
from app.peer import PeerConnection
from app.reporting import NullReporter, ProgressReporter
from app.torrent import load_torrent_file, metadata_from_raw_info
from app.tracker import TrackerClient

# How many peers to try for a single piece before giving the whole piece up.
_PIECE_RETRIES = 3

logger = logging.getLogger(__name__)


class TorrentClient:
    """High-level operations over a torrent or a magnet link."""

    def __init__(self, peer_id: bytes = PEER_ID, reporter: ProgressReporter | None = None) -> None:
        self.peer_id = peer_id
        self._reporter = reporter or NullReporter()
        self.tracker = TrackerClient(peer_id)

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
        return self.tracker.get_peers(meta.tracker_url, meta.info_hash, meta.length)

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
        peers = self.tracker.get_peers(magnet.tracker_url, magnet.info_hash, MAGNET_STUB_LENGTH)
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
            peers = self.tracker.get_peers(magnet.tracker_url, magnet.info_hash, MAGNET_STUB_LENGTH)
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

    def _atomic_write(self, output_path: str, data: bytes) -> None:
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
        """

        rotation = 0 # where in the peer list the next fresh connection starts
        opened: list[PeerConnection] = []
        stats = {"bytes": 0, "piece_failures": 0, "failovers": 0}

        def open_ready() -> PeerConnection:
            nonlocal rotation
            conn = PeerConnection(self.peer_id, reporter=self._reporter)
            opened.append(conn)
            count = len(peers) or 1
            start = rotation % count
            ordered = list(peers[start:]) + list(peers[:start])
            self._connect_with_retry(conn, ordered)
            conn.handshake(info_hash, magnet=magnet)
            conn.send_interested()
            rotation = start + 1
            return conn

        # Open the connection (for torrent) before announcing progress so the
        # "connected to ..." line keeps its original position in the output.
        conn = initial_conn if initial_conn is not None else open_ready()
        self._reporter.report(f"downloading to {output_path} ...")
        self._reporter.report(f"pieces to download: {len(meta.piece_hashes)}")
        started = time.perf_counter()
        try:
            for piece_index in range(len(meta.piece_hashes)):
                for attempt in range(1, _PIECE_RETRIES + 1):
                    try:
                        piece = conn.download_piece(meta, piece_index)
                        break
                    except PeerProtocolError as error:
                        stats["piece_failures"] += 1
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
                        if conn is not initial_conn:
                            conn.close()
                        if attempt == _PIECE_RETRIES:
                            raise
                        stats["failovers"] += 1
                        logger.debug(
                            "failing over to the next peer",
                            extra={"ctx": {"piece_index": piece_index}}
                        )
                        conn = open_ready()
                output_file.seek(piece_index * meta.piece_length)
                output_file.write(piece)
                stats["bytes"] += len(piece)
                self._reporter.report(f"piece_{piece_index} | {len(piece)} downloaded.")

            elapsed = time.perf_counter() - started
            logger.info(
                "download complete",
                extra={
                    "ctx": {
                        "info_hash": info_hash.hex()[:8],
                        "bytes": stats["bytes"],
                        "pieces": len(meta.piece_hashes),
                        "elapsed_ms": round(elapsed * 1000, 1),
                        "throughput_bps": round(stats["bytes"] / elapsed) if elapsed else 0,
                        "piece_failures": stats["piece_failures"],
                        "failovers": stats["failovers"],
                        "connections": len(opened) + (1 if initial_conn else 0)
                    }
                }
            )
        finally:
            for conn in opened:
                conn.close()