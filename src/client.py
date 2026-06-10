"""Application use cases: orchestrate tracker, peer, and metadata steps.

This layer wires the infrastructure together for each high-level action and
owns the connection lifecycle. The CLI calls these methods and handles all
formatting; the protocol details live in :mod:`src.peer` and :mod:`src.tracker`.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

import bencodepy

from src.constants import MAGNET_STUB_LENGTH, PEER_ID
from src.errors import BencodeError, PeerProtocolError
from src.magnet import parse_magnet_link
from src.models import MagnetLink, Peer, TorrentMetadata
from src.peer import PeerConnection
from src.reporting import NullReporter, ProgressReporter
from src.torrent import load_torrent_file, metadata_from_raw_info
from src.tracker import TrackerClient


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
            conn.connect(peers)
            conn.handshake(meta.info_hash)
            if conn.remote_peer_id is None:
                raise PeerProtocolError("Handshake did not yield a peer id")
            return conn.remote_peer_id

    def download_piece_to_file(self, meta: TorrentMetadata, piece_index: int, output_path: str) -> None:
        with self._ready_connection(meta) as conn:
            piece = conn.download_piece(meta, piece_index)
        Path(output_path).write_bytes(piece)

    def download_to_file(self, meta: TorrentMetadata, output_path: str) -> None:
        with self._ready_connection(meta) as conn:
            data = self._download_all_pieces(conn, meta, output_path)
        Path(output_path).write_bytes(data)

    @contextmanager
    def _ready_connection(self, meta: TorrentMetadata) -> Iterator[PeerConnection]:
        """A connection that has handshaked, read the bitfield, and unchocked."""
        with PeerConnection(self.peer_id, reporter=self._reporter) as conn:
            conn.connect(self.get_peers(meta))
            conn.handshake(meta.info_hash)
            conn.recv_message() # bitfield
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
        return metadata_from_raw_info(magnet.tracker_url, raw_info)

    def magnet_download_piece_to_file(self, magnet: MagnetLink, piece_index: int, output_path: str) -> None:
        with self._magnet_connection(magnet) as (conn, ext_id):
            meta = metadata_from_raw_info(magnet.tracker_url, conn.fetch_metadata(ext_id))
            conn.send_interested()
            piece = conn.download_piece(meta, piece_index)
        Path(output_path).write_bytes(piece)

    def magnet_download_to_file(self, magnet: MagnetLink, output_path: str) -> None:
        with self._magnet_connection(magnet) as (conn, ext_id):
            meta = metadata_from_raw_info(magnet.tracker_url, conn.fetch_metadata(ext_id))
            conn.send_interested()
            data = self._download_all_pieces(conn, meta, output_path)
        Path(output_path).write_bytes(data)

    @contextmanager
    def _magnet_connection(self, magnet: MagnetLink) -> Iterator[tuple[PeerConnection, int]]:
        """A connection that has completed the extension handshake.

        The same socket is kept open afterwards so metadata and pieces can be
        fetched without reconnecting.
        """

        peers = self.tracker.get_peers(magnet.tracker_url, magnet.info_hash, MAGNET_STUB_LENGTH)
        with PeerConnection(self.peer_id, reporter=self._reporter) as conn:
            conn.connect(peers)
            conn.handshake(magnet.info_hash, magnet=True)
            conn.recv_message() # bitfield
            ext_id = conn.extension_handshake()
            yield conn, ext_id

    def _download_all_pieces(self, conn: PeerConnection, meta: TorrentMetadata, output_path: str) -> bytes:
        self._reporter.report(f"downloading to {output_path} ...")
        self._reporter.report(f"pieces to download: {len(meta.piece_hashes)}")
        pieces = []
        for piece_index in range(len(meta.piece_hashes)):
            piece = conn.download_piece(meta, piece_index)
            pieces.append(piece)
            self._reporter.report(f"piece_{piece_index} | {len(piece)} downloaded.")
        return b"".join(pieces)
