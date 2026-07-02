"""Integration tests: PeerConnection against a real local TCP fake peer.

These exercise the full wire conversation - handshake, interleaved
informational frames, interested/unchoke, block requests and the BEP 9
metadata exchange - over an actual socket, not a scripted fake.
"""

import pytest

from app.errors import PeerProtocolError
from app.peer import PeerConnection

from tests.conftest import CLIENT_PEER_ID, FakePeer, ListReporter

from tests.unit.test_peer import _refused_address


@pytest.fixture
def torrent(make_torrent):
    return make_torrent(length=40, piece_length=16)  # pieces: 16, 16, 8


def test_connect_and_handshake(torrent):
    with FakePeer.for_torrent(torrent) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash)
            assert conn.remote_peer_id == fake.peer_id.hex()
            assert conn.reserved_bytes == bytes(8)


def test_connect_falls_through_dead_peer_to_live_one(torrent):
    reporter = ListReporter()
    with FakePeer.for_torrent(torrent) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=reporter) as conn:
            conn.connect([_refused_address(), fake.peer])
            conn.handshake(torrent.info_hash)
            assert conn.remote_peer_id == fake.peer_id.hex()
    assert reporter.lines == [f"connected to {fake.address}"]


def test_download_piece_over_the_wire(torrent):
    with FakePeer.for_torrent(torrent) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash)
            # The fake interleaves keep-alive/have/bitfield before unchoking.
            conn.send_interested()
            assert conn.download_piece(torrent.metadata, 0) == torrent.piece(0)


def test_download_short_last_piece_over_the_wire(torrent):
    with FakePeer.for_torrent(torrent) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash)
            conn.send_interested()
            piece = conn.download_piece(torrent.metadata, 2)
            assert piece == torrent.piece(2)
            assert len(piece) == 8


def test_multiple_pieces_on_one_connection(torrent):
    with FakePeer.for_torrent(torrent) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash)
            conn.send_interested()
            downloaded = b"".join(conn.download_piece(torrent.metadata, index) for index in range(3))
            assert downloaded == torrent.content
        assert fake.connections == 1  # everything rode a single socket


def test_extension_handshake_and_metadata_fetch(torrent):
    with FakePeer.for_torrent(torrent, extension=True, ut_metadata_id=7) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash, magnet=True)
            extension_id = conn.extension_handshake()
            assert extension_id == 7
            assert conn.fetch_metadata(extension_id) == torrent.raw_info


def test_peer_echoing_a_different_info_hash_is_rejected(torrent):
    with FakePeer.for_torrent(torrent, echo_info_hash=b"\x11" * 20) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            with pytest.raises(PeerProtocolError, match="info hash mismatch"):
                conn.handshake(torrent.info_hash)


def test_peer_speaking_the_wrong_protocol_is_rejected(torrent):
    with FakePeer.for_torrent(torrent, protocol=b"Bittorrent protocol") as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            with pytest.raises(PeerProtocolError, match="handshake protocol"):
                conn.handshake(torrent.info_hash)


def test_corrupt_piece_data_fails_hash_verification(torrent):
    with FakePeer.for_torrent(torrent, corrupt_data=True) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash)
            conn.send_interested()
            with pytest.raises(PeerProtocolError, match="Invalid piece hash"):
                conn.download_piece(torrent.metadata, 0)


def test_peer_without_extension_bits_refuses_metadata_negotiation(torrent):
    with FakePeer.for_torrent(torrent, extension=False) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash, magnet=True)
            with pytest.raises(PeerProtocolError, match="metadata extension"):
                conn.extension_handshake()


def test_bogus_metadata_total_size_is_rejected(torrent):
    with FakePeer.for_torrent(torrent, extension=True, total_size=-1) as fake:
        with PeerConnection(CLIENT_PEER_ID, reporter=ListReporter()) as conn:
            conn.connect([fake.peer])
            conn.handshake(torrent.info_hash, magnet=True)
            extension_id = conn.extension_handshake()
            with pytest.raises(PeerProtocolError, match="invalid metadata size"):
                conn.fetch_metadata(extension_id)
