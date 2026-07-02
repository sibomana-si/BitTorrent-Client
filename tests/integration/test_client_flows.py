"""Integration tests: TorrentClient use cases over stubbed tracker + fake peer.

The tracker announce is answered by ``stub_tracker`` (no HTTP leaves the process);
the peers it advertises are real ``FakePeer`` TCP servers on localhost. Every flow
below runs the same code path the CLI drives.
"""

import hashlib
import re
from dataclasses import replace

import bencodepy
import pytest

from app.client import TorrentClient
from app.constants import MAX_TORRENT_LENGTH
from app.errors import InvalidTorrentError, TrackerError
from app.models import TorrentMetadata

from tests.conftest import FakePeer, ListReporter, StubResponse, TRACKER_URL


@pytest.fixture
def torrent(make_torrent):
    return make_torrent(length=40, piece_length=16)  # pieces: 16, 16, 8


@pytest.fixture
def client():
    return TorrentClient(reporter=ListReporter())


def test_get_peers_round_trip(client, torrent, stub_tracker):
    stub_tracker.set_peers([("1.2.3.4", 6881)])
    meta = client.read_metadata(torrent.path)
    peers = client.get_peers(meta)
    assert [str(peer) for peer in peers] == ["1.2.3.4:6881"]
    # The announce carried the torrent's real length as "left".
    assert "left=40" in stub_tracker.urls[0]


def test_single_tracker_announces_exactly_once(client, torrent, stub_tracker):
    # The failover loop must not double-announce the common single-tracker case.
    stub_tracker.set_peers([("1.2.3.4", 6881)])
    client.get_peers(client.read_metadata(torrent.path))
    assert len(stub_tracker.urls) == 1


def test_get_peers_surfaces_tracker_failure_reason(client, torrent, stub_tracker):
    stub_tracker.default = StubResponse( bencodepy.encode({"failure reason": "torrent not found"}))
    meta = client.read_metadata(torrent.path)
    with pytest.raises(TrackerError, match="torrent not found"):
        client.get_peers(meta)


def test_get_peers_fails_over_to_the_next_tracker(client, torrent, stub_tracker):
    # The first tracker errors (a failure-reason response); the client falls
    # over to the second, which returns peers. Both announce URLs are tried.
    stub_tracker.set_peers([("9.9.9.9", 6881)])  # default = the second tracker
    stub_tracker.queue = [StubResponse(bencodepy.encode({"failure reason": "down"}))]
    meta = replace(
        client.read_metadata(torrent.path),
        trackers=("http://t1.test/announce", "http://t2.test/announce"),
    )
    peers = client.get_peers(meta)
    assert [str(peer) for peer in peers] == ["9.9.9.9:6881"]
    assert len(stub_tracker.urls) == 2
    assert stub_tracker.urls[0].startswith("http://t1.test/announce")
    assert stub_tracker.urls[1].startswith("http://t2.test/announce")


def test_get_peers_raises_when_every_tracker_fails(client, torrent, stub_tracker):
    stub_tracker.default = StubResponse(bencodepy.encode({"failure reason": "all down"}))
    meta = replace(
        client.read_metadata(torrent.path),
        trackers=("http://t1.test/announce", "http://t2.test/announce"),
    )
    with pytest.raises(TrackerError, match="all down"):
        client.get_peers(meta)
    assert len(stub_tracker.urls) == 2


def test_handshake_uses_the_tracker_peer_list(client, torrent, stub_tracker):
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        assert client.handshake(meta) == fake.peer_id.hex()


def test_handshake_with_an_explicit_peer_skips_the_tracker(client, torrent, stub_tracker):
    with FakePeer.for_torrent(torrent) as fake:
        meta = client.read_metadata(torrent.path)
        assert client.handshake(meta, fake.peer) == fake.peer_id.hex()
    assert stub_tracker.urls == []  # no announce was made


def test_download_piece_to_file(client, torrent, stub_tracker, tmp_path):
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        output = tmp_path / "piece0.bin"
        client.download_piece_to_file(meta, 0, str(output))
        assert output.read_bytes() == torrent.piece(0)


def test_download_short_last_piece_to_file(client, torrent, stub_tracker, tmp_path):
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        output = tmp_path / "piece2.bin"
        client.download_piece_to_file(meta, 2, str(output))
        assert output.read_bytes() == torrent.piece(2)


def test_download_to_file_reproduces_the_content(client, torrent, stub_tracker, tmp_path):
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        output = tmp_path / "whole.bin"
        client.download_to_file(meta, str(output))
        assert output.read_bytes() == torrent.content


def test_sequential_download_emits_ordered_per_piece_events(torrent, stub_tracker, tmp_path):
    # Behavioral shape of the progress stream (counts + ordering), checked
    # independently of the exact line wording the e2e suite pins: one connect,
    # and one "downloading"/"piece_" event per piece in strict index order.
    reporter = ListReporter()
    client = TorrentClient(reporter=reporter)
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        client.download_to_file(meta, str(tmp_path / "whole.bin"))
    pieces = len(meta.piece_hashes)
    assert sum(line.startswith("piece_") for line in reporter.lines) == pieces
    assert sum(line.startswith("connected to ") for line in reporter.lines) == 1
    downloading = [
        int(match.group())
        for line in reporter.lines
        if line.startswith("downloading piece_index")
        if (match := re.search(r"\d+", line)) is not None
    ]
    assert downloading == list(range(pieces))


def test_download_fails_over_from_a_corrupt_peer(
        client, torrent, stub_tracker, tmp_path, no_sleep
):
    # The first advertised peer serves garbage (hash mismatch); the client must
    # drop it and complete the download from the second.
    with FakePeer.for_torrent(torrent, corrupt_data=True) as bad:
        with FakePeer.for_torrent(torrent) as good:
            stub_tracker.set_peers([(bad.ip, bad.port), (good.ip, good.port)])
            meta = client.read_metadata(torrent.path)
            output = tmp_path / "whole.bin"
            client.download_to_file(meta, str(output))
            assert output.read_bytes() == torrent.content
            assert bad.connections >= 1
            assert good.connections >= 1


def test_concurrent_download_reproduces_content_and_orders_progress(
    torrent, stub_tracker, tmp_path, monkeypatch
):
    # BITTORRENT_MAX_PEERS > 1 stripes pieces across several connections; the
    # file must still be correct and the per-piece progress lines must still
    # come out strictly in piece-index order.
    monkeypatch.setenv("BITTORRENT_MAX_PEERS", "3")
    reporter = ListReporter()
    client = TorrentClient(reporter=reporter)
    with FakePeer.for_torrent(torrent) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        output = tmp_path / "whole.bin"
        client.download_to_file(meta, str(output))
        assert output.read_bytes() == torrent.content
        assert fake.connections == 3
    piece_lines = [line for line in reporter.lines if line.startswith("piece_")]
    assert piece_lines == [
        f"piece_{index} | {len(torrent.piece(index))} downloaded."
        for index in range(3)
    ]
    downloading = [
        line for line in reporter.lines if line.startswith("downloading piece_index")
    ]
    assert downloading == [f"downloading piece_index: {index} ..." for index in range(3)]


def test_concurrent_download_orders_progress_when_a_low_piece_finishes_last(
    torrent, stub_tracker, tmp_path, monkeypatch
):
    # Force piece 0 to complete after pieces 1 and 2 by delaying its block
    # server-side. The per-piece progress must still come out strictly in index
    # order - which can only happen if _OrderedProgress holds the later pieces
    # until piece 0 arrives. Unlike the sibling test above (where out-of-order
    # completion is only a race), this deterministically exercises the _held
    # reorder branch: with completion order 1, 2, 0, a downloader that emitted in
    # completion order would fail the [0, 1, 2] assertions below.
    monkeypatch.setenv("BITTORRENT_MAX_PEERS", "3")
    reporter = ListReporter()
    client = TorrentClient(reporter=reporter)
    with FakePeer.for_torrent(torrent, block_delays={0: 0.3}) as fake:
        stub_tracker.set_peers([(fake.ip, fake.port)])
        meta = client.read_metadata(torrent.path)
        output = tmp_path / "whole.bin"
        client.download_to_file(meta, str(output))
        assert output.read_bytes() == torrent.content
        assert fake.connections == 3
    piece_lines = [line for line in reporter.lines if line.startswith("piece_")]
    assert piece_lines == [
        f"piece_{index} | {len(torrent.piece(index))} downloaded."
        for index in range(3)
    ]
    downloading = [
        line for line in reporter.lines if line.startswith("downloading piece_index")
    ]
    assert downloading == [f"downloading piece_index: {index} ..." for index in range(3)]
    # Behavioral shape: one connection opened per worker (workers == 3 here).
    assert sum(line.startswith("connected to ") for line in reporter.lines) == 3


def test_concurrent_download_with_a_corrupt_peer_still_completes(
    torrent, stub_tracker, tmp_path, monkeypatch, no_sleep
):
    monkeypatch.setenv("BITTORRENT_MAX_PEERS", "2")
    client = TorrentClient(reporter=ListReporter())
    with FakePeer.for_torrent(torrent, corrupt_data=True) as bad:
        with FakePeer.for_torrent(torrent) as good:
            stub_tracker.set_peers([(bad.ip, bad.port), (good.ip, good.port)])
            meta = client.read_metadata(torrent.path)
            output = tmp_path / "whole.bin"
            client.download_to_file(meta, str(output))
            assert output.read_bytes() == torrent.content


def test_download_over_the_size_ceiling_is_refused_before_connecting(client):
    meta = TorrentMetadata(
        tracker_url=TRACKER_URL,
        length=MAX_TORRENT_LENGTH + 1,
        info_hash=hashlib.sha1(b"huge").digest(),
        piece_length=2**20,
        piece_hashes=[b"\x00" * 20],
    )
    # No stub_tracker fixture: the refusal must come before any tracker I/O.
    with pytest.raises(InvalidTorrentError, match="Refusing to download"):
        client.download_to_file(meta, "never-created.bin")


class TestMagnetFlows:
    def test_magnet_handshake(self, client, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent, extension=True, ut_metadata_id=9) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            magnet = client.parse_magnet(torrent.magnet_link)
            peer_id, extension_id = client.magnet_handshake(magnet)
            assert peer_id == fake.peer_id.hex()
            assert extension_id == 9
            # Before metadata is known, "left" is the stub value.
            assert "left=999" in stub_tracker.urls[0]

    def test_magnet_metadata_matches_the_torrent_file(self, client, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            magnet = client.parse_magnet(torrent.magnet_link)
            meta = client.magnet_metadata(magnet)
            file_meta = client.read_metadata(torrent.path)
            assert meta == file_meta

    def test_magnet_metadata_rejects_forged_info(self, client, torrent, stub_tracker):
        # The peer serves metadata whose SHA-1 differs from the magnet's hash.
        forged = torrent.raw_info[:-1] + b"X"
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            fake.raw_info = forged
            stub_tracker.set_peers([(fake.ip, fake.port)])
            magnet = client.parse_magnet(torrent.magnet_link)
            from app.errors import PeerProtocolError

            with pytest.raises(PeerProtocolError, match="info hash mismatch"):
                client.magnet_metadata(magnet)

    def test_magnet_download_piece_to_file(self, client, torrent, stub_tracker, tmp_path):
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            magnet = client.parse_magnet(torrent.magnet_link)
            output = tmp_path / "piece1.bin"
            client.magnet_download_piece_to_file(magnet, 1, str(output))
            assert output.read_bytes() == torrent.piece(1)

    def test_magnet_download_to_file(self, client, torrent, stub_tracker, tmp_path):
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            magnet = client.parse_magnet(torrent.magnet_link)
            output = tmp_path / "whole.bin"
            client.magnet_download_to_file(magnet, str(output))
            assert output.read_bytes() == torrent.content
            # Metadata and all pieces rode the single kept-open connection.
            assert fake.connections == 1
