"""Unit tests for metadata construction in app/torrent.py."""

import hashlib
from typing import cast

import bencodepy
import pytest

from app.constants import MAX_PIECE_LENGTH
from app.errors import InvalidTorrentError, PeerProtocolError
from app.torrent import _build, load_torrent_file, metadata_from_raw_info

from tests.conftest import TRACKER_URL


class TestLoadTorrentFile:
    def test_parses_a_valid_file(self, make_torrent):
        torrent = make_torrent(length=40, piece_length=16)  # short last piece
        meta = load_torrent_file(torrent.path)
        assert meta.tracker_url == torrent.tracker_url
        assert meta.length == 40
        assert meta.piece_length == 16
        assert meta.piece_hashes == torrent.piece_hashes
        assert len(meta.piece_hashes) == 3
        assert all(len(piece_hash) == 20 for piece_hash in meta.piece_hashes)

    def test_info_hash_is_sha1_of_reencoded_info(self, make_torrent):
        torrent = make_torrent()
        meta = load_torrent_file(torrent.path)
        assert meta.info_hash == hashlib.sha1(torrent.raw_info).digest()
        assert meta.info_hash_hex == torrent.info_hash.hex()

    def test_wrong_extension_is_rejected(self, tmp_path):
        path = tmp_path / "sample.txt"
        path.write_bytes(b"irrelevant")
        with pytest.raises(InvalidTorrentError, match="extension"):
            load_torrent_file(str(path))

    def test_missing_file_is_rejected(self, tmp_path):
        with pytest.raises(InvalidTorrentError, match="Cannot read"):
            load_torrent_file(str(tmp_path / "missing.torrent"))

    def test_garbage_bencode_is_rejected(self, tmp_path):
        path = tmp_path / "garbage.torrent"
        path.write_bytes(b"this is not bencode")
        with pytest.raises(InvalidTorrentError, match="Malformed"):
            load_torrent_file(str(path))

    def test_missing_info_dict_is_rejected(self, tmp_path):
        path = tmp_path / "noinfo.torrent"
        path.write_bytes(bencodepy.encode({"announce": TRACKER_URL}))
        with pytest.raises(InvalidTorrentError, match="Malformed"):
            load_torrent_file(str(path))

    def test_plain_torrent_announces_only_its_tracker(self, make_torrent):
        meta = load_torrent_file(make_torrent().path)
        assert meta.announce_urls == [meta.tracker_url]

    def test_announce_list_is_collected_into_trackers(self, make_torrent):
        torrent = make_torrent(announce_list=["http://a.test/announce", "http://b.test/announce"])
        meta = load_torrent_file(torrent.path)
        # The primary announce stays the display tracker; the list follows it,
        # in order, for failover.
        assert meta.tracker_url == torrent.tracker_url
        assert meta.announce_urls == [
            torrent.tracker_url,
            "http://a.test/announce",
            "http://b.test/announce",
        ]

    def test_duplicate_trackers_are_de_duplicated(self, make_torrent):
        # A tracker that also appears as the primary announce is not repeated.
        url = "http://dup.test/announce"
        torrent = make_torrent(tracker_url=url, announce_list=[url])
        meta = load_torrent_file(torrent.path)
        assert meta.announce_urls == [url]

    def test_missing_announce_raises_keyerror(self, tmp_path, make_torrent):
        # Pins current behavior: decoded[b"announce"] is read OUTSIDE the
        # try/except in load_torrent_file, so a missing announce key escapes as
        # a raw KeyError instead of an InvalidTorrentError. If this test starts
        # failing with InvalidTorrentError, the gap was fixed - update the test.
        torrent = make_torrent()
        decoded = cast(dict, bencodepy.decode(open(torrent.path, "rb").read()))
        del decoded[b"announce"]
        path = tmp_path / "noannounce.torrent"
        path.write_bytes(bencodepy.encode(decoded))
        with pytest.raises(KeyError):
            load_torrent_file(str(path))


class TestMetadataFromRawInfo:
    def test_builds_from_peer_metadata(self, make_torrent):
        torrent = make_torrent()
        meta = metadata_from_raw_info(torrent.tracker_url, torrent.raw_info)
        assert meta.length == torrent.length
        assert meta.piece_hashes == torrent.piece_hashes
        assert meta.info_hash == torrent.info_hash

    def test_expected_hash_match_is_accepted(self, make_torrent):
        torrent = make_torrent()
        meta = metadata_from_raw_info(torrent.tracker_url, torrent.raw_info, torrent.info_hash)
        assert meta.info_hash == torrent.info_hash

    def test_expected_hash_mismatch_is_rejected(self, make_torrent):
        # Forged metadata: bytes whose SHA-1 differs from the magnet's hash.
        torrent = make_torrent()
        with pytest.raises(PeerProtocolError, match="mismatch"):
            metadata_from_raw_info(torrent.tracker_url, torrent.raw_info, b"\x00" * 20)

    def test_undecodable_info_is_rejected(self):
        with pytest.raises(InvalidTorrentError, match="Malformed metadata"):
            metadata_from_raw_info(TRACKER_URL, b"not bencode at all")

    def test_non_dict_info_is_rejected(self):
        # Decodes fine (a list) but cannot be indexed by key.
        with pytest.raises(InvalidTorrentError, match="Malformed metadata"):
            metadata_from_raw_info(TRACKER_URL, bencodepy.encode([1, 2, 3]))


class TestBuildGuards:
    """The integer/blob sanity guards over untrusted metadata."""

    @staticmethod
    def _info(overrides: dict | None = None) -> dict:
        info = {
            b"length": 32,
            b"piece length": 16,
            b"pieces": b"\x01" * 20 + b"\x02" * 20,
        }
        info.update(overrides or {})
        return info

    def test_consistent_info_is_accepted(self):
        meta = _build(TRACKER_URL, self._info(), b"\xaa" * 20)
        assert meta.length == 32
        assert meta.piece_hashes == [b"\x01" * 20, b"\x02" * 20]

    def test_exact_multiple_length_is_accepted(self):
        # length an exact multiple of piece_length: no short last piece.
        meta = _build(TRACKER_URL, self._info(), b"\xaa" * 20)
        assert len(meta.piece_hashes) == 2

    @pytest.mark.parametrize("length", [0, -5, b"32", "32", None])
    def test_invalid_length_is_rejected(self, length):
        with pytest.raises(InvalidTorrentError, match="length"):
            _build(TRACKER_URL, self._info({b"length": length}), b"\xaa" * 20)

    @pytest.mark.parametrize("piece_length", [0, -16, MAX_PIECE_LENGTH + 1, b"16", None])
    def test_invalid_piece_length_is_rejected(self, piece_length):
        with pytest.raises(InvalidTorrentError, match="piece length"):
            _build(TRACKER_URL, self._info({b"piece length": piece_length}), b"\xaa" * 20)

    def test_max_piece_length_boundary_is_accepted(self):
        info = self._info(
            {b"length": MAX_PIECE_LENGTH, b"piece length": MAX_PIECE_LENGTH,
             b"pieces": b"\x01" * 20}
        )
        meta = _build(TRACKER_URL, info, b"\xaa" * 20)
        assert meta.piece_length == MAX_PIECE_LENGTH

    @pytest.mark.parametrize(
        "pieces",
        [
            pytest.param(b"\x01" * 19, id="misaligned"),
            pytest.param("not bytes", id="not-bytes"),
            pytest.param(b"", id="empty"),
        ],
    )
    def test_invalid_pieces_blob_is_rejected(self, pieces):
        with pytest.raises(InvalidTorrentError, match="[Pp]iece"):
            _build(TRACKER_URL, self._info({b"pieces": pieces}), b"\xaa" * 20)

    def test_piece_count_inconsistent_with_length_is_rejected(self):
        # 32 bytes / 16-byte pieces needs exactly 2 hashes; give 3.
        info = self._info({b"pieces": b"\x01" * 60})
        with pytest.raises(InvalidTorrentError, match="inconsistent"):
            _build(TRACKER_URL, info, b"\xaa" * 20)
