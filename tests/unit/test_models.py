"""Unit tests for the domain entities in app/models.py"""

import dataclasses

import pytest

from app.models import MagnetLink, Peer, TorrentMetadata


class TestPeer:
    def test_str_renders_ip_port(self):
        assert str(Peer("1.2.3.4", 6881)) == "1.2.3.4:6881"

    def test_from_address_roundtrip(self):
        peer = Peer.from_address("10.20.30.40:51413")
        assert peer == Peer("10.20.30.40", 51413)
        assert str(peer) == "10.20.30.40:51413"

    def test_from_address_splits_on_last_colon(self):
        # rsplit keeps colon-bearing hosts (e.g. IPv6 text) intact.
        peer = Peer.from_address("fe80::1:6881")
        assert peer.ip == "fe80::1"
        assert peer.port == 6881

    def test_from_address_non_numeric_port_raises(self):
        with pytest.raises(ValueError):
            Peer.from_address("1.2.3.4:notaport")

    def test_from_address_missing_port_raises(self):
        with pytest.raises(ValueError):
            Peer.from_address("1.2.3.4")

    def test_is_frozen(self):
        peer = Peer("1.2.3.4", 6881)
        with pytest.raises(dataclasses.FrozenInstanceError):
            peer.ip = "5.6.7.8"


class TestMagnetLink:
    def test_info_hash_hex(self):
        magnet = MagnetLink(info_hash=b"\xab" * 20, tracker_url="http://t.test/a")
        assert magnet.info_hash_hex == "ab" * 20

    def test_is_frozen(self):
        magnet = MagnetLink(info_hash=b"\x00" * 20, tracker_url="http://t.test/a")
        with pytest.raises(dataclasses.FrozenInstanceError):
            magnet.tracker_url = "http://other.test/a"


class TestTorrentMetadata:
    def _meta(self) -> TorrentMetadata:
        return TorrentMetadata(
            tracker_url="http://t.test/announce",
            length=32,
            info_hash=b"\x01" * 20,
            piece_length=16,
            piece_hashes=[b"\x02" * 20, b"\x03" * 20],
        )

    def test_info_hash_hex(self):
        assert self._meta().info_hash_hex == "01" * 20

    def test_piece_hashes_hex(self):
        assert self._meta().piece_hashes_hex == ["02" * 20, "03" * 20]

    def test_is_frozen(self):
        meta = self._meta()
        with pytest.raises(dataclasses.FrozenInstanceError):
            meta.length = 64
