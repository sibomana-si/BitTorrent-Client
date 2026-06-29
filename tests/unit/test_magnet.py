"""Unit tests for magnet URI parsing in app/magnet.py"""

import pytest

from app.errors import InvalidMagnetError
from app.magnet import parse_magnet_link

INFO_HASH_HEX = "ad42ce8109f54c99613ce38f9b4d87e70f24a165"
TRACKER = "http://bittorrent-test-tracker.codecrafters.io/announce"
TRACKER_ENCODED = "http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce"


class TestHappyPath:
    def test_parses_info_hash_and_tracker(self):
        link = f"magnet:?xt=urn:btih:{INFO_HASH_HEX}&tr={TRACKER_ENCODED}"
        magnet = parse_magnet_link(link)
        assert magnet.info_hash == bytes.fromhex(INFO_HASH_HEX)
        assert magnet.info_hash_hex == INFO_HASH_HEX
        # parse_qs percent-decodes the tracker URL.
        assert magnet.tracker_url == TRACKER

    def test_parameter_order_does_not_matter(self):
        link = f"magnet:?tr={TRACKER_ENCODED}&xt=urn:btih:{INFO_HASH_HEX}"
        magnet = parse_magnet_link(link)
        assert magnet.info_hash_hex == INFO_HASH_HEX
        assert magnet.tracker_url == TRACKER

    def test_extra_parameters_are_ignored(self):
        link = f"magnet:?xt=urn:btih:{INFO_HASH_HEX}&dn=sample.txt&tr={TRACKER_ENCODED}&x.pe=1.2.3.4%3A6881"
        magnet = parse_magnet_link(link)
        assert magnet.info_hash_hex == INFO_HASH_HEX
        assert magnet.tracker_url == TRACKER

    def test_first_of_duplicate_parameters_wins(self):
        other_hash = "ff" * 20
        link = (
            f"magnet:?xt=urn:btih:{INFO_HASH_HEX}&xt=urn:btih:{other_hash}"
            f"&tr={TRACKER_ENCODED}&tr=http%3A%2F%2Fsecond.test%2Fannounce"
        )
        magnet = parse_magnet_link(link)
        assert magnet.info_hash_hex == INFO_HASH_HEX
        assert magnet.tracker_url == TRACKER

    def test_single_tracker_announces_only_itself(self):
        link = f"magnet:?xt=urn:btih:{INFO_HASH_HEX}&tr={TRACKER_ENCODED}"
        magnet = parse_magnet_link(link)
        assert magnet.trackers == (TRACKER,)
        assert magnet.announce_urls == [TRACKER]

    def test_all_trackers_are_collected_in_order_for_failover(self):
        link = (
            f"magnet:?xt=urn:btih:{INFO_HASH_HEX}&tr={TRACKER_ENCODED}"
            f"&tr=http%3A%2F%2Fsecond.test%2Fannounce"
        )
        magnet = parse_magnet_link(link)
        # Primary stays first (what magnet_parse prints); both feed failover.
        assert magnet.tracker_url == TRACKER
        assert magnet.trackers == (TRACKER, "http://second.test/announce")
        assert magnet.announce_urls == [TRACKER, "http://second.test/announce"]


class TestErrors:
    @pytest.mark.parametrize(
        "link",
        [
            pytest.param(f"http://example.test/?xt=urn:btih:{INFO_HASH_HEX}", id="wrong-scheme"),
            pytest.param("not a uri at all", id="not-a-uri"),
            pytest.param(f"magnet:?tr={TRACKER_ENCODED}", id="missing-xt"),
            pytest.param(f"magnet:?xt=urn:btih:{INFO_HASH_HEX}", id="missing-tr"),
            pytest.param("magnet:?", id="empty-query"),
            pytest.param(
                f"magnet:?xt=urn:sha1:{INFO_HASH_HEX}&tr={TRACKER_ENCODED}",
                id="wrong-urn-prefix",
            ),
            pytest.param(
                f"magnet:?xt=urn:btih:{INFO_HASH_HEX[:-2]}&tr={TRACKER_ENCODED}",
                id="hash-too-short",
            ),
            pytest.param(
                f"magnet:?xt=urn:btih:{INFO_HASH_HEX}aa&tr={TRACKER_ENCODED}",
                id="hash-too-long",
            ),
            pytest.param(
                f"magnet:?xt=urn:btih:{'zz' * 20}&tr={TRACKER_ENCODED}",
                id="hash-not-hex",
            ),
        ],
    )
    def test_malformed_links_raise(self, link):
        with pytest.raises(InvalidMagnetError):
            parse_magnet_link(link)
