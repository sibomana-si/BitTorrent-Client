"""Unit tests for the tracker client and its SSRF/size guards in app/tracker.py"""
from typing import cast
from urllib.parse import quote_plus

import bencodepy
import pytest
import requests
from requests import Response

from app.constants import (
    ALLOW_PRIVATE_PEERS_ENV_VAR,
    MAX_REDIRECTS,
    MAX_TRACKER_RESPONSE_BYTES,
)
from app.errors import TrackerError
from app.models import Peer
from app.tracker import (
    TrackerClient,
    _get_validated,
    _is_blocked_ip,
    _peer_address_allowed,
    _read_capped,
    _validate_tracker_url,
)

from tests.conftest import TRACKER_URL, StubResponse, compact_peers_blob

INFO_HASH = b"\xaa" * 20


class TestParsePeers:
    def test_decodes_six_byte_records(self):
        blob = compact_peers_blob([("1.2.3.4", 6881), ("10.20.30.40", 51413)])
        assert TrackerClient._parse_peers(blob) == [
            Peer("1.2.3.4", 6881),
            Peer("10.20.30.40", 51413),
        ]

    def test_port_is_big_endian(self):
        blob = b"\x7f\x00\x00\x01" + b"\x1a\xe1"  # 0x1ae1 == 6881
        assert TrackerClient._parse_peers(blob) == [Peer("127.0.0.1", 6881)]

    @pytest.mark.parametrize(
        "blob",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"\x01" * 5, id="truncated-record"),
            pytest.param(b"\x01" * 7, id="trailing-partial-record"),
            pytest.param("not-bytes", id="not-bytes"),
            pytest.param([1, 2, 3], id="bencoded-list"),
        ],
    )
    def test_malformed_blob_is_rejected(self, blob):
        with pytest.raises(TrackerError, match="malformed peer list"):
            TrackerClient._parse_peers(blob)


class TestPeerIpFilter:
    """SEC1: tracker-supplied peer addresses go through the SSRF guard."""

    def test_address_allowed_blocks_internal_by_default(self, monkeypatch):
        monkeypatch.delenv(ALLOW_PRIVATE_PEERS_ENV_VAR, raising=False)
        assert _peer_address_allowed("1.2.3.4") is True
        assert _peer_address_allowed("127.0.0.1") is False
        assert _peer_address_allowed("169.254.169.254") is False
        assert _peer_address_allowed("10.0.0.1") is False

    def test_opt_out_allows_internal(self, monkeypatch):
        monkeypatch.setenv(ALLOW_PRIVATE_PEERS_ENV_VAR, "1")
        assert _peer_address_allowed("127.0.0.1") is True
        assert _peer_address_allowed("10.0.0.1") is True

    def test_get_peers_drops_blocked_records(self, stub_tracker, monkeypatch):
        monkeypatch.delenv(ALLOW_PRIVATE_PEERS_ENV_VAR, raising=False)
        stub_tracker.set_peers([("1.2.3.4", 6881), ("127.0.0.1", 6881), ("169.254.169.254", 80)])
        peers = TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)
        assert peers == [Peer("1.2.3.4", 6881)]

    def test_get_peers_all_blocked_raises(self, stub_tracker, monkeypatch):
        monkeypatch.delenv(ALLOW_PRIVATE_PEERS_ENV_VAR, raising=False)
        stub_tracker.set_peers([("127.0.0.1", 6881), ("10.0.0.1", 6881)])
        with pytest.raises(TrackerError, match="only blocked"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_get_peers_opt_out_keeps_loopback(self, stub_tracker, monkeypatch):
        monkeypatch.setenv(ALLOW_PRIVATE_PEERS_ENV_VAR, "1")
        stub_tracker.set_peers([("127.0.0.1", 6881)])
        peers = TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)
        assert peers == [Peer("127.0.0.1", 6881)]


class TestIsBlockedIp:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",          # loopback
            "10.0.0.1",           # private
            "172.16.0.1",         # private
            "192.168.1.1",        # private
            "169.254.169.254",    # link-local / cloud metadata
            "224.0.0.1",          # multicast
            "0.0.0.0",            # unspecified
            "240.0.0.1",          # reserved
            "::1",                # IPv6 loopback
        ],
    )
    def test_internal_addresses_are_blocked(self, ip):
        assert _is_blocked_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "1.1.1.1"])
    def test_public_addresses_are_allowed(self, ip):
        assert _is_blocked_ip(ip) is False


class TestValidateTrackerUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://tracker.example.test/announce",
            "ftp://tracker.example.test/announce",
            "tracker.example.test/announce",  # no scheme
        ],
    )
    def test_non_web_schemes_are_rejected(self, url, stub_tracker):
        with pytest.raises(TrackerError, match="scheme"):
            _validate_tracker_url(url)

    def test_url_without_host_is_rejected(self, stub_tracker):
        with pytest.raises(TrackerError, match="no host"):
            _validate_tracker_url("http:///announce")

    def test_unresolvable_host_is_rejected(self, stub_tracker):
        stub_tracker.resolve["unknown.test"] = OSError("Name or service not known")
        with pytest.raises(TrackerError, match="Cannot resolve"):
            _validate_tracker_url("http://unknown.test/announce")

    @pytest.mark.parametrize("blocked_ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254"])
    def test_host_resolving_to_blocked_address_is_rejected(self, stub_tracker, blocked_ip):
        stub_tracker.resolve["evil.test"] = blocked_ip
        with pytest.raises(TrackerError, match="blocked address"):
            _validate_tracker_url("http://evil.test/announce")

    def test_public_host_passes(self, stub_tracker):
        _validate_tracker_url(TRACKER_URL)  # must not raise


class TestReadCapped:
    def test_reads_a_small_body(self):
        body = b"x" * 1000
        assert _read_capped(cast(Response, StubResponse(body))) == body

    def test_body_at_the_limit_is_accepted(self):
        body = b"x" * MAX_TRACKER_RESPONSE_BYTES
        assert _read_capped(cast(Response, StubResponse(body))) == body

    def test_oversized_body_is_rejected(self):
        with pytest.raises(TrackerError, match="size limit"):
            _read_capped(cast(Response, StubResponse(b"x" * (MAX_TRACKER_RESPONSE_BYTES + 1))))


class TestGetValidated:
    def test_non_redirect_response_is_returned(self, stub_tracker):
        response = StubResponse(b"ok")
        stub_tracker.queue.append(response)
        assert _get_validated(TRACKER_URL) is response
        assert stub_tracker.urls == [TRACKER_URL]

    def test_redirect_is_followed_and_revalidated(self, stub_tracker):
        final = StubResponse(b"ok")
        stub_tracker.queue = [StubResponse(status=302, headers={"Location": "http://mirror.test/announce"}), final]
        assert _get_validated(TRACKER_URL) is final
        assert stub_tracker.urls == [TRACKER_URL, "http://mirror.test/announce"]

    def test_relative_redirect_is_resolved_against_the_url(self, stub_tracker):
        final = StubResponse(b"ok")
        stub_tracker.queue = [StubResponse(status=302, headers={"Location": "/other"}), final]
        assert _get_validated(TRACKER_URL) is final
        assert stub_tracker.urls[1] == "http://tracker.example.test/other"

    def test_redirect_to_blocked_host_is_rejected(self, stub_tracker):
        stub_tracker.resolve["internal.test"] = "127.0.0.1"
        stub_tracker.queue = [StubResponse(status=302, headers={"Location": "http://internal.test/admin"})]
        with pytest.raises(TrackerError, match="blocked address"):
            _get_validated(TRACKER_URL)

    def test_redirect_loop_is_bounded(self, stub_tracker):
        stub_tracker.queue = [
            StubResponse(status=302, headers={"Location": TRACKER_URL})
            for _ in range(MAX_REDIRECTS + 1)
        ]
        with pytest.raises(TrackerError, match="Too many tracker redirects"):
            _get_validated(TRACKER_URL)

    def test_redirect_without_location_is_returned_as_is(self, stub_tracker):
        response = StubResponse(status=302, headers={})
        stub_tracker.queue.append(response)
        assert _get_validated(TRACKER_URL) is response


class TestGetPeers:
    def test_happy_path_returns_peers(self, stub_tracker):
        stub_tracker.set_peers([("1.2.3.4", 6881), ("5.6.7.8", 51413)])
        peers = TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=12345)
        assert peers == [Peer("1.2.3.4", 6881), Peer("5.6.7.8", 51413)]

    def test_announce_url_carries_the_required_params(self, stub_tracker):
        stub_tracker.set_peers([("1.2.3.4", 6881)])
        client = TrackerClient(peer_id=b"P" * 20, port=7000)
        client.get_peers(TRACKER_URL, INFO_HASH, left=999)

        (url,) = stub_tracker.urls
        assert url.startswith(TRACKER_URL + "?")
        assert f"info_hash={quote_plus(INFO_HASH)}" in url
        assert f"peer_id={quote_plus(b'P' * 20)}" in url
        assert "port=7000" in url
        assert "left=999" in url
        assert "compact=1" in url
        assert "uploaded=0" in url and "downloaded=0" in url

    def test_http_error_becomes_tracker_error(self, stub_tracker):
        stub_tracker.queue.append(StubResponse(b"", status=500))
        with pytest.raises(TrackerError, match="request failed"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_connection_error_becomes_tracker_error(self, stub_tracker):
        stub_tracker.queue.append(requests.ConnectionError("connection refused"))
        with pytest.raises(TrackerError, match="request failed"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_undecodable_body_becomes_tracker_error(self, stub_tracker):
        stub_tracker.queue.append(StubResponse(b"<html>not bencode</html>"))
        with pytest.raises(TrackerError, match="Unexpected tracker response"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_missing_peers_key_becomes_tracker_error(self, stub_tracker):
        stub_tracker.queue.append(StubResponse(bencodepy.encode({"interval": 60})))
        with pytest.raises(TrackerError, match="Unexpected tracker response"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_failure_reason_becomes_tracker_error(self, stub_tracker):
        # A 200-OK {failure reason: ...} response is surfaced as the reason,
        # not as a confusing missing-peers error.
        body = bencodepy.encode({"failure reason": "torrent not registered"})
        stub_tracker.queue.append(StubResponse(body))
        with pytest.raises(TrackerError, match="torrent not registered"):
            TrackerClient().get_peers(TRACKER_URL, INFO_HASH, left=1)

    def test_blocked_tracker_is_rejected_before_any_request(self, stub_tracker):
        stub_tracker.resolve["evil.test"] = "192.168.0.1"
        with pytest.raises(TrackerError, match="blocked address"):
            TrackerClient().get_peers("http://evil.test/announce", INFO_HASH, left=1)
        assert stub_tracker.urls == []  # never reached the HTTP layer
