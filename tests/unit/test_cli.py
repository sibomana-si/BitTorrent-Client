"""Unit tests for argument parsing and the error boundary in app/cli.py"""

import pytest

import app.cli as cli
from app.cli import _build_parser, _jsonable, main
from app.client import TorrentClient
from app.errors import TrackerError


class TestJsonable:
    def test_bytes_become_str(self):
        assert _jsonable(b"hello") == "hello"

    def test_scalars_pass_through(self):
        assert _jsonable(42) == 42
        assert _jsonable(-7) == -7

    def test_lists_are_converted_recursively(self):
        assert _jsonable([b"a", 1, [b"b"]]) == ["a", 1, ["b"]]

    def test_dict_keys_and_values_are_converted(self):
        assert _jsonable({b"key": b"value", b"n": 3}) == {"key": "value", "n": 3}

    def test_nested_structure(self):
        value = {b"outer": [{b"inner": b"x"}, 5]}
        assert _jsonable(value) == {"outer": [{"inner": "x"}, 5]}

    def test_non_utf8_bytes_do_not_raise(self):
        # Strict UTF-8 would raise UnicodeDecodeError here (R5); decode leniently.
        assert _jsonable(b"\xff\xfe") == "��"

    def test_non_utf8_bytes_nested(self):
        value = {b"k": [b"\x80", b"ok"]}
        assert _jsonable(value) == {"k": ["�", "ok"]}


class TestParser:
    @pytest.fixture
    def parser(self):
        return _build_parser()

    def test_decode(self, parser):
        args = parser.parse_args(["decode", "5:hello"])
        assert args.handler is cli._decode
        assert args.value == "5:hello"

    @pytest.mark.parametrize(("command", "handler_name"), [("info", "_info"), ("peers", "_peers")])
    def test_torrent_readers(self, parser, command, handler_name):
        args = parser.parse_args([command, "sample.torrent"])
        assert args.handler is getattr(cli, handler_name)
        assert args.torrent == "sample.torrent"

    def test_handshake_with_explicit_peer(self, parser):
        args = parser.parse_args(["handshake", "sample.torrent", "1.2.3.4:6881"])
        assert args.handler is cli._handshake
        assert args.peer == "1.2.3.4:6881"

    def test_handshake_peer_is_optional(self, parser):
        args = parser.parse_args(["handshake", "sample.torrent"])
        assert args.peer is None

    def test_download_piece(self, parser):
        args = parser.parse_args(["download_piece", "-o", "/tmp/out", "sample.torrent", "2"])
        assert args.handler is cli._download_piece
        assert (args.output, args.torrent, args.index) == ("/tmp/out", "sample.torrent", 2)

    def test_download(self, parser):
        args = parser.parse_args(["download", "--output", "/tmp/out", "sample.torrent"])
        assert args.handler is cli._download
        assert (args.output, args.torrent) == ("/tmp/out", "sample.torrent")

    @pytest.mark.parametrize(
        ("command", "handler_name"),
        [("magnet_parse", "_magnet_parse"), ("magnet_handshake", "_magnet_handshake"), ("magnet_info", "_magnet_info")]
    )
    def test_magnet_readers(self, parser, command, handler_name):
        args = parser.parse_args([command, "magnet:?xt=urn:btih:00"])
        assert args.handler is getattr(cli, handler_name)
        assert args.link == "magnet:?xt=urn:btih:00"

    def test_magnet_download_piece(self, parser):
        args = parser.parse_args(["magnet_download_piece", "-o", "/tmp/out", "magnet:?x", "1"])
        assert args.handler is cli._magnet_download_piece
        assert (args.output, args.link, args.index) == ("/tmp/out", "magnet:?x", 1)

    def test_magnet_download(self, parser):
        args = parser.parse_args(["magnet_download", "-o", "/tmp/out", "magnet:?x"])
        assert args.handler is cli._magnet_download
        assert (args.output, args.link) == ("/tmp/out", "magnet:?x")

    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param([], id="no-command"),
            pytest.param(["not_a_command"], id="unknown-command"),
            pytest.param(["download", "sample.torrent"], id="download-missing-output"),
            pytest.param(["download_piece", "-o", "x", "t.torrent"], id="missing-index"),
            pytest.param(["download_piece", "-o", "x", "t.torrent", "NaN"], id="non-int-index"),
        ],
    )
    def test_bad_argv_exits_with_usage_error(self, parser, argv, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(argv)
        assert excinfo.value.code == 2
        assert "usage:" in capsys.readouterr().err


class TestMainBoundary:
    def test_operational_error_prints_and_exits_1(self, tmp_path, capsys):
        missing = tmp_path / "missing.torrent"
        with pytest.raises(SystemExit) as excinfo:
            main(["info", str(missing)])
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"error: Cannot read torrent file: {missing}\n"

    def test_any_bittorrent_error_is_reported_cleanly(self, monkeypatch, capsys):
        def explode(self, path):
            raise TrackerError("announce failed")

        monkeypatch.setattr(TorrentClient, "read_metadata", explode)
        with pytest.raises(SystemExit) as excinfo:
            main(["info", "whatever.torrent"])
        assert excinfo.value.code == 1
        assert capsys.readouterr().err == "error: announce failed\n"

    def test_keyboard_interrupt_exits_130(self, monkeypatch, capsys):
        def interrupt(self, path):
            raise KeyboardInterrupt

        monkeypatch.setattr(TorrentClient, "read_metadata", interrupt)
        with pytest.raises(SystemExit) as excinfo:
            main(["info", "whatever.torrent"])
        assert excinfo.value.code == 130
        assert capsys.readouterr().err == "interrupted\n"

    def test_unexpected_exceptions_stay_loud(self, monkeypatch):
        # Bugs must propagate as tracebacks, not be masked as clean errors.
        def explode(self, path):
            raise ValueError("a genuine bug")

        monkeypatch.setattr(TorrentClient, "read_metadata", explode)
        with pytest.raises(ValueError, match="a genuine bug"):
            main(["info", "whatever.torrent"])

    def test_decode_happy_path(self, capsys):
        main(["decode", "d3:foo3:bar5:helloi52ee"])
        assert capsys.readouterr().out == '{"foo": "bar", "hello": 52}\n'
