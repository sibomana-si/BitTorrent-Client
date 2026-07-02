"""Tests for the observability features.

The governing contract: with no verbosity flag and no env var, stdout AND
stderr are byte-identical to the pre-observability client — on happy and error
paths alike. Everything else (levels, formatters, timing, counters, summary,
lifecycle, boundary context) is opt-in stderr output.

These tests assert through capsys, not caplog, wherever the CLI is involved:
``_configure_logging`` puts the handler on the ``app`` logger with
``propagate=False`` (so caplog's root handler never sees CLI records), and it
creates a fresh ``StreamHandler(sys.stderr)`` on every ``main()`` call, which
binds the capsys-replaced stream. Library-level tests (reporters, the security
bridge) use caplog via propagation, which the reset fixture re-enables.
"""

import json
import logging
import logging.handlers
import re
from argparse import Namespace
from typing import cast

import pytest
from requests import Response

from app import __version__
from app.cli import (
    _JsonFormatter,
    _KeyValueFormatter,
    _RedactionFilter,
    _build_parser,
    _configure_logging,
    _resolve_log_level,
    main,
)
from app.constants import (
    BLOCK_SIZE,
    DEFAULT_LOG_LEVEL,
    LOG_LEVEL_ENV_VAR,
    MAX_TRACKER_RESPONSE_BYTES,
)
from app.errors import TrackerError
from app.reporting import CompositeReporter, LoggingReporter
from app.tracker import _read_capped

from tests.conftest import FakePeer


@pytest.fixture(autouse=True)
def pristine_logging(monkeypatch):
    """Undo CLI logging configuration around every test.

    ``main()`` mutates the shared ``app`` logger (handler, level, propagate=False);
    left in place it would leak DEBUG output or block caplog propagation in later tests.
    The env fallback is cleared so the shell can't change what "default" means.
    """
    monkeypatch.delenv(LOG_LEVEL_ENV_VAR, raising=False)

    def reset():
        app_logger = logging.getLogger("app")
        for handler in list(app_logger.handlers):
            if not isinstance(handler, logging.NullHandler):
                app_logger.removeHandler(handler)
                handler.close()  # flush + release any open log file
        app_logger.setLevel(logging.NOTSET)
        app_logger.propagate = True

    reset()
    yield
    reset()


@pytest.fixture
def torrent(make_torrent):
    return make_torrent(length=40, piece_length=16)  # pieces: 16, 16, 8


def stderr_records(err: str) -> list[dict]:
    """Parse ``--log-format json`` stderr into one dict per line."""
    return [json.loads(line) for line in err.splitlines() if line]


class TestDefaultSilence:
    """constraint: no flag, no env -> not one new byte on either stream."""

    def test_happy_path_emits_nothing_on_stderr(self, capsys):
        main(["decode", "5:hello"])
        captured = capsys.readouterr()
        assert captured.out == '"hello"\n'
        assert captured.err == ""

    def test_info_emits_nothing_on_stderr(self, capsys, torrent):
        main(["info", torrent.path])
        assert capsys.readouterr().err == ""

    def test_download_emits_nothing_on_stderr(
        self, capsys, torrent, stub_tracker, tmp_path
    ):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["download", "-o", str(output), torrent.path])
        assert capsys.readouterr().err == ""

    def test_error_path_is_exactly_one_line(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["decode", "i12"])
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error: Invalid bencoded value: 'i12'\n"


class TestVerbosityFlags:
    """-v / -vv / --log-level, before or after the subcommand, env fallback."""

    def test_v_before_the_subcommand(self, capsys, torrent):
        main(["-vv", "magnet_parse", torrent.magnet_link])
        assert "magnet link parsed" in capsys.readouterr().err

    def test_v_after_the_subcommand(self, capsys, torrent):
        main(["magnet_parse", "-vv", torrent.magnet_link])
        assert "magnet link parsed" in capsys.readouterr().err

    def test_single_v_is_info_only(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-v", "download", "-o", str(output), torrent.path])
        err = capsys.readouterr().err
        assert "INFO app.client: download complete" in err
        assert "DEBUG" not in err

    def test_log_level_flag_is_explicit(self, capsys, torrent):
        main(["--log-level", "DEBUG", "magnet_parse", torrent.magnet_link])
        assert "magnet link parsed" in capsys.readouterr().err

    def test_env_fallback_enables_logging(self, capsys, monkeypatch, torrent):
        monkeypatch.setenv(LOG_LEVEL_ENV_VAR, "DEBUG")
        main(["info", torrent.path])
        assert "DEBUG app.torrent: metadata built" in capsys.readouterr().err

    def test_flag_beats_env(self, capsys, monkeypatch, torrent):
        monkeypatch.setenv(LOG_LEVEL_ENV_VAR, "DEBUG")
        main(["--log-level", "CRITICAL", "info", torrent.path])
        assert capsys.readouterr().err == ""

    def test_stdout_stays_byte_exact_under_full_verbosity(
        self, capsys, torrent, stub_tracker, tmp_path
    ):
        # richer stderr must never perturb the graded stream.
        from tests.e2e.test_cli_commands import piece_progress_lines

        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "download", "-o", str(output), torrent.path])
            expected = [
                f"connected to {fake.address}",
                f"downloading to {output} ...",
                "pieces to download: 3",
            ]
            for index in range(3):
                expected += piece_progress_lines(torrent, index)
                expected.append(
                    f"piece_{index} | {len(torrent.piece(index))} downloaded."
                )
            expected.append("torrent file download completed.")
        captured = capsys.readouterr()
        assert captured.out == "\n".join(expected) + "\n"
        assert output.read_bytes() == torrent.content


class TestLevelResolution:
    def test_explicit_flag_wins_over_verbose(self):
        args = Namespace(log_level="ERROR", verbose=2)
        assert _resolve_log_level(args) == logging.ERROR

    @pytest.mark.parametrize(("verbose", "expected"), [(1, logging.INFO), (2, logging.DEBUG), (3, logging.DEBUG)],)
    def test_verbose_counts(self, verbose, expected):
        assert _resolve_log_level(Namespace(verbose=verbose)) == expected

    def test_no_flags_is_silent(self):
        assert _resolve_log_level(Namespace()) == DEFAULT_LOG_LEVEL
        assert DEFAULT_LOG_LEVEL > logging.CRITICAL

    def test_env_fallback_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv(LOG_LEVEL_ENV_VAR, "info")
        assert _resolve_log_level(Namespace()) == logging.INFO

    def test_invalid_env_value_is_ignored(self, monkeypatch):
        monkeypatch.setenv(LOG_LEVEL_ENV_VAR, "NOISY")
        assert _resolve_log_level(Namespace()) == DEFAULT_LOG_LEVEL


class TestParserFlags:
    """The SUPPRESS-default parent parser: globals survive the subparser."""

    @pytest.mark.parametrize(
        "argv", [["-v", "decode", "x"], ["decode", "-v", "x"]],
        ids=["before-subcommand", "after-subcommand"],
    )
    def test_verbose_parses_in_either_position(self, argv):
        args = _build_parser().parse_args(argv)
        assert getattr(args, "verbose", 0) == 1

    def test_absent_flags_set_no_attributes(self):
        args = _build_parser().parse_args(["decode", "x"])
        assert not hasattr(args, "verbose")
        assert not hasattr(args, "log_level")
        assert not hasattr(args, "log_format")


class TestFormatters:
    """ctx fields ride extra=, rendered as key=value or JSON."""

    @staticmethod
    def _record(message: str, ctx: dict | None = None, exc_info=None):
        record = logging.LogRecord("app.x", logging.INFO, __file__, 1, message, None, exc_info)
        if ctx is not None:
            record.ctx = ctx
        return record

    def test_key_value_appends_sorted_ctx(self):
        formatter = _KeyValueFormatter("%(levelname)s %(name)s: %(message)s")
        out = formatter.format(self._record("event happened", {"b": 2, "a": 1}))
        assert out == "INFO app.x: event happened a=1 b=2"

    def test_key_value_without_ctx_is_just_the_message(self):
        formatter = _KeyValueFormatter("%(levelname)s %(name)s: %(message)s")
        assert formatter.format(self._record("plain")) == "INFO app.x: plain"

    def test_json_flattens_ctx_into_the_object(self):
        payload = json.loads(_JsonFormatter().format(self._record("event", {"peer": "1.2.3.4:6881"})))
        assert payload["event"] == "event"
        assert payload["level"] == "INFO"
        assert payload["logger"] == "app.x"
        assert payload["peer"] == "1.2.3.4:6881"
        assert "ts" in payload

    def test_json_includes_the_traceback(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = self._record("failed", exc_info=sys.exc_info())
        payload = json.loads(_JsonFormatter().format(record))
        assert "ValueError: boom" in payload["traceback"]

    def test_cli_text_output_renders_ctx_fields(self, capsys, torrent):
        main(["-vv", "magnet_parse", torrent.magnet_link])
        assert (
            f"DEBUG app.magnet: magnet link parsed "
            f"info_hash={torrent.info_hash.hex()[:8]} tracker={torrent.tracker_url}"
        ) in capsys.readouterr().err

    def test_cli_json_output_is_one_object_per_line(self, capsys, torrent):
        main(["-vv", "--log-format", "json", "magnet_parse", torrent.magnet_link])
        records = stderr_records(capsys.readouterr().err)
        assert records  # every line parsed
        parsed = next(r for r in records if r["event"] == "magnet link parsed")
        assert parsed["logger"] == "app.magnet"
        assert parsed["info_hash"] == torrent.info_hash.hex()[:8]


class TestReporters:
    """the parallel log channel; the graded reporter is untouched."""

    def test_logging_reporter_logs_at_debug_by_default(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="app.progress"):
            LoggingReporter().report("downloading piece_index: 0 ...")
        record = caplog.records[-1]
        assert record.name == "app.progress"
        assert record.levelno == logging.DEBUG
        assert record.getMessage() == "downloading piece_index: 0 ..."

    def test_logging_reporter_honours_a_custom_logger_and_level(self, caplog):
        custom = logging.getLogger("app.custom")
        with caplog.at_level(logging.INFO, logger="app.custom"):
            LoggingReporter(custom, logging.INFO).report("hello")
        record = caplog.records[-1]
        assert (record.name, record.levelno) == ("app.custom", logging.INFO)

    def test_composite_reporter_fans_out_in_order(self):
        calls = []

        class Sink:
            def __init__(self, tag):
                self.tag = tag

            def report(self, message):
                calls.append((self.tag, message))

        CompositeReporter(Sink("first"), Sink("second")).report("x")
        assert calls == [("first", "x"), ("second", "x")]

    def test_cli_mirrors_progress_to_the_log(self, capsys, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "handshake", torrent.path])
        captured = capsys.readouterr()
        # Same event, both sinks: stdout verbatim, stderr via app.progress.
        assert f"connected to {fake.address}" in captured.out
        assert f"DEBUG app.progress: connected to {fake.address}" in captured.err


class TestConfigureLogging:
    def test_repeated_configuration_keeps_one_handler(self):
        _configure_logging(logging.INFO)
        _configure_logging(logging.DEBUG)
        app_logger = logging.getLogger("app")
        real = [h for h in app_logger.handlers if not isinstance(h, logging.NullHandler)]
        assert len(real) == 1
        assert app_logger.level == logging.DEBUG
        assert app_logger.propagate is False

    def test_library_null_handler_is_preserved(self):
        _configure_logging(logging.INFO)
        assert any(isinstance(h, logging.NullHandler) for h in logging.getLogger("app").handlers)


class TestInstrumentedDownload:
    """timing, counters, summary, lifecycle on a real flow."""

    def test_debug_run_traces_every_phase(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "download", "-o", str(output), torrent.path])
        err = capsys.readouterr().err
        assert "DEBUG app.tracker: tracker announce ok" in err
        assert "DEBUG app.peer: peer connect attempt" in err
        assert "DEBUG app.peer: peer connected" in err
        assert "DEBUG app.peer: handshake ok" in err
        assert "DEBUG app.peer: peer unchoked us" in err
        assert "DEBUG app.peer: piece downloaded" in err
        assert "elapsed_ms=" in err
        assert "INFO app.client: download complete" in err

    def test_summary_record_carries_the_run_counters(
        self, capsys, torrent, stub_tracker, tmp_path
    ):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-v", "--log-format", "json", "download", "-o", str(output), torrent.path])
        summaries = [
            r
            for r in stderr_records(capsys.readouterr().err)
            if r["event"] == "download complete"
        ]
        assert len(summaries) == 1
        summary = summaries[0]
        assert summary["level"] == "INFO"
        assert summary["logger"] == "app.client"
        assert summary["info_hash"] == torrent.info_hash.hex()[:8]
        assert summary["bytes"] == 40
        assert summary["pieces"] == 3
        assert summary["piece_failures"] == 0
        assert summary["failovers"] == 0
        assert summary["connections"] == 1
        assert summary["elapsed_ms"] > 0
        assert summary["throughput_bps"] > 0

    def test_failover_shows_up_in_the_summary(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent, corrupt_data=True) as bad:
            with FakePeer.for_torrent(torrent) as good:
                stub_tracker.set_peers([(bad.ip, bad.port), (good.ip, good.port)])
                main(["-v", "--log-format", "json", "download", "-o", str(output), torrent.path])
        summary = next(
            r
            for r in stderr_records(capsys.readouterr().err)
            if r["event"] == "download complete"
        )
        assert summary["piece_failures"] == 1
        assert summary["failovers"] == 1
        assert summary["connections"] == 2
        assert output.read_bytes() == torrent.content

    def test_magnet_flow_logs_the_extension_negotiation(self, capsys, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent, extension=True, ut_metadata_id=42) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "magnet_handshake", torrent.magnet_link])
        err = capsys.readouterr().err
        assert "extension handshake ok" in err
        assert "ut_metadata=42" in err


class TestSecurityBridge:
    """cap rejections log at WARNING (silent by default, visible opted-in)."""

    def test_oversized_tracker_body_warns_before_raising(self, caplog):
        class FakeResponse:
            def iter_content(self, size):
                yield b"x" * (MAX_TRACKER_RESPONSE_BYTES + 1)

            def close(self):
                pass

        with caplog.at_level(logging.WARNING, logger="app.tracker"):
            with pytest.raises(TrackerError):
                _read_capped(cast(Response, cast(object, FakeResponse())))
        record = next(
            r
            for r in caplog.records
            if r.getMessage() == "tracker response rejected by the size cap"
        )
        assert record.ctx["cap"] == MAX_TRACKER_RESPONSE_BYTES
        assert record.ctx["bytes"] > MAX_TRACKER_RESPONSE_BYTES


class TestBoundaryErrors:
    """full error context on the diagnostic side, untouched user line."""

    def test_error_record_precedes_the_unchanged_error_line(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--log-level", "ERROR", "decode", "i12"])
        assert excinfo.value.code == 1
        lines = capsys.readouterr().err.splitlines()
        assert lines[0].startswith("ERROR app.cli: command failed")
        assert "command=decode" in lines[0]
        assert "error_type=BencodeError" in lines[0]
        assert "cause=BencodeDecodeError" in lines[0]
        assert lines[-1] == "error: Invalid bencoded value: 'i12'"

    def test_debug_level_includes_the_traceback(self, capsys):
        with pytest.raises(SystemExit):
            main(["-vv", "decode", "i12"])
        err = capsys.readouterr().err
        assert "Traceback (most recent call last)" in err
        assert err.rstrip().endswith("error: Invalid bencoded value: 'i12'")

    def test_error_level_omits_the_traceback(self, capsys):
        with pytest.raises(SystemExit):
            main(["--log-level", "ERROR", "decode", "i12"])
        assert "Traceback" not in capsys.readouterr().err

    def test_keyboard_interrupt_leaves_a_debug_trace(self, capsys, monkeypatch):
        from app.client import TorrentClient

        def interrupt(self, path):
            raise KeyboardInterrupt

        monkeypatch.setattr(TorrentClient, "read_metadata", interrupt)
        with pytest.raises(SystemExit) as excinfo:
            main(["-vv", "info", "x.torrent"])
        assert excinfo.value.code == 130
        err = capsys.readouterr().err
        assert "interrupted by user" in err
        assert err.rstrip().endswith("interrupted")


class TestBlockSampling:
    """per-block DEBUG events are thinned so they don't flood the log."""

    def test_block_events_are_sampled_under_debug(
        self, capsys, make_torrent, stub_tracker, tmp_path, monkeypatch
    ):
        # One piece of three 16 KiB blocks; 1-in-2 sampling keeps 2 of the 3.
        monkeypatch.setattr("app.cli.LOG_BLOCK_SAMPLE_RATE", 2)
        torrent = make_torrent(length=BLOCK_SIZE * 3, piece_length=BLOCK_SIZE * 3)
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "download", "-o", str(output), torrent.path])
        block_lines = [
            line for line in capsys.readouterr().err.splitlines()
            if "block received" in line
        ]
        assert len(block_lines) == 2
        assert output.read_bytes() == torrent.content

    def test_no_block_events_without_verbosity(
        self, capsys, make_torrent, stub_tracker, tmp_path
    ):
        torrent = make_torrent(length=BLOCK_SIZE * 3, piece_length=BLOCK_SIZE * 3)
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["download", "-o", str(output), torrent.path])
        assert capsys.readouterr().err == ""


class TestRedaction:
    """opt-in masking of sensitive ctx fields; off by default."""

    def test_filter_masks_sensitive_keys_only(self):
        record = logging.LogRecord("app.x", logging.INFO, __file__, 1, "m", None, None)
        record.ctx = {
            "peer": "1.2.3.4:6881",
            "host": "5.6.7.8",
            "peer_id": "ABCDEFGH",
            "info_hash": "0123456789abcdef",
            "piece_index": 3,
        }
        assert _RedactionFilter().filter(record) is True
        masked = cast(dict, getattr(record, "ctx"))
        assert masked["peer"] == "1.x.x.x:6881"
        assert masked["host"] == "5.x.x.x"
        assert masked["peer_id"] == "ABCD..."
        assert masked["info_hash"] == "01234567"
        assert masked["piece_index"] == 3  # non-sensitive, untouched

    def test_cli_masks_peer_address_when_enabled(self, capsys, make_torrent, stub_tracker):
        torrent = make_torrent(length=40, piece_length=16)
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "--log-redact", "handshake", torrent.path])
        err = capsys.readouterr().err
        assert f"peer=127.x.x.x:{fake.port}" in err
        assert f"peer={fake.ip}:{fake.port}" not in err

    def test_cli_shows_peer_address_without_the_flag(self, capsys, make_torrent, stub_tracker):
        torrent = make_torrent(length=40, piece_length=16)
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["-vv", "handshake", torrent.path])
        assert f"peer={fake.ip}:{fake.port}" in capsys.readouterr().err


class TestRunId:
    """an opt-in per-invocation run id correlates one run's records."""

    def test_run_id_is_stamped_when_enabled(self, capsys, torrent):
        main(["-vv", "--log-run-id", "magnet_parse", torrent.magnet_link])
        assert re.search(r"run_id=[0-9a-f]{8}\b", capsys.readouterr().err)

    def test_no_run_id_by_default(self, capsys, torrent):
        main(["-vv", "magnet_parse", torrent.magnet_link])
        assert "run_id=" not in capsys.readouterr().err


class TestLogFile:
    """an opt-in rotating file sink for durable JSON-lines diagnostics."""

    def test_log_file_receives_json_records_with_a_run_id(self, capsys, torrent, tmp_path):
        path = tmp_path / "run.jsonl"
        main(["-vv", "--log-file", str(path), "magnet_parse", torrent.magnet_link])
        records = [json.loads(line) for line in path.read_text().splitlines() if line]
        parsed = next(r for r in records if r["event"] == "magnet link parsed")
        assert parsed["logger"] == "app.magnet"
        assert re.fullmatch(r"[0-9a-f]{8}", parsed["run_id"])  # file implies run-id

    def test_file_handler_is_rotating(self, torrent, tmp_path):
        path = tmp_path / "run.jsonl"
        main(["-vv", "--log-file", str(path), "magnet_parse", torrent.magnet_link])
        handlers = [
            h
            for h in logging.getLogger("app").handlers
            if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert len(handlers) == 1

    def test_no_file_written_by_default(self, capsys, torrent, tmp_path):
        path = tmp_path / "run.jsonl"
        main(["magnet_parse", torrent.magnet_link])
        assert not path.exists()


class TestProvenance:
    """a default-silent build/version preamble under verbose mode."""

    def test_startup_preamble_logs_versions(self, capsys, torrent):
        main(["-vv", "magnet_parse", torrent.magnet_link])
        err = capsys.readouterr().err
        assert "client starting" in err
        assert f"version={__version__}" in err
        assert "python=" in err
        assert "bencode_py=" in err

    def test_no_preamble_without_verbosity(self, capsys, torrent):
        main(["info", torrent.path])
        assert capsys.readouterr().err == ""


class TestSelftest:
    """a never-graded diagnostic subcommand."""

    def test_reports_versions_and_passes(self, capsys):
        main(["selftest"])
        out = capsys.readouterr().out
        assert f"client: {__version__}" in out
        assert "python:" in out
        assert "bencode.py:" in out
        assert "PASS python >= 3.8" in out
        assert "PASS bencodepy importable" in out

    def test_resolves_a_torrent_tracker(self, capsys, make_torrent, monkeypatch):
        monkeypatch.setattr(
            "app.cli.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))],
        )
        main(["selftest", make_torrent().path])
        assert "PASS resolve tracker.example.test" in capsys.readouterr().out

    def test_fails_on_a_bad_source(self, capsys, tmp_path):
        bad = tmp_path / "nope.torrent"
        bad.write_bytes(b"not bencode")
        with pytest.raises(SystemExit) as excinfo:
            main(["selftest", str(bad)])
        assert excinfo.value.code == 1
        assert "FAIL parse source" in capsys.readouterr().out
