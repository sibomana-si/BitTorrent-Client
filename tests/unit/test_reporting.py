"""Unit tests for the ProgressReporter port and its implementations."""

from app.cli import StdoutReporter
from app.reporting import NullReporter


def test_null_reporter_is_silent(capsys):
    NullReporter().report("should not appear")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_stdout_reporter_prints_the_message_verbatim(capsys):
    StdoutReporter().report("piece_0 | 16384 downloaded.")
    captured = capsys.readouterr()
    assert captured.out == "piece_0 | 16384 downloaded.\n"
    assert captured.err == ""


def test_reporters_satisfy_the_port():
    # Structural check: both sinks expose the single-method protocol surface.
    for reporter in (NullReporter(), StdoutReporter()):
        assert callable(reporter.report)
