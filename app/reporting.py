"""The progress-reporting port.

Inner layers (the application and infrastructure) describe what is happening by
calling :meth:`ProgressReporter.report`; they do not decide where it goes. The
interface layer supplies the concrete sink (``StdoutReporter`` in
:mod:`app.cli`), keeping all output at the boundary where it belongs.
"""

from __future__ import annotations

import logging
from typing import Protocol


class ProgressReporter(Protocol):
    """Receives human-readable progress/diagnostic messages."""

    def report(self, message: str) -> None: ...


class NullReporter:
    """Discards messages - the default, so library use stays silent."""

    def report(self, message: str) -> None:
        pass


class LoggingReporter:
    """Mirrors progress messages to the logging channel.

    A parallel sink for the same progress events the CLI prints: library
    callers (or a composed CLI) get them on the default-silent stderr logger
    instead of - never instead *and* - touching stdout.
    """

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.DEBUG) -> None:
        self._logger = logger or logging.getLogger("app.progress")
        self._level = level

    def report(self, message: str) -> None:
        self._logger.log(self._level, message)


class CompositeReporter:
    """Fans one report out to several sinks, in order."""

    def __init__(self, *reporters: ProgressReporter) -> None:
        self._reporters = reporters

    def report(self, message: str) -> None:
        for reporter in self._reporters:
            reporter.report(message)

