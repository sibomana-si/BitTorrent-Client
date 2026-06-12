"""The progress-reporting port.

Inner layers (the application and infrastructure) describe what is happening by
calling :meth:`ProgressReporter.report`; they do not decide where it goes. The
interface layer supplies the concrete sink (``StdoutReporter`` in
:mod:`app.cli`), keeping all output at the boundary where it belongs.
"""

from __future__ import annotations

from typing import Protocol


class ProgressReporter(Protocol):
    """Receives human-readable progress/diagnostic messages."""

    def report(self, message: str) -> None: ...


class NullReporter:
    """Discards messages - the default, so library use stays silent."""

    def report(self, message: str) -> None:
        pass
