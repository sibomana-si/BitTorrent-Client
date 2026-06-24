"""Command-line interface: argument parsing, dispatch, and all output.

Every command maps to a small handler that calls into :class:`TorrentClient`
and prints the result. This is the only layer that touches ``argv`` or writes
to stdout for presentation.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import logging
import logging.handlers
import os
import platform
import socket
import sys
import uuid
from urllib.parse import urlsplit

from app import __version__
from app.client import TorrentClient
from app.constants import (
    DEFAULT_LOG_LEVEL,
    LOG_BLOCK_SAMPLE_RATE,
    LOG_FILE_BACKUPS,
    LOG_FILE_ENV_VAR,
    LOG_FILE_MAX_BYTES,
    LOG_LEVEL_ENV_VAR,
    LOG_REDACT_ENV_VAR
)
from app.errors import BitTorrentError
from app.models import Peer, TorrentMetadata
from app.reporting import CompositeReporter, LoggingReporter


logger = logging.getLogger(__name__)

_LOG_LEVEL_CHOICES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_REDACT_ADDRESS_KEYS = ("peer", "address")
_REDACT_HOST_KEYS = ("ip", "host")


class StdoutReporter:
    """Renders progress to stdout - the only place output belongs."""

    def report(self, message: str) -> None:
        print(message)


class _KeyValueFormatter(logging.Formatter):
    """Terse human format: structured ``ctx`` fields appended as key=value.

    Call sites attach machine-parseable context via
    ``extra={"ctx": {...}}`` rather than interpolating it into the message, so
    one event can be rendered as text here or as JSON by
    :class:`_JsonFormatter` without touching the call site.
    """

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        ctx = getattr(record, "ctx", None)
        if not ctx:
            return base
        fields = " ".join(f"{key}={value}" for key, value in sorted(ctx.items()))
        return f"{base} {fields}"


class _JsonFormatter(logging.Formatter):
    """One JSON object per line, ``ctx`` fields flattened in - for ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            **(getattr(record, "ctx", None) or {})
        }
        if record.exc_info:
            payload["traceback"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _SamplingFilter(logging.Filter):
    """Thin out high-frequency records so they don't flood a verbose log.

    A record opts in by carrying a truthy ``sampled`` attribute (set via
    ``extra={"sampled": True}`` at the call site); such records are counted per
    ``(logger, message)`` and only every Nth is emitted. Every other record
    passes untouched, so ordinary lines are never dropped. One filter instance
    lives per handler, so each output stream samples independently.
    """

    def __init__(self, rate: int = LOG_BLOCK_SAMPLE_RATE) -> None:
        super().__init__()
        self._rate = max(1, rate)
        self._counts: dict[tuple[str, str], int] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "sampled", False):
            return True
        key = (record.name, str(record.msg))
        count = self._counts.get(key, 0)
        self._counts[key] = count + 1
        return count % self._rate == 0


class _RedactionFilter(logging.Filter):
    """Mask sensitive ctx fields so a verbose log excerpt is shareable.

    Peer addresses, hostnames/IPs, the peer id, and a full info hash identify who
    the client talked to. When enabled, mask them on a *copy* of the record's
    ctx, leaving the in-memory entity (and any other handler's own pass)
    untouched.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = getattr(record, "ctx", None)
        if ctx:
            record.ctx = {key: _redact(key, value) for key, value in ctx.items()}
        return True


def _redact(key: str, value):
    if key in _REDACT_ADDRESS_KEYS:
        return _mask_address(value)
    if key in _REDACT_HOST_KEYS:
        return _mask_host(value)
    if key == "peer_id":
        text = str(value)
        return f"{text[:4]}..." if len(text) > 4 else "..."
    if key == "info_hash":
        return str(value)[:8]
    return value


def _mask_address(value):
    host, sep, port = str(value).rpartition(":")
    if not sep:
        return _mask_host(value)
    return f"{_mask_host(host)}:{port}"


def _mask_host(value):
    parts = str(value).split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.x.x.x"
    return "<redacted>"


class _RunIdFilter(logging.Filter):
    """Stamp a per-invocation run id onto every record so one run correlates.

    Injected into a copy of ctx, so it renders as ``run_id=...`` (text) or a
    top-level field (JSON). Opt-in (``--log-run-id``, and implied by a log
    file), so default verbose output keeps its existing field order.
    """

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = dict(getattr(record, "ctx", None) or {})
        ctx["run_id"] = self._run_id
        record.ctx = ctx
        return True


def _logging_options() -> argparse.ArgumentParser:
    """The global logging flags, shared by the top-level parser and every
    subcommand (so ``-v`` works before and after the subcommand name).

    Every default is SUPPRESS: argparse subparsers parse into a fresh namespace
    and copy it back, so a real default here would clobber a flag given before
    the subcommand. Absent flags simply leave the attribute unset, which
    :func:`_resolve_log_level` reads with ``getattr`` fallbacks.
    """

    options = argparse.ArgumentParser(add_help=False)
    options.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="diagnostics on stderr: -v for INFO, -vv for DEBUG",
    )
    options.add_argument(
        "--log-level",
        choices=_LOG_LEVEL_CHOICES,
        default=argparse.SUPPRESS,
        help="explicit diagnostic level (overrides -v)"
    )
    options.add_argument(
        "--log-format",
        choices=("text", "json"),
        default=argparse.SUPPRESS,
        help="diagnostic format: terse key=value text or JSON lines"
    )
    options.add_argument(
        "--log-redact",
        action="store_true",
        default=argparse.SUPPRESS,
        help="mask peer addresses / ids in diagnostics so a log is shareable"
    )
    options.add_argument(
        "--log-run-id",
        action="store_true",
        default=argparse.SUPPRESS,
        help="stamp a per-invocation run id onto every diagnostic record"
    )
    options.add_argument(
        "--log-file",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="also write JSON-lines diagnostics to a rotating file at PATH"
    )
    return options


def _env_flag(name: str) -> bool:
    """A truthy environment variable (1/true/yes/on), case-insensitive."""

    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _dependency_version(package: str) -> str:
    """Installed version of a dependency, or ``"unknown"`` if absent."""

    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _resolve_log_level(args: argparse.Namespace) -> int:
    """Flag beats env beats the silent default."""

    explicit = getattr(args, "log_level", None)
    if explicit is not None:
        return getattr(logging, explicit)
    verbose = getattr(args, "verbose", 0)
    if verbose >= 2:
        return logging.DEBUG
    if verbose == 1:
        return logging.INFO
    env_level = os.environ.get(LOG_LEVEL_ENV_VAR, "").upper()
    if env_level in _LOG_LEVEL_CHOICES:
        return getattr(logging, env_level)
    return DEFAULT_LOG_LEVEL


def _configure_logging(
        level: int = DEFAULT_LOG_LEVEL,
        log_format: str = "text",
        *,
        redact: bool = False,
        run_id: str | None = None,
        log_file: str | None = None,
) -> None:
    """Attach the diagnostics handlers to the ``app`` logger hierarchy.

    Configuration belongs to the entry point: modules only emit through
    ``logging.getLogger(__name__)``. Handlers go on the ``app`` root with
    propagation off, so records never reach the global root (or its lastResort
    handler). Re-invocation replaces the previous handlers, so repeated
    in-process ``main()`` calls never stack handlers or hold a stale stream.

    A stderr handler is always attached; when ``log_file`` is given a rotating
    JSON-lines file handler is added alongside it for durable diagnostics.
    """

    app_logger = logging.getLogger("app")
    app_logger.propagate = False
    for handler in list(app_logger.handlers):
        if not isinstance(handler, logging.NullHandler):
            app_logger.removeHandler(handler)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_log_formatter(log_format))
    _attach_filters(stderr_handler, redact=redact, run_id=run_id)
    app_logger.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUPS
        )
        file_handler.setFormatter(_JsonFormatter())
        _attach_filters(file_handler, redact=redact, run_id=run_id)
        app_logger.addHandler(file_handler)

    app_logger.setLevel(level)


def _log_formatter(log_format: str) -> logging.Formatter:
    if log_format == "json":
        return _JsonFormatter()
    return _KeyValueFormatter("%(levelname)s %(name)s: %(message)s")


def _attach_filters(handler: logging.Handler, *, redact: bool, run_id: str | None) -> None:
    """One fresh filter set per handler (sampling state must not be shared)."""

    handler.addFilter(_SamplingFilter(LOG_BLOCK_SAMPLE_RATE))
    if run_id is not None:
        handler.addFilter(_RunIdFilter(run_id))
    if redact:
        handler.addFilter(_RedactionFilter())


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    redact = getattr(args, "log_redact", False) or _env_flag(LOG_REDACT_ENV_VAR)
    log_file = getattr(args, "log_file", None) or os.environ.get(LOG_FILE_ENV_VAR) or None
    level = _resolve_log_level(args)
    if log_file and level >= DEFAULT_LOG_LEVEL:
        level = logging.INFO
    run_id = uuid.uuid4().hex[:8] if (getattr(args, "log_run_id", False) or log_file) else None
    _configure_logging(
        level,
        getattr(args, "log_format", "text"),
        redact=redact,
        run_id=run_id,
        log_file=log_file
    )
    logger.debug(
        "client starting",
        extra={
            "ctx": {
                "version": __version__,
                "python": platform.python_version(),
                "bencode_py": _dependency_version("bencode.py"),
                "command": args.command
            }
        }
    )
    reporter = CompositeReporter(StdoutReporter(), LoggingReporter())
    client = TorrentClient(reporter=reporter)
    try:
        args.handler(args, client)
    except BitTorrentError as exc:
        ctx = {"command": args.command, "error_type": type(exc).__name__ }
        if exc.__cause__ is not None:
            ctx["cause"] = repr(exc.__cause__)
        logger.error(
            "command failed",
            extra={"ctx": ctx},
            exc_info=logger.isEnabledFor(logging.DEBUG)
        )
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        logger.debug("interrupted by user", extra={"ctx": {"command": args.command}})
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)


def _decode(args: argparse.Namespace, client: TorrentClient) -> None:
    print(json.dumps(_jsonable(client.decode(args.value))))


def _jsonable(value):
    """Make a decoded bencode value JSON-serializable (bytes -> str).

    Bencode strings are arbitrary bytes, not text, so decode leniently: a
    binary value (e.g. ``pieces``) must not crash ``decode`` with an uncaught
    UnicodeDecodeError, which - not being a BitTorrentError - would escape the
    CLI error boundary as a traceback. Invalid bytes become U+FFFD.
    """

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {_jsonable(key): _jsonable(val) for key, val in value.items()}
    return value


def _info(args: argparse.Namespace, client: TorrentClient) -> None:
    _print_metadata(client.read_metadata(args.torrent))


def _peers(args: argparse.Namespace, client: TorrentClient) -> None:
    peers = client.get_peers(client.read_metadata(args.torrent))
    print("\n".join(str(peer) for peer in peers))


def _handshake(args: argparse.Namespace, client: TorrentClient) -> None:
    peer = Peer.from_address(args.peer) if args.peer else None
    peer_id = client.handshake(client.read_metadata(args.torrent), peer)
    print(f"Peer ID: {peer_id}")


def _download_piece(args: argparse.Namespace, client: TorrentClient) -> None:
    meta = client.read_metadata(args.torrent)
    client.download_piece_to_file(meta, args.index, args.output)
    print(f"piece downloaded to {args.output}")


def _download(args: argparse.Namespace, client: TorrentClient) -> None:
    client.download_to_file(client.read_metadata(args.torrent), args.output)
    print("torrent file download completed.")


def _magnet_parse(args: argparse.Namespace, client: TorrentClient) -> None:
    magnet = client.parse_magnet(args.link)
    print(f"Tracker URL: {magnet.tracker_url}")
    print(f"Info Hash: {magnet.info_hash_hex}")


def _magnet_handshake(args: argparse.Namespace, client: TorrentClient) -> None:
    peer_id, extension_id = client.magnet_handshake(client.parse_magnet(args.link))
    print(f"Peer ID: {peer_id}")
    print(f"Peer Metadata Extension ID: {extension_id}")


def _magnet_info(args: argparse.Namespace, client: TorrentClient) -> None:
    _print_metadata(client.magnet_metadata(client.parse_magnet(args.link)))


def _magnet_download_piece(args: argparse.Namespace, client: TorrentClient) -> None:
    magnet = client.parse_magnet(args.link)
    client.magnet_download_piece_to_file(magnet, args.index, args.output)
    print(f"magnet piece downloaded to {args.output}")


def _magnet_download(args: argparse.Namespace, client: TorrentClient) -> None:
    client.magnet_download_to_file(client.parse_magnet(args.link), args.output)
    print("torrent magnet file download completed.")


def _selftest(args: argparse.Namespace, client: TorrentClient) -> None:
    """Diagnostic mode: report build provenance and run reachability checks.

    Prints version provenance, then PASS/FAIL
    lines for each check, exiting non-zero if any fails. A given ``source``
    (``.torrent``/magnet) adds a DNS-resolution check; ``--check-tracker`` adds
    a live announce for a ``.torrent``.
    """

    print(f"client: {__version__}")
    print(f"python: {platform.python_version()}")
    print(f"bencode.py: {_dependency_version('bencode.py')}")
    checks: list[tuple[str, bool]] = [
        ("python >= 3.8", sys.version_info >= (3, 8)),
        ("bencodepy importable", _can_import("bencodepy"))
    ]
    if args.source:
        checks.append(_check_source(client, args.source, args.check_tracker))
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    if not all(ok for _, ok in checks):
        raise SystemExit(1)


def _can_import(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False


def _check_source(client: TorrentClient, source: str, check_tracker: bool) -> tuple[str, bool]:
    meta = None
    try:
        if source.startswith("magnet:"):
            tracker_url = client.parse_magnet(source).tracker_url
        else:
            meta = client.read_metadata(source)
            tracker_url = meta.tracker_url
    except BitTorrentError as exc:
        return f"parse source ({exc})", False
    host = urlsplit(tracker_url).hostname
    try:
        socket.getaddrinfo(host, None)
    except OSError as exc:
        return f"resolve {host} ({exc})", False
    if check_tracker and meta is not None:
        try:
            peers = client.get_peers(meta)
            return f"announce {host} ({len(peers)} peers)", True
        except BitTorrentError as exc:
            return f"announce {host} ({exc})", False
    return f"resolve {host}", True


def _print_metadata(meta: TorrentMetadata) -> None:
    print(f"Tracker URL: {meta.tracker_url}")
    print(f"Length: {meta.length}")
    print(f"Info Hash: {meta.info_hash_hex}")
    print(f"Piece Length: {meta.piece_length}")
    print("Piece Hashes: ")
    print("\n".join(meta.piece_hashes_hex))


def _build_parser() -> argparse.ArgumentParser:
    logging_options = _logging_options()
    parser = argparse.ArgumentParser(prog="app.main", parents=[logging_options])
    subcommands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler) -> argparse.ArgumentParser:
        sub = subcommands.add_parser(name, parents=[logging_options])
        sub.set_defaults(handler=handler)
        return sub

    add("decode", _decode).add_argument("value")
    add("info", _info).add_argument("torrent")
    add("peers", _peers).add_argument("torrent")

    handshake = add("handshake", _handshake)
    handshake.add_argument("torrent")
    handshake.add_argument("peer", nargs="?")

    download_piece = add("download_piece", _download_piece)
    download_piece.add_argument("-o", "--output", required=True)
    download_piece.add_argument("torrent")
    download_piece.add_argument("index", type=int)

    download = add("download", _download)
    download.add_argument("-o", "--output", required=True)
    download.add_argument("torrent")

    add("magnet_parse", _magnet_parse).add_argument("link")
    add("magnet_handshake", _magnet_handshake).add_argument("link")
    add("magnet_info", _magnet_info).add_argument("link")

    magnet_piece = add("magnet_download_piece", _magnet_download_piece)
    magnet_piece.add_argument("-o", "--output", required=True)
    magnet_piece.add_argument("link")
    magnet_piece.add_argument("index", type=int)

    magnet_download = add("magnet_download", _magnet_download)
    magnet_download.add_argument("-o", "--output", required=True)
    magnet_download.add_argument("link")

    selftest = add("selftest", _selftest)
    selftest.add_argument("source", nargs="?")
    selftest.add_argument("--check-tracker", action="store_true")

    return parser
