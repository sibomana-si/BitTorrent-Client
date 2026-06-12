"""Command-line interface: argument parsing, dispatch, and all output.

Every command maps to a small handler that calls into :class:`TorrentClient`
and prints the result. This is the only layer that touches ``argv`` or writes
to stdout for presentation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from app.client import TorrentClient
from app.constants import DEFAULT_LOG_LEVEL, LOG_LEVEL_ENV_VAR
from app.errors import BitTorrentError
from app.models import Peer, TorrentMetadata


logger = logging.getLogger(__name__)

_LOG_LEVEL_CHOICES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class StdoutReporter:
    """Renders progress to stdout - the only place output belongs."""

    def report(self, message: str) -> None:
        print(message)


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

    return options


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


def _configure_logging(level: int = DEFAULT_LOG_LEVEL) -> None:
    """Attach the stderr diagnostics handler to the ``app`` logger hierarchy.

    Configuration belongs to the entry point: modules only emit through
    ``logging.getLogger(__name__)``. The handler goes on the ``app`` root with
    propagation off, so records never reach the global root (or its lastResort
    handler). Re-invocation replaces the previous handler, so repeated
    in-process ``main()`` calls never stack handlers or hold a stale stream.
    """

    app_logger = logging.getLogger("app")
    app_logger.propagate = False
    for handler in list(app_logger.handlers):
        if not isinstance(handler, logging.NullHandler):
            app_logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    app_logger.addHandler(handler)
    app_logger.setLevel(level)


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    _configure_logging(_resolve_log_level(args))
    client = TorrentClient(reporter=StdoutReporter())
    try:
        args.handler(args, client)
    except BitTorrentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)


def _decode(args: argparse.Namespace, client: TorrentClient) -> None:
    print(json.dumps(_jsonable(client.decode(args.value))))


def _jsonable(value):
    """Make a decoded bencode value JSON-serializable (bytes -> str)."""
    if isinstance(value, bytes):
        return value.decode()
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

    return parser
