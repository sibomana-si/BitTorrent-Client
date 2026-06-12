"""A BitTorrent client: bencode, trackers, the peer protocol and magnet links."""

import logging

# Library convention: a NullHandler on the package root logger so that, when the
# client is used as a library with no logging configured, WARNING+ records never
# fall through to logging's lastResort stderr handler. The CLI entry point
# (app.cli) attaches the real stderr handler.
logging.getLogger("app").addHandler(logging.NullHandler())
