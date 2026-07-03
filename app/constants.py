"""Protocol-level constants shared across the client.

Keeping these in one place avoids magic numbers scattered through the socket
and tracker code, and documents the few values the BitTorrent spec fixes.
"""

import logging
import os
import secrets


# Default level for the stderr diagnostic logger. Set above CRITICAL - fully
# silent - rather than the conventional WARNING, because the
# contract requires byte-identical stdout AND stderr when no verbosity option is
# given, including on error paths (where the CLI boundary logs at ERROR).
# Diagnostics are opted into with -v / -vv / --log-level.
DEFAULT_LOG_LEVEL = logging.CRITICAL + 10

# Environment fallback for the diagnostics level: consulted
# only when no -v / --log-level flag is given on the command line.
LOG_LEVEL_ENV_VAR = "BITTORRENT_LOG_LEVEL"

# Per-block DEBUG events number in the thousands per download; emit only 1 in
# every N of them so a verbose log stays representative without flooding.
LOG_BLOCK_SAMPLE_RATE = 64

# Opt-in switch (flag or env) to mask peer addresses / ids in diagnostics, so a
# verbose log excerpt can be shared without leaking who the client talked to.
LOG_REDACT_ENV_VAR = "BITTORRENT_LOG_REDACT"

# Opt-in durable diagnostics: when a path is given (flag or env), JSON-lines
# records are also written to a rotating file, bounded by these limits.
LOG_FILE_ENV_VAR = "BITTORRENT_LOG_FILE"
LOG_FILE_MAX_BYTES = 2**20 # 1 MiB per file before rotation
LOG_FILE_BACKUPS = 3

# Identifier this client announces to trackers and peers (must be 20 bytes).
# Pin a specific id via this env var (e.g. for reproducible captures or tests).
PEER_ID_ENV_VAR = "BITTORRENT_PEER_ID" # b"00112233445566998877"

# Azureus-style 8-byte prefix: '-' + 2-char client id 'CC' + 4-digit version +
# '-'. The remaining 12 bytes are random, so the id is unique per run.
_PEER_ID_PREFIX = b"-CC0100-"


def _resolve_peer_id() -> bytes:
    """The 20-byte peer id for this process, fixed for the whole run.

    A fixed id is fingerprintable, can collide in a swarm, and is penalised by
    some trackers, so a fresh random id is generated each run. ``PEER_ID_ENV_VAR``
    pins it when set (must encode to exactly 20 bytes).
    """

    override = os.getenv(PEER_ID_ENV_VAR)
    if override is not None:
        encoded = override.encode()
        if len(encoded) != 20:
            raise ValueError(f"{PEER_ID_ENV_VAR} must be exactly 20 bytes, got {len(encoded)}")
        return encoded
    peer_id = _PEER_ID_PREFIX + secrets.token_bytes(20 - len(_PEER_ID_PREFIX))
    assert len(peer_id) == 20
    return peer_id


PEER_ID = _resolve_peer_id()

# Port we claim to listen on when announcing to a tracker.
TRACKER_PORT = 6881

# Peers serve pieces in blocks of at most 16 KiB.
BLOCK_SIZE = 2**14

# Upper bound on the metadata blob (BEP 9) a peer may claim to send, so a hostile
# peer cannot drive a huge allocation via the advertised ``total_size``.
MAX_METADATA_BYTES = 2**20

# Upper bound on a torrent's declared piece length. Real torrents top out around
# a few tens of MiB; a larger value in untrusted metadata is rejected so it can't
# drive a huge per-piece allocation.
MAX_PIECE_LENGTH = 2**27 # 128 MiB

# Ceiling on a whole download. A crafted torrent/magnet cannot request a write
# larger than this, so it cannot be used to exhaust the disk.
MAX_TORRENT_LENGTH = 2**33 # 8 GiB

# Socket deadlines (seconds): a peer that stalls must not hang the client.
CONNECT_TIMEOUT = 5 # establishing the TCP connection
RECV_TIMEOUT = 30 # waiting for a single message from a connected peer

# Bounded retry with exponential backoff for transient connection failures.
CONNECT_RETRIES = 3  # total attempts to reach the peer set before giving up
RETRY_BASE_DELAY = 0.5  # seconds; doubled (plus jitter) between attempts

# How many block requests to keep in flight at once (pipelining depth).
PIPELINE_DEPTH = 16

# Opt-in cap on concurrent peer connections for a full download. Unset or 1
# keeps the original single-connection sequential behavior (and its exact
# output); higher values stripe pieces across that many peers.
MAX_PEERS_ENV_VAR = "BITTORRENT_MAX_PEERS"

# Fixed handshake protocol string and its companion reserved-bytes field.
PROTOCOL_NAME = b"BitTorrent protocol"

# Reserved bytes advertising support for the extension protocol (bit 20 set).
MAGNET_RESERVED = (1 << 20).to_bytes(8, "big")

# Placeholder "left" value sent to the tracker before metadata is known.
MAGNET_STUB_LENGTH = 999

# Tracker URLs come from an untrusted .torrent/magnet, so only plain web schemes
# are honoured (blocks file://, gopher://, ftp:// and similar SSRF vectors).
ALLOWED_SCHEMES = ("http", "https")

# Tracker-supplied peer addresses are equally untrusted: by default they are run
# through the same SSRF guard as the tracker URL, so a hostile tracker cannot
# point the client at loopback / link-local / private hosts. Set this (flag-free,
# env only) when the swarm legitimately lives on loopback/LAN - including the
# test harness, whose FakePeer binds 127.0.0.1.
ALLOW_PRIVATE_PEERS_ENV_VAR = "BITTORRENT_ALLOW_PRIVATE_PEERS"

# How many tracker redirects to follow before giving up. Each hop is re-checked
# against the SSRF guard, so this only bounds a redirect loop / chain.
MAX_REDIRECTS = 5

# Upper bound on a tracker response body. Compact peer lists are tiny, so this is
# generous; it stops a hostile tracker from streaming unbounded data into memory.
MAX_TRACKER_RESPONSE_BYTES = 2**18 # 256 KiB

# Peer wire message ids used by this client.
MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_REQUEST = 6
MSG_PIECE = 7
MSG_EXTENSION = 20
