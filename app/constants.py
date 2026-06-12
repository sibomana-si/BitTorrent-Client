"""Protocol-level constants shared across the client.

Keeping these in one place avoids magic numbers scattered through the socket
and tracker code, and documents the few values the BitTorrent spec fixes.
"""

# Identifier this client announces to trackers and peers (must be 20 bytes).
PEER_ID = b"00112233445566998877"

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

# Socket deadlines (seconds): a peer that stalls must not hang the client.
CONNECT_TIMEOUT = 5 # establishing the TCP connection
RECV_TIMEOUT = 30 # waiting for a single message from a connected peer

# Bounded retry with exponential backoff for transient connection failures.
CONNECT_RETRIES = 3  # total attempts to reach the peer set before giving up
RETRY_BASE_DELAY = 0.5  # seconds; doubled (plus jitter) between attempts

# How many block requests to keep in flight at once (pipelining depth).
PIPELINE_DEPTH = 4

# Fixed handshake protocol string and its companion reserved-bytes field.
PROTOCOL_NAME = b"BitTorrent protocol"

# Reserved bytes advertising support for the extension protocol (bit 20 set).
MAGNET_RESERVED = (1 << 20).to_bytes(8, "big")

# Placeholder "left" value sent to the tracker before metadata is known.
MAGNET_STUB_LENGTH = 999

# Tracker URLs come from an untrusted .torrent/magnet, so only plain web schemes
# are honoured (blocks file://, gopher://, ftp:// and similar SSRF vectors).
ALLOWED_SCHEMES = ("http", "https")

# How many tracker redirects to follow before giving up. Each hop is re-checked
# against the SSRF guard, so this only bounds a redirect loop / chain.
MAX_REDIRECTS = 5

# Peer wire message ids used by this client.
MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_REQUEST = 6
MSG_PIECE = 7
MSG_EXTENSION = 20
