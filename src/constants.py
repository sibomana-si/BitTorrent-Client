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

# Socket deadlines (seconds): a peer that stalls must not hang the client.
CONNECT_TIMEOUT = 5 # establishing the TCP connection
RECV_TIMEOUT = 30 # waiting for a single message from a connected peer

# How many block requests to keep in flight at once (pipelining depth).
PIPELINE_DEPTH = 4

# Fixed handshake protocol string and its companion reserved-bytes field.
PROTOCOL_NAME = b"BitTorrent protocol"

# Reserved bytes advertising support for the extension protocol (bit 20 set).
MAGNET_RESERVED = (1 << 20).to_bytes(8, "big")

# Placeholder "left" value sent to the tracker before metadata is known.
MAGNET_STUB_LENGTH = 999

# Peer wire message ids used by this client.
MSG_INTERESTED = 2
MSG_REQUEST = 6
MSG_EXTENSION = 20
