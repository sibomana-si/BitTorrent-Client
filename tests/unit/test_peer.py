"""Unit tests for the peer wire protocol in app/peer.py.

Socket-level behavior is driven through ``ScriptedSocket`` (an in-memory fake
injected as ``conn._sock``); only the connect() tests use real local sockets.
"""

import hashlib
import socket
from typing import cast

import bencodepy
import pytest

from app.constants import (
    BLOCK_SIZE,
    MAGNET_RESERVED,
    MSG_PIECE,
    MSG_UNCHOKE,
    PROTOCOL_NAME,
)
from app.errors import PeerProtocolError
from app.models import Peer
from app.peer import PeerConnection, _decode_leading

from tests.conftest import (
    CLIENT_PEER_ID,
    ListReporter,
    ScriptedSocket,
    build_metadata,
    frame,
    handshake_bytes,
)

INFO_HASH = hashlib.sha1(b"some torrent").digest()
REMOTE_PEER_ID = b"-FAKEPEER-0123456789"


def scripted_connection(script: bytes = b"", **kwargs) -> PeerConnection:
    conn = PeerConnection(CLIENT_PEER_ID, reporter=ListReporter())
    conn._sock = cast(socket.socket, ScriptedSocket(script, **kwargs))
    return conn


# -- pure helpers -------------------------------------------------------------


class TestBlockRequests:
    def test_full_piece_smaller_than_one_block(self):
        meta = build_metadata(b"x" * 40, piece_length=16)
        assert PeerConnection._block_requests(meta, 0) == [(0, 0, 16)]

    def test_short_last_piece(self):
        meta = build_metadata(b"x" * 40, piece_length=16)  # pieces: 16, 16, 8
        assert PeerConnection._block_requests(meta, 2) == [(2, 0, 8)]

    def test_exact_multiple_has_no_short_piece(self):
        meta = build_metadata(b"x" * 32, piece_length=16)
        assert PeerConnection._block_requests(meta, 1) == [(1, 0, 16)]

    def test_piece_is_split_into_16kib_blocks(self):
        size = BLOCK_SIZE * 2 + 100
        meta = build_metadata(b"x" * size, piece_length=size)
        assert PeerConnection._block_requests(meta, 0) == [
            (0, 0, BLOCK_SIZE),
            (0, BLOCK_SIZE, BLOCK_SIZE),
            (0, 2 * BLOCK_SIZE, 100),
        ]


def test_request_message_layout():
    message = PeerConnection._request_message((7, 16384, 1024))
    assert message == (
        (13).to_bytes(4, "big")
        + (6).to_bytes(1, "big")
        + (7).to_bytes(4, "big")
        + (16384).to_bytes(4, "big")
        + (1024).to_bytes(4, "big")
    )


def test_decode_leading_ignores_trailing_bytes():
    head = {b"msg_type": 1, b"piece": 0, b"total_size": 8}
    buf = bencodepy.encode({"msg_type": 1, "piece": 0, "total_size": 8}) + b"RAWINFO!"
    assert _decode_leading(buf) == head


# -- handshake ----------------------------------------------------------------


class TestHandshake:
    def test_success_records_peer_identity(self):
        conn = scripted_connection(handshake_bytes(INFO_HASH, REMOTE_PEER_ID))
        conn.handshake(INFO_HASH)
        assert conn.remote_peer_id == REMOTE_PEER_ID.hex()
        assert conn.reserved_bytes == bytes(8)

    def test_sends_a_spec_compliant_handshake(self):
        conn = scripted_connection(handshake_bytes(INFO_HASH, REMOTE_PEER_ID))
        conn.handshake(INFO_HASH)
        assert cast(ScriptedSocket, conn._sock).sent[0] == (bytes([19]) + PROTOCOL_NAME + bytes(8)
                                                            + INFO_HASH + CLIENT_PEER_ID)

    def test_magnet_handshake_advertises_extension_support(self):
        conn = scripted_connection(handshake_bytes(INFO_HASH, REMOTE_PEER_ID, reserved=MAGNET_RESERVED))
        conn.handshake(INFO_HASH, magnet=True)
        sent = cast(ScriptedSocket, conn._sock).sent[0]
        assert sent[20:28] == MAGNET_RESERVED  # bit 20 set
        assert conn.reserved_bytes == MAGNET_RESERVED

    def test_wrong_protocol_name_is_rejected(self):
        # Same length, different bytes - the peer is not speaking BitTorrent.
        bogus = b"Bittorrent protocol"
        conn = scripted_connection(handshake_bytes(INFO_HASH, REMOTE_PEER_ID, protocol=bogus))
        with pytest.raises(PeerProtocolError, match="handshake protocol"):
            conn.handshake(INFO_HASH)

    def test_info_hash_echo_mismatch_is_rejected(self):
        conn = scripted_connection(handshake_bytes(b"\x11" * 20, REMOTE_PEER_ID))
        with pytest.raises(PeerProtocolError, match="info hash mismatch"):
            conn.handshake(INFO_HASH)


# -- framing and receive loop -------------------------------------------------


class TestReceive:
    def test_recv_message_returns_header_and_body(self):
        conn = scripted_connection(frame(MSG_UNCHOKE))
        assert conn.recv_message() == frame(MSG_UNCHOKE)

    def test_oversized_message_announcement_is_rejected(self):
        conn = scripted_connection((2**20 + 1).to_bytes(4, "big"))
        with pytest.raises(PeerProtocolError, match="oversized"):
            conn.recv_message()

    def test_recv_exact_reassembles_short_reads(self):
        conn = scripted_connection(b"abcdef", chunk=2)
        assert conn._recv_exact(6) == b"abcdef"

    def test_closed_connection_is_reported(self):
        conn = scripted_connection(b"")
        with pytest.raises(PeerProtocolError, match="closed the connection"):
            conn._recv_exact(4)

    def test_socket_error_is_wrapped(self):
        conn = scripted_connection(recv_error=socket.timeout("timed out"))
        with pytest.raises(PeerProtocolError, match="read failed"):
            conn._recv_exact(4)

    def test_recv_until_skips_unrelated_frames(self):
        script = (
            frame(None)                            # keep-alive
            + frame(4, (3).to_bytes(4, "big"))     # have
            + frame(5, b"\xff")                    # bitfield
            + frame(MSG_UNCHOKE)
        )
        conn = scripted_connection(script)
        assert conn._recv_until(MSG_UNCHOKE) == frame(MSG_UNCHOKE)

    def test_choke_while_waiting_is_a_protocol_failure(self):
        conn = scripted_connection(frame(0))  # choke
        with pytest.raises(PeerProtocolError, match="choked"):
            conn._recv_until(MSG_UNCHOKE)

    def test_send_interested_waits_through_bitfield_for_unchoke(self):
        conn = scripted_connection(frame(5, b"\xff") + frame(MSG_UNCHOKE))
        conn.send_interested()
        assert cast(ScriptedSocket, conn._sock).sent == [(1).to_bytes(4, "big")
                                                         + (2).to_bytes(1, "big")]


# -- metadata extension (BEP 9) -----------------------------------------------


class TestExtensionHandshake:
    def test_peer_without_extension_support_is_rejected(self):
        conn = scripted_connection()
        conn.reserved_bytes = bytes(8)  # no bits set
        with pytest.raises(PeerProtocolError, match="metadata extension"):
            conn.extension_handshake()

    def test_negotiates_the_ut_metadata_id(self):
        payload = bencodepy.encode({"m": {"ut_metadata": 7}})
        conn = scripted_connection(frame(20, bytes([0]) + payload))
        conn.reserved_bytes = MAGNET_RESERVED
        assert conn.extension_handshake() == 7
        assert conn.metadata_extension_id == 7

    def test_response_without_ut_metadata_is_rejected(self):
        payload = bencodepy.encode({"m": {}})
        conn = scripted_connection(frame(20, bytes([0]) + payload))
        conn.reserved_bytes = MAGNET_RESERVED
        with pytest.raises(PeerProtocolError, match="extension handshake"):
            conn.extension_handshake()


class TestFetchMetadata:
    RAW_INFO = bencodepy.encode({"length": 16, "name": "x", "piece length": 16, "pieces": b"\x01" * 20})

    def _data_message(self, total_size) -> bytes:
        head = {"msg_type": 1, "piece": 0}
        if total_size is not None:
            head["total_size"] = total_size
        return frame(20, bytes([1]) + bencodepy.encode(head) + self.RAW_INFO)

    def test_returns_the_raw_info_bytes(self):
        conn = scripted_connection(self._data_message(len(self.RAW_INFO)))
        assert conn.fetch_metadata(extension_id=3) == self.RAW_INFO

    @pytest.mark.parametrize(
        "total_size",
        [
            pytest.param(None, id="missing"),
            pytest.param(0, id="zero"),
            pytest.param(-5, id="negative"),
            pytest.param(10**6, id="larger-than-received"),
        ],
    )
    def test_invalid_total_size_is_rejected(self, total_size):
        # (A total_size over MAX_METADATA_BYTES cannot be reached through
        # recv_message: the 1 MiB frame cap rejects the message first.)
        conn = scripted_connection(self._data_message(total_size))
        with pytest.raises(PeerProtocolError, match="invalid metadata size"):
            conn.fetch_metadata(extension_id=3)


# -- piece download -----------------------------------------------------------


def piece_frame(index: int, begin: int, block: bytes) -> bytes:
    return frame(MSG_PIECE, index.to_bytes(4, "big") + begin.to_bytes(4, "big") + block)


class TestDownloadPiece:
    def test_single_block_piece_is_verified_and_returned(self):
        content = bytes(range(20))
        meta = build_metadata(content, piece_length=20)
        conn = scripted_connection(piece_frame(0, 0, content))
        assert conn.download_piece(meta, 0) == content

    def test_out_of_order_blocks_are_reassembled(self):
        content = bytes((i * 7) % 256 for i in range(BLOCK_SIZE * 2))
        meta = build_metadata(content, piece_length=BLOCK_SIZE * 2)
        # Both blocks fit one pipeline batch; deliver them in reverse order.
        script = (piece_frame(0, BLOCK_SIZE, content[BLOCK_SIZE:])
                  + piece_frame(0, 0, content[:BLOCK_SIZE]))
        conn = scripted_connection(script)
        assert conn.download_piece(meta, 0) == content

    def test_block_for_the_wrong_piece_is_rejected(self):
        content = bytes(range(20))
        meta = build_metadata(content, piece_length=20)
        conn = scripted_connection(piece_frame(5, 0, content))
        with pytest.raises(PeerProtocolError, match="unexpected block"):
            conn.download_piece(meta, 0)

    def test_block_at_an_unrequested_offset_is_rejected(self):
        content = bytes(range(20))
        meta = build_metadata(content, piece_length=20)
        conn = scripted_connection(piece_frame(0, 999, content))
        with pytest.raises(PeerProtocolError, match="unexpected block"):
            conn.download_piece(meta, 0)

    def test_short_block_is_rejected(self):
        content = bytes(range(20))
        meta = build_metadata(content, piece_length=20)
        conn = scripted_connection(piece_frame(0, 0, content[:10]))
        with pytest.raises(PeerProtocolError, match="short block"):
            conn.download_piece(meta, 0)

    def test_hash_mismatch_is_rejected(self):
        content = bytes(range(20))
        meta = build_metadata(content, piece_length=20)
        wrong = bytes(20)  # right length, wrong bytes
        conn = scripted_connection(piece_frame(0, 0, wrong))
        with pytest.raises(PeerProtocolError, match="Invalid piece hash"):
            conn.download_piece(meta, 0)

    def test_every_block_is_requested_exactly_once(self):
        size = BLOCK_SIZE * 5  # 5 blocks: an initial window of 4, then 1 more
        content = bytes((i * 3) % 256 for i in range(size))
        meta = build_metadata(content, piece_length=size)
        script = b"".join(
            piece_frame(0, begin, content[begin : begin + BLOCK_SIZE])
            for begin in range(0, size, BLOCK_SIZE)
        )
        conn = scripted_connection(script)
        assert conn.download_piece(meta, 0) == content
        # Every block is requested exactly once; sends may be coalesced, so
        # parse request frames out of the concatenated stream.
        stream = b"".join(cast(ScriptedSocket, conn._sock).sent)
        begins = []
        offset = 0
        while offset < len(stream):
            length = int.from_bytes(stream[offset : offset + 4], "big")
            assert stream[offset + 4] == 6  # request
            begins.append(int.from_bytes(stream[offset + 9 : offset + 13], "big"))
            offset += 4 + length
        assert begins == [begin for begin in range(0, size, BLOCK_SIZE)]


# -- connection lifecycle -----------------------------------------------------


def _refused_address() -> Peer:
    """An address on localhost that nothing is listening on."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    _ip, port = probe.getsockname()
    probe.close()
    return Peer("127.0.0.1", port)


class TestConnect:
    def test_skips_unreachable_peer_and_uses_the_next(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        _ip, live_port = listener.getsockname()
        reporter = ListReporter()
        conn = PeerConnection(CLIENT_PEER_ID, reporter=reporter)
        try:
            conn.connect([_refused_address(), Peer("127.0.0.1", live_port)])
            assert reporter.lines == [f"connected to 127.0.0.1:{live_port}"]
        finally:
            conn.close()
            listener.close()

    def test_all_peers_unreachable_raises(self):
        reporter = ListReporter()
        conn = PeerConnection(CLIENT_PEER_ID, reporter=reporter)
        with pytest.raises(PeerProtocolError, match="failed to connect"):
            conn.connect([_refused_address(), _refused_address()])
        assert reporter.lines == ["failed to connect to all peers!"]

    def test_empty_peer_list_raises(self):
        conn = PeerConnection(CLIENT_PEER_ID)
        with pytest.raises(PeerProtocolError, match="failed to connect"):
            conn.connect([])


class TestLifecycle:
    def test_socket_property_requires_a_connection(self):
        with pytest.raises(RuntimeError, match="Not connected"):
            PeerConnection(CLIENT_PEER_ID)._socket

    def test_context_manager_closes_the_socket(self):
        sock = ScriptedSocket()
        with PeerConnection(CLIENT_PEER_ID) as conn:
            conn._sock = cast(socket.socket, sock)
        assert sock.closed is True
        assert conn._sock is None

    def test_close_is_idempotent(self):
        conn = PeerConnection(CLIENT_PEER_ID)
        conn._sock = cast(socket.socket, ScriptedSocket())
        conn.close()
        conn.close()  # second close must not raise
