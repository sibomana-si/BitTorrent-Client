"""Unit tests for tunables in app/constants.py"""

import pytest

from app.constants import (
    PEER_ID,
    PEER_ID_ENV_VAR,
    _PEER_ID_PREFIX,
    _resolve_peer_id,
)


class TestPeerId:
    def test_module_peer_id_is_twenty_bytes(self):
        assert isinstance(PEER_ID, bytes)
        assert len(PEER_ID) == 20

    def test_generated_id_is_random_and_prefixed(self, monkeypatch):
        monkeypatch.delenv(PEER_ID_ENV_VAR, raising=False)
        first = _resolve_peer_id()
        second = _resolve_peer_id()
        assert len(first) == len(second) == 20
        assert first.startswith(_PEER_ID_PREFIX)
        assert first != second  # 12 random bytes => effectively never equal

    def test_env_override_is_honoured(self, monkeypatch):
        monkeypatch.setenv(PEER_ID_ENV_VAR, "ABCDEFGHIJ0123456789")  # 20 bytes
        assert _resolve_peer_id() == b"ABCDEFGHIJ0123456789"

    @pytest.mark.parametrize("value", ["too-short", "this-id-is-far-too-long-to-fit"])
    def test_wrong_length_override_is_rejected(self, monkeypatch, value):
        monkeypatch.setenv(PEER_ID_ENV_VAR, value)
        with pytest.raises(ValueError, match="exactly 20 bytes"):
            _resolve_peer_id()
