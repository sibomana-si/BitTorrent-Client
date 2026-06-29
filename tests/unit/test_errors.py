"""Unit tests for the error contract in app/errors.py"""

import pytest

from app.errors import (
    BencodeError,
    BitTorrentError,
    InvalidMagnetError,
    InvalidTorrentError,
    PeerProtocolError,
    TrackerError,
)

LEAF_ERRORS = [
    BencodeError,
    InvalidTorrentError,
    InvalidMagnetError,
    TrackerError,
    PeerProtocolError,
]


@pytest.mark.parametrize("error_type", LEAF_ERRORS)
def test_every_error_is_a_bittorrent_error(error_type):
    # The CLI boundary catches the base class; every operational error must be catchable through it.
    with pytest.raises(BitTorrentError):
        raise error_type("boom")


@pytest.mark.parametrize("error_type", LEAF_ERRORS)
def test_message_is_preserved(error_type):
    assert str(error_type("something failed")) == "something failed"


def test_leaf_errors_are_distinct():
    # Catching one leaf type must not swallow another.
    for error_type in LEAF_ERRORS:
        siblings = [other for other in LEAF_ERRORS if other is not error_type]
        for sibling in siblings:
            assert not issubclass(error_type, sibling)
