"""End-to-end tests: every CLI command through app.cli.main(argv).

This is the exact code path ``python3 -m app.main`` runs (main.py only imports ``main``),
so these assert the full observable contract: byte-exact stdout (the CodeCrafters-graded surface),
stderr, exit codes and produced files. The tracker is stubbed in-process; peers are real local
``FakePeer`` servers.
"""

import hashlib
import json

import pytest

from app.cli import main

from tests.conftest import FakePeer


@pytest.fixture
def torrent(make_torrent):
    return make_torrent(length=40, piece_length=16)  # pieces: 16, 16, 8


def expected_info_output(torrent) -> str:
    lines = [
        f"Tracker URL: {torrent.tracker_url}",
        f"Length: {torrent.length}",
        f"Info Hash: {torrent.info_hash.hex()}",
        f"Piece Length: {torrent.piece_length}",
        "Piece Hashes: ",
        *[piece_hash.hex() for piece_hash in torrent.piece_hashes],
    ]
    return "\n".join(lines) + "\n"


def piece_progress_lines(torrent, index: int) -> list:
    digest = hashlib.sha1(torrent.piece(index)).hexdigest()
    return [
        f"downloading piece_index: {index} ...",
        f"valid piece hash: {digest} | {digest}",
    ]


class TestDecode:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("5:hello", '"hello"'),
            ("i42e", "42"),
            ("i-7e", "-7"),
            ("l5:helloi42ee", '["hello", 42]'),
            ("d3:foo3:bar5:helloi52ee", '{"foo": "bar", "hello": 52}'),
            ("le", "[]"),
            ("de", "{}"),
        ],
    )
    def test_decodes_to_json(self, capsys, value, expected):
        main(["decode", value])
        assert capsys.readouterr().out == expected + "\n"

    def test_output_is_valid_json(self, capsys):
        main(["decode", "d4:listl3:abci1ee3:numi9ee"])
        assert json.loads(capsys.readouterr().out) == {"list": ["abc", 1], "num": 9}

    def test_invalid_bencode_exits_1(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["decode", "i12"])
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.startswith("error: Invalid bencoded value")


class TestInfo:
    def test_prints_the_metadata(self, capsys, torrent):
        main(["info", torrent.path])
        assert capsys.readouterr().out == expected_info_output(torrent)

    def test_missing_file_exits_1(self, capsys, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            main(["info", str(tmp_path / "nope.torrent")])
        assert excinfo.value.code == 1
        assert capsys.readouterr().err.startswith("error: Cannot read torrent file")


class TestPeers:
    def test_prints_one_peer_per_line(self, capsys, torrent, stub_tracker):
        stub_tracker.set_peers([("1.2.3.4", 6881), ("5.6.7.8", 51413)])
        main(["peers", torrent.path])
        assert capsys.readouterr().out == "1.2.3.4:6881\n5.6.7.8:51413\n"


class TestHandshake:
    def test_with_an_explicit_peer(self, capsys, torrent):
        with FakePeer.for_torrent(torrent) as fake:
            main(["handshake", torrent.path, fake.address])
        assert capsys.readouterr().out == (
            f"connected to {fake.address}\n"
            f"Peer ID: {fake.peer_id.hex()}\n"
        )

    def test_falls_back_to_the_tracker_peer_list(self, capsys, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["handshake", torrent.path])
        assert f"Peer ID: {fake.peer_id.hex()}" in capsys.readouterr().out


class TestDownloadPiece:
    def test_downloads_and_reports(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "piece0.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["download_piece", "-o", str(output), torrent.path, "0"])
            expected = [
                f"connected to {fake.address}",
                *piece_progress_lines(torrent, 0),
                f"piece downloaded to {output}",
            ]
        assert capsys.readouterr().out == "\n".join(expected) + "\n"
        assert output.read_bytes() == torrent.piece(0)

    def test_downloads_the_short_last_piece(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "piece2.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["download_piece", "-o", str(output), torrent.path, "2"])
        assert output.read_bytes() == torrent.piece(2)
        assert len(torrent.piece(2)) == 8


class TestDownload:
    def test_downloads_the_whole_file_with_exact_output(
        self, capsys, torrent, stub_tracker, tmp_path
    ):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["download", "-o", str(output), torrent.path])
            expected = [
                f"connected to {fake.address}",
                f"downloading to {output} ...",
                "pieces to download: 3",
            ]
            for index in range(3):
                expected += piece_progress_lines(torrent, index)
                expected.append(
                    f"piece_{index} | {len(torrent.piece(index))} downloaded."
                )
            expected.append("torrent file download completed.")
        assert capsys.readouterr().out == "\n".join(expected) + "\n"
        assert output.read_bytes() == torrent.content

    def test_unreachable_tracker_exits_1(self, capsys, torrent, stub_tracker, tmp_path):
        import requests

        stub_tracker.queue.append(requests.ConnectionError("tracker down"))
        with pytest.raises(SystemExit) as excinfo:
            main(["download", "-o", str(tmp_path / "x.bin"), torrent.path])
        assert excinfo.value.code == 1
        assert capsys.readouterr().err.startswith("error: Tracker request failed")
        assert not (tmp_path / "x.bin").exists()


class TestMagnetParse:
    def test_prints_tracker_and_info_hash(self, capsys, torrent):
        main(["magnet_parse", torrent.magnet_link])
        assert capsys.readouterr().out == (
            f"Tracker URL: {torrent.tracker_url}\n"
            f"Info Hash: {torrent.info_hash.hex()}\n"
        )

    def test_invalid_link_exits_1(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["magnet_parse", "magnet:?tr=missing-the-hash"])
        assert excinfo.value.code == 1
        assert capsys.readouterr().err.startswith("error:")


class TestMagnetCommands:
    def test_magnet_handshake(self, capsys, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent, extension=True, ut_metadata_id=42) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["magnet_handshake", torrent.magnet_link])
        assert capsys.readouterr().out == (
            f"connected to {fake.address}\n"
            f"Peer ID: {fake.peer_id.hex()}\n"
            "Peer Metadata Extension ID: 42\n"
        )

    def test_magnet_info(self, capsys, torrent, stub_tracker):
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["magnet_info", torrent.magnet_link])
        out = capsys.readouterr().out
        assert out == f"connected to {fake.address}\n" + expected_info_output(torrent)

    def test_magnet_download_piece(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "piece1.bin"
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["magnet_download_piece", "-o", str(output), torrent.magnet_link, "1"])
        assert output.read_bytes() == torrent.piece(1)
        assert capsys.readouterr().out.endswith(f"magnet piece downloaded to {output}\n")

    def test_magnet_download(self, capsys, torrent, stub_tracker, tmp_path):
        output = tmp_path / "whole.bin"
        with FakePeer.for_torrent(torrent, extension=True) as fake:
            stub_tracker.set_peers([(fake.ip, fake.port)])
            main(["magnet_download", "-o", str(output), torrent.magnet_link])
        assert output.read_bytes() == torrent.content
        assert capsys.readouterr().out.endswith("torrent magnet file download completed.\n")


class TestArgvErrors:
    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param([], id="no-command"),
            pytest.param(["bogus_command"], id="unknown-command"),
            pytest.param(["download", "sample.torrent"], id="missing-output"),
        ],
    )
    def test_usage_errors_exit_2(self, argv, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 2
        assert "usage:" in capsys.readouterr().err
