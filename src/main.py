"""Entry point for the BitTorrent client (``python3 -m src.main``).

The implementation is split across the :mod:``src`` package:

- :mod:`src.models`       - domain entities (TorrentMetadata, Peer, MagnetLink)
- :mod:`src.reporting`    - the progress-reporting port (abstraction)
- :mod:`src.torrent`      - build metadata from a file or a metadata blob
- :mod:`src.magnet`       - magnet URI parsing
- :mod:`src.tracker`      - HTTP tracker client
- :mod:`src.peer`         - the peer wire protocol over one socket
- :mod:`src.client`       - high-level use cases
- :mod:`src.cli`          - argument parsing, output, and the stdout reporter
"""

from src.cli import main


if __name__ == "__main__":
    main()
