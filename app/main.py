"""Entry point for the BitTorrent client (``python3 -m app.main``).

The implementation is split across the :mod:``app`` package:

- :mod:`app.models`       - domain entities (TorrentMetadata, Peer, MagnetLink)
- :mod:`app.reporting`    - the progress-reporting port (abstraction)
- :mod:`app.torrent`      - build metadata from a file or a metadata blob
- :mod:`app.magnet`       - magnet URI parsing
- :mod:`app.tracker`      - HTTP tracker client
- :mod:`app.peer`         - the peer wire protocol over one socket
- :mod:`app.client`       - high-level use cases
- :mod:`app.cli`          - argument parsing, output, and the stdout reporter
"""

from app.cli import main


if __name__ == "__main__":
    main()
