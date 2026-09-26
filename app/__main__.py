"""Entry point: ``python -m app``.

Configuration via environment:
  SEAL_HOST     bind address (default 0.0.0.0 inside the container)
  SEAL_PORT     bind port inside the container (default 8080)
  SEAL_DB       SQLite database path (default /data/seal.db)
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from .server import build_server


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("SEAL_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("SEAL_HOST", "0.0.0.0")
    port = int(os.environ.get("SEAL_PORT", "8080"))
    db_path = os.environ.get("SEAL_DB", "/data/seal.db")

    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    httpd, store = build_server(host, port, db_path)

    def _shutdown(*_args) -> None:
        # httpd.shutdown() must not run in the serve_forever thread itself
        # (it would deadlock); nudge it from a helper thread instead.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        logging.getLogger(__name__).info("threshold config-seal listening on %s:%d", host, port)
        httpd.serve_forever()
    finally:
        httpd.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
