"""服务启动入口（uvicorn）。

运行方式：
    uv run uvicorn app.main:app --reload
或：
    uv run python -m app.main
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.api import create_app
from app.config import get_settings

settings = get_settings()


def _configure_logging(s: object) -> None:
    app_log = s.app_log
    Path(app_log).parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    root = logging.getLogger("iro")
    root.setLevel(logging.INFO)
    root.handlers.clear()
    fh = RotatingFileHandler(app_log, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)
    root.propagate = False


_configure_logging(settings)
app = create_app(settings)


def main() -> None:
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("IRO_HOST", "127.0.0.1"),
        port=int(os.environ.get("IRO_PORT", "8000")),
        log_level="info",
    )


if __name__ == "__main__":
    main()
