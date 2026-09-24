"""审计日志。

- 仅追加 JSONL，每条带进程内单调递增的 seq（启动时按已有行数重建）；
- 一把锁串行化写入 + fsync，并发/重试下不丢条、不重号、不错序；
- 所有自动与人工状态迁移都必须经过这里落痕。
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._rebuild_seq()

    def _rebuild_seq(self) -> int:
        if not os.path.exists(self._path):
            return 0
        count = 0
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def emit(
        self,
        kind: str,
        *,
        execution_id: str | None = None,
        event_id: str | None = None,
        actor: str | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
        policy_id: str | None = None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry = {
            "seq": 0,
            "ts": round(time.time(), 6),
            "kind": kind,
            "execution_id": execution_id,
            "event_id": event_id,
            "actor": actor,
            "from_state": from_state,
            "to_state": to_state,
            "policy_id": policy_id,
            "reason": reason,
            "details": details or {},
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            self._seq += 1
            entry["seq"] = self._seq
            line = json.dumps(entry, ensure_ascii=False)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def read_all(self) -> list[dict[str, Any]]:
        if not os.path.exists(self._path):
            return []
        with self._lock, open(self._path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
