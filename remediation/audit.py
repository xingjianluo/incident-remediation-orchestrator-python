"""审计与结构化日志。

每次提交判定、状态迁移、审批、取消、拒绝都写一条审计（事件内单调 seq），
并同时输出结构化日志，包含事件标识、策略判定、状态迁移与拒绝原因。
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from .models import AuditEntry
from .storage import Storage

log = logging.getLogger("remediation")


class AuditTrail:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        self._lock = threading.Lock()

    def record(
        self,
        event_id: str,
        transition: str,
        actor: str,
        reason: str = "",
        detail: str = "",
    ) -> int:
        """追加一条审计并输出日志；seq 在事件内连续递增，失败不静默。"""
        with self._lock:
            now = time.time()
            seq = self.storage.next_audit_seq(event_id)
            entry = AuditEntry(
                seq=seq,
                event_id=event_id,
                transition=transition,
                actor=actor,
                reason=reason,
                detail=detail,
                created_at=now,
            )
            self.storage.append_audit(entry)
        log.info(
            json.dumps(
                {
                    "type": "state_transition",
                    "event_id": event_id,
                    "seq": seq,
                    "transition": transition,
                    "actor": actor,
                    "reason": reason,
                    "detail": detail,
                },
                ensure_ascii=False,
            )
        )
        return seq

    def history(self, event_id: str) -> list[dict[str, Any]]:
        return [
            {
                "seq": e.seq,
                "event_id": e.event_id,
                "transition": e.transition,
                "actor": e.actor,
                "reason": e.reason,
                "detail": e.detail,
                "created_at": e.created_at,
            }
            for e in self.storage.list_audit(event_id)
        ]


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger("remediation")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
