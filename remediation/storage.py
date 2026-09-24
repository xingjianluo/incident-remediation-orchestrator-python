"""SQLite 持久化：执行记录与审计。WAL + 进程内锁 + 乐观版本号保证并发一致。"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .errors import RejectReason, StateError
from .models import RECOVERABLE_STATES, AuditEntry, ExecutionRecord, State


class Storage:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    # ---- 生命周期 ----
    def init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    event_id            TEXT PRIMARY KEY,
                    policy_id           TEXT NOT NULL,
                    state               TEXT NOT NULL,
                    action_names        TEXT NOT NULL,
                    completed_actions   TEXT NOT NULL,
                    current_index       INTEGER NOT NULL,
                    created_at          REAL NOT NULL,
                    updated_at          REAL NOT NULL,
                    deadline            REAL,
                    approver            TEXT,
                    approval_expires_at REAL,
                    approval_seq        INTEGER NOT NULL DEFAULT 0,
                    reject_reason       TEXT,
                    last_error          TEXT,
                    version             INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id    TEXT NOT NULL,
                    seq         INTEGER NOT NULL,
                    transition  TEXT NOT NULL,
                    actor       TEXT NOT NULL,
                    reason      TEXT NOT NULL DEFAULT '',
                    detail      TEXT NOT NULL DEFAULT '',
                    created_at  REAL NOT NULL,
                    UNIQUE(event_id, seq)
                );
                CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_id, seq);
                CREATE INDEX IF NOT EXISTS idx_exec_state ON executions(state);
                """
            )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ---- 行序列化 ----
    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ExecutionRecord:
        return ExecutionRecord(
            event_id=row["event_id"],
            policy_id=row["policy_id"],
            state=State(row["state"]),
            action_names=json.loads(row["action_names"]),
            completed_actions=json.loads(row["completed_actions"]),
            current_index=row["current_index"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            deadline=row["deadline"],
            approver=row["approver"],
            approval_expires_at=row["approval_expires_at"],
            approval_seq=row["approval_seq"],
            reject_reason=row["reject_reason"],
            last_error=row["last_error"],
            version=row["version"],
        )

    # ---- 执行记录 ----
    def insert_execution(self, record: ExecutionRecord) -> bool:
        """幂等插入：event_id 已存在时返回 False，不覆盖已有状态。"""
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO executions (
                    event_id, policy_id, state, action_names, completed_actions,
                    current_index, created_at, updated_at, deadline, approver,
                    approval_expires_at, approval_seq, reject_reason, last_error, version
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)
                """,
                (
                    record.event_id,
                    record.policy_id,
                    record.state.value,
                    json.dumps(record.action_names, ensure_ascii=False),
                    json.dumps(record.completed_actions, ensure_ascii=False),
                    record.current_index,
                    record.created_at,
                    record.updated_at,
                    record.deadline,
                    record.approver,
                    record.approval_expires_at,
                    record.approval_seq,
                    record.reject_reason,
                    record.last_error,
                ),
            )
            return cur.rowcount == 1

    def get_execution(self, event_id: str) -> ExecutionRecord | None:
        assert self._conn is not None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM executions WHERE event_id = ?", (event_id,)
            ).fetchone()
            return self._row_to_record(row) if row else None

    def save_execution(self, record: ExecutionRecord, expected_version: int) -> bool:
        """CAS 持久化：仅当数据库版本等于 expected_version 时写入，防止并发覆盖/状态倒退。"""
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE executions SET
                    policy_id = ?, state = ?, action_names = ?, completed_actions = ?,
                    current_index = ?, updated_at = ?, deadline = ?, approver = ?,
                    approval_expires_at = ?, approval_seq = ?, reject_reason = ?,
                    last_error = ?, version = ?
                WHERE event_id = ? AND version = ?
                """,
                (
                    record.policy_id,
                    record.state.value,
                    json.dumps(record.action_names, ensure_ascii=False),
                    json.dumps(record.completed_actions, ensure_ascii=False),
                    record.current_index,
                    record.updated_at,
                    record.deadline,
                    record.approver,
                    record.approval_expires_at,
                    record.approval_seq,
                    record.reject_reason,
                    record.last_error,
                    expected_version + 1,
                    record.event_id,
                    expected_version,
                ),
            )
            if cur.rowcount == 1:
                record.version = expected_version + 1
                return True
            return False

    def list_recoverable(self) -> list[ExecutionRecord]:
        """重启恢复：返回所有非终态记录，按创建时间确定顺序。"""
        assert self._conn is not None
        states = tuple(s.value for s in RECOVERABLE_STATES)
        placeholders = ",".join("?" for _ in states)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM executions WHERE state IN ({placeholders}) ORDER BY created_at, event_id",
                states,
            ).fetchall()
            return [self._row_to_record(r) for r in rows]

    # ---- 审计 ----
    def next_audit_seq(self, event_id: str) -> int:
        assert self._conn is not None
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM audit_log WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            return int(row["next"])

    def append_audit(self, entry: AuditEntry) -> int:
        """追加审计；序列号冲突时抛错，调用方重试，保证不丢、不重号、不乱序。"""
        assert self._conn is not None
        with self._lock:
            try:
                cur = self._conn.execute(
                    """
                    INSERT INTO audit_log (event_id, seq, transition, actor, reason, detail, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        entry.event_id,
                        entry.seq,
                        entry.transition,
                        entry.actor,
                        entry.reason,
                        entry.detail,
                        entry.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StateError(
                    RejectReason.ILLEGAL_STATE,
                    f"审计序列号冲突 event_id={entry.event_id} seq={entry.seq}",
                ) from exc
            return int(cur.lastrowid)

    def list_audit(self, event_id: str) -> list[AuditEntry]:
        assert self._conn is not None
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE event_id = ? ORDER BY seq ASC",
                (event_id,),
            ).fetchall()
            return [
                AuditEntry(
                    seq=r["seq"],
                    event_id=r["event_id"],
                    transition=r["transition"],
                    actor=r["actor"],
                    reason=r["reason"],
                    detail=r["detail"],
                    created_at=r["created_at"],
                )
                for r in rows
            ]
