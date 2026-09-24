"""持久化存储。

- store.json：执行记录与审批，写入采用 temp 文件 + os.replace 原子替换，
  进程内用 RLock 串行化，保证重复/并发提交下只有一个执行记录。
- effects.jsonl：副作用台账（仅追加），以 effect_key 去重，
  即使进程在步骤中途崩溃，恢复后续跑也不会产生第二次副作用。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from app.schemas import ApprovalRecord, ExecutionRecord


class _PersistedState:
    def __init__(self) -> None:
        self.executions: dict[str, ExecutionRecord] = {}
        self.event_index: dict[str, str] = {}
        self.approvals: list[ApprovalRecord] = []


class Store:
    def __init__(self, store_path: str, effects_path: str) -> None:
        self._path = store_path
        self._effects_path = effects_path
        self._lock = threading.RLock()
        self._state = _PersistedState()
        self._effects: dict[str, dict] = {}
        self._mtime: float = -1.0
        Path(store_path).parent.mkdir(parents=True, exist_ok=True)
        Path(effects_path).parent.mkdir(parents=True, exist_ok=True)
        self._load()
        self._rebuild_effects()

    # ---------- 持久化 ----------
    def _maybe_reload_locked(self) -> None:
        """支持多进程/多实例访问同一文件：文件被其他实例替换后自动重载。"""
        try:
            mtime = os.path.getmtime(self._path)
        except OSError:
            return
        if mtime == self._mtime:
            return
        state = _PersistedState()
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for item in raw.get("executions", []):
                rec = ExecutionRecord.model_validate(item)
                state.executions[rec.id] = rec
                state.event_index[rec.event_id] = rec.id
            for item in raw.get("approvals", []):
                state.approvals.append(ApprovalRecord.model_validate(item))
        self._state = state
        self._mtime = mtime

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for item in raw.get("executions", []):
            rec = ExecutionRecord.model_validate(item)
            self._state.executions[rec.id] = rec
            self._state.event_index[rec.event_id] = rec.id
        for item in raw.get("approvals", []):
            self._state.approvals.append(ApprovalRecord.model_validate(item))
        self._mtime = os.path.getmtime(self._path)

    def _flush_locked(self) -> None:
        # 约定：同一时刻只有一个活跃编排进程写盘（worker 单线程）；
        # 崩溃恢复属于“旧写者已终止”的新进程场景，由读路径 _maybe_reload 同步。
        payload = {
            "executions": [r.model_dump() for r in self._state.executions.values()],
            "approvals": [a.model_dump() for a in self._state.approvals],
        }
        directory = os.path.dirname(self._path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".store.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
            self._mtime = os.path.getmtime(self._path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _rebuild_effects(self) -> None:
        if not os.path.exists(self._effects_path):
            return
        with open(self._effects_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                self._effects[item["effect_key"]] = item

    # ---------- 锁 ----------
    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # ---------- 执行记录 ----------
    def get_by_event(self, event_id: str) -> ExecutionRecord | None:
        with self._lock:
            self._maybe_reload_locked()
            exec_id = self._state.event_index.get(event_id)
            return self._state.executions[exec_id] if exec_id else None

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            self._maybe_reload_locked()
            return self._state.executions.get(execution_id)

    def all_executions(self) -> list[ExecutionRecord]:
        with self._lock:
            self._maybe_reload_locked()
            return list(self._state.executions.values())

    def insert_execution(self, record: ExecutionRecord) -> None:
        """幂等插入：event_id 已存在时抛出 KeyError，由调用方返回既有记录。"""
        with self._lock:
            self._maybe_reload_locked()
            if record.event_id in self._state.event_index:
                raise KeyError(record.event_id)
            self._state.executions[record.id] = record
            self._state.event_index[record.event_id] = record.id
            self._flush_locked()

    def save_execution(self, record: ExecutionRecord) -> None:
        with self._lock:
            self._state.executions[record.id] = record
            self._state.event_index[record.event_id] = record.id
            self._flush_locked()

    # ---------- 审批 ----------
    def add_approval(self, approval: ApprovalRecord) -> None:
        with self._lock:
            self._state.approvals.append(approval)
            self._flush_locked()

    def find_valid_approval(
        self, execution_id: str, action_index: int, now: float
    ) -> ApprovalRecord | None:
        with self._lock:
            self._maybe_reload_locked()
            for approval in self._state.approvals:
                if approval.execution_id != execution_id:
                    continue
                if approval.action_index != action_index:
                    continue
                if approval.consumed:
                    continue
                if approval.expires_at <= now:
                    continue
                return approval
        return None

    def consume_approval(self, approval_id: str) -> None:
        with self._lock:
            for approval in self._state.approvals:
                if approval.id == approval_id:
                    approval.consumed = True
                    self._flush_locked()
                    return

    # ---------- 副作用台账（exactly-once） ----------
    def effect_exists(self, effect_key: str) -> dict | None:
        with self._lock:
            item = self._effects.get(effect_key)
            return dict(item) if item else None

    def record_effect(self, effect_key: str, result: dict) -> dict:
        """返回台账记录。已存在则直接返回旧记录，绝不重复执行副作用。"""
        with self._lock:
            existing = self._effects.get(effect_key)
            if existing is not None:
                return dict(existing)
            item = {"effect_key": effect_key, "result": result}
            self._effects[effect_key] = item
            # 仅追加落盘：进程崩溃后靠台账识别已发生的副作用
            with open(self._effects_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return dict(item)
