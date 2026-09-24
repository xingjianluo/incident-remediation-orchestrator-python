"""本地动作注册表与执行器。

所有副作用仅写入本地 effects 目录，且以「每事件每步固定产物 + 原子落盘」实现：
重试/恢复时重复执行产生同一结果文件，逻辑上恰好一次。
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

ActionHandler = Callable[[dict[str, Any], str], dict[str, Any]]


class ActionFailure(Exception):
    def __init__(self, action_name: str, message: str) -> None:
        super().__init__(message)
        self.action_name = action_name
        self.message = message


class SimulatedCrash(RuntimeError):
    """测试用：副作用已落盘、完成状态尚未持久化时模拟进程崩溃。"""


class ActionRegistry:
    def __init__(self, effects_dir: str = "data/effects") -> None:
        self.effects_dir = Path(effects_dir)
        self._handlers: dict[str, ActionHandler] = {}
        # 测试故障注入：在指定动作副作用完成后、状态持久化前“崩溃”
        self.crash_after: set[str] = set()

    def register_defaults(self) -> None:
        self.effects_dir.mkdir(parents=True, exist_ok=True)
        self._handlers["noop"] = self._noop
        self._handlers["write_file"] = self._write_file
        self._handlers["restart_service"] = self._restart_service
        self._handlers["simulate_fail"] = self._simulate_fail

    def known(self, action: str) -> bool:
        return action in self._handlers

    def register(self, action: str, handler: ActionHandler) -> None:
        self._handlers[action] = handler

    # ---- 原子写工具 ----
    def _atomic_write(self, target: Path, content: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)

    def _event_dir(self, event_id: str) -> Path:
        safe = event_id.replace("/", "_").replace("..", "_")
        d = self.effects_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ---- 内置动作 ----
    @staticmethod
    def _noop(params: dict[str, Any], event_id: str) -> dict[str, Any]:
        return {"action": "noop", "event_id": event_id}

    def _write_file(self, params: dict[str, Any], event_id: str) -> dict[str, Any]:
        name = params.get("filename") or "marker.txt"
        if not isinstance(name, str) or os.path.isabs(name) or ".." in name.split("/"):
            raise ActionFailure("write_file", f"非法 filename: {name!r}")
        content = params.get("content", "")
        target = self._event_dir(event_id) / name
        self._atomic_write(target, str(content))
        return {"action": "write_file", "path": str(target)}

    def _restart_service(self, params: dict[str, Any], event_id: str) -> dict[str, Any]:
        service = params.get("service", "unknown-service")
        # 不做真实重启，仅落一条确定性的重启记录（幂等覆盖同一文件）
        target = self._event_dir(event_id) / f"restart-{service}.json"
        self._atomic_write(
            target,
            json.dumps({"event_id": event_id, "service": service, "restarted": True}, ensure_ascii=False),
        )
        return {"action": "restart_service", "service": service, "path": str(target)}

    @staticmethod
    def _simulate_fail(params: dict[str, Any], event_id: str) -> dict[str, Any]:
        raise ActionFailure(
            params.get("action_name", "simulate_fail"),
            str(params.get("message", "模拟动作失败")),
        )

    # ---- 执行入口 ----
    def execute(
        self,
        action: str,
        params: dict[str, Any],
        event_id: str,
        step_name: str | None = None,
    ) -> dict[str, Any]:
        handler = self._handlers.get(action)
        if handler is None:
            raise ActionFailure(step_name or action, f"未知动作类型: {action}")
        result = handler(params, event_id)
        if step_name in self.crash_after:
            self.crash_after.discard(step_name)
            raise SimulatedCrash(
                f"动作 {step_name} 副作用已完成，模拟进程崩溃（完成状态未持久化）"
            )
        return result
