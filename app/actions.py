"""本地修复动作注册表。

所有动作均为纯本地操作（文件标记/本地计算），不调用外部服务、不使用真实凭据。
真正的“仅一次副作用”由 executor 通过 Store 的效果台账保证；
这里的 handler 只负责在被授权执行一次时产生本地可观测结果。
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from typing import Any

from app.errors import AuthorizationError
from app.schemas import RejectReason

ActionHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _write_local_marker(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    """在本地临时目录写一条动作标记，便于测试断言副作用发生次数。"""
    target = params.get("target", "local")
    marker_dir = os.path.join(tempfile.gettempdir(), "iro_actions")
    os.makedirs(marker_dir, exist_ok=True)
    marker = os.path.join(marker_dir, f"{kind}.jsonl")
    entry = {"kind": kind, "target": target, "params": {k: v for k, v in params.items() if k != "fail"}}
    with open(marker, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def _restart_service(params: dict[str, Any]) -> dict[str, Any]:
    return _write_local_marker("restart_service", params)


def _clear_disk_cache(params: dict[str, Any]) -> dict[str, Any]:
    return _write_local_marker("clear_disk_cache", params)


def _isolate_host(params: dict[str, Any]) -> dict[str, Any]:
    return _write_local_marker("isolate_host", params)


def _scale_workers(params: dict[str, Any]) -> dict[str, Any]:
    count = int(params.get("count", 1))
    result = _write_local_marker("scale_workers", params)
    result["scaled_to"] = count
    return result


_BUILTIN: dict[str, ActionHandler] = {
    "restart_service": _restart_service,
    "clear_disk_cache": _clear_disk_cache,
    "isolate_host": _isolate_host,
    "scale_workers": _scale_workers,
}


class ActionRegistry:
    def __init__(self, handlers: dict[str, ActionHandler] | None = None) -> None:
        self._handlers: dict[str, ActionHandler] = dict(_BUILTIN)
        if handlers:
            self._handlers.update(handlers)

    def register(self, name: str, handler: ActionHandler) -> None:
        """供测试覆盖/注入自定义动作（如注入故障）。"""
        self._handlers[name] = handler

    def names(self) -> list[str]:
        return sorted(self._handlers)

    def execute(self, action_name: str, params: dict[str, Any]) -> dict[str, Any]:
        handler = self._handlers.get(action_name)
        if handler is None:
            raise AuthorizationError(
                RejectReason.ACTION_UNKNOWN,
                f"unknown action: {action_name}",
                {"action": action_name},
            )
        # 测试与策略均可通过 fail=true 确定性地制造动作失败
        if bool(params.get("fail", False)):
            raise RuntimeError(f"action {action_name} failed by fail flag")
        return handler(dict(params))
