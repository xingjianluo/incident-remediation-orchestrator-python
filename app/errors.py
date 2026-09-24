"""统一异常：携带可区分的拒绝原因，供 API 层映射 HTTP 响应。"""
from __future__ import annotations

from typing import Any

from app.schemas import RejectReason


class OrchestratorError(Exception):
    """所有业务层拒绝/失败的基类。

    - reason: 稳定、可枚举的拒绝原因，便于调用方区分与断言
    - details: 附加上下文（事件标识、策略标识等），不携带敏感凭据
    """

    def __init__(
        self,
        reason: RejectReason,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details: dict[str, Any] = details or {}


class PolicyRejected(OrchestratorError):
    """事件层面的拒绝（非法事件 / 无策略），HTTP 4xx，不产生任何执行。"""


class AuthorizationError(OrchestratorError):
    """权限/审批边界拒绝，HTTP 403，且不得改变执行状态。"""


class ExecutionConflict(OrchestratorError):
    """不合法的状态迁移或目标不存在，HTTP 409/404。"""
