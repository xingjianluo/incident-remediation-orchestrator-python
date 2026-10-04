"""Pydantic 数据模型：事件、策略、动作、执行记录、审批、ACL。"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ActionRisk(str, Enum):
    SAFE = "safe"
    DANGEROUS = "dangerous"


class ExecutionState(str, Enum):
    PENDING = "pending"                      # 已受理，等待调度
    AWAITING_APPROVAL = "awaiting_approval"  # 危险动作等待审批
    RUNNING = "running"                      # 执行中（含崩溃恢复续跑）
    COMPLETED = "completed"
    FAILED = "failed"                        # 中途失败，可显式重试
    PARTIAL_FAILED = "partial_failed"        # 策略允许继续但部分动作失败（终态）
    RETRY_EXHAUSTED = "retry_exhausted"      # 失败次数耗尽的收敛终态，需人工确认后再试
    CANCELLED = "cancelled"                  # 终态
    TIMED_OUT = "timed_out"                  # 终态
    REJECTED = "rejected"                    # 终态：策略/事件层面拒绝


TERMINAL_STATES = frozenset(
    {
        ExecutionState.COMPLETED,
        ExecutionState.PARTIAL_FAILED,
        ExecutionState.RETRY_EXHAUSTED,
        ExecutionState.CANCELLED,
        ExecutionState.TIMED_OUT,
        ExecutionState.REJECTED,
    }
)


class RejectReason(str, Enum):
    # 事件层面四类可区分拒绝（需求显式要求调用方可分辨）：
    INVALID_EVENT = "invalid_event"             # 字段值本身不合法（非法枚举/空串/类型错误）
    MISSING_FIELD = "missing_field"             # 事件少了必填内容（必填字段缺失/请求体非对象）
    POLICY_NOT_FOUND = "policy_not_found"       # 事件合法但没有任何策略命中
    POLICY_CONFLICT = "policy_conflict"         # 命中策略在优先级与具体度上完全同级（配置冲突）
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    APPROVAL_REQUIRED = "approval_required"        # 非拒绝：进入待审批态
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_INVALID = "approval_invalid"
    APPROVER_NOT_ALLOWED = "approver_not_allowed"
    EXECUTION_NOT_FOUND = "execution_not_found"
    INVALID_STATE_TRANSITION = "invalid_state_transition"
    RETRY_EXHAUSTED = "retry_exhausted"            # 重试预算耗尽，未经人工确认不可再试
    ACTION_UNKNOWN = "action_unknown"


class StepStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"


_SEVERITIES = {"info", "warning", "critical"}


def _non_blank(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("must be a non-blank string")
    return value.strip()


class Event(BaseModel):
    event_id: str
    event_type: str
    source: str
    severity: str = "warning"
    labels: dict[str, str] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    submitted_by: str | None = None

    @field_validator("event_id", "event_type", "source")
    @classmethod
    def _check_non_blank(cls, v: str) -> str:
        return _non_blank(v)

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        v = _non_blank(v).lower()
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}")
        return v


class MatchRule(BaseModel):
    event_type: str | None = None
    source_prefix: str | None = None
    severities: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("severities")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return [s.lower() for s in v]


class ActionDef(BaseModel):
    name: str
    risk: ActionRisk = ActionRisk.SAFE
    required_role: str = "operator"
    params: dict[str, Any] = Field(default_factory=dict)
    continue_on_failure: bool = False
    # 测试用：在副作用落账之后、步骤状态提交之前模拟进程崩溃
    crash_after_effect: bool = False

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return _non_blank(v)


class Policy(BaseModel):
    id: str
    description: str = ""
    match: MatchRule
    priority: int = 100
    actions: list[ActionDef]

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        return _non_blank(v)

    @field_validator("actions")
    @classmethod
    def _check_actions(cls, v: list[ActionDef]) -> list[ActionDef]:
        if not v:
            raise ValueError("policy must contain at least one action")
        return v


class AclConfig(BaseModel):
    # username -> role
    users: dict[str, str] = Field(default_factory=dict)
    # role -> capabilities
    roles: dict[str, list[str]] = Field(default_factory=dict)


class StepResult(BaseModel):
    index: int
    action: str
    risk: ActionRisk
    status: StepStatus = StepStatus.PENDING
    effect_key: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    attempts: int = 0


class ApprovalRecord(BaseModel):
    id: str
    execution_id: str
    action_index: int
    action_name: str
    granted_by: str
    granted_at: float
    expires_at: float
    consumed: bool = False


class ExecutionRecord(BaseModel):
    id: str
    event_id: str
    event: Event
    policy_id: str
    state: ExecutionState
    steps: list[StepResult] = Field(default_factory=list)
    created_at: float
    updated_at: float
    started_at: float | None = None
    finished_at: float | None = None
    deadline: float | None = None
    cancel_requested: bool = False
    cancel_requested_by: str | None = None
    submitted_by: str | None = None
    error: str | None = None
    run_generation: int = 0  # 每次（含恢复）调度递增，用于识别陈旧执行
    # 失败收敛：attempts_used 为已消耗的尝试轮次（首次启动记 1），
    # 达到 max_attempts 后停在 retry_exhausted 终态，等待人工确认重试。
    attempts_used: int = 0
    max_attempts: int = 0


class ApprovalGrantRequest(BaseModel):
    granted_by: str
    ttl_seconds: int | None = None
    action_index: int | None = None  # 为空则授予全部待审批动作


class RetryRequest(BaseModel):
    requested_by: str | None = None
    # 仅当执行已停在 retry_exhausted 收敛终态时需要：
    # 显式的人工确认才会重新打开尝试预算，避免后台无限重跑。
    confirmed: bool = False


class CancellationRequest(BaseModel):
    requested_by: str | None = None


class RejectResponse(BaseModel):
    error: str
    reason: RejectReason
    details: dict[str, Any] = Field(default_factory=dict)
