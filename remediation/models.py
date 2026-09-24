"""领域模型：事件、策略、执行记录、审计条目。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class State(str, Enum):
    PENDING = "PENDING"                       # 已接收，等待调度
    WAITING_APPROVAL = "WAITING_APPROVAL"     # 危险动作待审批
    RUNNING = "RUNNING"                       # 正在执行动作
    COMPLETED = "COMPLETED"                   # 全部动作成功（终态）
    PARTIALLY_FAILED = "PARTIALLY_FAILED"     # 部分动作失败（终态）
    FAILED = "FAILED"                         # 全部失败（终态）
    CANCELLED = "CANCELLED"                   # 已取消（终态）
    TIMED_OUT = "TIMED_OUT"                   # 超时（终态）
    REJECTED = "REJECTED"                     # 策略/字段拒绝，未产生副作用（终态）


TERMINAL_STATES: frozenset[State] = frozenset(
    {
        State.COMPLETED,
        State.PARTIALLY_FAILED,
        State.FAILED,
        State.CANCELLED,
        State.TIMED_OUT,
        State.REJECTED,
    }
)

# 可在重启后恢复执行的非终态
RECOVERABLE_STATES: frozenset[State] = frozenset(
    {State.PENDING, State.WAITING_APPROVAL, State.RUNNING}
)

# 允许取消的状态
CANCELLABLE_STATES: frozenset[State] = frozenset(
    {State.PENDING, State.WAITING_APPROVAL, State.RUNNING}
)


_VALID_MATCH_KEYS = frozenset({"source", "alert_type", "severity", "severity_min"})
_SEVERITY_ORDER = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 10,
    Severity.MEDIUM.value: 20,
    Severity.HIGH.value: 30,
    Severity.CRITICAL.value: 40,
}


@dataclass(frozen=True)
class Event:
    event_id: str
    source: str
    alert_type: str
    severity: str
    payload: dict[str, Any] = field(default_factory=dict)
    occurred_at: str | None = None

    REQUIRED_FIELDS: tuple[str, ...] = ("event_id", "source", "alert_type", "severity")

    def validate(self) -> None:
        """校验必填字段非空、类型合法；失败由调用方映射为 MISSING_FIELD/MALFORMED_EVENT。"""
        for name in self.REQUIRED_FIELDS:
            value = getattr(self, name)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                raise ValueError(f"字段缺失或为空: {name}")
        if not isinstance(self.event_id, str) or len(self.event_id) > 200:
            raise ValueError("event_id 必须是长度不超过 200 的字符串")
        if self.severity not in _SEVERITY_ORDER:
            raise ValueError(
                f"severity 非法: {self.severity!r}，允许值 {sorted(_SEVERITY_ORDER)}"
            )

    @classmethod
    def from_raw(cls, raw: Any) -> "Event":
        """从未受信输入构造事件；结构性错误抛 ValueError（->MALFORMED_EVENT）。"""
        if not isinstance(raw, dict):
            raise ValueError("事件体必须是 JSON 对象")
        payload = raw.get("payload", {})
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ValueError("payload 必须是对象")
        event = cls(
            event_id=raw.get("event_id"),
            source=raw.get("source"),
            alert_type=raw.get("alert_type"),
            severity=raw.get("severity"),
            payload=payload,
            occurred_at=raw.get("occurred_at"),
        )
        event.validate()
        return event


@dataclass(frozen=True)
class ActionSpec:
    name: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    dangerous: bool = False
    required_role: str | None = None

    def validate(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("动作缺少 name")
        if not self.action or not isinstance(self.action, str):
            raise ValueError(f"动作 {self.name!r} 缺少 action")
        if not isinstance(self.params, dict):
            raise ValueError(f"动作 {self.name!r} 的 params 必须是对象")
        if self.required_role is not None and not isinstance(self.required_role, str):
            raise ValueError(f"动作 {self.name!r} 的 required_role 必须是字符串")

    @classmethod
    def from_dict(cls, raw: Any) -> "ActionSpec":
        if not isinstance(raw, dict):
            raise ValueError("动作定义必须是对象")
        spec = cls(
            name=raw.get("name"),
            action=raw.get("action"),
            params=raw.get("params") or {},
            dangerous=bool(raw.get("dangerous", False)),
            required_role=raw.get("required_role"),
        )
        spec.validate()
        return spec


@dataclass(frozen=True)
class Policy:
    policy_id: str
    priority: int
    match: dict[str, str]
    actions: list[ActionSpec]
    description: str = ""

    def matches(self, event: Event) -> bool:
        for key, expected in self.match.items():
            if key == "severity_min":
                if _SEVERITY_ORDER.get(event.severity, -1) < _SEVERITY_ORDER.get(expected, 10**9):
                    return False
            elif getattr(event, key, None) != expected:
                return False
        return True

    def validate(self) -> None:
        if not self.policy_id or not isinstance(self.policy_id, str):
            raise ValueError("策略缺少 policy_id")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise ValueError(f"策略 {self.policy_id} 的 priority 必须是整数")
        if not isinstance(self.match, dict) or not self.match:
            raise ValueError(f"策略 {self.policy_id} 的 match 必须是非空对象")
        unknown = set(self.match) - _VALID_MATCH_KEYS
        if unknown:
            raise ValueError(f"策略 {self.policy_id} 含未知匹配键: {sorted(unknown)}")
        if "severity_min" in self.match and self.match["severity_min"] not in _SEVERITY_ORDER:
            raise ValueError(
                f"策略 {self.policy_id} 的 severity_min 非法: {self.match['severity_min']!r}"
            )
        for key in ("source", "alert_type", "severity"):
            if key in self.match and not isinstance(self.match[key], str):
                raise ValueError(f"策略 {self.policy_id} 的 match.{key} 必须是字符串")
        if not self.actions:
            raise ValueError(f"策略 {self.policy_id} 必须至少包含一个动作")
        names: set[str] = set()
        for spec in self.actions:
            if spec.name in names:
                raise ValueError(f"策略 {self.policy_id} 中动作名重复: {spec.name}")
            names.add(spec.name)

    @classmethod
    def from_dict(cls, raw: Any) -> "Policy":
        if not isinstance(raw, dict):
            raise ValueError("策略定义必须是对象")
        actions = [ActionSpec.from_dict(a) for a in raw.get("actions", [])]
        match = raw.get("match")
        if match is None:
            match = {}
        policy = cls(
            policy_id=raw.get("policy_id"),
            priority=raw.get("priority", 0),
            match=match,
            actions=actions,
            description=raw.get("description", ""),
        )
        policy.validate()
        return policy


@dataclass
class ExecutionRecord:
    event_id: str
    policy_id: str
    state: State
    action_names: list[str]
    completed_actions: list[str] = field(default_factory=list)
    current_index: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    deadline: float | None = None
    approver: str | None = None
    approval_expires_at: float | None = None
    approval_seq: int = 0
    reject_reason: str | None = None
    last_error: str | None = None
    version: int = 0  # 乐观锁，每次持久化 +1

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    event_id: str
    transition: str
    actor: str
    reason: str
    detail: str
    created_at: float
