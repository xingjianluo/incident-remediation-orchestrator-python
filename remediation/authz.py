"""角色权限与审批校验。危险动作必须具备所需角色，且存在未过期的管理员审批。"""
from __future__ import annotations

from dataclasses import dataclass

from .errors import AuthzError, RejectReason
from .models import ActionSpec, ExecutionRecord

APPROVER_ROLE = "admin"
EXECUTOR_ROLE = "operator"
SUBMITTER_ROLE = "viewer"

# 高等级角色隐含低等级角色
ROLE_HIERARCHY: dict[str, frozenset[str]] = {
    "admin": frozenset({"admin", "operator", "viewer"}),
    "operator": frozenset({"operator", "viewer"}),
    "viewer": frozenset({"viewer"}),
}


@dataclass(frozen=True)
class Actor:
    name: str
    roles: frozenset[str]

    @classmethod
    def parse(cls, name: str | None, roles_csv: str | None) -> "Actor | None":
        if not name or not name.strip():
            return None
        roles = frozenset(r.strip() for r in (roles_csv or "").split(",") if r.strip())
        return cls(name=name.strip(), roles=roles or frozenset({"viewer"}))

    def has_role(self, required: str) -> bool:
        effective: set[str] = set()
        for role in self.roles:
            effective |= ROLE_HIERARCHY.get(role, frozenset({role}))
        return required in effective


class AuthzService:
    def __init__(self, approval_ttl_seconds: int) -> None:
        self.approval_ttl_seconds = approval_ttl_seconds

    def check_submit(self, actor: Actor | None) -> None:
        if actor is None:
            raise AuthzError(RejectReason.UNAUTHENTICATED, "缺少调用方身份（X-Actor 头）")
        if not actor.has_role(SUBMITTER_ROLE):
            raise AuthzError(RejectReason.FORBIDDEN, f"主体 {actor.name} 无提交权限")

    def check_cancel(self, actor: Actor | None) -> None:
        if actor is None:
            raise AuthzError(RejectReason.UNAUTHENTICATED, "缺少调用方身份（X-Actor 头）")
        if not actor.has_role(EXECUTOR_ROLE):
            raise AuthzError(
                RejectReason.PERMISSION_DENIED,
                f"主体 {actor.name} 无取消执行所需的 {EXECUTOR_ROLE} 角色",
            )

    def check_approve(self, actor: Actor | None) -> None:
        if actor is None:
            raise AuthzError(RejectReason.UNAUTHENTICATED, "缺少调用方身份（X-Actor 头）")
        if not actor.has_role(APPROVER_ROLE):
            raise AuthzError(
                RejectReason.PERMISSION_DENIED,
                f"主体 {actor.name} 无审批所需的 {APPROVER_ROLE} 角色",
            )

    @staticmethod
    def dangerous_actions(actions: list[ActionSpec]) -> list[ActionSpec]:
        return [a for a in actions if a.dangerous]

    def evaluate(
        self, record: ExecutionRecord, actions: list[ActionSpec], now: float
    ) -> tuple[bool, str]:
        """判断当前是否可自动继续执行。

        返回 (可执行, 原因码)。原因码为空字符串表示允许；否则为：
        APPROVAL_REQUIRED / APPROVAL_EXPIRED。
        """
        dangerous = self.dangerous_actions(actions)
        if not dangerous:
            return True, ""
        # 审批必须由 admin 作出且在 TTL 内
        if record.approver is None or record.approval_expires_at is None:
            return False, RejectReason.APPROVAL_REQUIRED.value
        if record.approval_expires_at < now:
            return False, RejectReason.APPROVAL_EXPIRED.value
        return True, ""
