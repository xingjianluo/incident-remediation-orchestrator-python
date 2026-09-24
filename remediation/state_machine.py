"""执行状态机：集中管理合法迁移，拒绝非法迁移且不改变状态。"""
from __future__ import annotations

from .errors import RejectReason, StateError
from .models import State

ALLOWED_TRANSITIONS: dict[State, frozenset[State]] = {
    State.PENDING: frozenset(
        {
            State.RUNNING,
            State.WAITING_APPROVAL,
            State.REJECTED,
            State.CANCELLED,
            State.TIMED_OUT,
            State.FAILED,
        }
    ),
    State.WAITING_APPROVAL: frozenset(
        {
            State.PENDING,          # 审批通过，回到待执行
            State.RUNNING,          # 审批通过后直接执行
            State.CANCELLED,
            State.TIMED_OUT,
            State.REJECTED,         # 审批过期/撤销，拒绝继续
        }
    ),
    State.RUNNING: frozenset(
        {
            State.COMPLETED,
            State.PARTIALLY_FAILED,
            State.FAILED,
            State.CANCELLED,
            State.TIMED_OUT,
            State.RUNNING,          # 步骤间推进（重启恢复时重入）
        }
    ),
    State.COMPLETED: frozenset(),
    State.PARTIALLY_FAILED: frozenset(),
    State.FAILED: frozenset(),
    State.CANCELLED: frozenset(),
    State.TIMED_OUT: frozenset(),
    State.REJECTED: frozenset(),
}


def can_transition(src: State, dst: State) -> bool:
    return dst in ALLOWED_TRANSITIONS.get(src, frozenset())


def assert_transition(src: State, dst: State) -> None:
    if not can_transition(src, dst):
        raise StateError(
            RejectReason.INVALID_TRANSITION,
            f"非法状态迁移: {src.value} -> {dst.value}",
        )
