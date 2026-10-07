"""待审批处置的取消语义：当场生效、无需审批；取消与审批并发结论唯一。

覆盖：
- 待审批（AWAITING_APPROVAL）的危险处置取消后立即进入 CANCELLED 终态，
  带结束时间，之后的批准一律 409，且任何动作都不会真正执行；
- 取消与审批并发发起时，无论谁先获锁，最终只有“已取消”一个结论，
  状态与留痕一致，无副作用；
- 已失败（含已应用步骤）的处置取消后，已应用步骤不回滚；
- 重复取消幂等：第二次被拒，不重复留痕。
"""
from __future__ import annotations

import threading

import pytest

from app.errors import ExecutionConflict
from app.schemas import (
    ActionDef,
    Event,
    ExecutionState,
    MatchRule,
    Policy,
    RejectReason,
    StepStatus,
)


def _dangerous_event(eid: str) -> Event:
    return Event(event_id=eid, event_type="security_intrusion", source="host-9",
                 severity="critical", submitted_by="alice")


def test_cancel_awaiting_approval_immediate_terminal(components):
    """待审批的危险处置：取消当场生效，落 CANCELLED 终态，无需再审批。"""
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cx-imm"))
    assert rec.state == ExecutionState.AWAITING_APPROVAL

    executor.request_cancel(rec.id, "alice")
    final = store.get(rec.id)
    # 立即终态：状态、结束时间、取消人都能从记录里查到
    assert final.state == ExecutionState.CANCELLED
    assert final.finished_at is not None
    assert final.cancel_requested is True
    assert final.cancel_requested_by == "alice"
    assert all(s.status == StepStatus.PENDING for s in final.steps)

    # 取消之后任何批准都不再起作用
    with pytest.raises(ExecutionConflict) as exc_info:
        executor.grant_approval(rec.id, "alice", None)
    assert exc_info.value.reason == RejectReason.INVALID_STATE_TRANSITION

    # 取消之后不会有任何动作被真正执行：worker 无事可做，台账为空
    assert executor.tick() is False
    assert list(store._effects) == []

    # 留痕：人工取消动作 + 进入终态的迁移各一条，可对外审计
    entries = [e for e in audit.read_all() if e["execution_id"] == rec.id]
    kinds = [e["kind"] for e in entries]
    assert kinds.count("cancel.requested") == 1
    assert kinds.count("run.cancelled") == 1
    cancelled = next(e for e in entries if e["kind"] == "run.cancelled")
    assert cancelled["from_state"] == "awaiting_approval"
    assert cancelled["to_state"] == "cancelled"


def test_cancel_awaiting_approval_over_api(client):
    """API 层面：取消返回成功后，对外查到的状态必须已是 cancelled。"""
    c, executor = client
    resp = c.post("/events", json={
        "event_id": "e-cx-api", "event_type": "security_intrusion",
        "source": "host-9", "severity": "critical", "submitted_by": "alice",
    })
    assert resp.status_code == 202
    exec_id = resp.json()["execution"]["id"]
    assert resp.json()["execution"]["state"] == "awaiting_approval"

    cancelled = c.post(f"/executions/{exec_id}/cancel", json={"requested_by": "alice"})
    assert cancelled.status_code == 200
    # 响应体与再次查询一致：已取消、有结束时间，不存在“返回成功却还挂待审批”
    assert cancelled.json()["state"] == "cancelled"
    final = c.get(f"/executions/{exec_id}").json()
    assert final["state"] == "cancelled"
    assert final["finished_at"] is not None

    # 取消后的批准 409；执行不会有任何副作用
    approval = c.post(f"/executions/{exec_id}/approvals", json={"granted_by": "alice"})
    assert approval.status_code == 409
    assert approval.json()["reason"] == "invalid_state_transition"
    assert executor.tick() is False
    assert list(executor.store._effects) == []


def test_cancel_then_approval_deterministic_order(components):
    """顺序确定：先取消后批准 => 批准被拒，结论唯一为已取消。"""
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cx-order1"))
    executor.request_cancel(rec.id, "alice")
    with pytest.raises(ExecutionConflict):
        executor.grant_approval(rec.id, "alice", None)
    assert store.get(rec.id).state == ExecutionState.CANCELLED
    assert executor.tick() is False
    assert list(store._effects) == []


def test_approval_then_cancel_cancels_before_any_execution(components):
    """顺序确定：先批准后取消（执行尚未启动）=> 取消当场生效，
    审批单仅留痕，不再产生任何执行效果。"""
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cx-order2"))
    executor.grant_approval(rec.id, "alice", None)
    executor.request_cancel(rec.id, "alice")

    final = store.get(rec.id)
    assert final.state == ExecutionState.CANCELLED
    assert final.finished_at is not None
    # 审批留痕还在，但执行从未启动、无任何副作用
    kinds = [e["kind"] for e in audit.read_all() if e["execution_id"] == rec.id]
    assert "approval.granted" in kinds
    assert "run.cancelled" in kinds
    assert "run.start" not in kinds
    assert "step.applied" not in kinds
    assert executor.tick() is False
    assert list(store._effects) == []


def test_concurrent_cancel_and_approval_single_outcome(components):
    """取消与审批并发：无论获锁顺序，最终都只有“已取消”一个确定结论，
    状态与留痕一致，且没有任何动作被真正执行。"""
    _, store, audit, executor, _ = components
    rounds = 30
    exec_ids: list[str] = []

    for i in range(rounds):
        rec, _ = executor.submit_event(_dangerous_event(f"e-cx-race-{i}"))
        exec_ids.append(rec.id)
        barrier = threading.Barrier(2)
        outcomes: dict[str, object] = {}

        def do_cancel() -> None:
            barrier.wait()
            try:
                executor.request_cancel(rec.id, "alice")
                outcomes["cancel"] = "ok"
            except ExecutionConflict as exc:  # pragma: no cover - 防御
                outcomes["cancel"] = f"rejected:{exc.reason.value}"

        def do_approve() -> None:
            barrier.wait()
            try:
                executor.grant_approval(rec.id, "alice", None)
                outcomes["approval"] = "granted"
            except ExecutionConflict as exc:
                outcomes["approval"] = f"rejected:{exc.reason.value}"

        threads = [threading.Thread(target=do_cancel),
                   threading.Thread(target=do_approve)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 取消一定成功（此刻执行尚未启动，取消必须当场生效）
        assert outcomes["cancel"] == "ok"
        # 审批只有两种合法结局：先获锁则授予成功（但不再执行），
        # 后获锁则被 409 拒绝；绝不允许“取消成功后又被批准执行”
        assert outcomes["approval"] in (
            "granted", f"rejected:{RejectReason.INVALID_STATE_TRANSITION.value}"
        )

    # 全部轮次的最终结论一致：已取消、无执行、无副作用
    assert executor.tick() is False
    entries = audit.read_all()
    for exec_id in exec_ids:
        final = store.get(exec_id)
        assert final.state == ExecutionState.CANCELLED
        assert final.finished_at is not None
        assert all(s.status == StepStatus.PENDING for s in final.steps)
        kinds = [e["kind"] for e in entries if e["execution_id"] == exec_id]
        assert kinds.count("run.cancelled") == 1
        assert "run.start" not in kinds
        assert "step.applied" not in kinds
        # 取消之后再批准一律 409
        with pytest.raises(ExecutionConflict):
            executor.grant_approval(exec_id, "alice", None)
    assert list(store._effects) == []


def test_repeated_cancel_idempotent_no_duplicate_audit(components):
    """重复取消：第二次落在终态上被拒，状态不变、不重复留痕。"""
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cx-dupe"))
    executor.request_cancel(rec.id, "alice")
    with pytest.raises(ExecutionConflict) as exc_info:
        executor.request_cancel(rec.id, "alice")
    assert exc_info.value.reason == RejectReason.INVALID_STATE_TRANSITION

    final = store.get(rec.id)
    assert final.state == ExecutionState.CANCELLED
    entries = [e for e in audit.read_all() if e["execution_id"] == rec.id]
    kinds = [e["kind"] for e in entries]
    assert kinds.count("cancel.requested") == 1
    assert kinds.count("run.cancelled") == 1


def test_cancel_failed_execution_keeps_applied_steps(components):
    """失败停机的处置取消：立即终态，已应用步骤不回滚、不再产生副作用。"""
    settings, store, _, executor, _ = components
    executor.policies[:] = [
        Policy(
            id="p-fail",
            match=MatchRule(event_type="disk_full"),
            actions=[
                ActionDef(name="restart_service", required_role="operator"),
                ActionDef(name="clear_disk_cache", required_role="operator",
                          params={"fail": True}),
            ],
        )
    ]
    rec, _ = executor.submit_event(Event(
        event_id="e-cx-failed", event_type="disk_full", source="host-1",
        severity="warning", submitted_by="carol"))
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.FAILED
    assert store.get(rec.id).steps[0].status == StepStatus.APPLIED

    executor.request_cancel(rec.id, "carol")
    final = store.get(rec.id)
    assert final.state == ExecutionState.CANCELLED
    assert final.finished_at is not None
    # 已执行成功的部分照旧不回滚；失败步骤保持原样，不再重试也不再执行
    assert final.steps[0].status == StepStatus.APPLIED
    assert final.steps[1].status == StepStatus.FAILED
    assert executor.tick() is False
    assert sorted(store._effects) == [f"{rec.id}:0"]
