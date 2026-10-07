"""待审批处置的取消语义：

- 待审批（一个动作都未执行）时取消必须当场生效为 CANCELLED，无需再审批；
- 取消之后任何审批都不再起作用，且不产生任何动作副作用；
- 取消与审批并发时结论唯一：取消先生效则之后的批准无效；
  审批先生效（审批补齐）则取消被拒、按原计划继续执行；
- RUNNING/终态取消该拒就拒且状态不动；重复取消不搅乱状态、不重复留痕；
- 取消结论从对外查询状态与审计记录均可见。
"""
from __future__ import annotations

import threading

import pytest

from app.errors import ExecutionConflict
from app.schemas import Event, ExecutionState, RejectReason, StepStatus


def _dangerous_event(eid: str, user: str = "alice") -> Event:
    return Event(
        event_id=eid, event_type="security_intrusion", source="fw-1",
        severity="critical", submitted_by=user,
    )


def _disk_event(eid: str) -> Event:
    return Event(event_id=eid, event_type="disk_full", source="host-1",
                 severity="warning", submitted_by="carol")


# ---------- 场景 1：待审批取消立即终态、无需再审批 ----------

def test_cancel_awaiting_approval_is_immediate_and_final(components):
    _, store, audit, executor, _ = components
    rec, created = executor.submit_event(_dangerous_event("e-cancel-await-1"))
    assert created is True
    assert rec.state == ExecutionState.AWAITING_APPROVAL

    # 取消接口当场返回的就必须是已取消终态，而不是“取消成功但还挂着”
    cancelled = executor.request_cancel(rec.id, "alice")
    assert cancelled.state == ExecutionState.CANCELLED
    assert cancelled.finished_at is not None
    assert cancelled.cancel_requested is True
    assert cancelled.cancel_requested_by == "alice"

    # 对外查询同样是终态
    viewed = store.get(rec.id)
    assert viewed.state == ExecutionState.CANCELLED
    assert viewed.finished_at is not None

    # 之后再怎么审批都不起作用：授权直接被 409 拒绝
    with pytest.raises(ExecutionConflict) as exc:
        executor.grant_approval(rec.id, "alice", None)
    assert exc.value.reason == RejectReason.INVALID_STATE_TRANSITION

    # worker 再怎么 tick 也不会把它推走
    assert executor.tick() is False
    final = store.get(rec.id)
    assert final.state == ExecutionState.CANCELLED
    assert all(s.status == StepStatus.PENDING for s in final.steps)
    # 关键：取消后没有任何动作被真正执行
    assert list(store._effects) == []

    # 留痕可追溯：一次 cancel.requested + 一次 run.cancelled（awaiting -> cancelled）
    entries = [e for e in audit.read_all() if e["execution_id"] == rec.id]
    trans = [e for e in entries if e["kind"] == "run.cancelled"]
    assert len(trans) == 1
    assert trans[0]["from_state"] == "awaiting_approval"
    assert trans[0]["to_state"] == "cancelled"
    assert trans[0]["actor"] == "alice"
    requested = [e for e in entries if e["kind"] == "cancel.requested"]
    assert len(requested) == 1


def test_cancel_awaiting_approval_takes_effect_without_approval_over_api(client):
    """对外 HTTP 视角：取消响应体即为 cancelled，无需任何审批介入。"""
    c, executor = client
    resp = c.post("/events", json={
        "event_id": "e-cancel-await-api", "event_type": "security_intrusion",
        "source": "fw-1", "severity": "critical", "submitted_by": "alice",
    })
    exec_id = resp.json()["execution"]["id"]
    assert resp.json()["execution"]["state"] == "awaiting_approval"

    cancelled = c.post(f"/executions/{exec_id}/cancel", json={"requested_by": "alice"})
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    assert cancelled.json()["finished_at"] is not None

    # 不调任何审批接口，对外查询就是终态
    viewed = c.get(f"/executions/{exec_id}").json()
    assert viewed["state"] == "cancelled"

    # 之后批准返回 409，且 tick 不会执行
    late = c.post(f"/executions/{exec_id}/approvals", json={"granted_by": "alice"})
    assert late.status_code == 409
    assert executor.tick() is False
    assert viewed["steps"][0]["status"] == "pending"


# ---------- 场景 2：取消与审批并发，结论唯一 ----------

def test_cancel_wins_when_approval_still_missing(components):
    """取消先生效（审批仍缺失）：之后的批准永不生效，无副作用。"""
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-race-cancel-wins"))

    executor.request_cancel(rec.id, "alice")
    # 取消之后再批准：直接冲突拒绝
    with pytest.raises(ExecutionConflict) as exc:
        executor.grant_approval(rec.id, "alice", None)
    assert exc.value.reason == RejectReason.INVALID_STATE_TRANSITION

    assert store.get(rec.id).state == ExecutionState.CANCELLED
    assert executor.tick() is False
    assert list(store._effects) == []
    # 唯一一次取消迁移，绝无 approval.complete / step.applied
    kinds = [e["kind"] for e in audit.read_all() if e["execution_id"] == rec.id]
    assert kinds.count("run.cancelled") == 1
    assert "approval.complete" not in kinds
    assert "step.applied" not in kinds


def test_approval_wins_when_completed_first(components):
    """审批补齐先于取消：取消被拒且状态不动，随后按原计划执行到底。"""
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-race-approval-wins"))

    # 审批先生效（危险动作授权已补齐，仍处 awaiting_approval，尚未起跑）
    executor.grant_approval(rec.id, "alice", None)
    # 此刻取消必须被拒，状态不能被改动
    with pytest.raises(ExecutionConflict) as exc:
        executor.request_cancel(rec.id, "alice")
    assert exc.value.reason == RejectReason.INVALID_STATE_TRANSITION
    viewed = store.get(rec.id)
    assert viewed.state == ExecutionState.AWAITING_APPROVAL
    assert viewed.cancel_requested is False

    # 按原计划继续执行
    assert executor.tick() is True
    done = store.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    assert done.steps[0].status == StepStatus.APPLIED
    assert len(store._effects) == 1


def test_concurrent_cancel_and_approval_has_single_outcome(components):
    """真并发多轮：每一轮都只能收敛到唯一结论，状态与留痕一致、无副作用矛盾。

    取消先拿到锁 -> cancelled 且无任何副作用；
    审批先补齐 -> 取消冲突，tick 后 completed 且恰一次副作用。
    两种裁决都必须在多轮中出现过（锁竞争双向都真实发生）。
    """
    _, store, audit, executor, _ = components

    def _do_cancel(start: threading.Event, target_id: str, result: dict) -> None:
        start.wait()
        try:
            executor.request_cancel(target_id, "alice")
            result["cancel"] = "ok"
        except ExecutionConflict:
            result["cancel"] = "rejected"

    def _do_approve(start: threading.Event, target_id: str, result: dict) -> None:
        start.wait()
        try:
            executor.grant_approval(target_id, "alice", None)
            result["approval"] = "ok"
        except ExecutionConflict:
            result["approval"] = "rejected"

    cancel_won = 0
    approval_won = 0
    rounds = 60
    for i in range(rounds):
        eid = f"e-race-mix-{i}"
        rec, _ = executor.submit_event(_dangerous_event(eid))
        # 用主线程 set() 放行，避免 Barrier 总是偏向最后到达线程
        start = threading.Event()
        result: dict[str, str] = {}

        t1 = threading.Thread(
            target=_do_cancel, args=(start, rec.id, result)
        )
        t2 = threading.Thread(
            target=_do_approve, args=(start, rec.id, result)
        )
        t1.start(); t2.start()
        start.set()
        t1.join(); t2.join()
        executor.tick()
        final = store.get(rec.id)

        if result["cancel"] == "ok":
            cancel_won += 1
            # 取消生效：之后批准必然被拒，绝无副作用
            assert result["approval"] == "rejected"
            assert final.state == ExecutionState.CANCELLED
            assert store.effect_exists(f"{rec.id}:0") is None
            assert all(s.status == StepStatus.PENDING for s in final.steps)
        else:
            approval_won += 1
            # 审批先生效：取消被拒，按计划执行
            assert result["cancel"] == "rejected"
            assert result["approval"] == "ok"
            assert final.state == ExecutionState.COMPLETED
            assert store.effect_exists(f"{rec.id}:0") is not None

        # 任一裁决下，取消迁移至多一条
        kinds = [
            e["kind"] for e in audit.read_all()
            if e["execution_id"] == rec.id
        ]
        assert kinds.count("run.cancelled") <= 1

    assert cancel_won > 0, "锁竞争中取消从未赢过，未覆盖取消先生效路径"
    assert approval_won > 0, "锁竞争中审批从未赢过，未覆盖审批先生效路径"


# ---------- 边界：RUNNING/终态拒绝且状态不动；重复取消幂等 ----------

def test_cancel_terminal_execution_rejected_without_state_change(components):
    """已经结束（completed）的处置取消：409 拒绝，状态与字段一律不动。

    RUNNING 的协作取消语义（在尚未生效的动作边界收敛、已生效不回滚）
    由 tests/test_recovery.py::test_cancel_during_recovery_does_not_replay 覆盖。
    """
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_disk_event("e-cancel-done"))
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.COMPLETED
    finished_at = store.get(rec.id).finished_at

    with pytest.raises(ExecutionConflict) as exc:
        executor.request_cancel(rec.id, "carol")
    assert exc.value.reason == RejectReason.INVALID_STATE_TRANSITION
    again = store.get(rec.id)
    assert again.state == ExecutionState.COMPLETED
    assert again.cancel_requested is False
    assert again.finished_at == finished_at
    # 拒绝不留任何取消痕迹
    assert not [
        e for e in audit.read_all() if e["execution_id"] == rec.id
        and e["kind"].startswith("cancel")
    ]


def test_cancel_parked_failed_execution_is_immediate(components, clock):
    """停在 FAILED 等待人工重试的处置：取消立即终态，之后不可重试；
    worker 也不会再自动捞起。已成功步骤保留不回滚。"""
    _, store, audit, executor, _ = components
    from app.schemas import ActionDef, MatchRule, Policy
    executor.policies[:] = [
        Policy(
            id="p-fail-cancel",
            match=MatchRule(event_type="disk_full"),
            actions=[
                ActionDef(name="clear_disk_cache", required_role="operator"),
                ActionDef(name="restart_service", required_role="operator",
                          params={"fail": True}),
            ],
        )
    ]
    rec, _ = executor.submit_event(_disk_event("e-failed-cancel"))
    executor.tick()
    parked = store.get(rec.id)
    assert parked.state == ExecutionState.FAILED
    assert parked.steps[0].status == StepStatus.APPLIED  # 已生效部分保留
    assert len(store._effects) == 1

    cancelled = executor.request_cancel(rec.id, "carol")
    assert cancelled.state == ExecutionState.CANCELLED
    assert cancelled.finished_at is not None
    # 已生效动作不回滚
    assert store.get(rec.id).steps[0].status == StepStatus.APPLIED
    assert len(store._effects) == 1
    # 之后显式重试被拒（终态），worker 也不会再碰它
    with pytest.raises(ExecutionConflict) as exc:
        executor.retry(rec.id, "carol")
    assert exc.value.reason == RejectReason.INVALID_STATE_TRANSITION
    clock.advance(100)
    assert executor.tick() is False
    assert store.get(rec.id).state == ExecutionState.CANCELLED
    trans = [
        e for e in audit.read_all()
        if e["execution_id"] == rec.id and e["kind"] == "run.cancelled"
    ]
    assert len(trans) == 1
    assert trans[0]["from_state"] == "failed"


def test_duplicate_cancel_while_running_does_not_duplicate_audit(components):
    """RUNNING 下取消请求重复到达：只留一次 cancel.requested。"""
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_disk_event("e-running-dup-cancel"))
    # 第一次真实取消（白盒把执行置为 RUNNING，模拟执行中收到取消）
    parked = store.get(rec.id)
    parked.state = ExecutionState.RUNNING
    store.save_execution(parked)
    executor.request_cancel(rec.id, "carol")
    assert store.get(rec.id).state == ExecutionState.RUNNING
    before = [
        e for e in audit.read_all()
        if e["execution_id"] == rec.id and e["kind"] == "cancel.requested"
    ]
    assert len(before) == 1

    # 重复请求：幂等返回，不新增留痕、不改状态
    again = executor.request_cancel(rec.id, "carol")
    assert again.state == ExecutionState.RUNNING
    after = [
        e for e in audit.read_all()
        if e["execution_id"] == rec.id and e["kind"] == "cancel.requested"
    ]
    assert len(after) == 1


def test_duplicate_cancel_does_not_rewrite_state_or_audit(components):
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cancel-dup"))

    first = executor.request_cancel(rec.id, "alice")
    finished_at = first.finished_at
    # 重复取消：幂等返回同一条终态记录
    second = executor.request_cancel(rec.id, "alice")
    third = executor.request_cancel(rec.id, "alice")
    assert second.state == ExecutionState.CANCELLED
    assert third.state == ExecutionState.CANCELLED
    assert second.finished_at == finished_at
    assert third.finished_at == finished_at
    assert store.get(rec.id).state == ExecutionState.CANCELLED

    entries = [e for e in audit.read_all() if e["execution_id"] == rec.id]
    assert [e["kind"] for e in entries].count("cancel.requested") == 1
    assert [e["kind"] for e in entries].count("run.cancelled") == 1
    assert list(store._effects) == []


def test_cancel_awaiting_approval_visible_in_list_and_record(components):
    """取消结论必须对外可见，不只是请求里记一笔。"""
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_dangerous_event("e-cancel-visible"))
    executor.request_cancel(rec.id, "alice")

    listed = {r.id: r for r in store.all_executions()}
    assert listed[rec.id].state == ExecutionState.CANCELLED
    assert listed[rec.id].finished_at is not None
