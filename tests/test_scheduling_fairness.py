"""调度公平性：待审批/已结束的执行不拖累后续普通事件；并发与重复提交只有一次副作用。"""
from __future__ import annotations

import threading

from app.schemas import Event, ExecutionState


def _disk_event(eid: str) -> Event:
    return Event(event_id=eid, event_type="disk_full", source="host-1",
                 severity="warning", submitted_by="carol")


def _dangerous_event(eid: str) -> Event:
    return Event(event_id=eid, event_type="security_intrusion", source="host-9",
                 severity="critical", submitted_by="alice")


def test_awaiting_approval_does_not_block_normal_events(components, clock):
    """挂着待审批的危险事件时，后续普通事件仍按提交顺序推进。"""
    _, store, _, executor, _ = components
    danger, _ = executor.submit_event(_dangerous_event("e-danger-1"))
    assert danger.state == ExecutionState.AWAITING_APPROVAL

    clock.advance(1)
    normal1, _ = executor.submit_event(_disk_event("e-normal-1"))
    clock.advance(1)
    normal2, _ = executor.submit_event(_disk_event("e-normal-2"))

    # 每一次 tick 都在推进普通事件，而不是卡在待审批事件上空转
    assert executor.tick() is True
    assert store.get(normal1.id).state == ExecutionState.COMPLETED
    assert executor.tick() is True
    assert store.get(normal2.id).state == ExecutionState.COMPLETED
    # 危险事件保持待审批，不被跳过也不被强推
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
    # 普通事件按提交顺序完成
    assert store.get(normal1.id).finished_at <= store.get(normal2.id).finished_at

    # 审批补齐后，危险事件自身也能继续推进
    executor.grant_approval(danger.id, "alice", None)
    assert executor.tick() is True
    assert store.get(danger.id).state == ExecutionState.COMPLETED


def test_terminal_records_do_not_block_scheduling(components):
    """队列里存在已结束的执行时，新事件照常推进。"""
    _, store, _, executor, _ = components
    done, _ = executor.submit_event(_disk_event("e-done"))
    executor.tick()
    assert store.get(done.id).state == ExecutionState.COMPLETED

    cancelled, _ = executor.submit_event(_disk_event("e-cancelled"))
    executor.request_cancel(cancelled.id, "carol")
    executor.tick()
    assert store.get(cancelled.id).state == ExecutionState.CANCELLED

    later, _ = executor.submit_event(_disk_event("e-later"))
    assert executor.tick() is True
    assert store.get(later.id).state == ExecutionState.COMPLETED


def test_concurrent_duplicate_submission_single_execution(components):
    """多线程并发提交同一事件：只建一条执行、只有一次有效副作用。"""
    _, store, _, executor, _ = components
    results = []
    barrier = threading.Barrier(8)

    def submit():
        barrier.wait()
        results.append(executor.submit_event(_disk_event("e-dup")))

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for _, created in results if created) == 1
    assert len({rec.id for rec, _ in results}) == 1
    assert len(store.all_executions()) == 1

    executor.tick()
    rec = store.get(results[0][0].id)
    assert rec.state == ExecutionState.COMPLETED
    # 两个步骤各一次副作用，绝无重复
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]


def test_concurrent_mixed_events_each_exactly_once(components):
    """多事件并发提交且夹杂重复提交：每个事件恰好一条执行、一份副作用。"""
    _, store, _, executor, _ = components
    event_ids = [f"e-mix-{i}" for i in range(5)]
    barrier = threading.Barrier(len(event_ids) * 3)

    def submit(eid: str):
        barrier.wait()
        executor.submit_event(_disk_event(eid))

    threads = [
        threading.Thread(target=submit, args=(eid,))
        for eid in event_ids for _ in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(store.all_executions()) == len(event_ids)
    while executor.tick():
        pass
    for rec in store.all_executions():
        assert rec.state == ExecutionState.COMPLETED
        assert store.effect_exists(f"{rec.id}:0") is not None
        assert store.effect_exists(f"{rec.id}:1") is not None
    assert len(store._effects) == len(event_ids) * 2


def test_in_flight_execution_no_state_regression_on_resubmit(components):
    """处理到一半的事件被重复提交/非法重试时，状态不倒退、不重复建单。"""
    _, store, _, executor, _ = components
    danger, _ = executor.submit_event(_dangerous_event("e-inflight"))
    assert danger.state == ExecutionState.AWAITING_APPROVAL

    # 重复提交返回同一条记录，状态保持
    again, created = executor.submit_event(_dangerous_event("e-inflight"))
    assert created is False
    assert again.id == danger.id
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
    assert len(store.all_executions()) == 1

    # 未 FAILED 的执行不允许 retry（非法迁移被拒绝，状态不变）
    from app.errors import ExecutionConflict
    from app.schemas import RejectReason
    try:
        executor.retry(danger.id, "alice")
        raise AssertionError("expected conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
