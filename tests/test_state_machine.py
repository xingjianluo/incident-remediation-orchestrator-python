"""取消、超时、部分失败的状态机语义，以及状态不倒退。"""
from __future__ import annotations

from app.errors import ExecutionConflict
from app.schemas import Event, ExecutionState, RejectReason, StepStatus


def _disk_event(eid: str, user: str = "carol") -> Event:
    return Event(event_id=eid, event_type="disk_full", source="host-1",
                 severity="warning", submitted_by=user)


def _overload_event(eid: str) -> Event:
    return Event(event_id=eid, event_type="service_overload", source="app-1",
                 severity="critical", labels={"tier": "backend"}, submitted_by="carol")


def test_cancel_before_run_produces_no_effect(components):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_disk_event("e-cancel-1"))
    executor.request_cancel(rec.id, "carol")
    executor.tick()
    final = store.get(rec.id)
    assert final.state == ExecutionState.CANCELLED
    assert final.finished_at is not None
    assert all(s.status == StepStatus.PENDING for s in final.steps)
    assert list(store._effects) == []


def test_cancel_terminal_execution_rejected(components):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_disk_event("e-cancel-2"))
    executor.tick()  # completed
    assert store.get(rec.id).state == ExecutionState.COMPLETED
    try:
        executor.request_cancel(rec.id, "carol")
        raise AssertionError("expected conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    assert store.get(rec.id).state == ExecutionState.COMPLETED


def test_retry_only_allowed_from_failed(components):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_disk_event("e-retry-guard"))
    executor.tick()
    # completed 不能 retry
    try:
        executor.retry(rec.id, "carol")
        raise AssertionError("expected conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    assert store.get(rec.id).state == ExecutionState.COMPLETED
    # 不存在的执行
    try:
        executor.retry("exec-missing", "carol")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.EXECUTION_NOT_FOUND


def test_partial_failure_is_terminal_and_keeps_applied_steps(components):
    _, store, audit, executor, _ = components
    # overload-partial 策略第一个动作 fail 且 continue_on_failure
    rec, _ = executor.submit_event(_overload_event("e-partial"))
    executor.tick()
    final = store.get(rec.id)
    assert final.state == ExecutionState.PARTIAL_FAILED
    assert final.steps[0].status == StepStatus.FAILED
    assert final.steps[1].status == StepStatus.APPLIED
    # 终态：不能再取消或重试
    for action in (executor.request_cancel, executor.retry):
        try:
            action(rec.id, "carol")
            raise AssertionError("expected terminal conflict")
        except ExecutionConflict as exc:
            assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    kinds = {e["kind"] for e in audit.read_all()}
    assert "step.failed" in kinds
    assert "run.finished" in kinds


def test_timeout_marks_terminal_without_state_regression(components, clock):
    settings, store, _, executor, _ = components
    from app.schemas import ActionDef, MatchRule, Policy
    executor.policies[:] = [
        Policy(id="p-t", match=MatchRule(event_type="disk_full"),
               actions=[ActionDef(name="restart_service", required_role="operator",
                                  params={"fail": True})])
    ]
    rec, _ = executor.submit_event(_disk_event("e-timeout"))
    executor.tick()  # 首次失败，设置 deadline
    assert store.get(rec.id).state == ExecutionState.FAILED
    executor.retry(rec.id, "carol")
    # 超过总截止时间后再调度 => TIMED_OUT，且不重新执行
    clock.advance(settings.execution_timeout_seconds + 1)
    executor.tick()
    final = store.get(rec.id)
    assert final.state == ExecutionState.TIMED_OUT
    assert final.finished_at is not None
    assert list(store._effects) == []
    # 超时是终态
    try:
        executor.retry(rec.id, "carol")
        raise AssertionError("expected terminal conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION


def test_cancel_api_happy_path(client):
    c, executor = client
    resp = c.post("/events", json={
        "event_id": "e-cancel-api", "event_type": "disk_full",
        "source": "host-7", "severity": "warning", "submitted_by": "carol",
    })
    exec_id = resp.json()["execution"]["id"]
    cancelled = c.post(f"/executions/{exec_id}/cancel", json={"requested_by": "carol"})
    assert cancelled.status_code == 200
    executor.tick()
    final = c.get(f"/executions/{exec_id}").json()
    assert final["state"] == "cancelled"
