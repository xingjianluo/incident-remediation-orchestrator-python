"""危险动作的权限与审批边界：拒绝不得改变执行状态，审批过期必须阻断。"""
from __future__ import annotations

from app.errors import AuthorizationError
from app.schemas import Event, ExecutionState, RejectReason, StepStatus


def _security_event(event_id: str, user: str | None = "alice") -> Event:
    return Event(
        event_id=event_id, event_type="security_intrusion", source="fw-1",
        severity="critical", submitted_by=user,
    )


def test_unauthenticated_submission_rejected_without_state(components):
    _, store, _, executor, _ = components
    # 无 submitted_by
    event = Event(event_id="e-anon", event_type="security_intrusion",
                  source="fw-1", severity="critical")
    try:
        executor.submit_event(event)
        raise AssertionError("expected AuthorizationError")
    except AuthorizationError as exc:
        assert exc.reason == RejectReason.UNAUTHORIZED
    assert store.get_by_event("e-anon") is None  # 不落任何执行状态

    # 未登记用户
    event2 = Event(event_id="e-stranger", event_type="security_intrusion",
                   source="fw-1", severity="critical", submitted_by="mallory")
    try:
        executor.submit_event(event2)
        raise AssertionError("expected AuthorizationError")
    except AuthorizationError as exc:
        assert exc.reason == RejectReason.UNAUTHORIZED
    assert store.get_by_event("e-stranger") is None


def test_insufficient_role_rejected_without_state(components):
    _, store, _, executor, _ = components
    # carol 是 operator，无权执行 admin 危险动作
    try:
        executor.submit_event(_security_event("e-lowrole", "carol"))
        raise AssertionError("expected AuthorizationError")
    except AuthorizationError as exc:
        assert exc.reason == RejectReason.FORBIDDEN
        assert exc.details["required_role"] == "admin"
    assert store.get_by_event("e-lowrole") is None


def test_viewer_denied_over_api(client):
    c, _ = client
    resp = c.post("/events", json={
        "event_id": "e-viewer", "event_type": "security_intrusion",
        "source": "fw-1", "severity": "critical", "submitted_by": "dave",
    })
    assert resp.status_code == 403
    assert resp.json()["reason"] == RejectReason.FORBIDDEN.value
    # 没有执行被创建
    assert c.get("/executions").json()["executions"] == []


def test_dangerous_action_waits_for_approval(components):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_security_event("e-need-approval"))
    assert rec.state == ExecutionState.AWAITING_APPROVAL
    executor.tick()
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.AWAITING_APPROVAL  # 无审批不推进
    assert rec.steps[0].status == StepStatus.PENDING
    assert list(store._effects) == []  # 未授权不产生任何副作用


def test_non_approver_role_cannot_grant(components):
    _, store, audit, executor, _ = components
    rec, _ = executor.submit_event(_security_event("e-approver"))
    # carol 无 approve 能力
    try:
        executor.grant_approval(rec.id, "carol", None)
        raise AssertionError("expected AuthorizationError")
    except AuthorizationError as exc:
        assert exc.reason == RejectReason.APPROVER_NOT_ALLOWED
    # 状态不变、无副作用
    assert store.get(rec.id).state == ExecutionState.AWAITING_APPROVAL
    assert list(store._effects) == []
    assert any(e["kind"] == "approval.denied" for e in audit.read_all())


def test_expired_approval_blocks_and_preserves_state(components, clock):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_security_event("e-expired"))
    # 授予一个立即过期的审批
    executor.grant_approval(rec.id, "alice", ttl_seconds=-1)
    clock.advance(1)
    executor.tick()  # 找到过期审批 => 仍挂起，且不得执行
    blocked = store.get(rec.id)
    assert blocked.state == ExecutionState.AWAITING_APPROVAL
    assert blocked.steps[0].status == StepStatus.PENDING
    assert list(store._effects) == []
    # 重新授权（有效期内）后可完成
    executor.grant_approval(rec.id, "alice", ttl_seconds=600)
    executor.tick()
    done = store.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    assert done.steps[0].status == StepStatus.APPLIED
    assert len(store._effects) == 1


def test_approval_is_consumed_once(components):
    _, store, _, executor, _ = components
    rec, _ = executor.submit_event(_security_event("e-consume"))
    approval = executor.grant_approval(rec.id, "alice", None)
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.COMPLETED
    stored = next(a for a in store._state.approvals if a.id == approval.id)
    assert stored.consumed is True


def test_approval_denied_for_unknown_execution(client):
    c, _ = client
    resp = c.post("/executions/nope/approvals", json={"granted_by": "alice"})
    assert resp.status_code == 404
    assert resp.json()["reason"] == RejectReason.EXECUTION_NOT_FOUND.value


def test_authorization_does_not_mutate_execution_state(client):
    c, executor = client
    # 正常建一个待审批执行
    resp = c.post("/events", json={
        "event_id": "e-guard", "event_type": "security_intrusion",
        "source": "fw-1", "severity": "critical", "submitted_by": "alice",
    })
    exec_id = resp.json()["execution"]["id"]
    # 越权审批（viewer）必须 403
    denied = c.post(f"/executions/{exec_id}/approvals", json={"granted_by": "dave"})
    assert denied.status_code == 403
    assert denied.json()["reason"] == RejectReason.APPROVER_NOT_ALLOWED.value
    # 再次查询状态仍为 awaiting_approval
    again = c.get(f"/executions/{exec_id}").json()
    assert again["state"] == "awaiting_approval"
    # 对已完成执行尝试审批返回状态冲突
    c.post(f"/executions/{exec_id}/approvals", json={"granted_by": "alice"})
    # worker 未启动（测试夹具），手动驱动一次
    executor.tick()
    conflict = c.post(f"/executions/{exec_id}/approvals", json={"granted_by": "alice"})
    assert conflict.status_code == 409
    assert conflict.json()["reason"] == RejectReason.INVALID_STATE_TRANSITION.value
