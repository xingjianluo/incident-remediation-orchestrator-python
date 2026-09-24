"""权限与审批边界：未授权/权限不足/审批过期必须拒绝且不改变状态。"""
from __future__ import annotations

import time

import pytest

from remediation.authz import Actor
from remediation.errors import AuthzError, StateError


def _event(event_id: str, alert_type: str = "service_down", source: str = "x") -> dict:
    return {"event_id": event_id, "source": source,
            "alert_type": alert_type, "severity": "high"}


def test_submit_requires_identity(orchestrator):
    with pytest.raises(AuthzError) as exc:
        orchestrator.submit(_event("a1"), None)
    assert exc.value.reason.value == "UNAUTHENTICATED"
    assert orchestrator.storage.get_execution("a1") is None


def test_role_hierarchy_admin_implies_operator():
    admin = Actor.parse("root", "admin")
    operator = Actor.parse("op", "operator")
    assert admin.has_role("operator") and admin.has_role("admin")
    assert operator.has_role("viewer")
    assert not operator.has_role("admin")


def test_operator_cannot_approve_dangerous_action(orchestrator):
    orchestrator.submit(_event("a2"), Actor.parse("op1", "operator"))
    before = orchestrator.get_status("a2")
    with pytest.raises(AuthzError) as exc:
        orchestrator.approve("a2", Actor.parse("op2", "operator"))
    assert exc.value.reason.value == "PERMISSION_DENIED"
    after = orchestrator.get_status("a2")
    # 拒绝审批不改变执行状态
    assert after["state"] == before["state"] == "WAITING_APPROVAL"
    assert after["approver"] is None and after["approval_seq"] == 0


def test_viewer_cannot_cancel(orchestrator):
    orchestrator.submit(_event("a3"), Actor.parse("op1", "operator"))
    with pytest.raises(AuthzError) as exc:
        orchestrator.cancel("a3", Actor.parse("v", "viewer"))
    assert exc.value.reason.value in ("FORBIDDEN", "PERMISSION_DENIED")
    assert orchestrator.get_status("a3")["state"] == "WAITING_APPROVAL"


def test_operator_can_cancel_and_terminal_is_immutable(orchestrator):
    orchestrator.submit(_event("a4"), Actor.parse("op1", "operator"))
    view = orchestrator.cancel("a4", Actor.parse("op2", "operator"))
    assert view["state"] == "CANCELLED"
    with pytest.raises(StateError) as exc:
        orchestrator.cancel("a4", Actor.parse("op2", "operator"))
    assert exc.value.reason.value == "ILLEGAL_STATE"
    assert orchestrator.get_status("a4")["state"] == "CANCELLED"


def test_approve_missing_execution(orchestrator):
    with pytest.raises(StateError) as exc:
        orchestrator.approve("ghost", Actor.parse("root", "admin"))
    assert exc.value.reason.value == "EXECUTION_NOT_FOUND"


def test_approval_expires_blocks_execution(components, paths, policy_file):
    from remediation.orchestrator import Orchestrator
    from remediation.actions import ActionRegistry
    from remediation.audit import AuditTrail
    from remediation.authz import AuthzService
    from remediation.policies import PolicyEngine
    from remediation.storage import Storage

    storage = Storage(str(paths / "data" / "ttl.db"))
    storage.init_db()
    engine = PolicyEngine.from_file(str(policy_file))
    registry = ActionRegistry(str(paths / "effects-ttl"))
    registry.register_defaults()
    ttl = 1  # 1 秒
    orch = Orchestrator(
        storage, engine, registry,
        AuthzService(approval_ttl_seconds=ttl),
        AuditTrail(storage), step_timeout_seconds=30,
    )
    orch.submit(_event("ttl-1"), Actor.parse("op1", "operator"))
    approved = orch.approve("ttl-1", Actor.parse("root", "admin"))
    assert approved["state"] == "COMPLETED"

    # 另一事件：审批后等待超过 TTL，再触发恢复 -> REJECTED(APPROVAL_EXPIRED)
    orch.submit(_event("ttl-2"), Actor.parse("op1", "operator"))
    rec = storage.get_execution("ttl-2")
    rec.approver = "root"
    rec.approval_expires_at = time.time() - 1
    rec.approval_seq = 1
    storage.save_execution(rec, rec.version)
    # 手工把审批写进去但状态仍为等待审批（模拟审批通过后 TTL 过期再被调度）
    n = orch.recover_all()
    assert n >= 1
    status = orch.get_status("ttl-2")
    assert status["state"] == "REJECTED"
    assert status["reject_reason"] == "APPROVAL_EXPIRED"
    # 过期审批未产生危险动作副作用
    assert not (paths / "effects-ttl" / "ttl-2").exists()
    storage.close()


def test_audit_monotonic_and_complete(orchestrator):
    orchestrator.submit(_event("au-1"), Actor.parse("op1", "operator"))
    try:
        orchestrator.approve("au-1", Actor.parse("op2", "operator"))
    except AuthzError:
        pass
    orchestrator.cancel("au-1", Actor.parse("op3", "operator"))
    history = orchestrator.audit.history("au-1")
    seqs = [e["seq"] for e in history]
    assert seqs == list(range(1, len(seqs) + 1)), "审计 seq 必须连续不乱序"
    transitions = [e["transition"] for e in history]
    assert transitions[0] == "PENDING"
    assert "WAITING_APPROVAL" in transitions
    assert "APPROVE_DENIED" in transitions
    assert transitions[-1] == "CANCELLED"
    # 拒绝审批的原因可追溯
    denied = [e for e in history if e["transition"] == "APPROVE_DENIED"]
    assert denied and denied[0]["reason"] == "PERMISSION_DENIED"


def test_concurrent_audit_no_gap_no_duplicate(orchestrator):
    import threading

    orchestrator.submit(_event("au-2"), Actor.parse("op1", "operator"))

    def deny() -> None:
        try:
            orchestrator.approve("au-2", Actor.parse("op", "operator"))
        except AuthzError:
            pass

    threads = [threading.Thread(target=deny) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    history = orchestrator.audit.history("au-2")
    seqs = [e["seq"] for e in history]
    assert seqs == list(range(1, len(seqs) + 1))
    assert len(seqs) == len(set(seqs))
