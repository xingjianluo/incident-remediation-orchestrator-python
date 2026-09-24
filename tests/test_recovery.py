"""执行中故障重启：恢复到确定状态，副作用恰好一次，超时/部分失败不重复执行。"""
from __future__ import annotations

from remediation.actions import SimulatedCrash
from remediation.authz import Actor
from remediation.orchestrator import Orchestrator
from remediation.actions import ActionRegistry
from remediation.audit import AuditTrail
from remediation.authz import AuthzService
from remediation.policies import PolicyEngine
from remediation.storage import Storage

OPERATOR = Actor.parse("op1", "operator")
ADMIN = Actor.parse("root", "admin")


def _new_orchestrator(paths, policy_file):
    storage = Storage(str(paths / "data" / "test.db"))
    storage.init_db()
    engine = PolicyEngine.from_file(str(policy_file))
    registry = ActionRegistry(str(paths / "effects"))
    registry.register_defaults()
    return Orchestrator(
        storage, engine, registry,
        AuthzService(approval_ttl_seconds=300),
        AuditTrail(storage), step_timeout_seconds=30,
    ), storage


def test_crash_after_side_effect_then_recovery_exactly_once(
    components, paths, policy_file
):
    orch = components["orchestrator"]
    # 先审批进入执行；在第二个（危险）动作副作用完成后、状态持久化前崩溃
    orch.submit(
        {"event_id": "crash-1", "source": "host-a",
         "alert_type": "disk_full", "severity": "high"},
        OPERATOR,
    )
    components["registry"].crash_after.add("restart")
    try:
        orch.approve("crash-1", ADMIN)
        raise AssertionError("应当抛出 SimulatedCrash")
    except SimulatedCrash:
        pass

    effects_dir = paths / "effects" / "crash-1"
    # 两个动作的副作用均已落盘
    assert (effects_dir / "marker.txt").read_text(encoding="utf-8") == "go"
    assert (effects_dir / "restart-log-agent.json").exists()

    # 模拟进程重启：全新编排器实例打开同一数据库
    orch2, storage2 = _new_orchestrator(paths, policy_file)
    recovered = orch2.recover_all()
    assert recovered == 1
    status = orch2.get_status("crash-1")
    # 重启后动作重放为幂等产物，执行收敛到 COMPLETED，completed 不重复
    assert status["state"] == "COMPLETED"
    assert status["completed_actions"] == ["mark", "restart"]

    # 每步只有一份产物文件，无 .tmp 残留
    assert sorted(p.name for p in effects_dir.iterdir() if p.is_file()) == [
        "marker.txt", "restart-log-agent.json",
    ]
    storage2.close()


def test_recovery_completes_safe_flow(components, paths, policy_file):
    orch = components["orchestrator"]
    # auto-noop 是安全动作，直接执行；这里改用注入崩溃在 noop 后验证恢复完成
    components["registry"].crash_after.add("ack")
    try:
        orch.submit(
            {"event_id": "crash-2", "source": "host-a",
             "alert_type": "anything", "severity": "low"},
            OPERATOR,
        )
        raise AssertionError("应当抛出 SimulatedCrash")
    except SimulatedCrash:
        pass

    orch2, storage2 = _new_orchestrator(paths, policy_file)
    assert orch2.recover_all() == 1
    status = orch2.get_status("crash-2")
    assert status["state"] == "COMPLETED"
    assert status["completed_actions"] == ["ack"]
    storage2.close()


def test_partial_failure_is_terminal_and_no_reexecution(orchestrator, components):
    view = orchestrator.submit(
        {"event_id": "pf-1", "source": "host-a",
         "alert_type": "flaky", "severity": "high"},
        OPERATOR,
    )
    assert view["state"] == "PARTIALLY_FAILED"
    assert view["completed_actions"] == ["ok-step"]
    assert "fail-step" in (view["last_error"] or "")

    # 重试提交：终态保持，已完成步骤不重复
    again = orchestrator.submit(
        {"event_id": "pf-1", "source": "host-a",
         "alert_type": "flaky", "severity": "high"},
        OPERATOR,
    )
    assert again["duplicate"] is True
    assert again["state"] == "PARTIALLY_FAILED"
    assert again["completed_actions"] == ["ok-step"]
    files = list((components["paths"] / "effects" / "pf-1").glob("*"))
    assert [p.name for p in files] == ["ok.txt"]


def test_timeout_terminal(components, paths, policy_file):
    # 用极小 step 超时构造 TIMED_OUT
    storage = Storage(str(paths / "data" / "timeout.db"))
    storage.init_db()
    engine = PolicyEngine.from_file(str(policy_file))
    registry = ActionRegistry(str(paths / "effects-timeout"))
    registry.register_defaults()
    orch = Orchestrator(
        storage, engine, registry,
        AuthzService(approval_ttl_seconds=300),
        AuditTrail(storage), step_timeout_seconds=0,
    )
    view = orch.submit(
        {"event_id": "to-1", "source": "host-a",
         "alert_type": "anything", "severity": "low"},
        OPERATOR,
    )
    # 截止时间已过：进入 RUNNING 前检查 -> TIMED_OUT（无副作用）
    assert view["state"] == "TIMED_OUT"
    assert view["completed_actions"] == []
    # 取消/审批终态均拒绝
    from remediation.errors import StateError

    try:
        orch.cancel("to-1", OPERATOR)
        raise AssertionError("终态不可取消")
    except StateError as exc:
        assert exc.reason.value == "ILLEGAL_STATE"
    storage.close()
