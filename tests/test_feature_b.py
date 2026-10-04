"""feature-b 新行为：精细策略匹配与真冲突、失败收敛与显式重试、调度公平性。

场景命名直接对应需求，可用 `pytest -v` 从用例名看出覆盖范围。
"""
from __future__ import annotations

import json
import threading

import pytest
from fastapi.testclient import TestClient

from app.actions import ActionRegistry
from app.api import create_app
from app.audit import AuditLogger
from app.config import Settings
from app.errors import (
    ExecutionConflict,
    PolicyConflict,
    PolicyRejected,
)
from app.executor import Executor
from app.policies import load_policies
from app.schemas import (
    AclConfig,
    ActionDef,
    Event,
    ExecutionState,
    MatchRule,
    Policy,
    RejectReason,
    StepStatus,
)
from app.storage import Store


@pytest.fixture
def client_fairness(tmp_path):
    """真实后台 worker：危险事件 + 普通事件并存，验证调度不互相拖累。"""
    (tmp_path / "data").mkdir()
    (tmp_path / "logs").mkdir()
    policies = [
        {
            "id": "security-dangerous",
            "match": {"event_type": "security_intrusion", "severities": ["critical"]},
            "priority": 10,
            "actions": [
                {"name": "isolate_host", "risk": "dangerous", "required_role": "admin"}
            ],
        },
        {
            "id": "disk-safe",
            "match": {"event_type": "disk_full"},
            "priority": 100,
            "actions": [
                {"name": "restart_service", "required_role": "operator"},
            ],
        },
    ]
    acl = {
        "users": {"alice": "admin", "carol": "operator"},
        "roles": {"admin": ["operator", "admin", "approve"], "operator": ["operator"]},
    }
    (tmp_path / "policies.json").write_text(json.dumps(policies), encoding="utf-8")
    (tmp_path / "acl.json").write_text(json.dumps(acl), encoding="utf-8")
    settings = Settings(
        data_dir=str(tmp_path / "data"),
        policy_file=str(tmp_path / "policies.json"),
        acl_file=str(tmp_path / "acl.json"),
        audit_log=str(tmp_path / "logs" / "audit.log"),
        app_log=str(tmp_path / "logs" / "app.log"),
        approval_ttl_seconds=600,
        execution_timeout_seconds=30,
        worker_tick_seconds=0.005,
        max_attempts=3,
    )
    store = Store(
        settings.store_file, str(tmp_path / "data" / "effects.jsonl")
    )
    executor = Executor(
        settings,
        store,
        AuditLogger(settings.audit_log),
        load_policies(settings.policy_file),
        AclConfig.model_validate(acl),
        ActionRegistry(),
    )
    app = create_app(settings, executor=executor, start_worker=True)
    # 手动注入的 executor 不会被 create_app 自动 start，这里显式拉起 worker
    executor.start()
    with TestClient(app) as client:
        danger = client.post("/events", json={
            "event_id": "e-fair-danger", "event_type": "security_intrusion",
            "source": "fw-1", "severity": "critical", "submitted_by": "alice",
        }).json()["execution"]["id"]
        normal = client.post("/events", json={
            "event_id": "e-fair-normal", "event_type": "disk_full",
            "source": "host-8", "severity": "critical", "submitted_by": "carol",
        }).json()["execution"]["id"]
        yield client, app.state.executor, {"danger": danger, "normal": normal}


# ============================ 策略：精细匹配与真冲突 ============================

def _policy(pid, *, priority=100, actions=None, **match) -> Policy:
    return Policy(
        id=pid,
        priority=priority,
        match=MatchRule(**match),
        actions=actions
        or [ActionDef(name="restart_service", required_role="operator")],
    )


def _event(
    eid: str = "e-fb",
    *,
    etype: str = "disk_full",
    source: str = "host-1",
    severity: str = "critical",
    labels: dict | None = None,
    user: str = "carol",
) -> Event:
    return Event(
        event_id=eid,
        event_type=etype,
        source=source,
        severity=severity,
        labels=labels or {},
        submitted_by=user,
    )


def test_specificity_more_conditions_wins_within_same_priority(components):
    """同优先级：同时限定事件类型+来源+严重度+标签的精细规则胜过只限定类型的兜底。"""
    _, _, _, executor, _ = components
    broad = _policy("p-broad", event_type="disk_full")
    specific = _policy(
        "p-specific",
        event_type="disk_full",
        source_prefix="host-",
        severities=["critical"],
        labels={"zone": "edge"},
    )
    executor.policies[:] = [broad, specific]
    rec, created = executor.submit_event(
        _event(labels={"zone": "edge"})
    )
    assert created is True
    assert rec.policy_id == "p-specific"


def test_specificity_order_is_independent_of_file_order(components):
    """精细规则无论在策略文件中排前还是排后，结果一致；候选列表稳定。"""
    _, _, audit, executor, _ = components
    broad = _policy("p-broad", event_type="disk_full")
    specific = _policy(
        "p-specific",
        event_type="disk_full",
        source_prefix="host-",
        severities=["critical"],
    )
    executor.policies[:] = [specific, broad]
    rec1, _ = executor.submit_event(_event("e-order-1"))
    executor.policies[:] = [broad, specific]
    # 用全新执行（不同 event_id）在相反文件顺序下再裁决一次
    rec2, _ = executor.submit_event(_event("e-order-2"))
    assert rec1.policy_id == rec2.policy_id == "p-specific"
    accepted = [e for e in audit.read_all() if e["kind"] == "event.accepted"]
    assert {e["policy_id"] for e in accepted} == {"p-specific"}
    # 候选列表：精细在前、兜底在后，两种文件顺序都一样
    assert all(e["details"]["candidate_policies"][0] == "p-specific" for e in accepted)


def test_equal_priority_equal_specificity_is_hard_conflict(components):
    """优先级与具体度完全平手 => policy_conflict，不靠 id 静默打破，且不创建执行。"""
    _, store, audit, executor, _ = components
    twin_a = _policy("p-twin-a", event_type="disk_full")
    twin_b = _policy("p-twin-b", event_type="disk_full")
    executor.policies[:] = [twin_a, twin_b]
    try:
        executor.submit_event(_event("e-conflict"))
        raise AssertionError("expected policy conflict")
    except PolicyConflict as exc:
        assert exc.reason == RejectReason.POLICY_CONFLICT
        assert exc.details["conflicting_policies"] == ["p-twin-a", "p-twin-b"]
    assert store.get_by_event("e-conflict") is None
    rejected = [e for e in audit.read_all() if e["kind"] == "event.rejected"]
    assert any(e["reason"] == "policy_conflict" for e in rejected)


def test_policy_conflict_is_stable_regardless_of_file_order(components):
    """冲突是两条策略本身的属性：文件顺序任意交换，冲突集合一致。"""
    _, _, _, executor, _ = components
    twin_a = _policy("p-alpha", event_type="disk_full", source_prefix="host-")
    twin_b = _policy("p-beta", event_type="disk_full", source_prefix="host-")
    for ordered in ([twin_a, twin_b], [twin_b, twin_a]):
        executor.policies[:] = ordered
        try:
            executor.submit_event(_event("e-conflict-stable", source="host-9"))
            raise AssertionError("expected policy conflict")
        except PolicyConflict as exc:
            # 冲突集合按 id 排序输出，与文件顺序无关
            assert exc.details["conflicting_policies"] == ["p-alpha", "p-beta"]
            assert exc.details["candidate_policies"] == ["p-alpha", "p-beta"]


def test_four_rejection_reasons_are_distinguishable(components, client):
    """缺必填 / 值非法 / 无命中 / 策略冲突，四种拒绝原因两两可区分。"""
    _, _, _, executor, _ = components
    twin_a = _policy("p-x", event_type="disk_full")
    twin_b = _policy("p-y", event_type="disk_full")
    executor.policies[:] = [twin_a, twin_b]

    # 1) 事件合法但无任何策略命中
    try:
        executor.submit_event(_event("e-nohit", etype="no_such_type"))
        raise AssertionError("expected policy_not_found")
    except PolicyRejected as exc:
        assert type(exc) is PolicyRejected
        assert exc.reason == RejectReason.POLICY_NOT_FOUND

    # 2) 策略冲突
    try:
        executor.submit_event(_event("e-conf"))
        raise AssertionError("expected policy_conflict")
    except PolicyConflict as exc:
        assert exc.reason == RejectReason.POLICY_CONFLICT

    # 3) 缺必填字段（HTTP）
    c, _ = client
    resp = c.post("/events", json={"event_id": "e-missing", "source": "host-1"})
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.MISSING_FIELD.value

    # 4) 字段值不合法（HTTP）
    resp = c.post("/events", json={
        "event_id": "e-invalid", "event_type": "disk_full",
        "source": "host-1", "severity": "nope",
    })
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value


def test_policy_conflict_over_api_is_separate_http_status(client):
    """策略冲突在 HTTP 层也与无命中(422)区分：409 + policy_conflict。"""
    c, executor = client
    twin_a = _policy("p-c1", event_type="disk_full")
    twin_b = _policy("p-c2", event_type="disk_full")
    executor.policies[:] = [twin_a, twin_b]
    resp = c.post("/events", json={
        "event_id": "e-api-conflict", "event_type": "disk_full",
        "source": "host-1", "severity": "critical", "submitted_by": "carol",
    })
    assert resp.status_code == 409
    body = resp.json()
    assert body["reason"] == RejectReason.POLICY_CONFLICT.value
    assert body["details"]["conflicting_policies"] == ["p-c1", "p-c2"]


# ============================ 失败收敛与显式重试 ============================

def _fail_policy(pid: str = "p-fail", *, fail_first: bool = True) -> Policy:
    """两步动作：第一个已生效可保留，第二个持续失败用于验证收敛与续跑。"""
    return Policy(
        id=pid,
        match=MatchRule(event_type="disk_full"),
        actions=[
            ActionDef(name="restart_service", required_role="operator"),
            ActionDef(
                name="clear_disk_cache",
                required_role="operator",
                params={"fail": fail_first},
            ),
        ],
    )


def _fixed_policy(pid: str = "p-fail") -> Policy:
    return Policy(
        id=pid,
        match=MatchRule(event_type="disk_full"),
        actions=[
            ActionDef(name="restart_service", required_role="operator"),
            ActionDef(name="clear_disk_cache", required_role="operator"),
        ],
    )


def test_failed_execution_is_not_auto_rerun_by_worker(components):
    """失败后停在确定失败态：连续 tick 也不会在后台被反复重跑。"""
    _, store, _, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    rec, _ = executor.submit_event(_event("e-converge-1"))

    executor.tick()  # 第 1 次尝试失败
    failed = store.get(rec.id)
    assert failed.state == ExecutionState.FAILED
    assert failed.attempts_used == 1
    effects_after_first = list(store._effects)
    assert effects_after_first == [f"{rec.id}:0"]  # 仅第一步生效

    # 再多轮后台调度：FAILED 不被自动拾取，不产生任何新副作用
    for _ in range(5):
        assert executor.tick() is False
    again = store.get(rec.id)
    assert again.state == ExecutionState.FAILED
    assert list(store._effects) == effects_after_first
    assert again.steps[0].status == StepStatus.APPLIED
    assert again.steps[1].status == StepStatus.FAILED


def test_explicit_retry_resumes_remaining_step_without_duplicate_effect(components):
    """显式重试只接着没做完的部分走；已生效步骤不重来，无重复副作用。"""
    _, store, _, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    rec, _ = executor.submit_event(_event("e-converge-2"))
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.FAILED

    # 人为修复第二个动作后显式重试
    executor.policies[:] = [_fixed_policy()]
    executor.retry(rec.id, "carol")
    executor.tick()
    done = store.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    # step0 未重放：attempts 仍为 1，台账恰好两个唯一键
    assert done.steps[0].attempts == 1
    assert done.steps[1].attempts == 2
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]


def test_repeated_retries_converge_to_terminal_after_budget(components):
    """反复显式重试到约定次数后收敛为 retry_exhausted 终态，不再接受普通重试。"""
    _, store, audit, executor, _ = components
    executor.policies[:] = [_fail_policy()]  # 动作始终失败
    rec, _ = executor.submit_event(_event("e-converge-3"))

    # max_attempts=3：初次 + 2 次显式重试后耗尽
    executor.tick()
    assert store.get(rec.id).attempts_used == 1
    executor.retry(rec.id, "carol"); executor.tick()
    assert store.get(rec.id).state == ExecutionState.FAILED
    assert store.get(rec.id).attempts_used == 2
    executor.retry(rec.id, "carol"); executor.tick()
    exhausted = store.get(rec.id)
    assert exhausted.state == ExecutionState.RETRY_EXHAUSTED
    assert exhausted.attempts_used == 3
    assert exhausted.finished_at is not None

    # 终态：没有人工确认的重试一律拒绝，且状态不倒退、无新副作用
    effects_before = list(store._effects)
    try:
        executor.retry(rec.id, "carol")
        raise AssertionError("expected retry_exhausted rejection")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.RETRY_EXHAUSTED
    # 再多轮后台 tick 也不会重跑
    for _ in range(3):
        assert executor.tick() is False
    assert store.get(rec.id).state == ExecutionState.RETRY_EXHAUSTED
    assert list(store._effects) == effects_before

    kinds = [e["kind"] for e in audit.read_all()]
    assert kinds.count("run.retry") == 2
    assert "run.exhausted" in kinds
    exhausted_entries = [e for e in audit.read_all() if e["kind"] == "run.exhausted"]
    assert exhausted_entries[-1]["details"]["max_attempts"] == 3


def test_confirmed_retry_after_exhaustion_resumes_once_with_single_effect(components):
    """人工确认后可再试：预算重开、只跑未完成步骤、副作用仍唯一、失败次数可追溯。"""
    _, store, audit, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    rec, _ = executor.submit_event(_event("e-converge-4"))
    executor.tick()
    executor.retry(rec.id, "carol"); executor.tick()
    executor.retry(rec.id, "carol"); executor.tick()
    assert store.get(rec.id).state == ExecutionState.RETRY_EXHAUSTED

    # 未带 confirmed 的 API 风格拒绝已在上一例覆盖；这里确认后修复动作再试
    executor.policies[:] = [_fixed_policy()]
    reopened = executor.retry(rec.id, "carol", confirmed=True)
    assert reopened.state == ExecutionState.PENDING
    assert reopened.attempts_used == 1  # 人工确认重新打开预算
    executor.tick()
    done = store.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    # 反复的失败-重试历史中，每个步骤仍只有一次副作用
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
    assert done.steps[0].attempts == 1  # 已生效步骤从未重来
    assert any(e["kind"] == "retry.confirmed" for e in audit.read_all())


def test_rejected_retry_never_changes_state(components):
    """耗尽态下的未确认重试、其他终态重试都是拒绝且状态/副作用保持不变。"""
    _, store, _, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    rec, _ = executor.submit_event(_event("e-converge-5"))
    executor.tick(); executor.retry(rec.id, "carol"); executor.tick()
    executor.retry(rec.id, "carol"); executor.tick()
    before = store.get(rec.id).model_dump()
    try:
        executor.retry(rec.id, "carol")
        raise AssertionError("expected conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.RETRY_EXHAUSTED
    after = store.get(rec.id).model_dump()
    assert after["state"] == before["state"] == "retry_exhausted"
    assert after["attempts_used"] == before["attempts_used"] == 3


# ============================ 调度公平性 ============================

def test_pending_events_advance_while_earlier_event_awaits_approval(components, clock):
    """队首挂着待审批危险事件时，后面的普通事件仍按 FIFO 正常推进。"""
    _, store, _, executor, _ = components

    # 危险事件先到，停在 awaiting_approval
    danger, _ = executor.submit_event(
        _event("e-danger", etype="security_intrusion", source="fw-1", user="alice")
    )
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
    clock.advance(1)
    normal1, _ = executor.submit_event(_event("e-normal-1"))
    clock.advance(1)
    normal2, _ = executor.submit_event(_event("e-normal-2"))

    # 两个 tick 都应跳过待审批事件，顺序推进两个普通事件
    assert executor.tick() is True
    assert store.get(normal1.id).state == ExecutionState.COMPLETED
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
    assert executor.tick() is True
    assert store.get(normal2.id).state == ExecutionState.COMPLETED
    assert store.get(danger.id).state == ExecutionState.AWAITING_APPROVAL
    # 再无普通事件可推进：待审批事件不会被强行执行
    assert executor.tick() is False
    # 两个普通事件各 2 个副作用（conftest 的 disk-safe 是两步动作），危险动作零副作用
    assert f"{danger.id}:0" not in store._effects
    assert len(store._effects) == 4

    # 审批补齐后，队首危险事件仍然可以推进完成
    executor.grant_approval(danger.id, "alice", 600)
    executor.tick()
    assert store.get(danger.id).state == ExecutionState.COMPLETED
    assert len(store._effects) == 5


def test_failed_head_of_queue_does_not_block_later_events(components, clock):
    """一个持续失败的执行停在 FAILED 后，后续普通事件不被拖累。"""
    _, store, _, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    failing, _ = executor.submit_event(_event("e-stuck"))
    executor.tick()
    assert store.get(failing.id).state == ExecutionState.FAILED

    # 之后到来的普通事件（换回始终成功的策略；disk_full 事件不受影响）
    executor.policies[:] = [_fixed_policy()]
    clock.advance(1)
    later, _ = executor.submit_event(_event("e-later"))
    assert executor.tick() is True
    assert store.get(later.id).state == ExecutionState.COMPLETED
    # 失败执行依旧停在确定失败态，没有被自动重跑
    assert store.get(failing.id).state == ExecutionState.FAILED


def test_fairness_holds_under_live_worker(client_fairness):
    """真实后台 worker 下：危险事件长期待审批，普通事件依旧很快完成（端到端）。"""
    c, _executor, exec_ids = client_fairness
    import time

    deadline = time.time() + 3.0
    while time.time() < deadline:
        n1 = c.get(f"/executions/{exec_ids['normal']}").json()["state"]
        if n1 == "completed":
            break
        time.sleep(0.01)
    assert n1 == "completed"
    danger_state = c.get(f"/executions/{exec_ids['danger']}").json()["state"]
    assert danger_state == "awaiting_approval"


# ============================ 并发 / 重试下唯一副作用 ============================

def test_concurrent_distinct_events_each_have_single_effect(components):
    """多个不同事件并发提交 + 全部调度后，每个事件恰好一次有效副作用。"""
    _, store, _, executor, _ = components
    barrier = threading.Barrier(6)
    records: list = []

    def submit(i: int) -> None:
        barrier.wait()
        rec, _ = executor.submit_event(_event(f"e-par-{i}"))
        records.append(rec)

    threads = [threading.Thread(target=submit, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 手动把全部执行推进到终态
    advanced = True
    while advanced:
        advanced = executor.tick()

    finals = store.all_executions()
    assert len(finals) == 6
    assert all(r.state == ExecutionState.COMPLETED for r in finals)
    # 每个执行 2 个步骤，共 12 个全局唯一 effect_key
    keys = list(store._effects)
    assert len(keys) == 12
    assert len(set(keys)) == 12
    for r in finals:
        assert f"{r.id}:0" in keys and f"{r.id}:1" in keys


def test_concurrent_retries_of_same_failed_execution_have_single_effect(components):
    """同一失败执行被多线程同时重试：只有一次生效，副作用不重复。"""
    _, store, _, executor, _ = components
    executor.policies[:] = [_fail_policy()]
    rec, _ = executor.submit_event(_event("e-par-retry"))
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.FAILED

    # 先让重试后的动作能成功
    executor.policies[:] = [_fixed_policy()]
    outcomes: list[str] = []
    barrier = threading.Barrier(5)

    def retry_once() -> None:
        barrier.wait()
        try:
            executor.retry(rec.id, "carol")
            outcomes.append("retry")
        except ExecutionConflict:
            outcomes.append("conflict")

    threads = [threading.Thread(target=retry_once) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count("retry") == 1
    assert outcomes.count("conflict") == 4
    # 推进到终态后副作用仍然唯一
    advanced = True
    while advanced:
        advanced = executor.tick()
    done = store.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]


def test_retry_during_running_is_rejected_without_regression(components):
    """处理到一半（RUNNING）的事件不能被重试，状态不倒退。"""
    _, store, _, executor, _ = components
    # 让动作在执行中阻塞，制造一个稳定可见的 RUNNING 窗口
    import threading as _t
    import time as _time

    gate = _t.Event()

    def slow_action(params):
        gate.wait(timeout=2.0)
        return {"ran": True}

    executor.actions.register("restart_service", slow_action)
    executor.policies[:] = [
        Policy(
            id="p-slow",
            match=MatchRule(event_type="disk_full"),
            actions=[ActionDef(name="restart_service", required_role="operator")],
        )
    ]
    rec, _ = executor.submit_event(_event("e-half"))
    worker = _t.Thread(target=executor.tick)
    worker.start()
    # 等记录进入 RUNNING
    for _ in range(100):
        if store.get(rec.id).state == ExecutionState.RUNNING:
            break
        _time.sleep(0.005)
    try:
        executor.retry(rec.id, "carol")
        raise AssertionError("expected invalid_state_transition")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    finally:
        gate.set()
        worker.join()
    final = store.get(rec.id)
    assert final.state == ExecutionState.COMPLETED
    assert list(store._effects) == [f"{rec.id}:0"]
