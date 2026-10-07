"""执行中断后重启恢复到确定状态，且不重复产生副作用。"""
from __future__ import annotations

import os

from app.actions import ActionRegistry
from app.audit import AuditLogger
from app.config import Settings
from app.executor import Executor
from app.schemas import (
    ActionDef,
    Event,
    ExecutionState,
    MatchRule,
    Policy,
    StepStatus,
)
from app.storage import Store


def _restart(settings: Settings, policies, acl, *, clock=None):
    """模拟进程重启：新建 Store/Executor 从磁盘恢复（旧实例不再使用）。"""
    store = Store(settings.store_file, os.path.join(settings.data_dir, "effects.jsonl"))
    audit = AuditLogger(settings.audit_log)
    executor = Executor(
        settings, store, audit, policies, acl, ActionRegistry(),
        clock=clock or (lambda: 1_000_000.0),
    )
    return executor, store, audit


CRASH_POLICY = Policy(
    id="crash-p",
    match=MatchRule(event_type="disk_full"),
    actions=[
        ActionDef(name="restart_service", required_role="operator", crash_after_effect=True),
        ActionDef(name="clear_disk_cache", required_role="operator"),
    ],
)
RECOVERED_POLICY = Policy(
    id="crash-p",
    match=MatchRule(event_type="disk_full"),
    actions=[
        ActionDef(name="restart_service", required_role="operator"),
        ActionDef(name="clear_disk_cache", required_role="operator"),
    ],
)


def test_crash_after_effect_recovers_without_duplicate(components):
    settings, store, _, executor, _ = components
    acl = executor.acl
    executor.policies[:] = [CRASH_POLICY]

    event = Event(event_id="e-crash", event_type="disk_full",
                  source="host-1", submitted_by="carol")
    rec, _ = executor.submit_event(event)

    # 模拟进程在“副作用落账后、步骤提交前”崩溃（worker 线程死亡）
    try:
        executor.tick()
        raise AssertionError("expected simulated crash")
    except SystemExit:
        pass

    crashed = store.get(rec.id)
    assert crashed.state == ExecutionState.RUNNING  # 状态未倒退、未完成
    assert crashed.steps[0].status == StepStatus.PENDING
    # 但副作用台账已记录 step0
    assert store.effect_exists(f"{rec.id}:0") is not None

    # 模拟重启：全新 Executor 从磁盘加载，崩溃动作恢复为普通动作
    executor2, store2, _ = _restart(settings, [RECOVERED_POLICY], acl)
    executor2.tick()
    recovered = store2.get(rec.id)
    assert recovered.state == ExecutionState.COMPLETED
    assert [s.status for s in recovered.steps] == [StepStatus.APPLIED, StepStatus.APPLIED]
    # step0 绝无第二次副作用：台账只有两个唯一键
    assert sorted(store2._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
    # 恢复仅修复状态，不重新执行动作，attempts 不增加
    assert recovered.steps[0].attempts == 1
    assert recovered.run_generation == 1  # 恢复未新建代际


def test_recovery_is_idempotent_across_multiple_restarts(components):
    settings, _, _, executor, _ = components
    acl = executor.acl
    executor.policies[:] = [CRASH_POLICY]
    event = Event(event_id="e-crash2", event_type="disk_full",
                  source="host-1", submitted_by="carol")
    rec, _ = executor.submit_event(event)
    try:
        executor.tick()
    except SystemExit:
        pass

    # 多次重启、多次恢复 tick 都不能制造重复副作用
    ex1, st1, _ = _restart(settings, [RECOVERED_POLICY], acl)
    ex1.tick()
    assert st1.get(rec.id).state == ExecutionState.COMPLETED
    ex2, st2, _ = _restart(settings, [RECOVERED_POLICY], acl)
    ex2.tick()  # 已完成，无可运行项
    assert st2.get(rec.id).state == ExecutionState.COMPLETED
    assert len(st2._effects) == 2


def test_failed_step_retry_resumes_without_replaying_applied(components):
    settings, _, _, executor, _ = components
    acl = executor.acl
    fail_policy = Policy(
        id="p-retry",
        match=MatchRule(event_type="disk_full"),
        actions=[
            ActionDef(name="restart_service", required_role="operator"),
            ActionDef(name="clear_disk_cache", required_role="operator",
                      params={"fail": True}),
        ],
    )
    executor.policies[:] = [fail_policy]
    event = Event(event_id="e-retry", event_type="disk_full",
                  source="host-1", submitted_by="carol")
    rec, _ = executor.submit_event(event)
    executor.tick()
    assert executor.store.get(rec.id).state == ExecutionState.FAILED

    # 重启后用“第二动作已修复”的策略重试
    fixed = Policy(
        id="p-retry",
        match=MatchRule(event_type="disk_full"),
        actions=[
            ActionDef(name="restart_service", required_role="operator"),
            ActionDef(name="clear_disk_cache", required_role="operator"),
        ],
    )
    ex2, store2, _ = _restart(settings, [fixed], acl)
    failed = store2.get(rec.id)
    assert failed.steps[0].status == StepStatus.APPLIED
    assert failed.steps[1].status == StepStatus.FAILED
    ex2.retry(rec.id, "carol")
    ex2.tick()
    done = store2.get(rec.id)
    assert done.state == ExecutionState.COMPLETED
    # step0 没有重放，台账仍只有两个唯一副作用
    assert sorted(store2._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
    assert done.steps[0].attempts == 1
    assert done.steps[1].attempts == 2


def test_cancel_running_execution_rejected_and_recovery_does_not_replay(components):
    """执行中（含崩溃中断的 RUNNING）取消被拒、状态不变；恢复后不重放副作用。"""
    from app.errors import ExecutionConflict
    from app.schemas import RejectReason

    settings, _, _, executor, _ = components
    acl = executor.acl
    executor.policies[:] = [CRASH_POLICY]
    event = Event(event_id="e-cancel-crash", event_type="disk_full",
                  source="host-1", submitted_by="carol")
    rec, _ = executor.submit_event(event)
    try:
        executor.tick()
    except SystemExit:
        pass

    ex2, store2, _ = _restart(settings, [RECOVERED_POLICY], acl)
    # 崩溃中断的执行处于 RUNNING：取消必须被拒，且状态不被改动
    assert store2.get(rec.id).state == ExecutionState.RUNNING
    try:
        ex2.request_cancel(rec.id, "carol")
        raise AssertionError("expected conflict")
    except ExecutionConflict as exc:
        assert exc.reason == RejectReason.INVALID_STATE_TRANSITION
    assert store2.get(rec.id).state == ExecutionState.RUNNING

    # 恢复续跑：step0 由台账修复不重放，step1 正常执行，最终完成
    ex2.tick()
    final = store2.get(rec.id)
    assert final.state == ExecutionState.COMPLETED
    assert final.steps[0].status == StepStatus.APPLIED
    assert final.steps[1].status == StepStatus.APPLIED
    assert sorted(store2._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
    assert final.steps[0].attempts == 1  # step0 未重新执行
