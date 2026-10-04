"""持续失败有界收敛：自动重试预算耗尽后停在 FAILED，等待人工显式重试。"""
from __future__ import annotations

import dataclasses

import pytest

from app.schemas import (
    ActionDef,
    Event,
    ExecutionState,
    MatchRule,
    Policy,
    StepStatus,
)


def _fail_policy(pid: str = "p-flaky", *, fail: bool = True) -> Policy:
    return Policy(
        id=pid,
        match=MatchRule(event_type="disk_full"),
        actions=[
            ActionDef(name="restart_service", required_role="operator"),
            ActionDef(
                name="clear_disk_cache", required_role="operator",
                params={"fail": fail},
            ),
        ],
    )


def _event(eid: str) -> Event:
    return Event(event_id=eid, event_type="disk_full", source="host-1",
                 submitted_by="carol")


@pytest.fixture
def conv_executor(components):
    """自动重试预算为 2 的执行器（默认夹具为 1，即失败即停）。"""
    _, _, _, executor, _ = components
    executor.settings = dataclasses.replace(executor.settings, max_step_attempts=2)
    executor.policies[:] = [_fail_policy()]
    return components


def test_persistent_failure_converges_to_parked_failed(conv_executor):
    """失败到约定次数后停在确定的 FAILED，worker 不再自动重跑。"""
    _, store, audit, executor, _ = conv_executor
    rec, _ = executor.submit_event(_event("e-conv-1"))

    executor.tick()  # 第 1 次失败：预算未用完，自动排队重试
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.PENDING
    assert rec.steps[1].attempts == 1

    executor.tick()  # 第 2 次失败：预算耗尽，停在 FAILED
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.FAILED
    assert rec.steps[1].status == StepStatus.FAILED
    assert rec.steps[1].attempts == 2

    # 之后无论多少 tick 都不会再自动重跑：状态与尝试次数都不再变化
    for _ in range(3):
        assert executor.tick() is False
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.FAILED
    assert rec.steps[1].attempts == 2

    # 失败收敛过程可追溯：自动重试与停机都有审计
    kinds = [e["kind"] for e in audit.read_all()]
    assert "run.auto_retry" in kinds
    assert "run.failed" in kinds
    failed_evt = next(e for e in audit.read_all() if e["kind"] == "run.failed")
    assert "budget exhausted" in failed_evt["reason"]


def test_manual_retry_renews_budget_and_stays_traceable(conv_executor):
    """人工显式重试获得新预算；累计失败次数不清零、逐步可追溯。"""
    _, store, audit, executor, _ = conv_executor
    rec, _ = executor.submit_event(_event("e-conv-2"))
    executor.tick()
    executor.tick()
    assert store.get(rec.id).state == ExecutionState.FAILED

    # 动作仍然失败：人工重试 -> 新预算 -> 再次收敛到 FAILED
    executor.retry(rec.id, "carol")
    assert store.get(rec.id).steps[1].cycle_attempts == 0  # 预算已重置
    executor.tick()  # 新预算第 1 次失败 -> 自动重试
    assert store.get(rec.id).state == ExecutionState.PENDING
    executor.tick()  # 新预算第 2 次失败 -> 再次停机
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.FAILED
    assert rec.steps[1].attempts == 4          # 累计次数不清零
    assert rec.steps[1].cycle_attempts == 2    # 本周期次数

    # 修复动作后人工重试 -> 完成；每一步副作用仍只有一次
    executor.policies[:] = [_fail_policy(fail=False)]
    executor.retry(rec.id, "carol")
    executor.tick()
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.COMPLETED
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
    # 每次状态变化都有审计：两次 run.retry、run.auto_retry、run.failed、run.finished
    kinds = [e["kind"] for e in audit.read_all()]
    assert kinds.count("run.retry") == 2
    assert kinds.count("run.auto_retry") == 2
    assert kinds.count("run.failed") == 2
    assert "run.finished" in kinds


def test_retry_only_resumes_unfinished_steps(conv_executor):
    """重试只接着没做完的步骤走，已生效步骤绝不重放。"""
    _, store, _, executor, _ = conv_executor
    rec, _ = executor.submit_event(_event("e-conv-3"))
    executor.tick()
    executor.tick()
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.FAILED
    assert rec.steps[0].status == StepStatus.APPLIED
    assert rec.steps[0].attempts == 1

    executor.policies[:] = [_fail_policy(fail=False)]
    executor.retry(rec.id, "carol")
    executor.tick()
    rec = store.get(rec.id)
    assert rec.state == ExecutionState.COMPLETED
    # step0 没有重放：attempts 仍为 1，台账仍只有两个唯一副作用键
    assert rec.steps[0].attempts == 1
    assert rec.steps[1].attempts == 3  # 2 次失败 + 1 次成功
    assert sorted(store._effects) == [f"{rec.id}:0", f"{rec.id}:1"]
