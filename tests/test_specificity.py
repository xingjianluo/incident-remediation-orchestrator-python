"""同优先级下更具体的规则优先；完全并列则按配置冲突拒绝，且结果与策略顺序无关。"""
from __future__ import annotations

import pytest

from app.errors import PolicyRejected
from app.policies import match_policy
from app.schemas import (
    ActionDef,
    Event,
    MatchRule,
    Policy,
    RejectReason,
)


def _policy(
    pid: str,
    priority: int,
    *,
    event_type: str | None = None,
    source_prefix: str | None = None,
    severities: list[str] | None = None,
    labels: dict[str, str] | None = None,
) -> Policy:
    return Policy(
        id=pid,
        priority=priority,
        match=MatchRule(
            event_type=event_type,
            source_prefix=source_prefix,
            severities=severities or [],
            labels=labels or {},
        ),
        actions=[ActionDef(name="restart_service", required_role="operator")],
    )


def _event(eid: str = "e-spec") -> Event:
    return Event(
        event_id=eid,
        event_type="disk_full",
        source="host-1",
        severity="warning",
        labels={"role": "db"},
        submitted_by="carol",
    )


def test_more_specific_rule_wins_at_same_priority(components):
    """同优先级：限定维度更多的精细规则先于兜底规则命中。"""
    _, _, _, executor, _ = components
    general = _policy("p-general", 100, event_type="disk_full")
    specific = _policy(
        "p-specific", 100, event_type="disk_full",
        source_prefix="host-", labels={"role": "db"},
    )
    executor.policies[:] = [general, specific]
    rec, _ = executor.submit_event(_event())
    assert rec.policy_id == "p-specific"


def test_priority_still_dominates_specificity(components):
    """优先级数值小者仍然优先，即使兜底规则更具体。"""
    _, _, _, executor, _ = components
    general = _policy("p-general", 100, event_type="disk_full")
    specific = _policy(
        "p-specific-low-prio", 200, event_type="disk_full",
        source_prefix="host-", labels={"role": "db"},
    )
    executor.policies[:] = [specific, general]
    rec, _ = executor.submit_event(_event())
    assert rec.policy_id == "p-general"


def test_specificity_outcome_independent_of_policy_file_order(components):
    """同一输入无论策略在配置里怎么排，命中结果一致。"""
    _, _, _, executor, _ = components
    general = _policy("p-general", 100, event_type="disk_full")
    specific = _policy(
        "p-specific", 100, event_type="disk_full",
        source_prefix="host-", labels={"role": "db"},
    )
    event = _event()
    forward = match_policy(event, [general, specific])
    backward = match_policy(event, [specific, general])
    assert forward[0].id == backward[0].id == "p-specific"
    assert forward[1] == backward[1] == ["p-specific", "p-general"]


def test_true_conflict_rejected_with_distinguishable_reason(components):
    """优先级与具体程度完全并列 -> policy_conflict，且与无匹配可区分。"""
    _, store, audit, executor, _ = components
    tied_a = _policy("p-tied-a", 100, event_type="disk_full")
    tied_b = _policy("p-tied-b", 100, event_type="disk_full")
    executor.policies[:] = [tied_a, tied_b]
    with pytest.raises(PolicyRejected) as excinfo:
        executor.submit_event(_event("e-conflict"))
    exc = excinfo.value
    assert exc.reason == RejectReason.POLICY_CONFLICT
    assert exc.reason != RejectReason.POLICY_NOT_FOUND
    assert exc.details["tied_policies"] == ["p-tied-a", "p-tied-b"]
    # 冲突拒绝不产生任何执行记录
    assert store.get_by_event("e-conflict") is None
    # 审计里能看到冲突原因与并列策略
    rejected = [e for e in audit.read_all() if e["kind"] == "event.rejected"]
    assert rejected[0]["reason"] == RejectReason.POLICY_CONFLICT.value
    assert rejected[0]["details"]["tied_policies"] == ["p-tied-a", "p-tied-b"]


def test_conflict_verdict_independent_of_policy_file_order(components):
    """并列冲突的裁决与策略顺序无关：反复跑、换顺序都是同一结果。"""
    tied_a = _policy("p-tied-a", 100, event_type="disk_full")
    tied_b = _policy("p-tied-b", 100, event_type="disk_full")
    event = _event()
    verdicts = set()
    for _ in range(5):
        for policies in ([tied_a, tied_b], [tied_b, tied_a]):
            with pytest.raises(Exception) as excinfo:
                match_policy(event, policies)
            verdicts.add(str(excinfo.value))
    assert len(verdicts) == 1  # 所有顺序、所有重复运行得到同一裁决


def test_unique_winner_despite_lower_tie(components):
    """第一名无并列时正常命中，即使更靠后的策略彼此并列。"""
    _, _, _, executor, _ = components
    winner = _policy("p-winner", 100, event_type="disk_full", source_prefix="host-")
    tied_a = _policy("p-tied-a", 100, event_type="disk_full")
    tied_b = _policy("p-tied-b", 100, event_type="disk_full")
    executor.policies[:] = [tied_a, winner, tied_b]
    rec, _ = executor.submit_event(_event())
    assert rec.policy_id == "p-winner"


def test_conflict_over_api_returns_distinguishable_reason(client):
    c, executor = client
    executor.policies[:] = [
        _policy("p-tied-a", 100, event_type="disk_full"),
        _policy("p-tied-b", 100, event_type="disk_full"),
    ]
    resp = c.post("/events", json={
        "event_id": "e-api-conflict", "event_type": "disk_full",
        "source": "host-1", "submitted_by": "carol",
    })
    assert resp.status_code == 422
    body = resp.json()
    assert body["reason"] == RejectReason.POLICY_CONFLICT.value
    assert body["details"]["tied_policies"] == ["p-tied-a", "p-tied-b"]
    # 与无匹配原因确实不同
    executor.policies[:] = []
    resp = c.post("/events", json={
        "event_id": "e-api-nomatch", "event_type": "disk_full",
        "source": "host-1", "submitted_by": "carol",
    })
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.POLICY_NOT_FOUND.value
