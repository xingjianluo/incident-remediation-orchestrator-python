"""策略匹配：优先级稳定裁决、冲突拒绝、字段缺失与无匹配不静默执行。"""
from __future__ import annotations

import pytest

from remediation.authz import Actor
from remediation.errors import PolicyError
from remediation.models import Event
from remediation.policies import PolicyEngine

OPERATOR = Actor.parse("op1", "operator")


def test_higher_priority_wins(orchestrator):
    view = orchestrator.submit(
        {"event_id": "e1", "source": "host-a", "alert_type": "disk_full", "severity": "high"},
        OPERATOR,
    )
    # disk-danger(100) 优先于 auto-noop(10)；含危险动作 -> 等审批，不执行
    assert view["policy_id"] == "disk-danger"
    assert view["state"] == "WAITING_APPROVAL"
    assert view["completed_actions"] == []


def test_conflict_is_deterministic_and_rejected(orchestrator):
    view = orchestrator.submit(
        {"event_id": "e2", "source": "any", "alert_type": "ambiguous", "severity": "low"},
        OPERATOR,
    )
    assert view["rejected"] is True
    assert view["state"] == "REJECTED"
    assert view["reject_reason"] == "POLICY_CONFLICT"
    # 冲突中两个策略 ID 都出现在原因里，顺序确定
    assert "conflict-a" in view["last_error"] and "conflict-b" in view["last_error"]
    # 未产生任何副作用
    assert view["completed_actions"] == []
    # 可重复查询且状态稳定
    again = orchestrator.get_status("e2")
    assert again["state"] == "REJECTED"
    assert again["reject_reason"] == "POLICY_CONFLICT"


def test_conflict_reproducible_order():
    cfg = {
        "policies": [
            {"policy_id": "z", "priority": 5, "match": {"alert_type": "t"},
             "actions": [{"name": "a", "action": "noop"}]},
            {"policy_id": "a", "priority": 5, "match": {"alert_type": "t"},
             "actions": [{"name": "b", "action": "noop"}]},
        ]
    }
    eng = PolicyEngine.from_dict(cfg)
    ev = Event.from_raw(
        {"event_id": "x", "source": "s", "alert_type": "t", "severity": "low"}
    )
    for _ in range(20):
        with pytest.raises(PolicyError) as exc:
            eng.select(ev)
        assert "['a', 'z']" in exc.value.message


def test_no_matching_policy_rejected(orchestrator):
    view = orchestrator.submit(
        {"event_id": "e3", "source": "unknown", "alert_type": "nope", "severity": "low"},
        OPERATOR,
    )
    assert view["rejected"] is True
    assert view["state"] == "REJECTED"
    assert view["reject_reason"] == "NO_MATCHING_POLICY"
    assert view["completed_actions"] == []
    # 重复提交被拒绝的事件：返回同一终态，不重新裁决/执行
    again = orchestrator.submit(
        {"event_id": "e3", "source": "unknown", "alert_type": "nope", "severity": "low"},
        OPERATOR,
    )
    assert again["duplicate"] is True
    assert again["state"] == "REJECTED"


def test_priority_vs_specificity(orchestrator):
    # priority 优先；相同 priority 时更具体的 match 胜出
    cfg = {
        "policies": [
            {"policy_id": "generic-highprio", "priority": 20,
             "match": {"source": "h"},
             "actions": [{"name": "g", "action": "noop"}]},
            {"policy_id": "specific-lowprio", "priority": 10,
             "match": {"source": "h", "alert_type": "t"},
             "actions": [{"name": "s", "action": "noop"}]},
        ]
    }
    eng = PolicyEngine.from_dict(cfg)
    ev = Event.from_raw(
        {"event_id": "x", "source": "h", "alert_type": "t", "severity": "low"}
    )
    assert eng.select(ev).policy_id == "generic-highprio"

    cfg2 = {
        "policies": [
            {"policy_id": "generic", "priority": 10, "match": {"source": "h"},
             "actions": [{"name": "g", "action": "noop"}]},
            {"policy_id": "specific", "priority": 10,
             "match": {"source": "h", "alert_type": "t"},
             "actions": [{"name": "s", "action": "noop"}]},
        ]
    }
    eng2 = PolicyEngine.from_dict(cfg2)
    assert eng2.select(ev).policy_id == "specific"


def test_severity_min_matching():
    cfg = {"policies": [
        {"policy_id": "sev", "priority": 1, "match": {"severity_min": "high"},
         "actions": [{"name": "s", "action": "noop"}]},
    ]}
    eng = PolicyEngine.from_dict(cfg)
    high = Event.from_raw(
        {"event_id": "h", "source": "s", "alert_type": "t", "severity": "high"}
    )
    low = Event.from_raw(
        {"event_id": "l", "source": "s", "alert_type": "t", "severity": "low"}
    )
    assert eng.select(high).policy_id == "sev"
    with pytest.raises(PolicyError):
        eng.select(low)


def test_invalid_policy_config_rejected():
    bad = {"policies": [
        {"policy_id": "p", "priority": 1, "match": {}, "actions": []},
    ]}
    with pytest.raises(PolicyError) as exc:
        PolicyEngine.from_dict(bad)
    assert exc.value.reason.value == "CONFIG_INVALID"
