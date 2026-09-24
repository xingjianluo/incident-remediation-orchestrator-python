"""策略冲突优先级、无匹配、非法事件的拒绝原因必须可区分。"""
from __future__ import annotations

from app.errors import PolicyRejected
from app.schemas import Event, RejectReason


def test_conflict_picks_highest_priority_deterministically(components):
    _, _, _, executor, _ = components
    event = Event(
        event_id="e-1", event_type="disk_full", source="host-9",
        severity="critical", submitted_by="carol",
    )
    rec, created = executor.submit_event(event)
    assert created is True
    assert rec.policy_id == "disk-safe"  # priority 100 < 200
    executor.tick()
    rec = executor.store.get(rec.id)
    assert rec.state.value == "completed"
    assert [s.action for s in rec.steps] == ["clear_disk_cache", "restart_service"]


def test_conflict_result_is_reproducible_in_any_policy_order(components):
    _, _, audit, executor, _ = components
    event = Event(
        event_id="e-2", event_type="disk_full", source="host-1",
        severity="warning", submitted_by="carol",
    )
    executor.submit_event(event)
    accepted = next(
        e for e in audit.read_all() if e["kind"] == "event.accepted"
    )
    # 全部候选策略按确定顺序记录，最优在前
    assert accepted["details"]["candidate_policies"] == ["disk-safe", "disk-low"]


def test_no_matching_policy_is_rejected_not_silent(components):
    _, store, audit, executor, _ = components
    event = Event(
        event_id="e-3", event_type="unknown_type", source="host-1",
        submitted_by="carol",
    )
    try:
        executor.submit_event(event)
        raise AssertionError("expected PolicyRejected")
    except PolicyRejected as exc:
        assert exc.reason == RejectReason.POLICY_NOT_FOUND
        assert exc.details["event_id"] == "e-3"
    # 不产生执行记录
    assert store.get_by_event("e-3") is None
    assert any(e["reason"] == "policy_not_found" for e in audit.read_all())


def test_invalid_event_over_api_returns_distinguishable_reason(client):
    c, _ = client
    # 缺少必填字段 event_type
    resp = c.post("/events", json={"event_id": "e-bad", "source": "host-1"})
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value
    # 非法 severity
    resp = c.post("/events", json={
        "event_id": "e-bad2", "event_type": "disk_full",
        "source": "host-1", "severity": "DOOMSDAY",
    })
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value
    # 空 event_id
    resp = c.post("/events", json={
        "event_id": "  ", "event_type": "disk_full", "source": "host-1",
    })
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value
    # 请求体不是 JSON 对象 / 非法 JSON 也不静默
    resp = c.post("/events", json=["not", "object"])
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value
    resp = c.post(
        "/events", content="not-json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422
    assert resp.json()["reason"] == RejectReason.INVALID_EVENT.value


def test_no_match_over_api_is_422_with_reason(client):
    c, _ = client
    resp = c.post("/events", json={
        "event_id": "e-nomatch", "event_type": "nope", "source": "host-1",
        "submitted_by": "carol",
    })
    assert resp.status_code == 422
    body = resp.json()
    assert body["reason"] == RejectReason.POLICY_NOT_FOUND.value
    assert body["details"]["event_id"] == "e-nomatch"
