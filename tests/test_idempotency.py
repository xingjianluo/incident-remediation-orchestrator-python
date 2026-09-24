"""同一事件重复提交、并发提交只能产生一次执行与一次副作用。"""
from __future__ import annotations

import threading

from app.schemas import Event


def _disk_event(event_id: str = "e-dup") -> Event:
    return Event(
        event_id=event_id, event_type="disk_full", source="host-1",
        severity="warning", submitted_by="carol",
    )


def test_duplicate_submission_returns_same_execution(components):
    _, store, _, executor, _ = components
    rec1, created1 = executor.submit_event(_disk_event())
    rec2, created2 = executor.submit_event(_disk_event())
    assert created1 is True
    assert created2 is False
    assert rec1.id == rec2.id
    assert len(store.all_executions()) == 1
    executor.tick()
    # 完成后重复提交依然返回同一条终态记录，不再执行
    rec3, created3 = executor.submit_event(_disk_event())
    assert created3 is False
    assert rec3.id == rec1.id
    assert rec3.state.value == "completed"
    # 只有一次副作用
    keys = list(store._effects)
    assert keys == [f"{rec1.id}:0", f"{rec1.id}:1"]


def test_concurrent_submissions_create_single_execution(components):
    _, store, audit, executor, _ = components
    results: list[tuple[str, bool]] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        rec, created = executor.submit_event(_disk_event())
        results.append((rec.id, created))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    exec_ids = {rid for rid, _ in results}
    assert len(exec_ids) == 1
    created_count = sum(1 for _, c in results if c)
    assert created_count == 1
    assert len(store.all_executions()) == 1
    # 每次提交都有审计痕迹（1 accepted + 7 duplicate）
    kinds = [e["kind"] for e in audit.read_all()]
    assert kinds.count("event.accepted") == 1
    assert kinds.count("submit.duplicate") == 7


def test_concurrent_duplicate_submission_over_api(client):
    c, _ = client
    payload = {
        "event_id": "e-api-conc", "event_type": "disk_full",
        "source": "host-2", "severity": "critical", "submitted_by": "carol",
    }
    responses: list = []
    barrier = threading.Barrier(6)

    def post() -> None:
        barrier.wait()
        responses.append(c.post("/events", json=payload))

    threads = [threading.Thread(target=post) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r.json()["created"] for r in responses]
    exec_ids = {r.json()["execution"]["id"] for r in responses}
    assert created.count(True) == 1
    assert created.count(False) == 5
    assert len(exec_ids) == 1
    listing = c.get("/executions").json()["executions"]
    assert len(listing) == 1
