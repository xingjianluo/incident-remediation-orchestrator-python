"""重复提交、并发提交与重试：只能产生一次有效副作用。"""
from __future__ import annotations

import threading

from remediation.authz import Actor

OPERATOR = Actor.parse("op1", "operator")


def _event(event_id: str, alert_type: str = "disk_full", source: str = "host-a") -> dict:
    return {
        "event_id": event_id,
        "source": source,
        "alert_type": alert_type,
        "severity": "high",
    }


def test_repeated_submit_single_execution(orchestrator, components):
    results = [orchestrator.submit(_event("dup-1"), OPERATOR) for _ in range(5)]
    # 首条进入 WAITING_APPROVAL（危险动作），其余均为 duplicate
    assert results[0]["duplicate"] is not True
    assert all(r["duplicate"] is True for r in results[1:])
    assert all(r["version"] == results[0]["version"] for r in results[1:])
    rec = orchestrator.get_status("dup-1")
    assert rec["state"] == "WAITING_APPROVAL"
    # 尚未审批，不应有任何动作副作用
    effects = list((components["paths"] / "effects").rglob("*"))
    assert not [p for p in effects if p.is_file()]


def test_concurrent_submit_single_winner(orchestrator):
    outcomes: list[dict] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        outcomes.append(orchestrator.submit(_event("conc-1"), OPERATOR))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [o for o in outcomes if not o.get("duplicate")]
    assert len(winners) == 1, f"期望唯一创建者，实际 {len(winners)}"
    assert all(o["policy_id"] == winners[0]["policy_id"] for o in outcomes)
    # 数据库中只有一条记录
    assert orchestrator.get_status("conc-1")["version"] == winners[0]["version"]


def test_retry_after_completion_no_reexecution(orchestrator, components):
    event = _event("ok-1", source="host-a")
    # 选择纯安全动作：临时把危险动作策略替换思路——使用 service_down 需审批，
    # 因此这里走 disk_full 审批完成后再重复提交
    orchestrator.submit(event, OPERATOR)
    admin = Actor.parse("root", "admin")
    done = orchestrator.approve("ok-1", admin)
    assert done["state"] == "COMPLETED"

    files_after = sorted(
        str(p.relative_to(components["paths"] / "effects"))
        for p in (components["paths"] / "effects").rglob("*") if p.is_file()
    )
    mtimes = {f: (components["paths"] / "effects" / f).stat().st_mtime_ns for f in files_after}

    # 重复提交 / 重试：终态保持，不重放动作
    again = orchestrator.submit(event, OPERATOR)
    assert again["duplicate"] is True
    assert again["state"] == "COMPLETED"
    assert again["completed_actions"] == ["mark", "restart"]

    files_retry = sorted(
        str(p.relative_to(components["paths"] / "effects"))
        for p in (components["paths"] / "effects").rglob("*") if p.is_file()
    )
    assert files_retry == files_after
    assert all(
        (components["paths"] / "effects" / f).stat().st_mtime_ns == mtimes[f]
        for f in files_after
    ), "重复提交导致副作用文件被重写"


def test_concurrent_approve_single_effective(orchestrator):
    orchestrator.submit(_event("appr-1"), OPERATOR)
    admin = Actor.parse("root", "admin")
    results: list[dict] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(5)

    def approve() -> None:
        barrier.wait()
        try:
            results.append(orchestrator.approve("appr-1", admin))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=approve) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 仅一次审批成功并完成执行
    assert len(results) == 1
    assert results[0]["state"] == "COMPLETED"
    assert len(errors) == 4
    status = orchestrator.get_status("appr-1")
    assert status["approval_seq"] == 1
