"""审计：所有自动/人工迁移留痕，并发与重试下不丢条、不重号、不错序。"""
from __future__ import annotations

import threading

from app.schemas import Event


def test_full_lifecycle_audit_trail(components):
    _, _, audit, executor, _ = components
    event = Event(event_id="e-trail", event_type="disk_full", source="host-1",
                  severity="warning", submitted_by="carol")
    rec, _ = executor.submit_event(event)
    executor.tick()
    entries = audit.read_all()
    kinds = [e["kind"] for e in entries]
    assert "event.accepted" in kinds
    assert "run.start" in kinds
    assert "step.applied" in kinds
    assert "run.finished" in kinds

    # 每条都有 event_id/execution_id；策略标识记录在事件与状态迁移条目上
    for e in entries:
        assert e["event_id"] == "e-trail"
        assert e["execution_id"] == rec.id
    for kind in ("event.accepted", "run.start", "run.finished"):
        match = [e for e in entries if e["kind"] == kind]
        assert match and all(e["policy_id"] == "disk-safe" for e in match)

    finished = next(e for e in entries if e["kind"] == "run.finished")
    assert finished["from_state"] == "running"
    assert finished["to_state"] == "completed"


def test_rejections_are_audited(components):
    _, _, audit, executor, _ = components
    # 无策略
    from app.errors import PolicyRejected
    try:
        executor.submit_event(
            Event(event_id="e-rej1", event_type="nope", source="x",
                  submitted_by="carol"))
    except PolicyRejected:
        pass
    # 重复提交
    event = Event(event_id="e-rej2", event_type="disk_full", source="host-1",
                  severity="warning", submitted_by="carol")
    executor.submit_event(event)
    executor.submit_event(event)

    kinds = [e["kind"] for e in audit.read_all()]
    assert "event.rejected" in kinds
    assert kinds.count("submit.duplicate") == 1
    all_entries = audit.read_all()
    rejected = next(e for e in all_entries if e["kind"] == "event.rejected")
    assert rejected["reason"] == "policy_not_found"


def test_audit_sequence_contiguous_under_concurrency(components):
    _, _, audit, executor, _ = components

    def fire(n: int) -> None:
        executor.audit.emit(
            "load.test", execution_id=f"x{n}", event_id=f"e{n}", actor="carol",
            details={"i": n},
        )

    threads = []
    for n in range(10):
        for _ in range(3):
            threads.append(threading.Thread(target=fire, args=(n,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    seqs = [e["seq"] for e in audit.read_all()]
    assert len(seqs) == 30
    assert seqs == list(range(1, 31))  # 连续、单调、不错序
    assert len(set(seqs)) == 30         # 不重号


def test_audit_persists_across_restart(components, tmp_env):
    settings, _, audit, executor, _ = components
    event = Event(event_id="e-restart-audit", event_type="disk_full",
                  source="host-1", severity="warning", submitted_by="carol")
    rec, _ = executor.submit_event(event)
    executor.tick()
    before = audit.read_all()
    assert before

    # 重启后从同一文件重建序列号，继续追加仍保持单调连续
    from app.audit import AuditLogger
    audit2 = AuditLogger(settings.audit_log)
    assert audit2._seq == len(before)
    entry = audit2.emit("restart.marker", execution_id=rec.id, event_id="e-restart-audit")
    assert entry["seq"] == len(before) + 1
    all_entries = audit2.read_all()
    seqs = [e["seq"] for e in all_entries]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))


def test_human_and_auto_transitions_both_recorded(components):
    _, _, audit, executor, _ = components
    rec, _ = executor.submit_event(
        Event(event_id="e-human", event_type="disk_full", source="host-1",
              severity="warning", submitted_by="carol"))
    executor.request_cancel(rec.id, "carol")  # 人工
    executor.tick()                            # 自动迁移
    kinds = [e["kind"] for e in audit.read_all()]
    assert "cancel.requested" in kinds          # 人工动作
    cancelled = [e for e in audit.read_all() if e["kind"] == "run.cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["actor"] == "carol"
