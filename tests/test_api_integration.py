"""通过真实 FastAPI 应用 + 后台 worker 验证端到端异步执行，
确保能力接入了服务的启动、配置与异常处理，而非独立脚本。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.config import Settings


def _app_settings(tmp: Path) -> Settings:
    return Settings(
        data_dir=str(tmp / "data"),
        policy_file=str(tmp / "policies.json"),
        acl_file=str(tmp / "acl.json"),
        audit_log=str(tmp / "logs" / "audit.log"),
        app_log=str(tmp / "logs" / "app.log"),
        approval_ttl_seconds=600,
        execution_timeout_seconds=30,
        worker_tick_seconds=0.01,
        max_attempts=3,
    )


POLICIES = [
    {
        "id": "disk-safe",
        "match": {"event_type": "disk_full", "source_prefix": "host-",
                  "severities": ["warning", "critical"]},
        "priority": 100,
        "actions": [
            {"name": "clear_disk_cache", "risk": "safe", "required_role": "operator"},
            {"name": "restart_service", "risk": "safe", "required_role": "operator"},
        ],
    },
    {
        "id": "security-dangerous",
        "match": {"event_type": "security_intrusion", "severities": ["critical"]},
        "priority": 10,
        "actions": [
            {"name": "isolate_host", "risk": "dangerous", "required_role": "admin"},
        ],
    },
    {
        "id": "disk-flaky",
        "match": {"event_type": "disk_flaky"},
        "priority": 100,
        "actions": [
            {"name": "restart_service", "required_role": "operator",
             "params": {"fail": True}},
        ],
    },
]
ACL = {
    "users": {"alice": "admin", "carol": "operator"},
    "roles": {"admin": ["operator", "admin", "approve"], "operator": ["operator"]},
}


@pytest.fixture
def running_client(tmp_path: Path):
    (tmp_path / "data").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "policies.json").write_text(json.dumps(POLICIES), encoding="utf-8")
    (tmp_path / "acl.json").write_text(json.dumps(ACL), encoding="utf-8")
    settings = _app_settings(tmp_path)
    app = create_app(settings, start_worker=True)
    with TestClient(app) as client:
        yield client, settings


def _wait_state(client, exec_id, expected, timeout=3.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        body = client.get(f"/executions/{exec_id}").json()
        last = body["state"]
        if last == expected:
            return body
        time.sleep(0.02)
    raise AssertionError(f"state never reached {expected}; last={last}")


def test_safe_event_auto_remediated_via_worker(running_client):
    client, _ = running_client
    resp = client.post("/events", json={
        "event_id": "api-e-1", "event_type": "disk_full",
        "source": "host-42", "severity": "critical", "submitted_by": "carol",
    })
    assert resp.status_code == 202, resp.text
    exec_id = resp.json()["execution"]["id"]
    final = _wait_state(client, exec_id, "completed")
    assert [s["status"] for s in final["steps"]] == ["applied", "applied"]
    effects = Path(_effect_path(client)).read_text(encoding="utf-8").strip().splitlines()
    keys = [json.loads(x)["effect_key"] for x in effects]
    assert keys == [f"{exec_id}:0", f"{exec_id}:1"]


def test_dangerous_event_full_approval_flow(running_client):
    client, _ = running_client
    resp = client.post("/events", json={
        "event_id": "api-e-2", "event_type": "security_intrusion",
        "source": "fw-edge", "severity": "critical", "submitted_by": "alice",
    })
    exec_id = resp.json()["execution"]["id"]
    waiting = _wait_state(client, exec_id, "awaiting_approval")
    assert waiting["steps"][0]["status"] == "pending"

    # 越权审批被拒
    denied = client.post(f"/executions/{exec_id}/approvals",
                         json={"granted_by": "carol"})
    assert denied.status_code == 403

    # 管理员审批
    granted = client.post(f"/executions/{exec_id}/approvals",
                          json={"granted_by": "alice"})
    assert granted.status_code == 200
    final = _wait_state(client, exec_id, "completed")
    assert final["steps"][0]["status"] == "applied"


def test_duplicate_event_returns_same_execution_over_http(running_client):
    client, _ = running_client
    payload = {
        "event_id": "api-e-dup", "event_type": "disk_full",
        "source": "host-9", "severity": "warning", "submitted_by": "carol",
    }
    r1 = client.post("/events", json=payload).json()
    r2 = client.post("/events", json=payload).json()
    assert r1["created"] is True
    assert r2["created"] is False
    assert r1["execution"]["id"] == r2["execution"]["id"]
    _wait_state(client, r1["execution"]["id"], "completed")
    assert len(client.get("/executions").json()["executions"]) == 1


def test_failure_convergence_and_confirmed_retry_over_http(running_client):
    """持续失败 -> FAILED -> 显式重试 -> 耗尽终态 -> 未确认拒绝 -> 确认后续跑。"""
    client, settings = running_client
    resp = client.post("/events", json={
        "event_id": "api-e-flaky", "event_type": "disk_flaky",
        "source": "host-3", "severity": "critical", "submitted_by": "carol",
    })
    exec_id = resp.json()["execution"]["id"]
    _wait_state(client, exec_id, "failed")

    # 第 2 次显式尝试
    assert client.post(f"/executions/{exec_id}/retry",
                       json={"requested_by": "carol"}).status_code == 200
    _wait_state(client, exec_id, "failed")
    # 第 3 次显式尝试 => 预算耗尽（max_attempts=3）
    client.post(f"/executions/{exec_id}/retry", json={"requested_by": "carol"})
    exhausted = _wait_state(client, exec_id, "retry_exhausted")
    assert exhausted["attempts_used"] == 3

    # 没有人工确认 => 409 + retry_exhausted，状态不变
    denied = client.post(f"/executions/{exec_id}/retry",
                         json={"requested_by": "carol"})
    assert denied.status_code == 409
    assert denied.json()["reason"] == "retry_exhausted"
    assert client.get(f"/executions/{exec_id}").json()["state"] == "retry_exhausted"

    # 模拟人为修复：改写策略文件并重启一个新实例读取同一数据目录
    fixed_policies = [
        {
            "id": "disk-flaky",
            "match": {"event_type": "disk_flaky"},
            "priority": 100,
            "actions": [
                {"name": "restart_service", "required_role": "operator"},
            ],
        }
    ]
    Path(settings.policy_file).write_text(json.dumps(fixed_policies), encoding="utf-8")
    # 直接在运行中的 executor 上热替换策略（本地验证场景），确认重试后续跑
    executor = client.app.state.executor
    from app.policies import load_policies
    executor.policies[:] = load_policies(settings.policy_file)
    confirmed = client.post(f"/executions/{exec_id}/retry",
                            json={"requested_by": "carol", "confirmed": True})
    assert confirmed.status_code == 200
    final = _wait_state(client, exec_id, "completed")
    assert final["state"] == "completed"
    # 整个历史只有一次有效副作用
    effects = Path(settings.data_dir, "effects.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    keys = [json.loads(x)["effect_key"] for x in effects]
    assert keys == [f"{exec_id}:0"]


def _effect_path(client) -> str:
    settings = client.app.state.settings
    return os.path.join(settings.data_dir, "effects.jsonl")
