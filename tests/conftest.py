"""pytest 共享夹具：临时目录、确定性策略、编排器与 TestClient。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.actions import ActionRegistry  # noqa: E402
from remediation.app import create_app  # noqa: E402
from remediation.audit import AuditTrail  # noqa: E402
from remediation.authz import AuthzService  # noqa: E402
from remediation.config import Settings  # noqa: E402
from remediation.orchestrator import Orchestrator  # noqa: E402
from remediation.policies import PolicyEngine  # noqa: E402
from remediation.storage import Storage  # noqa: E402

POLICIES = {
    "policies": [
        {
            "policy_id": "disk-danger",
            "priority": 100,
            "match": {"source": "host-a", "alert_type": "disk_full"},
            "actions": [
                {"name": "mark", "action": "write_file",
                 "params": {"filename": "marker.txt", "content": "go"},
                 "dangerous": False},
                {"name": "restart", "action": "restart_service",
                 "params": {"service": "log-agent"},
                 "dangerous": True, "required_role": "admin"},
            ],
        },
        {
            "policy_id": "service-danger",
            "priority": 90,
            "match": {"alert_type": "service_down"},
            "actions": [
                {"name": "restart", "action": "restart_service",
                 "params": {"service": "svc"},
                 "dangerous": True, "required_role": "admin"},
            ],
        },
        {
            "policy_id": "auto-noop",
            "priority": 10,
            "match": {"source": "host-a"},
            "actions": [{"name": "ack", "action": "noop", "dangerous": False}],
        },
        {
            "policy_id": "conflict-a",
            "priority": 50,
            "match": {"alert_type": "ambiguous"},
            "actions": [{"name": "a", "action": "noop", "dangerous": False}],
        },
        {
            "policy_id": "conflict-b",
            "priority": 50,
            "match": {"alert_type": "ambiguous"},
            "actions": [{"name": "b", "action": "noop", "dangerous": False}],
        },
        {
            "policy_id": "partial-fail",
            "priority": 100,
            "match": {"alert_type": "flaky"},
            "actions": [
                {"name": "ok-step", "action": "write_file",
                 "params": {"filename": "ok.txt", "content": "1"},
                 "dangerous": False},
                {"name": "fail-step", "action": "simulate_fail",
                 "params": {"message": "boom"}, "dangerous": False},
            ],
        },
        {
            "policy_id-mistake": None,  # 占位，测试中不使用
        },
    ]
}
# 去掉无效占位
POLICIES["policies"] = [p for p in POLICIES["policies"] if p.get("policy_id")]


@pytest.fixture()
def paths(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir()
    return tmp_path


@pytest.fixture()
def policy_file(paths: Path) -> Path:
    import json

    p = paths / "policies.json"
    p.write_text(json.dumps(POLICIES), encoding="utf-8")
    return p


@pytest.fixture()
def components(paths: Path, policy_file: Path):
    storage = Storage(str(paths / "data" / "test.db"))
    storage.init_db()
    engine = PolicyEngine.from_file(str(policy_file))
    registry = ActionRegistry(str(paths / "effects"))
    registry.register_defaults()
    authz = AuthzService(approval_ttl_seconds=300)
    audit = AuditTrail(storage)
    orchestrator = Orchestrator(storage, engine, registry, authz, audit, step_timeout_seconds=30)
    yield {
        "storage": storage,
        "engine": engine,
        "registry": registry,
        "authz": authz,
        "audit": audit,
        "orchestrator": orchestrator,
        "paths": paths,
    }
    storage.close()


@pytest.fixture()
def orchestrator(components):
    return components["orchestrator"]


@pytest.fixture()
def client(paths: Path, policy_file: Path):
    settings = Settings(
        policy_file=str(policy_file),
        db_path=str(paths / "data" / "api.db"),
        effects_dir=str(paths / "effects"),
        approval_ttl_seconds=300,
        step_timeout_seconds=30,
        log_level="WARNING",
    )
    app = create_app(settings)
    with TestClient(app) as c:
        c.app_state_settings = settings
        yield c
