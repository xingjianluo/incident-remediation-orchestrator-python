"""测试夹具：每个用例使用隔离的临时目录与可控时钟，不依赖外部服务。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.actions import ActionRegistry
from app.api import create_app
from app.audit import AuditLogger
from app.config import Settings
from app.executor import Executor
from app.policies import load_policies
from app.schemas import AclConfig
from app.storage import Store


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _settings(tmp: Path) -> Settings:
    return Settings(
        data_dir=str(tmp / "data"),
        policy_file=str(tmp / "policies.json"),
        acl_file=str(tmp / "acl.json"),
        audit_log=str(tmp / "logs" / "audit.log"),
        app_log=str(tmp / "logs" / "app.log"),
        approval_ttl_seconds=600,
        execution_timeout_seconds=30,
        worker_tick_seconds=0.005,
        # 既有用例的默认语义：失败一次即停在 FAILED，不做自动重试；
        # 失败收敛用例自行构造更大的预算
        max_step_attempts=1,
    )


POLICIES: list[dict[str, Any]] = [
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
        "id": "disk-low",
        "description": "冲突低优先级策略",
        "match": {"event_type": "disk_full"},
        "priority": 200,
        "actions": [
            {"name": "scale_workers", "risk": "safe", "required_role": "operator"},
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
        "id": "overload-partial",
        "match": {"event_type": "service_overload", "labels": {"tier": "backend"}},
        "priority": 50,
        "actions": [
            {"name": "scale_workers", "risk": "safe", "required_role": "operator",
             "continue_on_failure": True, "params": {"count": 2, "fail": True}},
            {"name": "restart_service", "risk": "safe", "required_role": "operator"},
        ],
    },
]

ACL = {
    "users": {"alice": "admin", "carol": "operator", "dave": "viewer"},
    "roles": {
        "admin": ["operator", "admin", "approve"],
        "operator": ["operator"],
        "viewer": ["read"],
    },
}


@pytest.fixture
def tmp_env(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "policies.json").write_text(json.dumps(POLICIES), encoding="utf-8")
    (tmp_path / "acl.json").write_text(json.dumps(ACL), encoding="utf-8")
    return tmp_path


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def components(tmp_env: Path, clock: FakeClock):
    """直接组装 executor，不启 worker（用例自行 tick 控制时序）。"""
    settings = _settings(tmp_env)
    store = Store(settings.store_file, os.path.join(settings.data_dir, "effects.jsonl"))
    audit = AuditLogger(settings.audit_log)
    policies = load_policies(settings.policy_file)
    with open(settings.acl_file, encoding="utf-8") as fh:
        acl = AclConfig.model_validate(json.load(fh))
    executor = Executor(
        settings, store, audit, policies, acl, ActionRegistry(), clock=clock
    )
    return settings, store, audit, executor, tmp_env


@pytest.fixture
def client(components):
    settings, _store, _audit, executor, _tmp_env = components
    app = create_app(settings, executor=executor, start_worker=False)
    with TestClient(app) as c:
        yield c, executor
