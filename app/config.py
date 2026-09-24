"""应用配置：存储路径、审批有效期、执行超时等。

接入既有服务的配置方式：通过环境变量覆盖默认值，不依赖外部配置中心。
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    data_dir: str
    policy_file: str
    acl_file: str
    audit_log: str
    app_log: str
    approval_ttl_seconds: int
    execution_timeout_seconds: int
    worker_tick_seconds: float

    @property
    def store_file(self) -> str:
        return os.path.join(self.data_dir, "store.json")


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def get_settings() -> Settings:
    """从环境变量构造配置；未设置时使用仓库内的本地默认值。"""
    base = _env("IRO_BASE_DIR", ".")
    data_dir = _env("IRO_DATA_DIR", os.path.join(base, "var", "data"))
    log_dir = _env("IRO_LOG_DIR", os.path.join(base, "var", "log"))
    return Settings(
        data_dir=data_dir,
        policy_file=_env("IRO_POLICY_FILE", os.path.join(base, "config", "policies.json")),
        acl_file=_env("IRO_ACL_FILE", os.path.join(base, "config", "acl.json")),
        audit_log=_env("IRO_AUDIT_LOG", os.path.join(log_dir, "audit.log")),
        app_log=_env("IRO_APP_LOG", os.path.join(log_dir, "app.log")),
        approval_ttl_seconds=int(_env("IRO_APPROVAL_TTL_SECONDS", "600")),
        execution_timeout_seconds=int(_env("IRO_EXECUTION_TIMEOUT_SECONDS", "30")),
        worker_tick_seconds=float(_env("IRO_WORKER_TICK_SECONDS", "0.02")),
    )
