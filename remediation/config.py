"""服务配置，通过环境变量注入，提供 FastAPI 依赖。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    policy_file: str = "config/policies.json"
    db_path: str = "data/remediation.db"
    effects_dir: str = "data/effects"
    approval_ttl_seconds: int = 300
    action_timeout_seconds: int = 10
    step_timeout_seconds: int = 30
    max_event_size: int = 65536
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        def _int(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if raw is None or raw.strip() == "":
                return default
            try:
                value = int(raw)
            except ValueError as exc:
                raise ValueError(f"环境变量 {name} 必须是整数，实际为 {raw!r}") from exc
            if value <= 0:
                raise ValueError(f"环境变量 {name} 必须为正整数，实际为 {value}")
            return value

        return cls(
            policy_file=os.environ.get("REMEDIATION_POLICY_FILE", "config/policies.json"),
            db_path=os.environ.get("REMEDIATION_DB_PATH", "data/remediation.db"),
            effects_dir=os.environ.get("REMEDIATION_EFFECTS_DIR", "data/effects"),
            approval_ttl_seconds=_int("REMEDIATION_APPROVAL_TTL_SECONDS", 300),
            action_timeout_seconds=_int("REMEDIATION_ACTION_TIMEOUT_SECONDS", 10),
            step_timeout_seconds=_int("REMEDIATION_STEP_TIMEOUT_SECONDS", 30),
            max_event_size=_int("REMEDIATION_MAX_EVENT_SIZE", 65536),
            log_level=os.environ.get("REMEDIATION_LOG_LEVEL", "INFO").upper(),
        )


def load_settings() -> Settings:
    return Settings.from_env()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
