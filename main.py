"""服务入口：`uv run uvicorn main:app` 启动本地告警修复编排服务。"""
from __future__ import annotations

from remediation.app import create_app

app = create_app()
