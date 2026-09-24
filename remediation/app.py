"""应用装配：启动时加载配置与策略、初始化存储并执行崩溃恢复。"""
from __future__ import annotations

import contextlib
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .actions import ActionRegistry
from .audit import AuditTrail, configure_logging
from .authz import AuthzService
from .config import Settings, load_settings
from .errors import DomainError, RejectReason
from .api import _STATUS_BY_REASON, router as remediation_router
from .orchestrator import Orchestrator
from .policies import PolicyEngine
from .storage import Storage

log = logging.getLogger("remediation")


def build_components(settings: Settings) -> dict:
    """根据配置构造全部组件（供应用启动与测试复用）。"""
    storage = Storage(settings.db_path)
    storage.init_db()
    policies = PolicyEngine.from_file(settings.policy_file)
    actions = ActionRegistry(settings.effects_dir)
    actions.register_defaults()
    authz = AuthzService(settings.approval_ttl_seconds)
    audit = AuditTrail(storage)
    orchestrator = Orchestrator(
        storage=storage,
        policies=policies,
        actions=actions,
        authz=authz,
        audit=audit,
        step_timeout_seconds=settings.step_timeout_seconds,
    )
    return {
        "storage": storage,
        "policies": policies,
        "actions": actions,
        "authz": authz,
        "audit": audit,
        "orchestrator": orchestrator,
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(settings.log_level)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        components = build_components(settings)
        app.state.storage = components["storage"]
        app.state.orchestrator = components["orchestrator"]
        app.state.audit = components["audit"]
        recovered = components["orchestrator"].recover_all()
        log.info('{"type":"startup","recovered":%d,"policy_file":"%s"}', recovered, settings.policy_file)
        try:
            yield
        finally:
            components["storage"].close()

    app = FastAPI(
        title="本地告警自动修复编排服务",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        status = _STATUS_BY_REASON.get(exc.reason, 422)
        log.info(
            '{"type":"request_rejected","path":"%s","reason":"%s","message":%s}',
            request.url.path,
            exc.reason.value,
            _json(exc.message),
        )
        return JSONResponse(
            status_code=status,
            content={"rejected": True, "reason": exc.reason.value, "message": exc.message},
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        log.exception('{"type":"unhandled_error","path":"%s"}', request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "rejected": True,
                "reason": RejectReason.ILLEGAL_STATE.value,
                "message": f"服务内部错误: {exc.__class__.__name__}",
            },
        )

    app.include_router(remediation_router)

    @app.get("/")
    def root() -> dict:
        return {"service": "incident-remediation-orchestrator", "status": "ok"}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    return app


def _json(text: str) -> str:
    import json as _json

    return _json.dumps(text, ensure_ascii=False)
