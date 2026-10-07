"""FastAPI 路由与异常处理接入。

路由：
- POST /events                提交告警（重复提交返回同一执行记录，200）
- GET  /executions/{id}       查询执行状态
- POST /executions/{id}/approvals  人工授权危险动作
- POST /executions/{id}/retry      FAILED 后显式重试
- POST /executions/{id}/cancel     取消（未开始执行/失败停机当场落 cancelled；running/终态 409）
- GET  /executions                  列出全部执行（调试/验证）
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.actions import ActionRegistry
from app.audit import AuditLogger
from app.config import Settings, get_settings
from app.errors import (
    AuthorizationError,
    ExecutionConflict,
    OrchestratorError,
    PolicyRejected,
)
from app.executor import Executor
from app.policies import load_policies
from app.schemas import (
    AclConfig,
    ApprovalGrantRequest,
    CancellationRequest,
    Event,
    RejectReason,
    RejectResponse,
    RetryRequest,
)
from app.storage import Store

log = logging.getLogger("iro.api")

# 请求体整体不是“一个事件”的结构错误（非 JSON、非对象），
# 与“是事件但字段缺失/值非法”区分开
_STRUCTURAL_TYPES = {"json_invalid", "model_attributes_type", "model_type"}


def _validation_reason(errors: list[dict[str, Any]]) -> RejectReason:
    types = {str(e.get("type")) for e in errors}
    if types & _STRUCTURAL_TYPES:
        return RejectReason.INVALID_EVENT
    if "missing" in types:
        return RejectReason.MISSING_FIELD
    return RejectReason.INVALID_FIELD


def _safe_errors(exc: Any) -> list[dict[str, Any]]:
    # pydantic v2 的 ctx 里可能含异常对象，需转成可序列化字符串
    safe: list[dict[str, Any]] = []
    for err in exc.errors():
        item = {
            "loc": [str(p) for p in err.get("loc", [])],
            "type": err.get("type"),
            "msg": err.get("msg"),
        }
        ctx = err.get("ctx")
        if ctx:
            item["ctx"] = {k: str(v) for k, v in ctx.items()}
        safe.append(item)
    return safe


def _load_acl(path: str) -> AclConfig:
    with open(path, "r", encoding="utf-8") as fh:
        return AclConfig.model_validate(json.load(fh))


def build_executor(
    settings: Settings,
    *,
    actions: ActionRegistry | None = None,
    start_worker: bool = True,
) -> Executor:
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    store = Store(settings.store_file, Path(settings.data_dir, "effects.jsonl").as_posix())
    audit = AuditLogger(settings.audit_log)
    policies = load_policies(settings.policy_file)
    acl = _load_acl(settings.acl_file)
    executor = Executor(
        settings,
        store,
        audit,
        policies,
        acl,
        actions or ActionRegistry(),
    )
    if start_worker:
        executor.start()
    return executor


def create_app(
    settings: Settings | None = None,
    *,
    executor: Executor | None = None,
    start_worker: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="incident-remediation-orchestrator", version="0.1.0")
    app.state.settings = settings

    if executor is None:
        executor = build_executor(settings, start_worker=start_worker)
    app.state.executor = executor

    @app.exception_handler(OrchestratorError)
    async def _on_orch_error(_: Request, exc: OrchestratorError) -> JSONResponse:
        status_code = 400
        if isinstance(exc, AuthorizationError):
            status_code = 403
        elif isinstance(exc, ExecutionConflict):
            status_code = 404 if exc.reason == RejectReason.EXECUTION_NOT_FOUND else 409
        elif isinstance(exc, PolicyRejected):
            status_code = 422
        body = RejectResponse(
            error=exc.message, reason=exc.reason, details=exc.details
        ).model_dump()
        log.warning(
            "request rejected reason=%s details=%s", exc.reason.value, exc.details
        )
        return JSONResponse(status_code=status_code, content=body)

    @app.exception_handler(ValidationError)
    async def _on_validation(_: Request, exc: ValidationError) -> JSONResponse:
        safe_errors = _safe_errors(exc)
        reason = _validation_reason(safe_errors)
        # 字段缺失/值非法不得静默：给出可区分的拒绝原因
        body = RejectResponse(
            error="event payload failed validation",
            reason=reason,
            details={"errors": safe_errors},
        ).model_dump()
        log.warning("invalid event rejected reason=%s: %s", reason.value, safe_errors)
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(RequestValidationError)
    async def _on_request_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # 请求体非对象 / 类型错误等框架层校验失败，同样给出可区分的拒绝原因
        safe_errors = _safe_errors(exc)
        reason = _validation_reason(safe_errors)
        body = RejectResponse(
            error="event payload failed validation",
            reason=reason,
            details={"errors": safe_errors},
        ).model_dump()
        log.warning("malformed request rejected reason=%s: %s", reason.value, safe_errors)
        return JSONResponse(status_code=422, content=body)

    @app.get("/")
    def root() -> dict[str, str]:
        return {"service": "incident-remediation-orchestrator", "status": "ok"}

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "executions": len(executor.store.all_executions())}

    @app.post("/events", status_code=202)
    def submit_event(event: Event) -> dict[str, Any]:
        # FastAPI 已按 Event 模型校验，非法结构经 _on_request_validation
        # 统一映射为 invalid_event，确保不静默执行
        record, created = executor.submit_event(event)
        return {
            "created": created,
            "execution": record.model_dump(mode="json"),
        }

    @app.get("/executions")
    def list_executions() -> dict[str, Any]:
        return {
            "executions": [
                r.model_dump(mode="json") for r in executor.store.all_executions()
            ]
        }

    @app.get("/executions/{execution_id}")
    def get_execution(execution_id: str) -> dict[str, Any]:
        record = executor.store.get(execution_id)
        if record is None:
            raise ExecutionConflict(
                RejectReason.EXECUTION_NOT_FOUND,
                "execution not found",
                {"execution_id": execution_id},
            )
        return record.model_dump(mode="json")

    @app.post("/executions/{execution_id}/approvals")
    def grant_approval(execution_id: str, req: ApprovalGrantRequest) -> dict[str, Any]:
        approval = executor.grant_approval(
            execution_id, req.granted_by, req.ttl_seconds
        )
        return approval.model_dump(mode="json")

    @app.post("/executions/{execution_id}/retry")
    def retry_execution(execution_id: str, req: RetryRequest) -> dict[str, Any]:
        record = executor.retry(execution_id, req.requested_by)
        return record.model_dump(mode="json")

    @app.post("/executions/{execution_id}/cancel")
    def cancel_execution(execution_id: str, req: CancellationRequest) -> dict[str, Any]:
        record = executor.request_cancel(execution_id, req.requested_by)
        return record.model_dump(mode="json")

    @app.on_event("shutdown")
    def _shutdown() -> None:
        executor.stop()

    return app
