"""HTTP API：接入 FastAPI 的路由、请求头身份与统一异常响应。"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .authz import Actor
from .errors import DomainError, RejectReason
from .orchestrator import Orchestrator

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


def get_orchestrator(request: Request) -> Orchestrator:
    return request.app.state.orchestrator  # type: ignore[no-any-return]


def _actor_from_request(request: Request) -> Actor | None:
    return Actor.parse(
        request.headers.get("x-actor"),
        request.headers.get("x-actor-roles"),
    )


def _error_response(exc: DomainError) -> JSONResponse:
    status = _STATUS_BY_REASON.get(exc.reason, 422)
    return JSONResponse(
        status_code=status,
        content={
            "rejected": True,
            "reason": exc.reason.value,
            "message": exc.message,
        },
    )


_STATUS_BY_REASON: dict[RejectReason, int] = {
    RejectReason.MALFORMED_EVENT: 400,
    RejectReason.MISSING_FIELD: 400,
    RejectReason.NO_MATCHING_POLICY: 422,
    RejectReason.POLICY_CONFLICT: 422,
    RejectReason.UNAUTHENTICATED: 401,
    RejectReason.FORBIDDEN: 403,
    RejectReason.PERMISSION_DENIED: 403,
    RejectReason.APPROVAL_REQUIRED: 409,
    RejectReason.APPROVAL_EXPIRED: 410,
    RejectReason.APPROVAL_REVOKED: 409,
    RejectReason.INVALID_TRANSITION: 409,
    RejectReason.ILLEGAL_STATE: 409,
    RejectReason.EXECUTION_NOT_FOUND: 404,
    RejectReason.CONFIG_INVALID: 500,
}


async def _read_body(request: Request) -> Any:
    raw_bytes = await request.body()
    if len(raw_bytes) > request.app.state.settings.max_event_size:
        raise DomainError(
            RejectReason.MALFORMED_EVENT,
            f"事件体超过大小上限 {request.app.state.settings.max_event_size} 字节",
        )
    if not raw_bytes:
        raise DomainError(RejectReason.MALFORMED_EVENT, "请求体为空")
    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainError(RejectReason.MALFORMED_EVENT, f"事件体不是合法 JSON: {exc}") from exc


@router.post("/events")
async def submit_event(request: Request) -> JSONResponse:
    orch = get_orchestrator(request)
    actor = _actor_from_request(request)
    raw = await _read_body(request)
    view = orch.submit(raw, actor)
    if view.pop("rejected", False):
        # 首次提交即被策略拒绝（已持久化为 REJECTED，不产生副作用）
        return JSONResponse(status_code=422, content=view)
    status = 200 if view.get("duplicate") else 201
    return JSONResponse(status_code=status, content=view)


@router.get("/executions/{event_id}")
async def get_execution(event_id: str, request: Request) -> JSONResponse:
    return JSONResponse(get_orchestrator(request).get_status(event_id))


@router.post("/executions/{event_id}/approve")
async def approve_execution(event_id: str, request: Request) -> JSONResponse:
    actor = _actor_from_request(request)
    return JSONResponse(get_orchestrator(request).approve(event_id, actor))


@router.post("/executions/{event_id}/cancel")
async def cancel_execution(event_id: str, request: Request) -> JSONResponse:
    actor = _actor_from_request(request)
    return JSONResponse(get_orchestrator(request).cancel(event_id, actor))


@router.get("/executions/{event_id}/audit")
async def get_audit(event_id: str, request: Request) -> JSONResponse:
    orch = get_orchestrator(request)
    orch.get_status(event_id)  # 不存在则 404
    return JSONResponse({"event_id": event_id, "entries": orch.audit.history(event_id)})
