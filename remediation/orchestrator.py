"""编排核心：提交 / 审批 / 取消 / 执行循环 / 崩溃恢复。

并发模型：每个 event_id 一把互斥锁串行化该事件的全部迁移；
持久化使用 version 乐观锁双保险。重复/并发提交通过 INSERT OR IGNORE 去重。
恰好一次：动作按固定 current_index 推进，先落状态再执行；崩溃后
completed_actions 之外的步骤重放，处理器以固定产物保证幂等。
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from .actions import ActionFailure, ActionRegistry, SimulatedCrash
from .audit import AuditTrail
from .authz import Actor, AuthzService
from .errors import AuthzError, DomainError, PolicyError, RejectReason, StateError
from .models import Event, ExecutionRecord, Policy, State
from .policies import PolicyEngine
from .state_machine import assert_transition
from .storage import Storage

log = logging.getLogger("remediation")


class Orchestrator:
    def __init__(
        self,
        storage: Storage,
        policies: PolicyEngine,
        actions: ActionRegistry,
        authz: AuthzService,
        audit: AuditTrail,
        step_timeout_seconds: int = 30,
    ) -> None:
        self.storage = storage
        self.policies = policies
        self.actions = actions
        self.authz = authz
        self.audit = audit
        self.step_timeout_seconds = step_timeout_seconds
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._validate_action_types()

    def _validate_action_types(self) -> None:
        for policy in self.policies.policies:
            for spec in policy.actions:
                if not self.actions.known(spec.action):
                    raise PolicyError(
                        RejectReason.CONFIG_INVALID,
                        f"策略 {policy.policy_id} 的动作 {spec.name!r} 引用未知动作类型 "
                        f"{spec.action!r}",
                    )

    # ---- 工具 ----
    def _event_lock(self, event_id: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(event_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[event_id] = lock
            return lock

    @staticmethod
    def _record_view(record: ExecutionRecord, **extra: Any) -> dict[str, Any]:
        view = {
            "event_id": record.event_id,
            "policy_id": record.policy_id,
            "state": record.state.value,
            "actions": record.action_names,
            "completed_actions": record.completed_actions,
            "current_index": record.current_index,
            "approver": record.approver,
            "approval_seq": record.approval_seq,
            "approval_expires_at": record.approval_expires_at,
            "deadline": record.deadline,
            "reject_reason": record.reject_reason,
            "last_error": record.last_error,
            "duplicate": False,
            "rejected": False,
            "version": record.version,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        view.update(extra)
        return view

    def _persist(self, record: ExecutionRecord, expected: int) -> None:
        if not self.storage.save_execution(record, expected):
            raise StateError(
                RejectReason.ILLEGAL_STATE,
                f"事件 {record.event_id} 状态版本冲突（expected={expected}），"
                "检测到并发修改，本次迁移中止",
            )

    def _find_policy(self, event: Event) -> Policy:
        return self.policies.select(event)

    # ---- 提交 ----
    def submit(self, raw: dict[str, Any], actor: Actor | None) -> dict[str, Any]:
        # 1) 身份/权限（未授权不得产生任何执行状态）
        self.authz.check_submit(actor)
        assert actor is not None

        # 2) 事件解析：结构性错误与字段缺失区分拒绝原因
        try:
            event = Event.from_raw(raw)
        except ValueError as exc:
            msg = str(exc)
            reason = (
                RejectReason.MISSING_FIELD
                if msg.startswith("字段缺失或为空")
                else RejectReason.MALFORMED_EVENT
            )
            log.info(
                '{"type":"event_rejected","event_id":%s,"reason":"%s","detail":%s}',
                (raw.get("event_id") if isinstance(raw, dict) else None),
                reason.value,
                _json_str(msg),
            )
            raise DomainError(reason, msg) from exc

        lock = self._event_lock(event.event_id)
        with lock:
            # 3) 幂等：已存在则直接返回既有确定结果，不重复执行
            existing = self.storage.get_execution(event.event_id)
            if existing is not None:
                self.audit.record(
                    event.event_id,
                    "SUBMIT_DEDUP",
                    actor.name,
                    detail=f"重复提交，保持状态 {existing.state.value}",
                )
                return self._record_view(existing, duplicate=True)

            # 4) 策略裁决（确定、可复现；无匹配/冲突都拒绝且不执行）
            try:
                policy = self._find_policy(event)
            except PolicyError as exc:
                record = self._store_rejected(event, exc, actor.name)
                return self._record_view(record, rejected=True)

            log.info(
                '{"type":"policy_decision","event_id":"%s","selected_policy":"%s"}',
                event.event_id,
                policy.policy_id,
            )

            now = time.time()
            record = ExecutionRecord(
                event_id=event.event_id,
                policy_id=policy.policy_id,
                state=State.PENDING,
                action_names=[a.name for a in policy.actions],
                created_at=now,
                updated_at=now,
            )
            # INSERT OR IGNORE 决出并发提交的唯一赢家
            if not self.storage.insert_execution(record):
                winner = self.storage.get_execution(event.event_id)
                assert winner is not None
                self.audit.record(
                    event.event_id,
                    "SUBMIT_DEDUP",
                    actor.name,
                    detail="并发提交，另一请求已创建执行",
                )
                return self._record_view(winner, duplicate=True)

            self.audit.record(
                event.event_id,
                "PENDING",
                actor.name,
                detail=f"策略 {policy.policy_id} 命中，已接收",
            )
            return self._continue_execution(record, policy, actor.name)

    def _store_rejected(self, event: Event, exc: PolicyError, actor: str) -> ExecutionRecord:
        now = time.time()
        policy_id = ""
        if exc.reason is RejectReason.POLICY_CONFLICT:
            policy_id = "conflict"
        record = ExecutionRecord(
            event_id=event.event_id,
            policy_id=policy_id,
            state=State.REJECTED,
            action_names=[],
            reject_reason=exc.reason.value,
            last_error=exc.message,
            created_at=now,
            updated_at=now,
        )
        self.storage.insert_execution(record)
        self.audit.record(
            event.event_id,
            "REJECTED",
            actor,
            reason=exc.reason.value,
            detail=exc.message,
        )
        return record

    # ---- 执行推进 ----
    def _continue_execution(
        self,
        record: ExecutionRecord,
        policy: Policy | None,
        actor: str,
    ) -> dict[str, Any]:
        """调用方必须持有事件锁。record 为刚从 DB 读出的最新状态。"""
        if policy is None:
            policy = self._load_policy(record.policy_id)
        now = time.time()

        # 危险动作审批门禁
        allowed, why = self.authz.evaluate(record, policy.actions, now)
        if not allowed:
            if why == RejectReason.APPROVAL_EXPIRED.value:
                return self._view_transition(
                    record, State.REJECTED, actor, RejectReason.APPROVAL_EXPIRED.value,
                    "审批已过期，拒绝继续执行",
                )
            if record.state is not State.WAITING_APPROVAL:
                assert_transition(record.state, State.WAITING_APPROVAL)
                expected = record.version
                record.state = State.WAITING_APPROVAL
                record.updated_at = now
                self._persist(record, expected)
                self.audit.record(
                    record.event_id, "WAITING_APPROVAL", actor,
                    reason=RejectReason.APPROVAL_REQUIRED.value,
                    detail="含危险动作，等待管理员审批",
                )
            return self._record_view(record)

        return self._run_loop(record, policy, actor)

    def _view_transition(
        self, record: ExecutionRecord, dst: State, actor: str,
        reason: str, detail: str,
    ) -> dict[str, Any]:
        assert_transition(record.state, dst)
        expected = record.version
        record.state = dst
        record.reject_reason = reason if dst is State.REJECTED else record.reject_reason
        record.last_error = detail
        record.updated_at = time.time()
        self._persist(record, expected)
        self.audit.record(record.event_id, dst.value, actor, reason=reason, detail=detail)
        return self._record_view(record)

    def _run_loop(
        self,
        record: ExecutionRecord,
        policy: Policy,
        actor: str,
    ) -> dict[str, Any]:
        # 进入 RUNNING 并设置整体截止时间
        if record.deadline is None:
            record.deadline = time.time() + self.step_timeout_seconds
        if record.state is not State.RUNNING:
            assert_transition(record.state, State.RUNNING)
            expected = record.version
            record.state = State.RUNNING
            record.updated_at = time.time()
            self._persist(record, expected)
            self.audit.record(record.event_id, "RUNNING", actor, detail="开始执行动作序列")

        failures = 0
        while record.current_index < len(policy.actions):
            now = time.time()
            if record.deadline is not None and now > record.deadline:
                return self._view_transition(
                    record, State.TIMED_OUT, "system",
                    RejectReason.ILLEGAL_STATE.value,
                    f"执行超过截止时间 {record.deadline}",
                )

            spec = policy.actions[record.current_index]
            if spec.name in record.completed_actions:
                # 恢复重放：崩溃窗口前已完成的步骤不重复产生副作用
                record.current_index += 1
                continue

            expected = record.version
            record.updated_at = time.time()
            self._persist(record, expected)  # 先落当前 index，崩溃后据此重放
            self.audit.record(
                record.event_id, "ACTION_START", "system",
                detail=f"动作 {spec.name} ({spec.action}) index={record.current_index}",
            )

            try:
                result = self.actions.execute(
                    spec.action, dict(spec.params), record.event_id, step_name=spec.name
                )
            except SimulatedCrash:
                # 测试注入的“进程崩溃”：异常向上抛出，完成状态不落盘，
                # 重启后由 recover_all 依据已落盘进度确定性重放（幂等）。
                raise
            except ActionFailure as exc:
                failures += 1
                record.last_error = f"动作 {spec.name} 失败: {exc.message}"
                # 失败步骤不推进 index 以外的执行：首个失败即停止，避免冒险执行后续动作
                expected2 = record.version
                record.updated_at = time.time()
                self._persist(record, expected2)
                self.audit.record(
                    record.event_id, "ACTION_FAILED", "system",
                    reason="ACTION_FAILURE", detail=record.last_error,
                )
                break

            record.completed_actions.append(spec.name)
            record.current_index += 1
            expected = record.version
            record.updated_at = time.time()
            self._persist(record, expected)
            self.audit.record(
                record.event_id, "ACTION_COMPLETED", "system",
                detail=f"动作 {spec.name} 完成: {result}",
            )

        done = len(record.completed_actions)
        total = len(policy.actions)
        if failures > 0:
            dst = State.PARTIALLY_FAILED if 0 < done < total else State.FAILED
            reason = "PARTIAL_FAILURE" if dst is State.PARTIALLY_FAILED else "ACTION_FAILURE"
            return self._view_transition(
                record, dst, "system", reason, record.last_error or "存在失败动作"
            )
        if record.current_index >= total and done == total:
            return self._view_transition(
                record, State.COMPLETED, "system", "", "全部动作成功"
            )
        return self._record_view(record)

    # ---- 审批 ----
    def approve(self, event_id: str, actor: Actor | None) -> dict[str, Any]:
        # 身份缺失无法归属审计，直接拒绝；角色权限在事件锁内判定并留痕
        if actor is None:
            raise AuthzError(
                RejectReason.UNAUTHENTICATED, "缺少调用方身份（X-Actor 头）"
            )
        record = self.storage.get_execution(event_id)
        if record is None:
            raise StateError(RejectReason.EXECUTION_NOT_FOUND, f"执行不存在: {event_id}")

        with self._event_lock(event_id):
            record = self.storage.get_execution(event_id)
            assert record is not None
            # 审批权限（角色）拒绝也要留痕，且不改变执行状态
            if not actor.has_role("admin"):
                self.audit.record(
                    event_id, "APPROVE_DENIED", actor.name,
                    reason=RejectReason.PERMISSION_DENIED.value,
                    detail=f"主体 {actor.name} 缺少 admin 角色，审批拒绝，状态不变",
                )
                raise AuthzError(
                    RejectReason.PERMISSION_DENIED,
                    f"主体 {actor.name} 无审批所需的 admin 角色",
                )
            if record.state is not State.WAITING_APPROVAL:
                self.audit.record(
                    event_id, "APPROVE_DENIED", actor.name,
                    reason=RejectReason.ILLEGAL_STATE.value,
                    detail=f"当前状态 {record.state.value} 不允许审批，状态不变",
                )
                raise StateError(
                    RejectReason.ILLEGAL_STATE,
                    f"仅 WAITING_APPROVAL 可审批，当前为 {record.state.value}，状态不变",
                )

            now = time.time()
            expected = record.version
            record.approver = actor.name
            record.approval_expires_at = now + self.authz.approval_ttl_seconds
            record.approval_seq += 1
            record.updated_at = now
            self._persist(record, expected)
            self.audit.record(
                event_id, "APPROVED", actor.name,
                detail=f"审批通过，TTL={self.authz.approval_ttl_seconds}s seq={record.approval_seq}",
            )
            return self._continue_execution(record, None, actor.name)

    # ---- 取消 ----
    def cancel(self, event_id: str, actor: Actor | None) -> dict[str, Any]:
        if actor is None:
            raise AuthzError(
                RejectReason.UNAUTHENTICATED, "缺少调用方身份（X-Actor 头）"
            )
        record = self.storage.get_execution(event_id)
        if record is None:
            raise StateError(RejectReason.EXECUTION_NOT_FOUND, f"执行不存在: {event_id}")

        with self._event_lock(event_id):
            record = self.storage.get_execution(event_id)
            assert record is not None
            if not actor.has_role("operator"):
                self.audit.record(
                    event_id, "CANCEL_DENIED", actor.name,
                    reason=RejectReason.PERMISSION_DENIED.value,
                    detail=f"主体 {actor.name} 缺少 operator 角色，取消拒绝，状态不变",
                )
                raise AuthzError(
                    RejectReason.PERMISSION_DENIED,
                    f"主体 {actor.name} 无取消执行所需的 operator 角色",
                )
            if record.state not in (State.PENDING, State.WAITING_APPROVAL, State.RUNNING):
                self.audit.record(
                    event_id, "CANCEL_DENIED", actor.name,
                    reason=RejectReason.ILLEGAL_STATE.value,
                    detail=f"终态 {record.state.value} 不可取消，状态不变",
                )
                raise StateError(
                    RejectReason.ILLEGAL_STATE,
                    f"终态 {record.state.value} 不可取消，状态不变",
                )
            return self._view_transition(
                record, State.CANCELLED, actor.name,
                "CANCELLED", f"由 {actor.name} 取消",
            )

    # ---- 查询 ----
    def get_status(self, event_id: str) -> dict[str, Any]:
        record = self.storage.get_execution(event_id)
        if record is None:
            raise StateError(RejectReason.EXECUTION_NOT_FOUND, f"执行不存在: {event_id}")
        return self._record_view(record)

    def run_pending(self, event_id: str) -> dict[str, Any]:
        with self._event_lock(event_id):
            record = self.storage.get_execution(event_id)
            if record is None:
                raise StateError(RejectReason.EXECUTION_NOT_FOUND, f"执行不存在: {event_id}")
            return self._continue_execution(record, None, "system")

    # ---- 崩溃恢复 ----
    def recover_all(self) -> int:
        records = self.storage.list_recoverable()
        recovered = 0
        for record in records:
            with self._event_lock(record.event_id):
                fresh = self.storage.get_execution(record.event_id)
                if fresh is None or fresh.is_terminal():
                    continue
                recovered += 1
                log.info(
                    '{"type":"recovery_start","event_id":"%s","state":"%s","index":%d}',
                    fresh.event_id, fresh.state.value, fresh.current_index,
                )
                if fresh.state is State.WAITING_APPROVAL:
                    allowed, why = self.authz.evaluate(
                        fresh, self._load_policy(fresh.policy_id).actions, time.time()
                    )
                    if not allowed and why == RejectReason.APPROVAL_EXPIRED.value:
                        self._view_transition(
                            fresh, State.REJECTED, "system",
                            RejectReason.APPROVAL_EXPIRED.value, "恢复时发现审批已过期",
                        )
                        continue
                    if not allowed:
                        continue  # 仍在等待审批，保持确定状态
                self._continue_execution(fresh, None, "system")
        return recovered

    def _load_policy(self, policy_id: str) -> Policy:
        for policy in self.policies.policies:
            if policy.policy_id == policy_id:
                return policy
        raise PolicyError(
            RejectReason.CONFIG_INVALID, f"策略已不在当前配置中: {policy_id}"
        )


def _json_str(text: str) -> str:
    import json as _json

    return _json.dumps(text, ensure_ascii=False)
