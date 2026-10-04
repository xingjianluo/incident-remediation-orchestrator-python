"""修复执行编排核心：策略判定、状态机、幂等、恢复、取消、超时、权限审批。

线程模型：单个后台 worker 轮询可运行的执行记录；所有状态变更在 Store 的
进程内 RLock 下完成并原子落盘，保证重复提交/并发提交只有一次有效副作用。
崩溃恢复：RUNNING 中断重启后，未提交步骤状态但已写效果台账的动作会被
识别为 APPLIED 并跳过，绝不重复执行。
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from app.actions import ActionRegistry
from app.audit import AuditLogger
from app.config import Settings
from app.errors import (
    AuthorizationError,
    ExecutionConflict,
    PolicyConflict,
    PolicyRejected,
)
from app.policies import match_policy
from app.schemas import (
    TERMINAL_STATES,
    AclConfig,
    ActionDef,
    ApprovalRecord,
    Event,
    ExecutionRecord,
    ExecutionState,
    Policy,
    RejectReason,
    StepResult,
    StepStatus,
)
from app.storage import Store

log = logging.getLogger("iro.executor")


class Executor:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        audit: AuditLogger,
        policies: list[Policy],
        acl: AclConfig,
        actions: ActionRegistry,
        *,
        clock: Any = time.time,
    ) -> None:
        self.settings = settings
        self.store = store
        self.audit = audit
        self.policies = policies
        self.acl = acl
        self.actions = actions
        self._clock = clock
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()

    # ================= 权限 =================
    def _role_of(self, username: str) -> str | None:
        return self.acl.users.get(username)

    def _can(self, username: str, capability: str) -> bool:
        role = self._role_of(username)
        if role is None:
            return False
        return capability in self.acl.roles.get(role, [])

    def _check_action_permission(self, action: ActionDef, actor: str | None) -> None:
        if not actor or self._role_of(actor) is None:
            raise AuthorizationError(
                RejectReason.UNAUTHORIZED,
                "submitter is unknown or carries no role",
                {"required_role": action.required_role, "action": action.name},
            )
        if not self._can(actor, action.required_role):
            raise AuthorizationError(
                RejectReason.FORBIDDEN,
                "role lacks capability for this action",
                {
                    "required_role": action.required_role,
                    "action": action.name,
                    "actor": actor,
                },
            )

    # ================= 事件提交 =================
    def submit_event(self, event: Event) -> tuple[ExecutionRecord, bool]:
        """返回 (执行记录, 是否新建)。重复/并发提交返回同一条记录。"""
        with self.store.lock:
            existing = self.store.get_by_event(event.event_id)
            if existing is not None:
                log.info(
                    "event_id=%s policy=%s state=%s duplicate submission -> existing execution_id=%s",
                    event.event_id,
                    existing.policy_id,
                    existing.state.value,
                    existing.id,
                )
                self.audit.emit(
                    "submit.duplicate",
                    execution_id=existing.id,
                    event_id=event.event_id,
                    actor=event.submitted_by,
                    policy_id=existing.policy_id,
                    to_state=existing.state.value,
                )
                return existing, False

            try:
                policy, all_hits = match_policy(event, self.policies)
            except IndexError:
                policy = None  # type: ignore[assignment]
                all_hits = []
            except PolicyConflict as conflict:
                # 配置冲突：明确拒绝且不创建任何执行记录，原因与其他拒绝可区分
                log.warning(
                    "event_id=%s rejected reason=%s conflicting=%s",
                    event.event_id,
                    RejectReason.POLICY_CONFLICT.value,
                    conflict.details.get("conflicting_policies"),
                )
                self.audit.emit(
                    "event.rejected",
                    event_id=event.event_id,
                    actor=event.submitted_by,
                    reason=RejectReason.POLICY_CONFLICT.value,
                    details={
                        "conflicting_policies": conflict.details.get(
                            "conflicting_policies"
                        ),
                        "candidate_policies": conflict.details.get(
                            "candidate_policies"
                        ),
                    },
                )
                raise

            if policy is None:
                # 非法/无匹配绝不静默执行：记录拒绝审计，但不创建执行记录
                log.warning(
                    "event_id=%s rejected reason=%s",
                    event.event_id,
                    RejectReason.POLICY_NOT_FOUND.value,
                )
                self.audit.emit(
                    "event.rejected",
                    event_id=event.event_id,
                    actor=event.submitted_by,
                    reason=RejectReason.POLICY_NOT_FOUND.value,
                )
                raise PolicyRejected(
                    RejectReason.POLICY_NOT_FOUND,
                    "no remediation policy matches the event",
                    {"event_id": event.event_id, "event_type": event.event_type},
                )

            # 权限预检：任一危险动作越权 => 整体拒绝且不落任何执行状态
            for action in policy.actions:
                self._check_action_permission(action, event.submitted_by)

            now = self._clock()
            needs_approval = any(
                a.risk.value == "dangerous" for a in policy.actions
            )
            record = ExecutionRecord(
                id=f"exec-{uuid.uuid4().hex[:12]}",
                event_id=event.event_id,
                event=event,
                policy_id=policy.id,
                state=(
                    ExecutionState.AWAITING_APPROVAL
                    if needs_approval
                    else ExecutionState.PENDING
                ),
                steps=[
                    StepResult(
                        index=i,
                        action=a.name,
                        risk=a.risk,
                    )
                    for i, a in enumerate(policy.actions)
                ],
                created_at=now,
                updated_at=now,
                submitted_by=event.submitted_by,
                max_attempts=self.settings.max_attempts,
                attempts_used=0,
            )
            self.store.insert_execution(record)
            self.audit.emit(
                "event.accepted",
                execution_id=record.id,
                event_id=event.event_id,
                actor=event.submitted_by,
                policy_id=policy.id,
                to_state=record.state.value,
                details={"candidate_policies": all_hits},
            )
            log.info(
                "event_id=%s policy=%s candidates=%s accepted execution_id=%s state=%s",
                event.event_id,
                policy.id,
                all_hits,
                record.id,
                record.state.value,
            )
            self._wake.set()
            return record, True

    # ================= 审批 =================
    def grant_approval(
        self, execution_id: str, granted_by: str, ttl_seconds: int | None
    ) -> ApprovalRecord:
        with self.store.lock:
            record = self.store.get(execution_id)
            if record is None:
                raise ExecutionConflict(
                    RejectReason.EXECUTION_NOT_FOUND,
                    "execution not found",
                    {"execution_id": execution_id},
                )
            if record.state not in (
                ExecutionState.AWAITING_APPROVAL,
                ExecutionState.RUNNING,
            ):
                raise ExecutionConflict(
                    RejectReason.INVALID_STATE_TRANSITION,
                    "execution is not awaiting approval",
                    {"execution_id": execution_id, "state": record.state.value},
                )
            if not granted_by or self._role_of(granted_by) is None:
                raise AuthorizationError(
                    RejectReason.APPROVER_NOT_ALLOWED,
                    "approver is unknown",
                    {"execution_id": execution_id},
                )
            if not self._can(granted_by, "approve"):
                # 拒绝授权且不改变执行状态
                self.audit.emit(
                    "approval.denied",
                    execution_id=execution_id,
                    event_id=record.event_id,
                    actor=granted_by,
                    from_state=record.state.value,
                    to_state=record.state.value,
                    reason=RejectReason.APPROVER_NOT_ALLOWED.value,
                )
                raise AuthorizationError(
                    RejectReason.APPROVER_NOT_ALLOWED,
                    "role may not grant approvals",
                    {"execution_id": execution_id, "actor": granted_by},
                )

            now = self._clock()
            ttl = ttl_seconds or self.settings.approval_ttl_seconds
            # 找到尚缺有效审批的第一个危险动作（简化：逐动作授予/校验）
            pending_index = self._first_unapproved_dangerous_index(record, now)
            if pending_index is None:
                raise ExecutionConflict(
                    RejectReason.INVALID_STATE_TRANSITION,
                    "no action awaiting approval",
                    {"execution_id": execution_id},
                )
            action_name = record.steps[pending_index].action
            approval = ApprovalRecord(
                id=f"apr-{uuid.uuid4().hex[:12]}",
                execution_id=execution_id,
                action_index=pending_index,
                action_name=action_name,
                granted_by=granted_by,
                granted_at=now,
                expires_at=now + ttl,
            )
            self.store.add_approval(approval)
            self.audit.emit(
                "approval.granted",
                execution_id=execution_id,
                event_id=record.event_id,
                actor=granted_by,
                from_state=record.state.value,
                to_state=record.state.value,
                details={
                    "approval_id": approval.id,
                    "action_index": pending_index,
                    "expires_at": approval.expires_at,
                },
            )
            log.info(
                "execution_id=%s approval granted by=%s action_index=%s expires_at=%s",
                execution_id,
                granted_by,
                pending_index,
                approval.expires_at,
            )
            self._wake.set()
            return approval

    def _first_unapproved_dangerous_index(
        self, record: ExecutionRecord, now: float
    ) -> int | None:
        for step in record.steps:
            if step.risk.value != "dangerous":
                continue
            if step.status != StepStatus.PENDING:
                continue
            if self.store.find_valid_approval(record.id, step.index, now) is None:
                return step.index
        return None

    def request_cancel(
        self, execution_id: str, requested_by: str | None
    ) -> ExecutionRecord:
        with self.store.lock:
            record = self.store.get(execution_id)
            if record is None:
                raise ExecutionConflict(
                    RejectReason.EXECUTION_NOT_FOUND,
                    "execution not found",
                    {"execution_id": execution_id},
                )
            if record.state in TERMINAL_STATES:
                raise ExecutionConflict(
                    RejectReason.INVALID_STATE_TRANSITION,
                    "terminal execution cannot be cancelled",
                    {"execution_id": execution_id, "state": record.state.value},
                )
            record.cancel_requested = True
            record.cancel_requested_by = requested_by
            record.updated_at = self._clock()
            self.store.save_execution(record)
            self.audit.emit(
                "cancel.requested",
                execution_id=execution_id,
                event_id=record.event_id,
                actor=requested_by,
                from_state=record.state.value,
                to_state=record.state.value,
            )
            log.info(
                "execution_id=%s cancel requested by=%s",
                execution_id,
                requested_by,
            )
            return record

    # ================= 调度与执行 =================
    def _transition(
        self,
        record: ExecutionRecord,
        new_state: ExecutionState,
        *,
        kind: str,
        actor: str | None = None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        old = record.state
        record.state = new_state
        record.updated_at = self._clock()
        if new_state in TERMINAL_STATES:
            record.finished_at = record.updated_at
        self.store.save_execution(record)
        self.audit.emit(
            kind,
            execution_id=record.id,
            event_id=record.event_id,
            actor=actor,
            from_state=old.value,
            to_state=new_state.value,
            policy_id=record.policy_id,
            reason=reason,
            details=details,
        )
        log.info(
            "execution_id=%s event_id=%s transition %s -> %s reason=%s",
            record.id,
            record.event_id,
            old.value,
            new_state.value,
            reason,
        )

    def _pick_runnable_locked(self, now: float) -> ExecutionRecord | None:
        """选择本轮要推进的执行。

        调度公平性边界：
        - 崩溃恢复（RUNNING）最优先，且仍按创建时间 FIFO；
        - 其次是 PENDING，按创建时间 FIFO；待审批记录只要审批未补齐就
          “跳过而非选中后卡住”，因此前面挂着待审批/终态执行不会阻塞
          后面的普通事件；
        - FAILED / RETRY_EXHAUSTED 不会被后台自动拾取，只允许显式重试，
          杜绝一直失败的动作在后台被反复重跑。
        """
        recovery: list[ExecutionRecord] = []
        pending: list[ExecutionRecord] = []
        approvable: list[ExecutionRecord] = []
        for record in self.store.all_executions():
            if record.state == ExecutionState.RUNNING:
                recovery.append(record)
            elif record.state == ExecutionState.PENDING:
                pending.append(record)
            elif (
                record.state == ExecutionState.AWAITING_APPROVAL
                # 审批全部有效才可继续；否则跳过，不占用本轮调度位
                and self._first_unapproved_dangerous_index(record, now) is None
            ):
                approvable.append(record)
        ordered = sorted(recovery + pending + approvable, key=lambda r: (r.created_at, r.id))
        return ordered[0] if ordered else None

    def tick(self) -> bool:
        """推进一次。返回是否处理了某个执行。"""
        with self.store.lock:
            now = self._clock()
            record = self._pick_runnable_locked(now)
            if record is None:
                return False

            if record.state == ExecutionState.RUNNING:
                # 崩溃恢复路径：沿用已有 generation/started_at/deadline
                gen = record.run_generation
            elif record.state == ExecutionState.AWAITING_APPROVAL:
                # picker 只在审批已补齐时选中它；这里再防御一次：未齐则挂起
                if self._first_unapproved_dangerous_index(record, now) is not None:
                    return False
                if record.run_generation == 0:
                    record.run_generation = 1
                    record.started_at = now
                    record.deadline = now + self.settings.execution_timeout_seconds
                    if record.max_attempts <= 0:  # 兼容旧版本落盘记录
                        record.max_attempts = self.settings.max_attempts
                    record.attempts_used = 1
                    record.updated_at = now
                    self.store.save_execution(record)
                gen = record.run_generation
            else:
                # PENDING：首次启动或显式重试后续跑。
                # 首次启动记第 1 次尝试；重试时 attempts_used 已由 retry() 递增。
                now = self._clock()
                if record.run_generation == 0:
                    record.run_generation = 1
                    record.started_at = now
                    record.deadline = now + self.settings.execution_timeout_seconds
                    if record.max_attempts <= 0:  # 兼容旧版本落盘记录
                        record.max_attempts = self.settings.max_attempts
                    record.attempts_used = 1
                gen = record.run_generation
                self._transition(
                    record,
                    ExecutionState.RUNNING,
                    kind="run.start",
                    actor=record.submitted_by,
                    details={
                        "generation": gen,
                        "attempt": record.attempts_used,
                        "max_attempts": record.max_attempts,
                    },
                )

        self._run_execution(record.id, gen)
        return True

    def _reconcile_crashed_step(
        self, record: ExecutionRecord, step: StepResult
    ) -> bool:
        """崩溃恢复：效果台账已存在但步骤未落 APPLIED 时补齐状态。返回是否已应用。"""
        effect_key = f"{record.id}:{step.index}"
        if self.store.effect_exists(effect_key) is not None:
            if step.status != StepStatus.APPLIED:
                step.status = StepStatus.APPLIED
                step.effect_key = effect_key
                # 仅做状态修复，不增加 attempts（动作并未重新执行）
                self.store.save_execution(record)
                self.audit.emit(
                    "step.recovered",
                    execution_id=record.id,
                    event_id=record.event_id,
                    details={"action_index": step.index, "action": step.action},
                )
                log.info(
                    "execution_id=%s recovered step=%s action=%s from effect ledger",
                    record.id,
                    step.index,
                    step.action,
                )
            return True
        return False

    def _run_execution(self, execution_id: str, generation: int) -> None:
        # 重新取锁内快照，逐个动作推进；动作本地执行也在锁内（动作很快，
        # 且能与效果台账写入构成一致顺序）。
        with self.store.lock:
            record = self.store.get(execution_id)
            if record is None:
                return
            # 以落盘的最新代际为准；存在更新代际时本次陈旧调用退出
            if record.run_generation != generation:
                return
            policy = next(p for p in self.policies if p.id == record.policy_id)

            # 待审批执行在 worker 接手时：审批齐全则继续，仍缺失则挂起
            if record.state == ExecutionState.AWAITING_APPROVAL:
                if self._first_unapproved_dangerous_index(record, self._clock()) is not None:
                    return
                record.state = ExecutionState.RUNNING
                record.updated_at = self._clock()
                self.store.save_execution(record)
                self.audit.emit(
                    "approval.complete",
                    execution_id=record.id,
                    event_id=record.event_id,
                    from_state=ExecutionState.AWAITING_APPROVAL.value,
                    to_state=ExecutionState.RUNNING.value,
                )

            for step, action_def in zip(record.steps, policy.actions):
                now = self._clock()

                # 超时检查：超时为终态，不回退已应用步骤
                if record.deadline is not None and now >= record.deadline:
                    self._transition(
                        record,
                        ExecutionState.TIMED_OUT,
                        kind="run.timeout",
                        reason="execution deadline exceeded",
                    )
                    return

                if step.status == StepStatus.APPLIED:
                    continue

                effect_key = f"{record.id}:{step.index}"

                # 崩溃恢复优先：台账中已有副作用 => 修复步骤状态，绝不重复执行
                if self._reconcile_crashed_step(record, step):
                    continue

                # 取消协作点：在“尚未生效”的动作边界检查，已落账动作不回滚
                if record.cancel_requested:
                    self._transition(
                        record,
                        ExecutionState.CANCELLED,
                        kind="run.cancelled",
                        actor=record.cancel_requested_by,
                        reason="cancel requested before step boundary",
                    )
                    return

                # 危险动作：审批必须存在且未过期；过期拒绝且不改变执行状态
                if action_def.risk.value == "dangerous":
                    approval = self.store.find_valid_approval(
                        record.id, step.index, now
                    )
                    if approval is None:
                        if step.status == StepStatus.PENDING and step.attempts == 0:
                            # 首次遇到：转入待审批，等待人工授权
                            self._transition(
                                record,
                                ExecutionState.AWAITING_APPROVAL,
                                kind="approval.required",
                                reason=RejectReason.APPROVAL_REQUIRED.value,
                                details={"action_index": step.index},
                            )
                            return
                        # 已有审批过期/被消费：拒绝推进，状态保持
                        log.warning(
                            "execution_id=%s step=%s blocked reason=%s state unchanged=%s",
                            record.id,
                            step.index,
                            RejectReason.APPROVAL_EXPIRED.value,
                            record.state.value,
                        )
                        self.audit.emit(
                            "approval.missing",
                            execution_id=record.id,
                            event_id=record.event_id,
                            from_state=record.state.value,
                            to_state=record.state.value,
                            reason=RejectReason.APPROVAL_EXPIRED.value,
                            details={"action_index": step.index},
                        )
                        self._transition(
                            record,
                            ExecutionState.AWAITING_APPROVAL,
                            kind="approval.required",
                            reason=RejectReason.APPROVAL_EXPIRED.value,
                            details={"action_index": step.index},
                        )
                        return

                # 崩溃恢复：台账中已有副作用 => 绝不重复执行
                if self._reconcile_crashed_step(record, step):
                    continue

                step.attempts += 1
                self.store.save_execution(record)

                # 1) 执行本地副作用
                try:
                    result = self.actions.execute(action_def.name, action_def.params)
                except Exception as exc:  # noqa: BLE001 - 可插拔动作的任意失败都需收敛为步骤失败
                    step.status = StepStatus.FAILED
                    step.error = str(exc)
                    record.error = f"step {step.index} ({action_def.name}) failed: {exc}"
                    self.store.save_execution(record)
                    self.audit.emit(
                        "step.failed",
                        execution_id=record.id,
                        event_id=record.event_id,
                        details={
                            "action_index": step.index,
                            "action": action_def.name,
                            "error": str(exc),
                            "continue_on_failure": action_def.continue_on_failure,
                        },
                    )
                    log.warning(
                        "execution_id=%s step=%s action=%s failed: %s",
                        record.id,
                        step.index,
                        action_def.name,
                        exc,
                    )
                    if action_def.continue_on_failure:
                        continue
                    # 失败收敛：还有尝试预算 => FAILED（确定失败态，等待显式
                    # 重试，worker 不会自动拾取）；预算耗尽 => RETRY_EXHAUSTED
                    # 终态，必须经人工 confirmed 后才能再试。两种状态都不会
                    # 在后台被反复重跑。
                    if record.attempts_used >= record.max_attempts:
                        self._transition(
                            record,
                            ExecutionState.RETRY_EXHAUSTED,
                            kind="run.exhausted",
                            reason=record.error,
                            details={
                                "attempts_used": record.attempts_used,
                                "max_attempts": record.max_attempts,
                            },
                        )
                    else:
                        self._transition(
                            record,
                            ExecutionState.FAILED,
                            kind="run.failed",
                            reason=record.error,
                            details={
                                "attempts_used": record.attempts_used,
                                "max_attempts": record.max_attempts,
                                "retries_left": record.max_attempts
                                - record.attempts_used,
                            },
                        )
                    return

                # 2) 副作用落账（exactly-once 的真相来源）
                self.store.record_effect(effect_key, result)
                step.effect_key = effect_key

                # 测试用：在副作用已落账、步骤状态提交之前模拟进程崩溃
                if action_def.crash_after_effect:
                    self.audit.emit(
                        "step.crash_injected",
                        execution_id=record.id,
                        event_id=record.event_id,
                        details={"action_index": step.index},
                    )
                    log.error(
                        "execution_id=%s step=%s simulated crash after effect; "
                        "record left RUNNING for recovery",
                        record.id,
                        step.index,
                    )
                    raise SystemExit("simulated crash after effect")

                # 3) 步骤状态提交
                step.status = StepStatus.APPLIED
                step.result = result
                if action_def.risk.value == "dangerous":
                    approval = self.store.find_valid_approval(
                        record.id, step.index, self._clock()
                    )
                    if approval is not None:
                        self.store.consume_approval(approval.id)
                self.store.save_execution(record)
                self.audit.emit(
                    "step.applied",
                    execution_id=record.id,
                    event_id=record.event_id,
                    details={
                        "action_index": step.index,
                        "action": action_def.name,
                        "effect_key": effect_key,
                    },
                )

            # 全部动作处理完
            any_failed = any(s.status == StepStatus.FAILED for s in record.steps)
            final_state = (
                ExecutionState.PARTIAL_FAILED if any_failed else ExecutionState.COMPLETED
            )
            self._transition(
                record,
                final_state,
                kind="run.finished",
                reason="partial failure" if any_failed else "all steps applied",
            )

    # ================= 显式重试（FAILED / RETRY_EXHAUSTED 之后） =================
    def retry(
        self,
        execution_id: str,
        requested_by: str | None,
        *,
        confirmed: bool = False,
    ) -> ExecutionRecord:
        with self.store.lock:
            record = self.store.get(execution_id)
            if record is None:
                raise ExecutionConflict(
                    RejectReason.EXECUTION_NOT_FOUND,
                    "execution not found",
                    {"execution_id": execution_id},
                )
            if record.state == ExecutionState.RETRY_EXHAUSTED:
                # 收敛终态：必须有人显式确认，拒绝静默自动/误触发的重跑
                if not confirmed:
                    raise ExecutionConflict(
                        RejectReason.RETRY_EXHAUSTED,
                        "attempt budget exhausted; human confirmation required",
                        {
                            "execution_id": execution_id,
                            "attempts_used": record.attempts_used,
                            "max_attempts": record.max_attempts,
                        },
                    )
                record.attempts_used = 1
                if record.max_attempts <= 0:  # 兼容旧版本落盘记录
                    record.max_attempts = self.settings.max_attempts
                self.store.save_execution(record)
                self.audit.emit(
                    "retry.confirmed",
                    execution_id=record.id,
                    event_id=record.event_id,
                    actor=requested_by,
                    reason="human confirmation reopens attempt budget",
                    details={
                        "attempts_used": record.attempts_used,
                        "max_attempts": record.max_attempts,
                    },
                )
                log.warning(
                    "execution_id=%s manual confirmation by=%s reopens attempt budget",
                    execution_id,
                    requested_by,
                )
            elif record.state != ExecutionState.FAILED:
                raise ExecutionConflict(
                    RejectReason.INVALID_STATE_TRANSITION,
                    "only failed executions can be retried",
                    {"execution_id": execution_id, "state": record.state.value},
                )
            else:
                # FAILED：仍在预算内（落 FAILED 的前提），消耗下一次尝试
                if record.max_attempts <= 0:  # 兼容旧版本落盘记录
                    record.max_attempts = self.settings.max_attempts
                    record.attempts_used = max(1, record.attempts_used)
                if record.attempts_used >= record.max_attempts:
                    raise ExecutionConflict(
                        RejectReason.RETRY_EXHAUSTED,
                        "attempt budget exhausted; human confirmation required",
                        {
                            "execution_id": execution_id,
                            "attempts_used": record.attempts_used,
                            "max_attempts": record.max_attempts,
                        },
                    )
                record.attempts_used += 1
                self.store.save_execution(record)

            # 幂等恢复语义：已 APPLIED 的步骤保留，仅失败步骤重置为 PENDING；
            # 效果台账保证已生效的动作绝不会再次执行（只接着没做完的部分走）。
            for step in record.steps:
                if step.status == StepStatus.FAILED:
                    step.status = StepStatus.PENDING
                    step.error = None
            record.error = None
            record.cancel_requested = False
            self._transition(
                record,
                ExecutionState.PENDING,
                kind="run.retry",
                actor=requested_by,
                details={
                    "attempt": record.attempts_used,
                    "max_attempts": record.max_attempts,
                    "confirmed": confirmed,
                },
            )
            self._wake.set()
            return record

    # ================= 后台 worker =================
    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stopping.clear()
        self._worker = threading.Thread(
            target=self._loop, name="iro-worker", daemon=True
        )
        self._worker.start()
        log.info("executor worker started")

    def stop(self, timeout: float = 2.0) -> None:
        self._stopping.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
        log.info("executor worker stopped")

    def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                did = self.tick()
            except SystemExit:
                raise  # 模拟进程崩溃：让线程带着 RUNNING 状态终止
            except Exception:
                log.exception("worker tick error")
                did = False
            if not did:
                self._wake.wait(timeout=self.settings.worker_tick_seconds)
                self._wake.clear()

    def wake(self) -> None:
        self._wake.set()
