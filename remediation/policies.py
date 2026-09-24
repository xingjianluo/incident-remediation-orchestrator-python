"""策略加载与稳定匹配：确定性优先级、唯一选择与冲突检测。"""
from __future__ import annotations

import json
from pathlib import Path

from .errors import PolicyError, RejectReason
from .models import Event, Policy


def _match_rank(match: dict[str, str]) -> tuple:
    """匹配条件特异度：具体字段越多、含 severity_min 的条件越具体。"""
    return (
        len(match),
        1 if "severity" in match else 0,
        1 if "severity_min" in match else 0,
    )


class PolicyEngine:
    def __init__(self, policies: list[Policy]) -> None:
        self._validate_unique(policies)
        # 确定性顺序：priority 降序 -> 特异度降序 -> policy_id 升序
        self.policies = sorted(
            policies,
            key=lambda p: (-p.priority, tuple(-x for x in _match_rank(p.match)), p.policy_id),
        )

    @staticmethod
    def _validate_unique(policies: list[Policy]) -> None:
        seen: set[str] = set()
        for policy in policies:
            if policy.policy_id in seen:
                raise PolicyError(
                    RejectReason.CONFIG_INVALID,
                    f"策略 ID 重复: {policy.policy_id}",
                )
            seen.add(policy.policy_id)

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        p = Path(path)
        if not p.exists():
            raise PolicyError(
                RejectReason.CONFIG_INVALID, f"策略文件不存在: {path}"
            )
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(
                RejectReason.CONFIG_INVALID, f"策略文件 JSON 解析失败: {exc}"
            ) from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: object) -> "PolicyEngine":
        if not isinstance(raw, dict) or not isinstance(raw.get("policies"), list):
            raise PolicyError(
                RejectReason.CONFIG_INVALID, "策略配置必须是含 policies 数组的对象"
            )
        try:
            policies = [Policy.from_dict(item) for item in raw["policies"]]
        except ValueError as exc:
            raise PolicyError(RejectReason.CONFIG_INVALID, str(exc)) from exc
        return cls(policies)

    def matched(self, event: Event) -> list[Policy]:
        return [p for p in self.policies if p.matches(event)]

    def select(self, event: Event) -> Policy:
        """返回唯一匹配策略。

        - 无匹配 -> NO_MATCHING_POLICY
        - 最高分并列（priority 与特异度都相同）-> POLICY_CONFLICT
        排序键完全确定，结果可复现。
        """
        candidates = self.matched(event)
        if not candidates:
            raise PolicyError(
                RejectReason.NO_MATCHING_POLICY,
                f"事件 {event.event_id} 无匹配策略 "
                f"(source={event.source}, alert_type={event.alert_type}, severity={event.severity})",
            )
        top = candidates[0]
        tied = [
            p
            for p in candidates[1:]
            if p.priority == top.priority and _match_rank(p.match) == _match_rank(top.match)
        ]
        if tied:
            ids = sorted([top.policy_id, *(p.policy_id for p in tied)])
            raise PolicyError(
                RejectReason.POLICY_CONFLICT,
                f"事件 {event.event_id} 匹配到优先级冲突的策略 {ids}，"
                f"无法稳定裁决；请调整 priority 或匹配条件特异度",
            )
        return top
