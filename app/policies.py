"""策略加载与确定性匹配。

匹配结果必须稳定可复现：
- 全部命中策略按 (priority 升序, policy_id 升序) 排序；
- 冲突时取排序后的第一条；同一份输入永远得到同一结果。
"""
from __future__ import annotations

import json

from app.schemas import Event, MatchRule, Policy


def load_policies(path: str) -> list[Policy]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise TypeError("policy file must contain a JSON array")
    policies = [Policy.model_validate(item) for item in raw]
    seen: set[str] = set()
    for policy in policies:
        if policy.id in seen:
            raise ValueError(f"duplicate policy id: {policy.id}")
        seen.add(policy.id)
    return policies


def _rule_matches(rule: MatchRule, event: Event) -> bool:
    if rule.event_type is not None and rule.event_type != event.event_type:
        return False
    if rule.source_prefix is not None and not event.source.startswith(rule.source_prefix):
        return False
    if rule.severities and event.severity not in rule.severities:
        return False
    for key, value in rule.labels.items():
        if event.labels.get(key) != value:
            return False
    return True


def _sort_key(policy: Policy) -> tuple[int, str]:
    # 数值小者优先；同优先级按 id 字典序，保证冲突结果确定
    return policy.priority, policy.id


def matching_policies(event: Event, policies: list[Policy]) -> list[Policy]:
    hits = [p for p in policies if _rule_matches(p.match, event)]
    hits.sort(key=_sort_key)
    return hits


def match_policy(event: Event, policies: list[Policy]) -> tuple[Policy, list[str]]:
    """返回 (最优策略, 全部命中策略id有序列表)；无命中由调用方按拒绝处理。"""
    hits = matching_policies(event, policies)
    return hits[0], [p.id for p in hits]
