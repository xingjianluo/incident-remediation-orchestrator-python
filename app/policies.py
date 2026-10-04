"""策略加载与确定性匹配。

匹配结果必须稳定可复现，与策略在配置文件中的排列顺序无关：
- 全部命中策略按 (priority 升序, 具体程度 specificity 降序, policy_id 升序) 排序；
- 具体程度 = 规则中实际限定的条件维度数（event_type、source_prefix、
  severities 各计 1，labels 按条目数计），限定越多越具体，越先命中；
- 若前两名在 (priority, specificity) 上完全并列，说明配置层面无法稳定
  分出先后，按 PolicyConflict 明确拒绝，绝不靠文件顺序“碰运气”。
"""
from __future__ import annotations

import json

from app.schemas import Event, MatchRule, Policy


class NoPolicyMatch(Exception):
    """事件合法但没有任何策略命中。"""


class PolicyConflict(Exception):
    """最优位置出现 (priority, specificity) 完全并列，无法确定裁决。"""

    def __init__(self, policy_ids: list[str]) -> None:
        super().__init__(f"ambiguous policies: {policy_ids}")
        self.policy_ids = policy_ids


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


def rule_specificity(rule: MatchRule) -> int:
    """规则具体程度：限定的条件维度越多，数值越大，越优先命中。"""
    score = 0
    if rule.event_type is not None:
        score += 1
    if rule.source_prefix is not None:
        score += 1
    if rule.severities:
        score += 1
    score += len(rule.labels)
    return score


def _decision_key(policy: Policy) -> tuple[int, int]:
    # 裁决键：数值小的优先级优先；同级中更具体（specificity 大）的优先
    return policy.priority, -rule_specificity(policy.match)


def _sort_key(policy: Policy) -> tuple[int, int, str]:
    # 展示/候选列表键：裁决键 + id 字典序，保证候选列表本身也确定
    return (*_decision_key(policy), policy.id)


def matching_policies(event: Event, policies: list[Policy]) -> list[Policy]:
    hits = [p for p in policies if _rule_matches(p.match, event)]
    hits.sort(key=_sort_key)
    return hits


def match_policy(event: Event, policies: list[Policy]) -> tuple[Policy, list[str]]:
    """返回 (最优策略, 全部命中策略id有序列表)。

    无命中抛 NoPolicyMatch；最优位置 (priority, specificity) 并列抛
    PolicyConflict。两种失败都由调用方映射为可区分的拒绝原因。
    """
    hits = matching_policies(event, policies)
    if not hits:
        raise NoPolicyMatch()
    if len(hits) >= 2 and _decision_key(hits[0]) == _decision_key(hits[1]):
        tied = [p.id for p in hits if _decision_key(p) == _decision_key(hits[0])]
        raise PolicyConflict(sorted(tied))
    return hits[0], [p.id for p in hits]
