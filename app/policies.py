"""策略加载与确定性匹配。

匹配结果必须稳定可复现：
- 全部命中策略按 (priority 升序, 具体度降序, policy_id 升序) 排序；
- 数值小的优先级仍然优先；同一优先级内，条件限定得更具体的先命中
  （event_type/source_prefix/severities/labels 每个出现的限定维度各计 1，
  labels 内每个键值对各计 1）；
- 排序仅用于得到稳定的候选列表；最终裁决取排序后的第一条，但若第一条
  与紧随其后的候选在 (priority, 具体度) 上完全相同，则不存在唯一最优，
  判定为配置冲突（PolicyConflict），绝不靠 policy_id 静默打破平手；
- 同一份输入无论跑多少次、策略在文件里怎么排，结果都一致。
"""
from __future__ import annotations

import json

from app.errors import PolicyConflict
from app.schemas import Event, MatchRule, Policy, RejectReason


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


def specificity(rule: MatchRule) -> int:
    """规则的条件具体度：每个实际出现的限定维度计 1 分，labels 逐键各计 1 分。"""
    score = 0
    if rule.event_type is not None:
        score += 1
    if rule.source_prefix is not None:
        score += 1
    if rule.severities:
        score += 1
    score += len(rule.labels)
    return score


def _sort_key(policy: Policy) -> tuple[int, int, str]:
    # priority 升序（小者优先），同优先级具体度降序（限定多者优先），
    # 最后以 id 字典序保证候选列表本身稳定可复现。
    return policy.priority, -specificity(policy.match), policy.id


def matching_policies(event: Event, policies: list[Policy]) -> list[Policy]:
    hits = [p for p in policies if _rule_matches(p.match, event)]
    hits.sort(key=_sort_key)
    return hits


def match_policy(event: Event, policies: list[Policy]) -> tuple[Policy, list[str]]:
    """返回 (唯一最优策略, 全部命中策略id有序列表)。

    - 无命中：抛 IndexError，由调用方按 policy_not_found 拒绝；
    - 最优不唯一（priority 与具体度完全平手）：抛 PolicyConflict。
    """
    hits = matching_policies(event, policies)
    if not hits:
        raise IndexError("no policy matches")
    ids = [p.id for p in hits]
    best = hits[0]
    tied = [
        p.id
        for p in hits[1:]
        if p.priority == best.priority and specificity(p.match) == specificity(best.match)
    ]
    if tied:
        raise PolicyConflict(
            RejectReason.POLICY_CONFLICT,
            "multiple policies match with the same priority and specificity",
            {
                "event_id": event.event_id,
                "conflicting_policies": [best.id, *tied],
                "candidate_policies": ids,
            },
        )
    return best, ids
