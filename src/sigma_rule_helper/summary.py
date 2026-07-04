from __future__ import annotations

from collections import Counter
from typing import Any

from sigma_rule_helper.loader import LoadedRule
from sigma_rule_helper.tags import attack_techniques


def rule_title(rule: LoadedRule) -> str:
    title = rule.data.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return rule.path.name


def rule_level(rule: LoadedRule) -> str:
    return _text_field(rule.data.get("level"), "unknown")


def rule_status(rule: LoadedRule) -> str:
    return _text_field(rule.data.get("status"), "unknown")


def rule_logsource(rule: LoadedRule) -> str:
    logsource = rule.data.get("logsource")
    if not isinstance(logsource, dict):
        return "unknown"
    parts = [
        _text_field(logsource.get("product"), ""),
        _text_field(logsource.get("service"), ""),
        _text_field(logsource.get("category"), ""),
    ]
    return "/".join(part for part in parts if part) or "unknown"


def rule_attack_techniques(rule: LoadedRule) -> list[str]:
    return attack_techniques(rule.data)


def summarize_counts(rules: list[LoadedRule]) -> list[str]:
    levels = Counter(rule_level(rule) for rule in rules)
    statuses = Counter(rule_status(rule) for rule in rules)
    lines = [f"rules: {len(rules)}"]
    if levels:
        lines.append("levels: " + _format_counter(levels))
    if statuses:
        lines.append("statuses: " + _format_counter(statuses))
    return lines


def _format_counter(counter: Counter[str]) -> str:
    return ", ".join(f"{name}={count}" for name, count in sorted(counter.items()))


def _text_field(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback
