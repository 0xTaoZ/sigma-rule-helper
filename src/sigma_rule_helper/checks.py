from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sigma_rule_helper.loader import LoadedRule
from sigma_rule_helper.tags import attack_tags, attack_techniques

REQUIRED_FIELDS = ("title", "id", "status", "logsource", "detection", "level")
KNOWN_LEVELS = {"informational", "low", "medium", "high", "critical"}
KNOWN_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
CONDITION_KEYWORDS = {"and", "or", "not", "near", "of", "all", "them"}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str


def check_rule(rule: LoadedRule) -> list[Finding]:
    findings: list[Finding] = []
    data = rule.data

    for field in REQUIRED_FIELDS:
        if field not in data:
            findings.append(
                Finding("error", "missing-field", f"missing required field: {field}")
            )

    status = data.get("status")
    if isinstance(status, str) and status not in KNOWN_STATUSES:
        findings.append(Finding("warning", "unknown-status", f"unknown status: {status}"))

    if "id" in data:
        findings.extend(_check_id(data["id"]))
    findings.extend(_check_rule_dates(data))

    level = data.get("level")
    if isinstance(level, str) and level.lower() not in KNOWN_LEVELS:
        findings.append(Finding("warning", "unknown-level", f"unknown level: {level}"))

    if data.get("falsepositives") in (None, []):
        findings.append(
            Finding(
                "warning",
                "missing-falsepositives",
                "falsepositives should describe expected benign matches",
            )
        )

    findings.extend(_check_logsource(data.get("logsource")))
    findings.extend(_check_detection(data.get("detection")))
    if attack_tags(data) and not attack_techniques(data):
        findings.append(
            Finding(
                "warning",
                "missing-attack-technique",
                "ATT&CK tags found but no technique tag such as attack.t1110",
            )
        )
    return findings


def _check_logsource(logsource: Any) -> list[Finding]:
    if logsource is None:
        return []
    if not isinstance(logsource, dict):
        return [Finding("error", "bad-logsource", "logsource should be a mapping")]
    if not any(key in logsource for key in ("product", "service", "category")):
        return [
            Finding(
                "warning",
                "empty-logsource",
                "logsource should include product, service, or category",
            )
        ]
    return []


def _check_detection(detection: Any) -> list[Finding]:
    if detection is None:
        return []
    if not isinstance(detection, dict):
        return [Finding("error", "bad-detection", "detection should be a mapping")]
    if "condition" not in detection:
        return [Finding("error", "missing-condition", "detection missing condition")]
    selectors = [key for key in detection if key != "condition"]
    if not selectors:
        return [
            Finding("warning", "no-selectors", "detection has condition but no selectors")
        ]
    findings: list[Finding] = []
    for selector in selectors:
        selector_body = detection[selector]
        if selector_body in ({}, [], None):
            findings.append(
                Finding(
                    "warning",
                    "empty-selector",
                    f"detection selector has no fields: {selector}",
                )
            )
        elif not isinstance(selector_body, (dict, list)):
            findings.append(
                Finding(
                    "warning",
                    "bad-selector",
                    f"detection selector should be a mapping or list: {selector}",
                )
            )
    condition = detection["condition"]
    if isinstance(condition, str):
        if _uses_broad_them_condition(condition):
            findings.append(
                Finding(
                    "warning",
                    "broad-condition",
                    "condition uses 'them'; name selector prefixes for clearer scope",
                )
            )
        known_selectors = {key for key in selectors if isinstance(key, str)}
        for name in _missing_condition_selectors(condition, known_selectors):
            findings.append(
                Finding(
                    "error",
                    "missing-condition-selector",
                    f"condition references missing selector: {name}",
                )
            )
    return findings


def _uses_broad_them_condition(condition: str) -> bool:
    return bool(re.search(r"\b(?:all|\d+)\s+of\s+them\b", condition, re.IGNORECASE))


def _missing_condition_selectors(condition: str, known_selectors: set[str]) -> list[str]:
    missing: list[str] = []
    wildcard_prefixes = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\*", condition)
    for prefix in wildcard_prefixes:
        if not any(selector.startswith(prefix) for selector in known_selectors):
            missing.append(f"{prefix}*")

    for name in _condition_selector_names(condition):
        if name in known_selectors:
            continue
        if any(name == prefix for prefix in wildcard_prefixes):
            continue
        if name not in missing:
            missing.append(name)
    return missing


def _condition_selector_names(condition: str) -> list[str]:
    names: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition):
        if token.lower() in CONDITION_KEYWORDS:
            continue
        if token not in names:
            names.append(token)
    return names


def _check_id(rule_id: Any) -> list[Finding]:
    if not isinstance(rule_id, str):
        return [Finding("error", "invalid-id-type", "id must be a string")]
    try:
        uuid.UUID(rule_id)
    except ValueError:
        return [Finding("error", "invalid-id-format", "id must be a valid UUID")]
    return []


def _check_rule_dates(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for field in ("date", "modified"):
        value = data.get(field)
        if value is None or isinstance(value, date):
            continue
        if not isinstance(value, str) or not _is_sigma_date(value):
            findings.append(
                Finding(
                    "warning",
                    "invalid-date-format",
                    f"{field} should use YYYY/MM/DD format",
                )
            )
    return findings


def _is_sigma_date(value: str) -> bool:
    if not re.fullmatch(r"\d{4}/\d{2}/\d{2}", value):
        return False
    try:
        datetime.strptime(value, "%Y/%m/%d")
    except ValueError:
        return False
    return True
