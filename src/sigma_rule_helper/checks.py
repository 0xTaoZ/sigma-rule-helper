from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sigma_rule_helper.loader import LoadedRule
from sigma_rule_helper.tags import attack_tags, attack_techniques

REQUIRED_FIELDS = ("title", "id", "status", "logsource", "detection", "level")
KNOWN_LEVELS = {"informational", "low", "medium", "high", "critical"}
KNOWN_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}


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

    level = data.get("level")
    if isinstance(level, str) and level.lower() not in KNOWN_LEVELS:
        findings.append(Finding("warning", "unknown-level", f"unknown level: {level}"))

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
    return []


def _check_id(rule_id: Any) -> list[Finding]:
    if not isinstance(rule_id, str):
        return [Finding("error", "invalid-id-type", "id must be a string")]
    try:
        uuid.UUID(rule_id)
    except ValueError:
        return [Finding("error", "invalid-id-format", "id must be a valid UUID")]
    return []
