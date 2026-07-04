from __future__ import annotations

import argparse
import json

from sigma_rule_helper.checks import check_rule
from sigma_rule_helper.files import iter_rule_files
from sigma_rule_helper.loader import load_rules
from sigma_rule_helper.summary import (
    rule_level,
    rule_logsource,
    rule_attack_techniques,
    rule_status,
    rule_title,
    summarize_counts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma-rule-helper",
        description="Review small sets of Sigma rule files.",
    )
    parser.add_argument(
        "command",
        choices=["check", "summary"],
        help="Action to run against Sigma rule files.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Rule files or directories to inspect.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    files = iter_rule_files(args.paths)
    rules = load_rules(files)
    if args.command == "check":
        if args.format == "json":
            print(json.dumps(_check_json(rules), indent=2))
            return 1 if any(item["findings"] for item in _check_json(rules)) else 0

        total_findings = 0
        for rule in rules:
            findings = check_rule(rule)
            if findings:
                print(rule.path)
                for finding in findings:
                    print(f"  {finding.severity}: {finding.code}: {finding.message}")
            total_findings += len(findings)
        print(f"checked {len(rules)} rule file(s), found {total_findings} issue(s)")
        return 1 if any(check_rule(rule) for rule in rules) else 0

    if args.format == "json":
        print(json.dumps(_summary_json(rules), indent=2))
        return 0

    for rule in rules:
        print(
            f"{rule.path}: {rule_title(rule)} "
            f"[level={rule_level(rule)} status={rule_status(rule)} "
            f"logsource={rule_logsource(rule)} "
            f"attack={','.join(rule_attack_techniques(rule)) or 'none'}]"
        )
    for line in summarize_counts(rules):
        print(line)
    return 0


def _check_json(rules):
    return [
        {
            "path": str(rule.path),
            "title": rule_title(rule),
            "findings": [
                {
                    "severity": finding.severity,
                    "code": finding.code,
                    "message": finding.message,
                }
                for finding in check_rule(rule)
            ],
        }
        for rule in rules
    ]


def _summary_json(rules):
    return {
        "rules": [
            {
                "path": str(rule.path),
                "title": rule_title(rule),
                "level": rule_level(rule),
                "status": rule_status(rule),
                "logsource": rule_logsource(rule),
                "attack_techniques": rule_attack_techniques(rule),
            }
            for rule in rules
        ],
        "counts": summarize_counts(rules),
    }


if __name__ == "__main__":
    raise SystemExit(main())
