from __future__ import annotations

import argparse

from sigma_rule_helper.checks import check_rule
from sigma_rule_helper.files import iter_rule_files
from sigma_rule_helper.loader import load_rules


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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    files = iter_rule_files(args.paths)
    rules = load_rules(files)
    if args.command == "check":
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

    print(f"loaded {len(rules)} rule file(s)")
    return 0
