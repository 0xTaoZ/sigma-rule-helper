from __future__ import annotations

import argparse

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
    print(f"loaded {len(rules)} rule file(s)")
    return 0
