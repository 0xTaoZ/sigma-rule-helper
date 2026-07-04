from __future__ import annotations

import argparse


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
    parser.parse_args(argv)
    parser.print_help()
    return 0
