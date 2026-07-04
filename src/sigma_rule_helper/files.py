from __future__ import annotations

from pathlib import Path

RULE_SUFFIXES = {".yml", ".yaml"}


def iter_rule_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            files.extend(
                candidate
                for candidate in sorted(path.rglob("*"))
                if candidate.is_file() and candidate.suffix.lower() in RULE_SUFFIXES
            )
        elif path.is_file() and path.suffix.lower() in RULE_SUFFIXES:
            files.append(path)
    return sorted(dict.fromkeys(files))
