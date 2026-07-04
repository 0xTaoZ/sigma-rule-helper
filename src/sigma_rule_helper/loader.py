from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class LoadedRule:
    path: Path
    data: dict[str, Any]


def load_rule(path: Path) -> LoadedRule:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the document root")

    return LoadedRule(path=path, data=data)


def load_rules(paths: list[Path]) -> list[LoadedRule]:
    return [load_rule(path) for path in paths]
