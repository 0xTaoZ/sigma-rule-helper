from __future__ import annotations

import re
from typing import Any

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def attack_tags(data: dict[str, Any]) -> list[str]:
    tags = data.get("tags")
    if not isinstance(tags, list):
        return []

    found: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.lower().startswith("attack."):
            found.append(tag.lower())
    return sorted(dict.fromkeys(found))


def attack_techniques(data: dict[str, Any]) -> list[str]:
    return [tag for tag in attack_tags(data) if TECHNIQUE_RE.match(tag)]
