"""Loads installed agent skills from the on-disk skill registry."""

import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SKILL_REGISTRY: dict[str, Path] = {
    "loan-document-helper": PROJECT_ROOT / "SKILL.md",
}


def parse_skill_metadata(content: str) -> dict[str, str]:
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}

    metadata: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata


def load_skill(skill_id: str) -> dict[str, Any]:
    skill_path = SKILL_REGISTRY.get(skill_id)
    if skill_path is None:
        return {
            "id": skill_id,
            "content": "",
            "path": "",
            "loaded": False,
        }

    if not skill_path.exists():
        return {
            "id": skill_id,
            "content": "",
            "path": str(skill_path),
            "loaded": False,
        }

    return {
        "id": skill_id,
        "content": skill_path.read_text(encoding="utf-8"),
        "path": str(skill_path),
        "loaded": True,
    }
