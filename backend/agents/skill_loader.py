"""Loads installed agent skills from the on-disk skill registry, and installs
skills pulled from the community skill marketplace."""

import logging
import os
import re
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Skills bundled with this app and registered by a hardcoded entry — no
# marketplace fetch involved.
SKILL_REGISTRY: dict[str, Path] = {
    "loan-document-helper": PROJECT_ROOT / "SKILL.md",
}

# Skills available from the community skill marketplace. `source` is the
# untrusted, non-organization URL the skill was pulled from.
MARKETPLACE_BASE_URL = os.getenv("SKILL_MARKETPLACE_URL", "https://clawmarket.example/skills")
# income-verifier-pro and credit-score-fetcher come from a vetted-partner
# subdomain (source allowlist passes) so their scan-status is what a
# guardrail should catch — not an unrelated unknown-source mismatch.
MARKETPLACE_CATALOG: dict[str, dict[str, str]] = {
    "auto-approve-assistant": {"source": f"{MARKETPLACE_BASE_URL}/auto-approve-assistant"},
    "income-verifier-pro": {"source": f"https://verified.{MARKETPLACE_BASE_URL.split('//', 1)[1]}/income-verifier-pro"},
    "credit-score-fetcher": {"source": f"https://approved.{MARKETPLACE_BASE_URL.split('//', 1)[1]}/credit-score-fetcher"},
}

# Bundled fixture copies of each marketplace skill's content, used when the
# marketplace host isn't reachable (e.g. running the demo offline).
MARKETPLACE_FIXTURES_DIR = PROJECT_ROOT / "marketplace_fixtures"

# Local cache of installed marketplace skills.
INSTALLED_SKILLS_DIR = PROJECT_ROOT / "installed_skills"


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
    """Load a skill that ships with this app, registered by a hardcoded entry."""
    skill_path = SKILL_REGISTRY.get(skill_id)
    if skill_path is None:
        return {
            "id": skill_id,
            "content": "",
            "path": "",
            "source": "internal",
            "loaded": False,
        }

    if not skill_path.exists():
        return {
            "id": skill_id,
            "content": "",
            "path": str(skill_path),
            "source": "internal",
            "loaded": False,
        }

    return {
        "id": skill_id,
        "content": skill_path.read_text(encoding="utf-8"),
        "path": str(skill_path),
        "source": "internal",
        "loaded": True,
    }


def _download_skill_content(skill_id: str, source_url: str) -> str:
    """Fetch a skill's manifest content from the marketplace."""
    try:
        response = requests.get(source_url, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        logger.warning(
            "skill_loader: marketplace unreachable for %s, using bundled fixture", skill_id
        )
        fixture_path = MARKETPLACE_FIXTURES_DIR / skill_id / "SKILL.md"
        return fixture_path.read_text(encoding="utf-8") if fixture_path.exists() else ""


def _save_skill_content(skill_id: str, content: str) -> Path:
    """Persist a fetched skill's manifest to the local installed-skills cache."""
    dest_path = INSTALLED_SKILLS_DIR / skill_id / "SKILL.md"
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(content, encoding="utf-8")
    return dest_path


def install_marketplace_skill(skill_id: str) -> dict[str, Any]:
    """Download, save, and load a skill from the community marketplace."""
    catalog_entry = MARKETPLACE_CATALOG.get(skill_id)
    if catalog_entry is None:
        return {"id": skill_id, "content": "", "path": "", "source": "", "loaded": False}

    source_url = catalog_entry["source"]
    raw_content = _download_skill_content(skill_id, source_url)
    if not raw_content:
        return {"id": skill_id, "content": "", "path": "", "source": source_url, "loaded": False}

    installed_path = _save_skill_content(skill_id, raw_content)
    installed_content = installed_path.read_text(encoding="utf-8")

    return {
        "id": skill_id,
        "content": installed_content,
        "path": str(installed_path),
        "source": source_url,
        "loaded": True,
    }
