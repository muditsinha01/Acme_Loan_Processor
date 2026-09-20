"""Loads installed agent skills from the on-disk skill registry, and installs
skills pulled from the community skill marketplace."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m


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
    # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    try:
        metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
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
        # LINEAJE: enforce() `response` at api->agent post_tool — scan flagged AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:d62e1673796d5e84b03ddb7ed1ece327efeab3126533a97caf913c3dc975e497'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d62e1673796d5e84b03ddb7ed1ece327efeab3126533a97caf913c3dc975e497', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=89)
        except _gr_client.GuardrailUnavailableError:
            pass
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        # LINEAJE: enforce() `skill_id` at agent->log log_emit — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:1a950cb2413e783bbb97b00693a06f9189f65d6bb4b609a2a02ca892bdaabbeb'
        _lineaje_skill_id_evidence = {'skill_id': skill_id, 'project': 'source-code'}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1a950cb2413e783bbb97b00693a06f9189f65d6bb4b609a2a02ca892bdaabbeb', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_skill_id_evidence = _gr_client.enforce(_gr_site, _lineaje_skill_id_evidence, content_type='application/json')
            skill_id = _lineaje_skill_id_evidence.get('skill_id', skill_id) if isinstance(_lineaje_skill_id_evidence, dict) else skill_id
        except _gr_client.GuardrailUnavailableError:
            pass
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
    # LINEAJE: enforce() `dest_path` at agent->user_interface data_egress — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:d99b14765d1f9a8a532cecfd110c7bf39eb8bc175b01c53762b072406d120a50'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d99b14765d1f9a8a532cecfd110c7bf39eb8bc175b01c53762b072406d120a50', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    try:
        dest_path = _gr_client.enforce(_gr_site, dest_path, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    return dest_path


def install_marketplace_skill(skill_id: str) -> dict[str, Any]:
    """Download, save, and load a skill from the community marketplace."""
    catalog_entry = MARKETPLACE_CATALOG.get(skill_id)
    if catalog_entry is None:
        return {"id": skill_id, "content": "", "path": "", "source": "", "loaded": False}

    source_url = catalog_entry["source"]
    # LINEAJE: enforce() `skill_id` at skill_manifest->skill_check skill_check — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:8daa0f142d9417a790b3c36d3854aef7d17cdff0a598921b1d73e8cd19e8ddb3'
    _lineaje_skill_id_evidence = {'skill_id': skill_id, 'project': 'source-code'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8daa0f142d9417a790b3c36d3854aef7d17cdff0a598921b1d73e8cd19e8ddb3', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='skill_manifest', destination_type='skill_check')
    try:
        _lineaje_skill_id_evidence = _gr_client.enforce(_gr_site, _lineaje_skill_id_evidence, content_type='application/json')
        skill_id = _lineaje_skill_id_evidence.get('skill_id', skill_id) if isinstance(_lineaje_skill_id_evidence, dict) else skill_id
    except _gr_client.GuardrailUnavailableError:
        pass
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
