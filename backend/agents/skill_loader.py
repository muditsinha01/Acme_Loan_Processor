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
    current_key: str | None = None
    for line in match.group(1).splitlines():
        if current_key and (line.startswith("  ") or line.startswith("\t")):
            continuation = line.strip()
            if continuation:
                existing = metadata.get(current_key, "")
                metadata[current_key] = (
                    f"{existing} {continuation}".strip() if existing else continuation
                )
            continue

        if ":" not in line:
            current_key = None
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"')
        if value in (">", "|"):
            metadata[key] = ""
            current_key = key
        else:
            metadata[key] = value
            current_key = None
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

    # LINEAJE: enforce() `_lineaje_skill_content` at skill_manifest->skill_check skill_check — scan flagged AI_SKILL_DAT_SEC_001 (Do not allow skills that exfiltrate data); AI_SKILL_SEC_001 (Do not allow malicious skills); AI_SKILL_SEC_002 (Do not allow suspicious skills). Mask/block; do not remove without review. site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205'
    _lineaje__lineaje_skill_content_evidence = {'skill_path': str(skill_path), 'skill_id': skill_id}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
    try:
        _lineaje__lineaje_skill_content_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_skill_content_evidence, content_type='application/json')
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except _gr_client.GuardrailUnavailableError:
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except PermissionError:
        _lineaje_skill_content = ""
        __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
    return {
        "id": skill_id,
        "content": _lineaje_skill_content,
        "path": str(skill_path),
        "source": "internal",
        "loaded": True,
    }


def load_marketplace_fixture(skill_id: str) -> dict[str, Any]:
    """Load a skill and companion files from marketplace_fixtures/{skill_id}."""
    fixture_dir = MARKETPLACE_FIXTURES_DIR / skill_id
    skill_path = fixture_dir / "SKILL.md"
    source = f"marketplace_fixtures/{skill_id}"

    if not skill_path.exists():
        return {
            "id": skill_id,
            "content": "",
            "path": str(skill_path),
            "source": source,
            "loaded": False,
            "references": {},
            "fixture_dir": str(fixture_dir),
        }

    references: dict[str, str] = {}
    if fixture_dir.is_dir():
        for extra in sorted(fixture_dir.iterdir()):
            if extra.is_file() and extra.name != "SKILL.md":
                references[extra.name] = extra.read_text(encoding="utf-8")

    # LINEAJE: enforce() `_lineaje_skill_content` at skill_manifest->skill_check skill_check — scan flagged AI_SKILL_DAT_SEC_001 (Do not allow skills that exfiltrate data); AI_SKILL_SEC_001 (Do not allow malicious skills); AI_SKILL_SEC_002 (Do not allow suspicious skills). Mask/block; do not remove without review. site_id='site:sha256:745c45949ea630369a3049a35e5284678fcef6fbe83c318fa77b73fe5d13e609'
    _lineaje__lineaje_skill_content_evidence = {'skill_path': str(skill_path), 'skill_id': skill_id}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:745c45949ea630369a3049a35e5284678fcef6fbe83c318fa77b73fe5d13e609', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
    try:
        _lineaje__lineaje_skill_content_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_skill_content_evidence, content_type='application/json')
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except _gr_client.GuardrailUnavailableError:
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except PermissionError:
        _lineaje_skill_content = ""
        __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
    return {
        "id": skill_id,
        "content": _lineaje_skill_content,
        "path": str(skill_path),
        "source": source,
        "loaded": True,
        "references": references,
        "fixture_dir": str(fixture_dir),
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
    # LINEAJE: enforce() `skill_id` at skill_manifest->skill_check skill_check — scan flagged AI_SKILL_DAT_SEC_001 (Do not allow skills that exfiltrate data); AI_SKILL_SEC_001 (Do not allow malicious skills); AI_SKILL_SEC_002 (Do not allow suspicious skills). Mask/block; do not remove without review. site_id='site:sha256:d971df3a3f854db3814f9f70aaed91a3e7a72dc4690ed550763bf7ed0def3701'
    _lineaje_skill_id_evidence = {'skill_id': skill_id, 'project': 'source-code'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d971df3a3f854db3814f9f70aaed91a3e7a72dc4690ed550763bf7ed0def3701', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
    try:
        _lineaje_skill_id_evidence = _gr_client.enforce(_gr_site, _lineaje_skill_id_evidence, content_type='application/json')
        skill_id = _lineaje_skill_id_evidence.get('skill_id', skill_id) if isinstance(_lineaje_skill_id_evidence, dict) else skill_id
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    raw_content = _download_skill_content(skill_id, source_url)
    if not raw_content:
        return {"id": skill_id, "content": "", "path": "", "source": source_url, "loaded": False}

    installed_path = _save_skill_content(skill_id, raw_content)
    installed_content = installed_path.read_text(encoding="utf-8")
    # LINEAJE: enforce() `installed_content` at skill_manifest->skill_check skill_check — scan flagged AI_SKILL_DAT_SEC_001 (Do not allow skills that exfiltrate data); AI_SKILL_SEC_001 (Do not allow malicious skills); AI_SKILL_SEC_002 (Do not allow suspicious skills). Mask/block; do not remove without review. site_id='site:sha256:0f01b13a75013a6b539245d93f3ff95d77e15dcff68f0e51c28892769f9bb487'
    _lineaje_installed_content_evidence = {'installed_content': installed_content, 'skill_path': str(installed_path), 'skill_id': skill_id, 'skill_body': installed_content, 'project': 'source-code'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0f01b13a75013a6b539245d93f3ff95d77e15dcff68f0e51c28892769f9bb487', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
    try:
        _lineaje_installed_content_evidence = _gr_client.enforce(_gr_site, _lineaje_installed_content_evidence, content_type='application/json')
        installed_content = _lineaje_installed_content_evidence.get('installed_content', installed_content) if isinstance(_lineaje_installed_content_evidence, dict) else installed_content
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        installed_content = (dict(installed_content, content="", loaded=False) if isinstance(installed_content, dict) else "")
        __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")

    return {
        "id": skill_id,
        "content": installed_content,
        "path": str(installed_path),
        "source": source_url,
        "loaded": True,
    }
