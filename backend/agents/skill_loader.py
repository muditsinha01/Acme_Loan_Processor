"""Loads installed agent skills from the on-disk skill registry, and installs
skills pulled from the community skill marketplace."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

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
    try:
        metadata = gr_check(metadata, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:238ee03853a0346d24018c14db67938c7e35183d9d63505949ad8d39ba67316b')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        metadata = metadata
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
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


def load_marketplace_fixture(skill_id: str) -> dict[str, Any]:
    """Load a skill and companion files from marketplace_fixtures/{skill_id}."""
    fixture_dir = MARKETPLACE_FIXTURES_DIR / skill_id
    skill_path = fixture_dir / "SKILL.md"
    source = f"marketplace_fixtures/{skill_id}"
    try:
        source = gr_check(source, "skill", "llm", candidate_policies=['AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_SKILL_SEC_004'], site_id='site:sha256:302dcd1854f39b5c6c6cfa27bb6c536a20ba96d2aa7cb009b227469f459e76f0')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        source = source
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'skill->llm' — passing data through unchecked")

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

    return {
        "id": skill_id,
        "content": skill_path.read_text(encoding="utf-8"),
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
        try:
            response = gr_check(response, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:d62e1673796d5e84b03ddb7ed1ece327efeab3126533a97caf913c3dc975e497')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            response = response
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        try:
            skill_id = gr_check(skill_id, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:1a950cb2413e783bbb97b00693a06f9189f65d6bb4b609a2a02ca892bdaabbeb')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            skill_id = skill_id
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
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
    try:
        dest_path = gr_check(dest_path, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:d99b14765d1f9a8a532cecfd110c7bf39eb8bc175b01c53762b072406d120a50')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        dest_path = dest_path
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return dest_path


def install_marketplace_skill(skill_id: str) -> dict[str, Any]:
    """Download, save, and load a skill from the community marketplace."""
    catalog_entry = MARKETPLACE_CATALOG.get(skill_id)
    if catalog_entry is None:
        return {"id": skill_id, "content": "", "path": "", "source": "", "loaded": False}

    source_url = catalog_entry["source"]
    try:
        skill_id = gr_check(skill_id, "skill_manifest", "skill_check", candidate_policies=['AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_SKILL_SEC_004'], site_id='site:sha256:d971df3a3f854db3814f9f70aaed91a3e7a72dc4690ed550763bf7ed0def3701')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        skill_id = skill_id
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'skill_manifest->skill_check' — passing data through unchecked")
    raw_content = _download_skill_content(skill_id, source_url)
    if not raw_content:
        return {"id": skill_id, "content": "", "path": "", "source": source_url, "loaded": False}

    installed_path = _save_skill_content(skill_id, raw_content)
    installed_content = installed_path.read_text(encoding="utf-8")
    try:
        installed_content = gr_check(installed_content, "skill_manifest", "skill_check", candidate_policies=['AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_SKILL_SEC_004'], site_id='site:sha256:0f01b13a75013a6b539245d93f3ff95d77e15dcff68f0e51c28892769f9bb487')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        installed_content = installed_content
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'skill_manifest->skill_check' — passing data through unchecked")

    return {
        "id": skill_id,
        "content": installed_content,
        "path": str(installed_path),
        "source": source_url,
        "loaded": True,
    }
