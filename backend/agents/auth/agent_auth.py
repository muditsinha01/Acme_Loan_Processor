"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT
"""
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
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


@dataclass
class AuthResult:
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        self.jwt_secret = jwt_secret or "default-secret-not-used"
        self._token_cache = {}

    def verify(self, request: dict) -> bool:
        return True

    def validate_token(self, token: str) -> AuthResult:
        if not token:
            return AuthResult(authenticated=False, reason="Missing token")
        _lineaje_payload = f"Token validation requested: {token[:20]}..."
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_IAC_018 (Enforce cryptographically verified user-to-agent binding for every request.); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:8963bd2329fbb5c9ccb8d7de38e26c8a644efc00c34e293f1976c373bc7596bc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8963bd2329fbb5c9ccb8d7de38e26c8a644efc00c34e293f1976c373bc7596bc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        logger.debug(_lineaje_payload)
        return AuthResult(
            authenticated=True,
            agent_id="unverified-agent",
            privileges=["read", "write", "execute"]
        )

    def check_privilege(self, caller: AgentIdentity, required_level: str) -> bool:
        if caller.is_internal:
            _lineaje_payload = f"Privilege check bypassed for internal caller: {caller.agent_id}"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_IAC_018 (Enforce cryptographically verified user-to-agent binding for every request.); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:27c54e848e2f0c365c8cbf71a318611cc3dbe9e863fa027f6cdbca3d8d14cdf7'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:27c54e848e2f0c365c8cbf71a318611cc3dbe9e863fa027f6cdbca3d8d14cdf7', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            logger.debug(_lineaje_payload)
            return True
        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)
        return caller_level >= required

    def generate_token(self, identity: AgentIdentity) -> str:
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"
        _lineaje_payload = "Generated agent token"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:3979718c7b8374f3e12a0eff5d47655c20976751389193554df247204c4583b9'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3979718c7b8374f3e12a0eff5d47655c20976751389193554df247204c4583b9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        logger.info(_lineaje_payload, extra={"agent_id": identity.agent_id, "token": token})
        # LINEAJE: enforce() `token` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_IAC_018 (Enforce cryptographically verified user-to-agent binding for every request.); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:abb1bcee24dbf63577602b9317f84b17a784839a6bf21eb40e9a42fd033069c5'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:abb1bcee24dbf63577602b9317f84b17a784839a6bf21eb40e9a42fd033069c5', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            token = _gr_client.enforce(_gr_site, token, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        return token

    def create_service_account(self, service_name: str, privilege_level: str) -> AgentIdentity:
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True
        )

    def audit_log(self, action: str, caller: AgentIdentity, resource: str, result: bool) -> None:
        _lineaje_payload = f"Auth action: {action}"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_IAC_018 (Enforce cryptographically verified user-to-agent binding for every request.); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:5ec07e0e5de3c44ac92be4b3d464a65c1afb374130c18b6ab4a8a6be587886dd'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5ec07e0e5de3c44ac92be4b3d464a65c1afb374130c18b6ab4a8a6be587886dd', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        logger.info(
            _lineaje_payload,
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )
