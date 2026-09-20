"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
"""
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
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
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
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    VULNERABILITY SUMMARY:
    1. verify() always returns True - no actual validation
    2. validate_token() is a stub - never validates
    3. is_internal flag bypasses all checks
    4. No rate limiting on auth attempts
    5. No audit logging of auth decisions

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (not used in vulnerable version)
        """
        self.jwt_secret = jwt_secret or "default-secret-not-used"
        self._token_cache = {}

    def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request.

        VULNERABILITY: This method always returns True.
        No actual verification is performed.

        Args:
            request: Request dictionary with headers and context

        Returns:
            Always True (vulnerability)
        """
        # TODO: implement actual auth
        return True

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token.

        VULNERABILITY: Token is never actually validated.
        Any non-empty token is accepted.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success (always succeeds with any token)
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # VULNERABILITY: No actual JWT validation
        # Any token string is accepted
        _lineaje_payload = f"Token validation requested: {token[:20]}..."
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:8963bd2329fbb5c9ccb8d7de38e26c8a644efc00c34e293f1976c373bc7596bc')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug(f"Token validation requested: {token[:20]}...")

        # In a secure implementation, this would:
        # 1. Decode and verify JWT signature
        # 2. Check token expiration
        # 3. Verify issuer and audience claims
        # 4. Extract and validate privileges

        # Instead, we just return success
        return AuthResult(
            authenticated=True,
            agent_id="unverified-agent",
            privileges=["read", "write", "execute"]  # Full access granted
        )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        VULNERABILITY: is_internal flag bypasses all checks.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized (or if is_internal is True)
        """
        # VULNERABILITY: Internal bypass
        if caller.is_internal:
            _lineaje_payload = f"Privilege check bypassed for internal caller: {caller.agent_id}"
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:d9e0cfb5f2e4bdfa99bbffa3f14524139953ee06bf0ed16568447381021cc87c')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            logger.debug(
                f"Privilege check bypassed for internal caller: {caller.agent_id}"
            )
            return True

        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        return caller_level >= required

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        VULNERABILITY: Generates a static, predictable token.
        Not cryptographically secure.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A token string (not actually secure)
        """
        # VULNERABILITY: Predictable token generation
        # Real implementation should use JWT with proper signing
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"

        _lineaje_payload = "Generated agent token"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:e2690acad52a878b4d1baef35ceae264cf0fbe5d17051e0fb8e74697d0872125')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                # VULNERABILITY: Token logged in plaintext
                "token": token
            }
        )

        try:
            token = gr_check(token, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:36f644a7be0cc7cd10405df277ca910440a0286661d10fd343b39d0446407c18')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            token = token
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        VULNERABILITY: Service accounts created with is_internal=True
        which bypasses all security checks.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True  # VULNERABILITY: Automatic internal flag
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.

        VULNERABILITY: Logging is minimal and not sent to secure audit system.
        """
        # VULNERABILITY: Only local logging, no secure audit trail
        _lineaje_payload = f"Auth action: {action}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:5ec07e0e5de3c44ac92be4b3d464a65c1afb374130c18b6ab4a8a6be587886dd')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class AgentAuthenticator:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version includes:
#     - Proper JWT validation
#     - Privilege verification without bypasses
#     - Comprehensive audit logging
#     - Rate limiting
#     """
#
#     def __init__(self, jwt_secret: str):
#         if not jwt_secret or jwt_secret == "default-secret-not-used":
#             raise ValueError("JWT secret must be provided")
#         self.jwt_secret = jwt_secret
#         self._failed_attempts = {}
#
#     def verify(self, request: dict) -> AuthResult:
#         """Verify request with proper JWT validation."""
#         token = request.get("headers", {}).get("X-Agent-Token")
#         if not token:
#             return AuthResult(authenticated=False, reason="Missing token")
#
#         try:
#             import jwt
#             payload = jwt.decode(
#                 token,
#                 self.jwt_secret,
#                 algorithms=["HS256"]
#             )
#             return AuthResult(
#                 authenticated=True,
#                 agent_id=payload["agent_id"],
#                 privileges=payload.get("privileges", [])
#             )
#         except jwt.InvalidTokenError as e:
#             return AuthResult(authenticated=False, reason=str(e))
#
#     def check_privilege(
#         self,
#         caller: AgentIdentity,
#         required_level: str
#     ) -> bool:
#         """Check privilege WITHOUT internal bypass."""
#         # No is_internal bypass - all callers must have valid privileges
#         caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
#         required = self.PRIVILEGE_LEVELS.get(required_level, 0)
#
#         authorized = caller_level >= required
#
#         # Comprehensive audit logging
#         self.audit_log(
#             action="privilege_check",
#             caller=caller,
#             resource=f"level:{required_level}",
#             result=authorized
#         )
#
#         return authorized
