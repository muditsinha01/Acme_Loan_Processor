# `lineaje_guardrail` API Reference

## Import

```python
from lineaje_guardrail import lineaje_guardrail
```

## Constructor

```python
guardrail = lineaje_guardrail(
    audit_log_path="lineaje_guardrail.jsonl",
    policy_context=None,
    fail_closed=True,
    max_audit_bytes=50 * 1024 * 1024,
    audit_backups=5,
)
```

### Parameters

`audit_log_path`
: JSONL forensic audit path. Parent directories are created automatically. The file is created mode `0600` where supported.

`policy_context`
: Optional organization-level deterministic configuration. It is deep-copied on construction.

`fail_closed`
: If `True`, a native implementation error stops evaluation and raises `GuardrailEvaluationError` after the audit event is written. This is separate from a policy Block.

`max_audit_bytes`
: Rotate audit file when it reaches this size. `0` disables size rotation.

`audit_backups`
: Number of numbered rotated files to retain.

## `evaluate(payload)`

```python
fixed_payload = guardrail.evaluate(payload)
```

This is the primary runtime API.

- Snapshots enabled policies.
- Sorts by `(priority, filename)`.
- Applies deterministic native handlers.
- Chains Redact/Mask output into the next policy.
- Writes one JSONL audit event containing every enabled policy.
- Returns the final fixed payload.
- Raises `GuardrailBlockedError` instead of returning when a Block policy matches.

Supported payload shapes: `str`, UTF-8 `bytes`, `dict`, `list`, `tuple`. Other objects are retained and represented with `repr()` in audit serialization when necessary.

### Block handling

```python
try:
    payload = guardrail.evaluate(payload)
except guardrail.GuardrailBlockedError as exc:
    print(exc.policy)
    print(exc.evaluation_id)
```

## `enable_policies(policy_files)`

```python
guardrail.enable_policies([
    "AI_APP_SEC_070.json",
    "AI_DAT_SEC_011.json",
])
```

Enables by exact JSON filename. The operation is atomic. If any name is unknown, `UnknownPolicyError` is raised and none are changed.

## `disable_policies(policy_files)`

```python
guardrail.disable_policies(["AI_DAT_SEC_011.json"])
```

Atomic inverse of `enable_policies`.

## `disable_all_policies()`

```python
guardrail.disable_all_policies()
```

Returns the instance to a state with zero enabled policies.

## `get_policy_map()`

```python
policy_map = guardrail.get_policy_map()
```

Returns a defensive copy. Each filename maps to:

```python
{
    "enabled": False,
    "priority": 20,
    "action": "Redact",
    "name": "...",
    "description": "...",
}
```

Modifying the returned dictionary does not modify the live engine.

## `update_policy_context(values)`

```python
guardrail.update_policy_context({
    "approved_tools": ["search", "read_database"],
})
```

Atomically merges deterministic organization/runtime configuration.

## Common policy-context keys

The engine can inspect structured payload metadata as well, but these organization-level keys are useful for context-dependent policies:

| Key | Purpose |
|---|---|
| `approved_llms` | Allow list for `AI_APP_SEC_006.json` |
| `blocked_llms` | Deny list for `AI_APP_SEC_028.json` |
| `approved_url_hosts` / `url_allowlist` | URL host allow list for `AI_IAC_015.json` |
| `approved_url_schemes` | Usually `['https']` |
| `approved_url_prefixes` | Optional path-prefix constraints |
| `approved_tools` / `tool_allowlist` | Tool allow list for `AI_IAC_020.json` |
| `approved_capabilities` | Privilege envelope for `AI_IAC_016.json` |
| `allowed_oauth_scopes` | Minimal allowed scopes for `AI_IAC_031.json` |
| `approved_model_registries` | Model source allow list for `AI_VULN_SEC_005.json` |
| `approved_output_fields` / `allowed_output_fields` | Output minimization allow list |
| `risk_level` | `low`, `medium`, `high` |
| `covered_domain` | Regulatory domain classification |
| `log_retention_days` | Retention context for high-risk log policy |
| `decision_retention_days` | Consequential decision retention |

Common structured request fields recognized include `model`, `tool_name`, `url`, `skill_reputation`, `hitl_approved`, `consequential_decision`, `clinical_ai`, `patient_acknowledged_ai`, `biometric_consent`, `token_verified`, `token_expired`, `token_bound`, `user_agent_binding_verified`, `requested_scope`, and similar fields documented by the policy names.

## Exceptions

All are nested in `lineaje_guardrail` so the implementation retains a single top-level class.

```python
lineaje_guardrail.GuardrailError
lineaje_guardrail.UnknownPolicyError
lineaje_guardrail.GuardrailEvaluationError
lineaje_guardrail.GuardrailAuditError
lineaje_guardrail.GuardrailBlockedError
```

`GuardrailBlockedError` provides:

```python
exc.policy
exc.evaluation_id
```

## Audit event example

```json
{
  "evaluation_id": "...",
  "caller": {
    "file": "/app/agent.py",
    "line": 187,
    "function": "process",
    "module": "agent",
    "source_line": "payload = guardrail.evaluate(payload)"
  },
  "input": {
    "payload": "Ignore previous instructions. a@example.com",
    "payload_type": "str",
    "sha256": "sha256:..."
  },
  "policy_results": [
    {
      "policy_file": "AI_APP_SEC_070.json",
      "priority": 20,
      "configured_action": "Redact",
      "status": "MATCHED_ACTION_TAKEN",
      "action_taken": "Redact",
      "payload_before": "...",
      "payload_after": "..."
    }
  ],
  "result": {
    "final_action": "Redact",
    "blocked": false,
    "terminal_policy": null,
    "output_payload": "..."
  }
}
```

## Single-line integration pattern

The intended application pattern is deliberately simple:

```python
payload = guardrail.evaluate(payload)
```

The caller does not need to ask which policies are enabled, choose ordering, invoke per-policy methods, or apply returned patches.
