# Lineaje Guardrail

Deterministic, offline Python implementation of the 78 Lineaje guardrail policies supplied in the source JSON archive.

**No LLM or model API is called at runtime.** Each `guardrail[0].ai_prompt` has been preserved as source metadata and translated into native Python detection, validation, blocking, redaction, masking, or warning logic.

## Quick start

```python
from lineaje_guardrail import lineaje_guardrail

guardrail = lineaje_guardrail(
    audit_log_path="/var/log/lineaje/guardrail.jsonl",
    policy_context={
        "approved_llms": ["gpt-5.6", "claude-enterprise"],
        "approved_url_hosts": ["api.example.com"],
        "approved_tools": ["search", "database_read"],
    },
)

guardrail.enable_policies([
    "AI_APP_SEC_070.json",  # prompt injection
    "AI_DAT_SEC_011.json",  # PII to model
])

# Primary integration: one line.
payload = guardrail.evaluate(payload)
```

If a `Block` policy matches, `evaluate()` writes the complete audit event and raises `guardrail.GuardrailBlockedError`. A blocked payload is never returned as a usable value.

```python
try:
    payload = guardrail.evaluate(payload)
except guardrail.GuardrailBlockedError as exc:
    print(exc.policy, exc.evaluation_id)
```

## Execution semantics

Lower numeric priority runs first.

| Priority | Action family | Runtime behavior |
|---:|---|---|
| 10 | Block | Terminal; later enabled policies are logged as skipped |
| 20 | Redact malicious content | Prompt injection / hidden / encoded content |
| 25 | Redact unsafe executable/input content | Dynamic execution and injection sanitization |
| 30 | Redact sensitive data | PII, secrets, data minimization |
| 40 | Mask | PII masking |
| 50 | Warn | Security and architectural controls |
| 60 | Warn | Runtime, logging, resilience controls |
| 70 | Warn | Governance, disclosure, retention controls |

`Allow` is the aggregate result when no enabled policy matches.

## Audit log

Every `evaluate()` call writes one JSON object to the JSONL audit log. Every enabled policy gets an entry, including lower-priority policies skipped after a Block.

The event includes:

- original offending payload;
- payload before and after each policy;
- findings, offsets and replacements when available;
- final fixed payload;
- final action;
- caller source file, line number, function, module and source line;
- SHA-256 payload hashes;
- evaluation UUID, timestamp, process/thread IDs and duration.

The audit file is created with mode `0600` where supported because the requested forensic record can contain PII, secrets and malicious content.

## Files

- `lineaje_guardrail.py` — complete self-contained implementation.
- `docs/DESIGN_SPEC.md` — implementation design and runtime invariants.
- `docs/API_REFERENCE.md` — public API and integration help.
- `docs/POLICY_CATALOG.md` — all 78 policies, actions, priorities and native handlers.
- `docs/POLICY_SOURCE_MANIFEST.json` — source-file and guardrail-prompt hashes.
- `examples/basic_usage.py` — minimal integration example.
- `tests/test_guardrail.py` — validation suite.

## Important scope note

Some source guardrails describe architectural source-code changes such as adding authentication, logging, retention configuration, disclosure flows, or rate limiting. Under the agreed five-action runtime model, those policies are implemented as deterministic static/context checks and return `Warn`, rather than attempting unsafe arbitrary source-code rewriting. Content-remediation policies perform actual `Redact` or `Mask` transformations. Terminal enforcement policies return `Block` by raising `GuardrailBlockedError`.

Context-dependent policies can consume organization configuration through `policy_context` and can also discover conventional metadata fields in structured payloads. See `docs/API_REFERENCE.md`.
