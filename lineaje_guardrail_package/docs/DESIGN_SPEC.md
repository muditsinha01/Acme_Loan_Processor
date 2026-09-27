# Lineaje Guardrail Class — Implementation Design Specification

## 1. Goal

`lineaje_guardrail` is a single deterministic enforcement gateway for the 78 supplied policy files. Applications do not select individual guardrail functions or understand ordering. The normal integration is one line:

```python
payload = guardrail.evaluate(payload)
```

The class selects enabled policies, orders them, enforces them, writes a complete forensic JSONL audit event, and returns the fixed payload unless a terminal Block policy fires.

## 2. Policy identity and initialization

The canonical runtime identifier is the **JSON filename**, not `ai_policy_id`. This avoids collisions in the supplied corpus. The class embeds all 78 definitions and creates an instance policy map in which every policy starts disabled.

Each embedded definition retains the source:

- filename;
- `ai_policy_id` as informational metadata;
- name and description;
- severity and applicability;
- guardrail name and description;
- original `guardrail[0].ai_prompt`;
- deterministic runtime action;
- priority.

The source JSON files are not needed at runtime.

## 3. No LLM execution

The class contains no model executor and does not import or call OpenAI, Anthropic, Gemini, LiteLLM, LangChain or any inference service. The source guardrail prompt is a **generation-time specification**, not a runtime prompt.

The remediation intent is implemented with native Python primitives including:

- regular-expression and Unicode inspection;
- base64/hex/URL/Unicode/ROT13/Morse decoding for injection detection;
- prompt-injection classifiers expressed as deterministic patterns;
- PII detection/redaction/masking;
- secret detection and environment-variable remediation;
- URL parsing, host/scheme allowlists and private-address checks;
- tool/model/skill allowlist and status checks;
- authentication, token, RBAC and scope checks;
- deterministic static checks for missing logging, retention, disclosure, HITL, rate-limit and observability controls;
- common vulnerability and memory-safety pattern checks.

## 4. Actions

Exactly five actions exist in the runtime model:

- **Allow** — aggregate outcome when no enabled policy matches.
- **Warn** — payload unchanged; finding recorded.
- **Block** — terminal; audit is written and a block exception is raised.
- **Redact** — offending payload content is replaced; fixed payload continues to the next policy.
- **Mask** — offending content is obscured; fixed payload continues to the next policy.

Architectural remediation instructions that cannot safely be expressed as payload edits are represented as deterministic `Warn` checks, as agreed during design.

## 5. Priority and overlap

Lower numbers run first. The bands are:

1. `10`: Block.
2. `20`: malicious/prompt-injection Redact.
3. `25`: executable/injection sanitization Redact.
4. `30`: PII/secrets/data-minimization Redact.
5. `40`: Mask.
6. `50`: security/architecture Warn.
7. `60`: runtime/resilience/monitoring Warn.
8. `70`: governance/disclosure/retention Warn.

Policies in the same band are sorted by filename for stable deterministic execution.

This ensures, for example, that a suspicious prompt is evaluated before PII redaction so a lower-priority data transformation cannot hide evidence from a higher-priority security control.

## 6. Evaluation pipeline

At the start of each call the class atomically snapshots the enabled policy map and organization policy context. This snapshot remains fixed for that evaluation even if another thread changes enablement concurrently.

```text
caller -> snapshot enabled policies -> priority sort -> evaluate policy
                                                       |
                      +--------------------------------+------------------+
                      |                                |                  |
                  no match                           Warn             Redact/Mask
                      |                                |                  |
                      +---------------------> continue with current/fixed payload
                                                       |
                                                     Block
                                                       |
                                                  terminal stop
                                                       |
                                            audit every enabled policy
                                                       |
                                     return fixed payload OR raise Block
```

## 7. Block accounting

Block is terminal for execution, but not for audit accounting. Every lower-priority enabled policy receives a `SKIPPED_TERMINAL_ACTION` entry identifying the higher-priority blocking policy.

Higher-priority *enablement alone* never suppresses a later policy. The higher-priority policy must actually match and take a terminal action.

## 8. Payload support

The runtime handles common AI payload forms:

- `str`;
- UTF-8 `bytes`;
- `dict`;
- `list`;
- `tuple`.

Structured objects are traversed recursively while preserving logical structure. Finding paths use JSONPath-like locations such as `$.messages[0].content`.

## 9. Fixed-payload semantics

The engine keeps two objects:

- `original_payload` — immutable forensic snapshot;
- `working_payload` — current payload passed from policy to policy.

Redact and Mask handlers return a transformed `working_payload`. The final working payload is the return value from `evaluate()`.

## 10. Context-dependent enforcement

Some policies require enterprise facts that cannot be derived from content alone: approved LLMs, approved tools, URL allowlists, model registries, token verification, consent status, reviewer authority, etc.

The constructor accepts deterministic `policy_context`; no model inference is used to fill missing facts. Structured payload fields can also supply conventional runtime metadata.

A policy records a violation only when the deterministic implementation has concrete evidence. It does not guess unknown facts.

## 11. Audit contract

Each `evaluate()` invocation emits exactly one JSONL event containing:

- `schema_version`;
- `evaluation_id`;
- UTC timestamp;
- process and thread identity;
- caller source location;
- original payload, type and hash;
- one result for every enabled policy;
- before/after payload and hash for each executed policy;
- findings and offending content;
- final action, block state, terminal policy and output payload;
- duration.

Per-policy statuses include:

- `MATCHED_ACTION_TAKEN`;
- `EVALUATED_NO_MATCH`;
- `SKIPPED_TERMINAL_ACTION`;
- `ERROR`.

## 12. Caller location

The class walks Python stack frames and returns the first source frame outside `lineaje_guardrail.py`, rather than relying on a fixed `f_back.f_back` depth. This supports wrappers and decorators more reliably.

The audit contains file, line, function, module and source statement when Python can retrieve it.

## 13. Sensitive logging

The user requirement is forensic reconstruction of the offending payload, so original content is intentionally recorded. The audit file therefore has security sensitivity comparable to application secrets/PII logs. It is created with `0600` permissions where supported and supports size-based rotation.

## 14. Errors

Exceptions are nested under the single public class:

- `lineaje_guardrail.UnknownPolicyError`;
- `lineaje_guardrail.GuardrailEvaluationError`;
- `lineaje_guardrail.GuardrailAuditError`;
- `lineaje_guardrail.GuardrailBlockedError`.

Enable/disable is atomic: a list containing any unknown filename causes the entire request to fail without partial modification.

`fail_closed=True` (default) stops processing if an enabled native policy implementation itself errors. This is a technical failure, distinct from a policy Block decision.

## 15. Thread safety

Configuration changes use a re-entrant lock. Evaluations operate on immutable snapshots. Audit writes are process-thread serialized, opened with append semantics and use `flock` where available.

## 16. Core invariants

1. All 78 supplied real policies exist in the embedded map.
2. All are disabled by default.
3. Filename is the canonical policy identifier.
4. No enabled policy is silently omitted from an audit event.
5. No disabled policy executes.
6. Priority ordering is explicit and stable.
7. Block precedes destructive transformation and is terminal.
8. Prompt-injection remediation precedes PII transformation.
9. Redact/Mask results become input to the next policy.
10. Warn never changes the payload.
11. Blocked input is never returned as usable payload.
12. No LLM or inference service is invoked by the class.
13. The original guardrail prompt is retained as traceable source metadata.
14. The normal runtime integration remains `payload = guardrail.evaluate(payload)`.
