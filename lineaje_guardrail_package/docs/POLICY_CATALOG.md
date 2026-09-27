# Policy Implementation Catalog

All 78 source policies are embedded and independently enableable by filename. The original `guardrail[0].ai_prompt` is retained inside `lineaje_guardrail._POLICY_DEFINITIONS` for traceability but is **never executed**. `Native handler` is the Python implementation selected at runtime.

| Policy file | Priority | Action | Native handler | Policy name |
|---|---:|---|---|---|
| `AI_APP_SEC_059.json` | 10 | Block | `_p_command_execution_block` | Do not allow prompts that can execute malicious commands at runtime. |
| `AI_APP_SEC_064.json` | 10 | Block | `_p_synthetic_provenance` | Enforce synthetic content provenance, labeling, and watermarking for AI-generated outputs. |
| `AI_APP_SEC_068.json` | 10 | Block | `_p_llm_security_decision` | Detect LLM output used directly in security-sensitive decisions without Human in the Loop (HITL) validation |
| `AI_APP_SEC_069.json` | 10 | Block | `_p_risky_operation_hitl` | AI Agent must implement Human in the Loop (HITL) approval flow for risky operations like delete, purge, destroy |
| `AI_APP_SEC_071.json` | 10 | Block | `_p_cbrn` | Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems |
| `AI_APP_SEC_073.json` | 10 | Block | `_p_consequential_human_review` | AI consequential decisions must include a human review pathway before final determination |
| `AI_APP_SEC_075.json` | 10 | Block | `_p_facial_recognition_employment` | Detect and block use of facial recognition APIs or libraries in employment decision workflows |
| `AI_APP_SEC_078.json` | 10 | Block | `_p_meaningful_human_review` | Human review workflows for AI consequential decisions must enforce override authority, reviewer context, and no auto-approve defaults |
| `AI_DAT_SEC_033.json` | 10 | Block | `_p_patient_acknowledgement` | Patient acknowledgment of AI-assisted care must be documented and retained before clinical AI use |
| `AI_DAT_SEC_036.json` | 10 | Block | `_p_biometric_consent` | Biometric data collection must be preceded by explicit, documented consent capture |
| `AI_IAC_015.json` | 10 | Block | `_p_url_allowlist` | Enforce URL allowlists for agent fetches, tools, and outbound HTTP. |
| `AI_IAC_016.json` | 10 | Block | `_p_privilege_escalation` | Detect and block agent privilege escalation attempts. |
| `AI_IAC_017.json` | 10 | Block | `_p_session_token_integrity` | Maintain session token integrity with signing, verification, expiry, and binding. |
| `AI_IAC_018.json` | 10 | Block | `_p_user_agent_binding` | Enforce cryptographically verified user-to-agent binding for every request. |
| `AI_IAC_020.json` | 10 | Block | `_p_tool_allowlist` | Restrict AI agents to an explicit tool allow list. |
| `AI_IAC_031.json` | 10 | Block | `_p_rbac_scopes` | AI model endpoints must enforce role-based access control with minimal OAuth scopes |
| `AI_SKILL_DAT_SEC_001.json` | 10 | Block | `_p_skill_exfiltration` | Do not allow skills that exfiltrate data |
| `AI_SKILL_SEC_001.json` | 10 | Block | `_p_skill_malicious` | Do not allow malicious skills |
| `AI_SKILL_SEC_002.json` | 10 | Block | `_p_skill_suspicious` | Do not allow suspicious skills |
| `AI_SKILL_SEC_003.json` | 10 | Block | `_p_skill_pending` | Do not allow skills that are pending a scan |
| `AI_VULN_SEC_005.json` | 10 | Block | `_p_model_registry` | Enforce foundation model identity, version pinning, and approved model registry for all AI workloads. |
| `AI_APP_SEC_001.json` | 20 | Redact | `_p_hidden_prompt` | Do not allow malicious content via hidden prompts |
| `AI_APP_SEC_002.json` | 20 | Redact | `_p_encoded_prompt` | Do not allow malicious content via encoded prompts |
| `AI_APP_SEC_032.json` | 20 | Redact | `_p_leetspeak` | Do not allow malicious content via hidden prompts written in leetspeak. |
| `AI_APP_SEC_040.json` | 20 | Redact | `_p_malicious_file_content` | Do not allow malicious content via prompts included in uploaded files. |
| `AI_APP_SEC_066.json` | 20 | Redact | `_p_malicious_file_content` | Do not allow malicious content via prompts included in source files. |
| `AI_APP_SEC_070.json` | 20 | Redact | `_p_prompt_injection` | Detect and block all forms of prompt injection attacks in user inputs and file contents |
| `AI_APP_SEC_014.json` | 25 | Redact | `_p_sanitize_input` | MCP server must validate and sanitize all input |
| `AI_APP_SEC_023.json` | 25 | Redact | `_p_sanitize_input` | Client must validate and sanitize any output from a MCP server |
| `AI_APP_SEC_029.json` | 25 | Redact | `_p_dynamic_execution` | Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output. |
| `AI_APP_SEC_038.json` | 25 | Redact | `_p_sanitize_input` | The AI Model must validate and sanitize any input before processing. |
| `AI_APP_SEC_039.json` | 25 | Redact | `_p_sanitize_input` | Sanitize and validate all input to the AI Model. |
| `AI_DAT_SEC_001.json` | 30 | Redact | `_p_secrets` | Do not store secrets in code. |
| `AI_DAT_SEC_009.json` | 30 | Redact | `_p_pii_redact` | If PII data must be shared, it must be encrypted |
| `AI_DAT_SEC_011.json` | 30 | Redact | `_p_pii_redact` | Do not send PII to AI Models |
| `AI_DAT_SEC_023.json` | 30 | Redact | `_p_pii_redact` | Redact PII from uploaded files. |
| `AI_DAT_SEC_024.json` | 30 | Redact | `_p_singapore_pii_redact` | Uploaded files must not contain PII (Singapore). |
| `AI_DAT_SEC_025.json` | 30 | Redact | `_p_pii_redact` | No file should contain any PII. |
| `AI_DAT_SEC_027.json` | 30 | Redact | `_p_data_minimization` | Enforce output data minimisation for model, tool, and API responses. |
| `AI_DAT_SEC_010.json` | 40 | Mask | `_p_pii_mask` | Do not log PII. |
| `AI_DAT_SEC_012.json` | 40 | Mask | `_p_pii_mask` | Mask PII on user interfaces |
| `AI_APP_SEC_006.json` | 50 | Warn | `_p_approved_llm` | Use only LLMs from the organization's approved list. |
| `AI_APP_SEC_028.json` | 50 | Warn | `_p_disallowed_llm` | Do not use LLMs from the organization's disallowed list |
| `AI_APP_SEC_033.json` | 50 | Warn | `_p_mcp_direct_llm` | MCP server must not interact directly with an LLM |
| `AI_APP_SEC_067.json` | 50 | Warn | `_p_prompt_interpolation` | Detect direct string interpolation of untrusted input into LLM prompts |
| `AI_DAT_SEC_039.json` | 50 | Warn | `_p_encryption_tls` | AI data stores must enforce encryption at rest and TLS in transit. |
| `AI_IAC_002.json` | 50 | Warn | `_p_mcp_client_auth` | MCP client must authenticate MCP server |
| `AI_IAC_006.json` | 50 | Warn | `_p_mcp_server_auth` | MCP server must authenticate all clients |
| `AI_IAC_007.json` | 50 | Warn | `_p_interagent_auth` | Inter agent communication must be authenticated. |
| `AI_IAC_008.json` | 50 | Warn | `_p_excessive_credentials` | Agents must not hold excessive external system credentials |
| `AI_IAC_009.json` | 50 | Warn | `_p_llm_endpoint_auth` | LLM endpoints must require authentication |
| `AI_IAC_014.json` | 50 | Warn | `_p_agent_user_auth` | A user must authenticate before accessing the AI Agent. |
| `AI_VULN_SEC_002.json` | 50 | Warn | `_p_common_vulnerabilities` | Do not allow critical or high vulnerabilities in the code. |
| `AI_VULN_SEC_006.json` | 50 | Warn | `_p_memory_safety` | Memory safety and buffer overflow prevention in native AI code (C/C++/Rust) |
| `AI_APP_SEC_022.json` | 60 | Warn | `_p_mcp_logging` | MCP clients must log all interactions with the MCP server |
| `AI_APP_SEC_034.json` | 60 | Warn | `_p_agent_exit` | Clear exit or termination criteria must exist for the agent to consider its task complete and stop executing. |
| `AI_APP_SEC_035.json` | 60 | Warn | `_p_llm_logging` | Agents must log all interactions with an LLM |
| `AI_APP_SEC_074.json` | 60 | Warn | `_p_emergency_shutdown` | AI systems must implement emergency shutdown and forced-termination mechanisms |
| `AI_APP_SEC_079.json` | 60 | Warn | `_p_rate_limiting` | Enforce rate limiting and throttling on AI API calls |
| `AI_DAT_SEC_029.json` | 60 | Warn | `_p_decision_audit` | Enforce decision logging, audit trail, and forensic readiness for AI-driven actions. |
| `AI_IAC_022.json` | 60 | Warn | `_p_subagent_bounds` | Enforce resource bounds, termination limits, and traceability for subagent spawning |
| `AI_VULN_SEC_007.json` | 60 | Warn | `_p_incident_observability` | AI systems must implement incident detection, structured logging, and reporting mechanisms |
| `AI_APP_SEC_072.json` | 70 | Warn | `_p_explainability` | AI systems making consequential decisions must implement explainability mechanisms disclosing decision factors |
| `AI_APP_SEC_076.json` | 70 | Warn | `_p_high_risk_disclosure` | High-risk AI systems must provide enhanced disclosures including decision factors, known limitations, accuracy metrics, and appeal rights |
| `AI_APP_SEC_077.json` | 70 | Warn | `_p_admt_notice` | AI systems must provide consumer notice before using ADMT in a consequential decision |
| `AI_DAT_SEC_030.json` | 70 | Warn | `_p_retention_180` | Enforce minimum six-month log retention for high-risk AI systems |
| `AI_DAT_SEC_031.json` | 70 | Warn | `_p_training_data_disclosure` | Disclose training data sources including categories, types, timeframes, and geography. |
| `AI_DAT_SEC_032.json` | 70 | Warn | `_p_data_acquisition_disclosure` | Disclose data acquisition methods including permissions, licensing, and preprocessing steps. |
| `AI_DAT_SEC_037.json` | 70 | Warn | `_p_biometric_retention` | Biometric data stores must declare a retention limit and deletion scheduling mechanism |
| `AI_DAT_SEC_038.json` | 70 | Warn | `_p_decision_retention_3y` | AI consequential decision records must be retained for a minimum of three years |
| `AI_IAC_023.json` | 70 | Warn | `_p_ai_identity_disclosure` | Chatbot and AI interfaces must disclose AI identity to the user |
| `AI_IAC_024.json` | 70 | Warn | `_p_model_card` | General purpose AI model integrations must reference a model card or technical documentation |
| `AI_IAC_025.json` | 70 | Warn | `_p_healthcare_disclosure` | Healthcare AI systems must disclose AI use to patients before diagnosis, treatment, or imaging |
| `AI_IAC_026.json` | 70 | Warn | `_p_clinician_authority` | AI clinical recommendations must disclose that human clinicians retain final decision authority |
| `AI_IAC_027.json` | 70 | Warn | `_p_human_only_review` | Healthcare AI communications must include patient instructions to request human-only review |
| `AI_IAC_028.json` | 70 | Warn | `_p_risk_classification` | AI system deployments must declare a risk classification level in configuration metadata |
| `AI_IAC_029.json` | 70 | Warn | `_p_model_versioning` | AI model deployments must maintain version tracking, change logs, and release documentation |
| `AI_IAC_030.json` | 70 | Warn | `_p_covered_domain` | AI system deployments must declare a covered domain classification per automated decision-making regulations |
