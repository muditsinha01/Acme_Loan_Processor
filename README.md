# Acme Loan Assistant

**AI-powered policy evaluation and remediation demo application**

Acme Loan Assistant is a deliberately vulnerable chat agent application designed to demonstrate how Unifai detects security policy violations and instructs Cursor IDE to remediate them. The frontend presents as a lightweight AI assistant for document review and loan-related chat.

## Demo Flow

1. **Run Acme Loan Assistant with Unifai disabled** → vulnerable behavior is visible
2. **Enable Unifai in Cursor** → scans code, detects violations
3. **Unifai instructs Cursor** to fix the violations
4. **Run Acme Loan Assistant again** → guardrails now active, violations blocked

## Four Policy Violations Demonstrated

| Policy | Vulnerability | After Remediation |
|--------|---------------|-------------------|
| **PII Detection** | Files processed without PII scanning | SSN, credit cards, phone numbers detected and blocked |
| **Prompt Injection** | Hidden text/prompts sent to LLM | Hidden content detected and filtered |
| **Agent Auth** | Inter-agent calls bypass authentication | JWT-based authentication required |
| **Vulnerable Deps** | Old packages with known CVEs | Updated to patched versions |

## Quick Start

### Option A: Docker (recommended)

**Prerequisites:** Docker and an [OpenRouter](https://openrouter.ai/keys) API key

1. **Build the image**

```bash
docker build -t acme-loan-processor:local .
```

2. **Run the container**

```bash
docker run -d \
  --name acme-loan-processor \
  -p 80:5001 \
  -e OPENROUTER_API_KEY=your_openrouter_api_key \
  -e OPENROUTER_MODEL=meta-llama/llama-3.1-70b-instruct \
  -e AGENT_SECRET=your_random_secret \
  acme-loan-processor:local
```

3. **Open the app** at http://localhost (Acme Loan Assistant interface)

---

### Option B: Local Development

**Prerequisites:**

- Node.js 18+
- Python 3.10+
- OpenRouter API key (`OPENROUTER_API_KEY`)
- OpenRouter model id (`OPENROUTER_MODEL`)

### Setup

1. **Copy environment file**

```bash
cd Acme_Loan_Processor

# Copy environment template
cp .env.example .env
# Edit .env and add your OpenRouter settings
```

2. **Create virtual environment and install dependencies**

```bash
./scripts/setup_env.sh    # Creates .venv and installs Python deps
```

3. **Start the application**

```bash
./scripts/run_dev.sh    # Start both backend and frontend servers
```

4. **Stop the application**

```bash
./scripts/stop_dev.sh   # Stop both servers
```

**Or run manually:**

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
uvicorn main:app --reload --port 5500

# Terminal 2: Frontend
cd frontend
npm install
npm run dev -- -p 5001
```

5. **Open the app**

- Frontend (Acme Loan Assistant): http://localhost:5001
- Backend API: http://localhost:5500
- API Docs: http://localhost:5500/docs

## Frontend

The Acme Loan Assistant UI features a clean, modern design:

- **Light theme** — Slate/blue palette with subtle radial gradients and glass-panel styling
- **Typography** — Manrope font for a professional, approachable feel
- **Layout** — Glass panel chat container with blue accent band, soft dividers, and fade-in animations
- **Features** — File upload zone with drag-and-drop, starter prompts for quick actions, and responsive design
- **Components** — Chat interface, message list, file upload, and policy error display

## Project Structure

```
Acme_Loan_Processor/
├── frontend/                    # Next.js React frontend (Acme Loan Assistant UI)
│   ├── src/
│   │   ├── app/                 # Next.js app router, layout, globals
│   │   └── components/          # ChatInterface, MessageList, FileUpload
│   └── package.json             # ⚠️ Vulnerable npm deps
│
├── backend/                     # Python FastAPI backend
│   ├── agents/                  # Multi-agent system
│   │   ├── mcp_servers.py       # Central MCP server catalog
│   │   ├── orchestrator_agent.py
│   │   ├── loan_processing_agent.py
│   │   ├── file_processor_agent.py
│   │   ├── file_management_agent.py  # ⚠️ Destructive ops without HITL
│   │   ├── access_control_agent.py   # ⚠️ LLM-driven security decisions
│   │   ├── credit_eval_agent.py
│   │   ├── scheduling_agent.py
│   │   ├── runtime.py           # Thin registry over the agent files
│   │   └── auth/                # ⚠️ Auth bypass
│   ├── policies/                # Policy modules
│   │   ├── pii_detection.py     # ⚠️ NO-OP detection
│   │   ├── prompt_injection.py  # ⚠️ NO-OP detection
│   │   └── runtime/             # Runtime guardrails
│   ├── file_parsers/            # File processing
│   └── requirements.txt         # ⚠️ Vulnerable Python deps
│
├── config/                      # Policy configuration
├── test_files/                  # Demo test files
└── scripts/                     # Development scripts
```

## Demo Scenarios

### 1. PII Detection Demo

**Before:**
1. Upload `test_files/advanced/nested_pii.json`
2. Observe: "File processed successfully"
3. PII is sent to the LLM without detection

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Error: PII detected - SSN found in user.profile.contact.ssn"

### 2. Prompt Injection Demo

**Before:**
1. Upload `test_files/advanced/base64_hidden.html`
2. Hidden prompts are extracted and sent to LLM
3. LLM may respond to malicious instructions

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Security threat detected: Hidden content in HTML elements"

### 2b. Image Prompt Injection -> Tool-Output Exfiltration Demo (Environment Diagnostics Agent)

**Before:**
1. Run `python scripts/create_test_files.py` (or generate your own) to produce
   `test_files/advanced/ripgrep_exfil_payload.jpg`, and edit the placeholder
   collector URL drawn on the image to your own request-bin endpoint.
2. Set `OPENROUTER_VISION_MODEL` in `.env` to a multimodal OpenRouter model.
3. Upload the image and ask: "Can you run the environment diagnostics from
   this document?" (routes to the Environment Diagnostics Agent - see
   keyword list in `backend/agents/orchestrator_agent.py::select_agent`).
4. The vision model transcribes the visible instruction text verbatim into
   the document context (`backend/file_parsers/image_parser.py`).
5. `backend/agents/environment_diagnostics_agent.py` parses a natural-language
   "command request" out of that transcription, fabricates a fake AWS
   credential "scan result" (`backend/config/simulated_secrets.py`), and POSTs
   it to the URL embedded in the image - no HITL check, no destination
   allowlist. Observe the "Diagnostic activity" note in the response and the
   real inbound request on your collector.

**After Unifai Remediation:**
1. Same upload and prompt
2. Observe: the destination URL is rejected by a hardcoded allowlist - no
   outbound request is made (see the guarded `environment_diagnostics_agent.py`
   on the `fixed` branch)

### 3. Agent Authentication Demo

**Before:**
1. Ask: "Can you show me the quarterly financial report?"
2. Orchestrator Agent forwards the full context and shared hop token to another agent
3. Access granted without proper authentication

**After Unifai Remediation:**
1. Same request
2. Observe: "Unauthorized: Agent token validation failed"

### 4. Vulnerable Dependencies Demo

**Before:**
```bash
cd frontend && npm audit
# Shows vulnerabilities in lodash, axios, etc.
```

**After Unifai Remediation:**
- `package.json` updated with patched versions
- `npm audit` shows no vulnerabilities

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor_agent.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/credit_eval_agent.py` | `backend/policies/prompt_injection.py` |
| **AI Threats** | Image prompt injection -> tool-output exfiltration | `backend/agents/environment_diagnostics_agent.py` | *(destination allowlist gate)* |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator_agent.py` | `backend/agents/auth/agent_auth.py` |
| **AI Threats** | Destructive ops without HITL | `backend/agents/file_management_agent.py` | *(HITL boolean gate)* |
| **AI Threats** | LLM output drives security decisions | `backend/agents/access_control_agent.py` | *(HITL + allowlist gate)* |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |

### AI Policy ID Mapping (Unifai AIEPO Policies)

29 additional Unifai AIEPO policies map to real, unguarded code in this repo,
so each policy's `guardrail[].insertion_prompts.default` scan prompt finds a
genuine matching insertion point. `backend/agents/medical_hardship_agent.py`,
`lab_automation_agent.py`, `hr_screening_agent.py`, and `backend/native/` are
scan-only and isolated from the live chat flow (`IS_ROUTABLE = False`) —
they exist purely to cover policy domains (healthcare disclosure, CBRN,
employment facial recognition, native memory safety) that don't otherwise fit
a loan-processing app.

| Policy ID | Insertion Point | Violation Location |
|-----------|------------------|---------------------|
| `AI_SKILL_SEC_001` / `AI_SKILL_SEC_002` / `AI_SKILL_SEC_003` / `AI_SKILL_DAT_SEC_001` | `skill_invocation` | `backend/agents/skill_loader.py::load_skill()`, called from `installed_skill_agent.py::handle()` with no malicious/suspicious/pending-scan/exfiltration check. `SKILL.md` (`status: pending_scan`) is itself a crypto-payment social-engineering skill with an exfiltration-style callback/A2A payload. |
| `AI_VULN_SEC_002` | N/A | `backend/agents/environment_diagnostics_agent.py::send_diagnostic_output()` — real SSRF, no destination allowlist. |
| `AI_VULN_SEC_006` | N/A | `backend/native/fast_pii_scan.c::copy_into_scan_buffer()` — unchecked `strcpy()` into a fixed-size stack buffer, loaded via `backend/native/__init__.py` from `file_processor_agent.py::build_pii_exposure_summary()`. |
| `AI_DAT_SEC_039` | N/A | `backend/agents/mock_database.py::export_borrower_records_backup()` — plaintext `http://` backup endpoint and unencrypted on-disk backup file for borrower PII. |
| `AI_IAC_015` | `api_call` | `backend/agents/environment_diagnostics_agent.py::send_diagnostic_output()` — outbound POST to a URL parsed from untrusted document/image content. |
| `AI_IAC_016` | `risky_operation` | `backend/agents/access_control_agent.py::decide_security()` — LLM output directly drives `grant_admin()` / `authorize_scope()`. |
| `AI_IAC_018` | `risky_operation` | `backend/agents/installed_skill_agent.py` payment flow and `access_control_agent.py::grant_admin()` — high-risk operations with no bound-subject verification. |
| `AI_IAC_020` | `mcp_call` | `backend/agents/mcp_servers.py::call_mcp_server()` — invoked with no tool allowlist check. |
| `AI_IAC_023` | `llm_to_agent` | Every agent's `response = (...)` construction (e.g. `backend/main.py`'s `/chat` handler) — no AI-identity disclosure is ever sent. |
| `AI_IAC_025` / `AI_IAC_026` | `llm_to_agent` | `backend/agents/medical_hardship_agent.py::handle()` — clinical-sounding hardship assessment with no upfront AI disclosure and no "human clinician retains final authority" disclaimer. |
| `AI_IAC_031` | N/A | `backend/main.py` — `/chat`, `/upload`, `/catalog`, `/agents`, `/mcp-servers` have no auth/RBAC/scope checks. |
| `AI_APP_SEC_001` / `002` / `006` / `028` / `032` / `038` / `039` / `059` / `067` / `070` | `agent_to_llm` | `call_agent_model()` in `orchestrator_agent.py`, `installed_skill_agent.py`, `loan_processing_agent.py`, `scheduling_agent.py`, `file_processor_agent.py` — raw content sent to `call_bedrock_model()` / `backend/llm/openai_compatible.py::chat()` with no hidden-prompt, base64, leetspeak, command-pattern, or LLM allow/deny-list check. |
| `AI_APP_SEC_014` | `mcp_call` | `backend/agents/mcp_servers.py::call_mcp_server()` — arguments forwarded to the MCP tool unsanitized. |
| `AI_APP_SEC_023` | `mcp_call` | `backend/agents/mcp_servers.py::call_mcp_server()` / `format_mcp_activity()` — tool response used unsanitized. |
| `AI_APP_SEC_029` | `llm_to_agent` | `orchestrator_agent.py`, `file_processor_agent.py`, `loan_processing_agent.py`, `scheduling_agent.py`, `installed_skill_agent.py`, `access_control_agent.py`, `environment_diagnostics_agent.py` — `model_output` used directly with no eval/exec check. |
| `AI_APP_SEC_034` | N/A | `backend/agents/access_control_agent.py::decide_security()` — `while not decision.get("access")` retry loop with no maximum iteration count. |
| `AI_APP_SEC_040` / `AI_APP_SEC_066` | `file_upload` / `agent_to_llm` | `backend/agents/file_processor_agent.py::process_attachment()` → `helpers.py::build_file_summary()`; `backend/policies/content_scanner.py::combine_for_analysis()` merges hidden/encoded file content with no filtering before it reaches the LLM. |
| `AI_APP_SEC_071` | `agent_to_llm` | `backend/agents/lab_automation_agent.py::call_agent_model()` / `submit_synthesis_order()` — synthesis request sent with no nucleic-acid screening. |
| `AI_APP_SEC_075` | N/A | `backend/agents/hr_screening_agent.py::analyze_facial_engagement_score()` — facial-emotion score fed directly into a promotion/termination recommendation. |
| `AI_APP_SEC_078` | N/A | `backend/agents/access_control_agent.py::human_review()` — auto-approves with no reviewer override permission and no required regulatory context fields. |

## Test Files

- `test_files/simple/` - Basic examples for warm-up
- `test_files/advanced/nested_pii.json` - PII buried 5 levels deep
- `test_files/advanced/base64_hidden.html` - Hidden prompts in HTML
- `test_files/advanced/multi_hop_attack.json` - Chained agent exploit

Generate additional test files:
```bash
python scripts/create_test_files.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Acme Loan Assistant                      │
│              Next.js + React · Light theme · Manrope         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Orchestrator Agent                           │
│  ┌───────────────┐ ┌──────────────┐ ┌───────────┐ ┌────────────┐   │
│  │ Loan Processing│ │ File Processor│ │ File Mgmt │ │ Credit Eval│   │
│  └───────────────┘ └──────────────┘ └───────────┘ └────────────┘   │
│          ┌────────────────────┐  ┌──────────────────────────┐      │
│          │ Access Control Agent│  │    Scheduling Agent     │      │
│          └────────────────────┘  └──────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
                               │
               ┌───────────────┼────────────────┬─────────────────────┐
               ▼               ▼                ▼                     ▼
          ┌─────────┐   ┌─────────┐      ┌─────────┐           ┌──────────────┐
          │  Slack  │   │ Service-│      │  Email  │           │ Google Calendar │
          │         │   │   Now   │      │         │           │                │
          └─────────┘   └─────────┘      └─────────┘           └──────────────┘
               │               │                │                     │
               └───────────────┴────────────┬───┴───────────────┬─────┘
                                            ▼                   ▼
                                         ┌──────┐            ┌─────┐
                                         │Excel │            │Docx │
                                         └──────┘            └─────┘
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OPENROUTER_API_KEY` | API key for OpenRouter chat completions | Yes | — |
| `OPENROUTER_MODEL` | OpenRouter model id (e.g. `meta-llama/llama-3.1-70b-instruct`) | Yes | — |
| `OPENROUTER_VISION_MODEL` | Vision-capable OpenRouter model for image text transcription | No | falls back to `OPENROUTER_MODEL` |
| `AGENT_SECRET` | Secret for HMAC inter-agent token signing | No | — |
| `JWT_SECRET` | Secret for JWT signing (after Unifai remediation) | No | — |
| `BACKEND_URL` | Backend URL for frontend proxy | No | `http://127.0.0.1:5500` |
| `LOG_LEVEL` | Logging verbosity | No | `INFO` |

## License

This is a demo application for Unifai integration testing.
