# Prompts

Use this file to capture system prompts, rule-generation instructions, or LLM-assisted workflows for the auditor.

## Audit log (turn prompts)

Per project convention, each turn is logged here in short form. The full initial Lead Architect charter (Untitled-1) is **not** duplicated here to avoid confusion; only a summary of what was asked.

| When (UTC) | Summary |
|------------|---------|
| 2026-05-12 | **Turn:** User attached Lead Architect charter for Project 2 (API-first guardrail auditor, free DB, dashboard, no manual edits, audit log + time reporting). **Action:** Acknowledged rules; confirmed repo already matches MVP (FastAPI scans, SQLite/`DATABASE_URL`, rules, Streamlit risk UI, tests). **Timer:** MVP target 4–6h (max 16h); treat as **T+0** at this acknowledgement for elapsed reporting. |
| 2026-05-12 | **Turn:** “First steps: plan for code + test cases + run initial tests.” **Action:** Documented layered plan + test pyramid; added `tests/conftest.py`, `tests/test_api.py`; fixed in-memory SQLite for tests via `StaticPool` in `app/db.py`; `pytest tests -v` → **12 passed**. |
| 2026-05-13 | **Turn:** Code run; paste results into `README.md`; document commands, parameters, files. **Action:** Ran `pip install -e ".[dev]"`, `pytest tests -v --tb=short`, fixture dry-run script; appended **Code execution log** to `README.md` with outputs, env table, file list. |
| 2026-05-13 | **Turn:** Markdown presentation of execution flow, code parts, responsibilities for tech + business stakeholders. **Action:** Created `STAKEHOLDER_OVERVIEW.md` (flow diagrams, rule table, component matrix, data model, glossary). |

## Scan interpretation

- Summarize findings by severity and cloud provider.
- Map each finding to the relevant rule id and resource block.
