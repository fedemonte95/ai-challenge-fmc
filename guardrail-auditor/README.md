# guardrail-auditor

Enterprise-style **IaC guardrail auditor**: scan Terraform and CloudFormation against security baselines, persist results in a database, expose an **API-first** workflow, and review a **visual risk score** in Streamlit.

## Features

- **FastAPI** — `POST /scans` ingests raw IaC, parses it, runs registered rules, stores **findings** and a **0–100 risk score** (SQLite by default).
- **Rules** — AWS (S3 public exposure, wide-open security groups on sensitive ports, IAM `Action *` + `Resource *`) and Azure (HTTPS-only on storage accounts, internet-facing NSG rules for SSH/RDP).
- **Streamlit dashboard** — charts and tables over `GET /scans` and `GET /scans/{id}` (set `GUARDRAIL_API_URL` if the API is not on `http://127.0.0.1:8000`).

## Layout

- `app/` — API, database, parsers, rules, scoring, routes
- `dashboard/` — Streamlit UI
- `fixtures/` — sample IaC for local testing
- `tests/` — pytest suite

## Quick start

```bash
cd guardrail-auditor
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Create a scan with a JSON body: `source_name`, `source_kind` (`terraform` or `cloudformation`), and `content` (full file text). Example with PowerShell:

```powershell
$body = @{
  source_name = "demo"
  source_kind = "terraform"
  content     = (Get-Content -Raw fixtures/insecure_aws.tf)
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scans -Body $body -ContentType "application/json"
```

Streamlit (after the API is up):

```bash
streamlit run dashboard/app.py
```

## Database

Default: **SQLite** at `./guardrail.db`. For PostgreSQL (or another SQLAlchemy URL), set:

`DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname`

## Tests

```bash
python -m pytest tests -q
```

## Code execution log (recorded run)

This section captures a real local run: commands, environment, inputs considered, and raw output for traceability.

### When / where

- **Date:** 2026-05-13  
- **OS:** Windows (`win32`)  
- **Python:** 3.12.10  
- **Working directory:** `guardrail-auditor` (repository subfolder)

### Commands executed

From the repo root, enter the project and install in editable mode with dev extras, then run the automated suite:

```powershell
cd guardrail-auditor
python --version
pip install -e ".[dev]" -q
python -m pytest tests -v --tb=short
```

Optional **fixture-only scan** (no HTTP server; exercises parsers + rules + scoring on files under `fixtures/`):

```powershell
cd guardrail-auditor
python -c "
from pathlib import Path
from app.scan_service import parse_payload, evaluate_all_rules
from app.scoring import compute_risk_score

root = Path('fixtures')
for name in ['insecure_aws.tf', 'secure_aws.tf', 'insecure.cfn.yaml', 'insecure_azure.tf']:
    p = root / name
    text = p.read_text(encoding='utf-8')
    kind = 'cloudformation' if name.endswith('.yaml') else 'terraform'
    parsed = parse_payload(kind, text)
    findings = evaluate_all_rules(parsed, kind)
    score = compute_risk_score(findings)
    rules = sorted({f.rule_id for f in findings})
    print(f'=== {name} ({kind}) ===')
    print(f'  findings: {len(findings)}  risk_score: {score}')
    print(f'  rule_ids: {rules}')
print('OK')
"
```

### Parameters and environment

| Name | Value (this run) | Notes |
|------|------------------|--------|
| `DATABASE_URL` | *(unset in shell)* | **Pytest** sets `sqlite:///:memory:` via `tests/conftest.py` before `app.db` loads; `app/db.py` uses `StaticPool` for in-memory SQLite so tables and sessions share one DB. |
| `GUARDRAIL_API_URL` | *(not used)* | Used by `dashboard/app.py` when pointing Streamlit at a non-default API base URL. |
| `pip install -e ".[dev]"` | dev extra | Pulls `pytest`, `httpx`, `pytest-asyncio` per `pyproject.toml`. |
| `pytest` | `tests -v --tb=short` | Config from `[tool.pytest.ini_options]` in `pyproject.toml` (`testpaths = ["tests"]`, `asyncio_mode = auto`). |

### Files and modules taken into account

- **Project config:** `pyproject.toml` (dependencies, pytest config, package discovery for `app`).
- **Application:** `app/main.py`, `app/db.py`, `app/models.py`, `app/schemas.py`, `app/scan_service.py`, `app/scoring.py`, `app/iac_nav.py`, `app/parsers/*`, `app/routes/*`, `app/rules/*`.
- **Tests:** `tests/conftest.py`, `tests/test_api.py`, `tests/test_rules_fixtures.py`, `tests/test_scoring.py`.
- **Sample IaC (fixture dry-run):** `fixtures/insecure_aws.tf`, `fixtures/secure_aws.tf`, `fixtures/insecure.cfn.yaml`, `fixtures/insecure_azure.tf`.

### Results: `python -m pytest tests -v --tb=short`

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.0.3, pluggy-1.6.0 -- C:\Users\feder\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\feder\OneDrive\Documents\GitHub\ai-challenge-fmc\guardrail-auditor
configfile: pyproject.toml
plugins: anyio-4.13.0, asyncio-1.3.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 12 items

tests/test_api.py::test_health PASSED                                    [  8%]
tests/test_api.py::test_list_rules PASSED                                [ 16%]
tests/test_api.py::test_post_scan_list_get_roundtrip PASSED              [ 25%]
tests/test_api.py::test_post_scan_invalid_terraform_returns_400 PASSED   [ 33%]
tests/test_rules_fixtures.py::test_insecure_aws_tf_flags_high_risk_patterns PASSED [ 41%]
tests/test_rules_fixtures.py::test_secure_aws_tf_minimal_findings PASSED [ 50%]
tests/test_rules_fixtures.py::test_insecure_cfn_yaml PASSED              [ 58%]
tests/test_rules_fixtures.py::test_insecure_azure_tf PASSED              [ 66%]
tests/test_rules_fixtures.py::test_create_scan_wraps_parser_errors PASSED [ 75%]
tests/test_scoring.py::test_risk_score_empty PASSED                      [ 83%]
tests/test_scoring.py::test_risk_score_caps PASSED                       [ 91%]
tests/test_scoring.py::test_risk_score_weights PASSED                    [100%]

============================== warnings summary ===============================
tests/test_api.py::test_post_scan_list_get_roundtrip
  C:\Users\feder\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\LocalCache\local-packages\Python312\site-packages\sqlalchemy\sql\schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 12 passed, 1 warning in 0.60s ========================
```

### Results: fixture dry-run (`fixtures/*.tf`, `fixtures/*.yaml`)

```text
=== insecure_aws.tf (terraform) ===
  findings: 3  risk_score: 65.0
  rule_ids: ['aws.iam.wildcard_admin', 'aws.network.sg_ingress_0_0_0_0', 'aws.s3.public_access']
=== secure_aws.tf (terraform) ===
  findings: 0  risk_score: 0.0
  rule_ids: []
=== insecure.cfn.yaml (cloudformation) ===
  findings: 2  risk_score: 40.0
  rule_ids: ['aws.network.sg_ingress_0_0_0_0', 'aws.s3.public_access']
=== insecure_azure.tf (terraform) ===
  findings: 2  risk_score: 40.0
  rule_ids: ['azure.network.nsg_open_inbound', 'azure.storage.https_only']
OK
```
