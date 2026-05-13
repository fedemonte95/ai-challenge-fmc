"""HTTP API smoke and scan lifecycle tests (in-memory DB via tests/conftest.py)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_rules(client: TestClient) -> None:
    resp = client.get("/rules")
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = {r["rule_id"] for r in data}
    assert "aws.s3.public_access" in rule_ids
    assert "aws.network.sg_ingress_0_0_0_0" in rule_ids
    assert "azure.storage.https_only" in rule_ids


def test_post_scan_list_get_roundtrip(client: TestClient) -> None:
    content = (FIXTURES / "insecure_aws.tf").read_text(encoding="utf-8")
    create = client.post(
        "/scans",
        json={
            "source_name": "api-roundtrip",
            "source_kind": "terraform",
            "content": content,
        },
    )
    assert create.status_code == 200, create.text
    body = create.json()
    assert body["source_name"] == "api-roundtrip"
    assert body["risk_score"] > 0
    assert len(body["findings"]) >= 1
    scan_id = body["id"]

    listed = client.get("/scans")
    assert listed.status_code == 200
    ids = {row["id"] for row in listed.json()}
    assert scan_id in ids

    one = client.get(f"/scans/{scan_id}")
    assert one.status_code == 200
    again = one.json()
    assert again["id"] == scan_id
    assert len(again["findings"]) == len(body["findings"])


def test_post_scan_invalid_terraform_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/scans",
        json={
            "source_name": "bad",
            "source_kind": "terraform",
            "content": "{{{ not hcl",
        },
    )
    assert resp.status_code == 400
    assert "Failed to parse" in resp.json()["detail"]
