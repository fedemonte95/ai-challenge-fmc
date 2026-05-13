"""Streamlit risk dashboard (reads data from the Guardrail Auditor API)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

import pandas as pd
import streamlit as st

DEFAULT_API = os.environ.get("GUARDRAIL_API_URL", "http://127.0.0.1:8000")


def _get_json(base: str, path: str) -> Any:
    url = f"{base.rstrip('/')}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    st.set_page_config(page_title="Guardrail Risk Dashboard", layout="wide")
    st.title("Enterprise Security Guardrail Auditor")
    st.caption("Risk scores and findings from stored scans (API-first).")

    api_base = st.sidebar.text_input("API base URL", value=DEFAULT_API)
    st.sidebar.markdown("Run the API with: `uvicorn app.main:app --reload` from the `guardrail-auditor` folder.")

    try:
        scans = _get_json(api_base, "/scans")
    except urllib.error.URLError as e:
        st.error(f"Could not reach API at {api_base}: {e}")
        st.info("Start the FastAPI server, then refresh this page.")
        return

    if not scans:
        st.warning("No scans yet. POST a Terraform or CloudFormation document to `/scans`.")
        return

    df = pd.DataFrame(scans)
    st.subheader("Risk score overview")
    chart_df = df[["id", "risk_score", "source_name"]].copy()
    st.bar_chart(chart_df.set_index("id")["risk_score"])

    st.dataframe(
        df,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk score",
                min_value=0,
                max_value=100,
                format="%.1f",
            )
        },
        use_container_width=True,
        hide_index=True,
    )

    scan_id = st.selectbox("Inspect scan", options=df["id"].tolist(), format_func=lambda i: f"#{i}")
    if scan_id is None:
        return

    try:
        detail = _get_json(api_base, f"/scans/{scan_id}")
    except urllib.error.HTTPError as e:
        st.error(f"Failed to load scan: {e}")
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk score", f"{detail.get('risk_score', 0):.1f}")
    col2.metric("Findings", len(detail.get("findings", [])))
    col3.metric("Kind", detail.get("source_kind", ""))

    st.subheader("Findings")
    findings = detail.get("findings") or []
    if not findings:
        st.success("No findings for this scan.")
        return

    st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
