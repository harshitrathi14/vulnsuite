"""VulnSuite - Streamlit CISO dashboard."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text

from ..core.config import get_settings

settings = get_settings()

st.set_page_config(
    page_title="VulnSuite — CISO Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Sync engine for Streamlit (it does not play well with async)
_sync_url = settings.database.url.replace("+asyncpg", "+psycopg2")
engine = create_engine(_sync_url, pool_pre_ping=True)


def _set_tenant(conn, tenant_id: str) -> None:
    conn.execute(text("SET app.tenant_id = :t"), {"t": tenant_id})


def _evidence_raw(evidence) -> dict:
    """evidence column -> raw dict (handles jsonb dicts and JSON strings)."""
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (TypeError, ValueError):
            return {}
    if not isinstance(evidence, dict):
        return {}
    raw = evidence.get("raw")
    return raw if isinstance(raw, dict) else {}


@st.cache_data(ttl=60)
def load_findings(tenant_id: str) -> pd.DataFrame:
    with engine.connect() as conn:
        _set_tenant(conn, tenant_id)
        df = pd.read_sql(
            text("""
                SELECT finding_id, tool, module, title, severity,
                       cvss_base, epss, risk_score, risk_bucket,
                       status, first_seen, last_seen, cve, evidence,
                       is_new, scan_count, fixed_at
                FROM findings
                ORDER BY risk_score DESC
            """),
            conn,
        )
    if df.empty:
        return df
    # Flatten the Claude Fable 5 enrichment (Phase 3) into columns.
    raw = df["evidence"].map(_evidence_raw)
    df["risk_escalated_by"] = raw.map(lambda r: r.get("risk_escalated_by") or [])
    df["escalated"] = df["risk_escalated_by"].map(bool)
    df["ai_fp_likelihood"] = raw.map(lambda r: (r.get("ai_triage") or {}).get("fp_likelihood"))
    df["ai_exploitability"] = raw.map(lambda r: (r.get("ai_triage") or {}).get("exploitability"))
    df["ai_reasoning"] = raw.map(lambda r: (r.get("ai_triage") or {}).get("reasoning"))
    df["actively_exploited"] = raw.map(
        lambda r: bool((r.get("ai_threat_intel") or {}).get("actively_exploited"))
    )
    df["kev_listed"] = raw.map(
        lambda r: bool((r.get("ai_threat_intel") or {}).get("kev_listed"))
    )
    df["ai_suggested_bucket"] = raw.map(lambda r: r.get("ai_suggested_bucket"))
    df["attack_chains"] = raw.map(lambda r: r.get("ai_attack_chains") or [])
    df["ai_remediation"] = raw.map(lambda r: (r.get("ai_remediation") or {}).get("summary"))
    return df.drop(columns=["evidence"])


@st.cache_data(ttl=60)
def load_assets(tenant_id: str) -> pd.DataFrame:
    with engine.connect() as conn:
        _set_tenant(conn, tenant_id)
        return pd.read_sql(
            text("SELECT asset_id, name, asset_type, criticality, exposure FROM assets"),
            conn,
        )


# ---------- sidebar ----------

st.sidebar.title("🛡️ VulnSuite")
tenant_id = st.sidebar.text_input(
    "Tenant ID", value=settings.tenant_default_id,
)
st.sidebar.markdown("---")
st.sidebar.caption(f"Env: **{settings.environment}**")
st.sidebar.caption(f"Refreshed: {datetime.now(timezone.utc):%H:%M UTC}")
if st.sidebar.button("🔄 Refresh"):
    st.cache_data.clear()
    st.rerun()

# ---------- header ----------

st.title("Cybersecurity Posture — Executive View")

try:
    df = load_findings(tenant_id)
    assets_df = load_assets(tenant_id)
except Exception as e:
    st.error(f"Failed to load data: {e}")
    st.stop()

# ---------- KPI strip ----------

# open findings only for the live KPIs (auto-closed findings shouldn't inflate counts)
open_df = df[df["status"] == "open"] if not df.empty else df
buckets = open_df["risk_bucket"].value_counts().to_dict() if not open_df.empty else {}
exploited_count = int(open_df["actively_exploited"].sum()) if not open_df.empty else 0
new_count = int(open_df["is_new"].sum()) if not open_df.empty else 0
fixed_count = int((df["status"] == "fixed").sum()) if not df.empty else 0

col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)
col1.metric("P0 Critical", buckets.get("P0", 0))
col2.metric("P1 High", buckets.get("P1", 0))
col3.metric("P2 Medium", buckets.get("P2", 0))
col4.metric("P3 Low", buckets.get("P3", 0))
col5.metric("🆕 New", new_count)
col6.metric("🔥 Exploited", exploited_count)
col7.metric("✅ Fixed", fixed_count)
col8.metric("Assets", len(assets_df))

# ---------- new + live-threat banners ----------

if new_count > 0:
    st.warning(
        f"🆕 **{new_count} new finding(s) since the last scan.** "
        f"Newly-introduced exposure is what attackers look for first — triage the New "
        f"tab before anything else."
    )

if exploited_count > 0:
    st.error(
        f"🔥 **{exploited_count} open finding(s) involve CVEs with ACTIVE in-the-wild "
        f"exploitation or CISA KEV listing** — risk auto-escalated to P0. Patch these "
        f"first; attackers are already using them."
    )

# ---------- CERT-In clock ----------

p0_count = buckets.get("P0", 0)
if p0_count > 0:
    st.error(
        f"⏰ **{p0_count} P0 finding(s) — CERT-In 6-hour reporting clock is running.** "
        f"Review and file incident report via the Reports tab."
    )

st.markdown("---")

# ---------- tabs ----------

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["📊 Risk Overview", "🔝 Top Risks", "🏷️ Modules", "🏛️ Compliance", "🤖 AI Insights"]
)

with tab1:
    st.subheader("Risk Distribution")
    if not df.empty:
        bucket_df = (
            df["risk_bucket"].value_counts()
            .reindex(["P0", "P1", "P2", "P3", "P4"], fill_value=0)
        )
        st.bar_chart(bucket_df)

        st.subheader("Findings Aging")
        if "first_seen" in df.columns:
            df["first_seen"] = pd.to_datetime(df["first_seen"])
            df["age_days"] = (
                pd.Timestamp.now(tz="UTC") - df["first_seen"]
            ).dt.days
            aging = df.groupby("risk_bucket")["age_days"].mean().round(1)
            st.dataframe(aging.rename("Avg age (days)"))

with tab2:
    new_only = st.checkbox("Show only NEW findings (since last scan)", value=False)
    view = open_df[open_df["is_new"]] if new_only else open_df
    st.subheader(f"Top 25 {'New ' if new_only else ''}Open Risks")
    if not view.empty:
        top = view.head(25)[
            ["risk_bucket", "risk_score", "is_new", "escalated",
             "actively_exploited", "kev_listed",
             "tool", "module", "title", "severity", "cve"]
        ].rename(columns={
            "is_new": "🆕", "escalated": "⬆️", "actively_exploited": "🔥",
            "kev_listed": "KEV",
        })
        st.dataframe(top, use_container_width=True)
    else:
        st.info("No findings match.")

with tab3:
    st.subheader("Findings by Module")
    if not df.empty:
        by_mod = (
            df.groupby(["module", "risk_bucket"])
            .size().unstack(fill_value=0)
        )
        st.bar_chart(by_mod)
        st.dataframe(by_mod)

    st.subheader("Findings by Tool")
    if not df.empty:
        by_tool = df.groupby("tool").size().sort_values(ascending=False)
        st.bar_chart(by_tool)

with tab4:
    st.subheader("RBI CSF + CERT-In Compliance Snapshot")
    st.info(
        "This snapshot maps findings to RBI CSF Annex-I controls "
        "(6.2 crypto/TLS, 6.3 patching, 6.4 hardening, 6.5 certificates, "
        "6.13 cloud, 6.14 SDLC, 6.15 secrets, 6.16 database)."
    )
    if not df.empty:
        # Quick heuristic: module -> control
        mod_to_ctrl = {
            "sca": "6.3 Patching",
            "container": "6.3 Patching",
            "sast": "6.14 SDLC",
            "secrets": "6.15 Secrets",
            "network": "6.2/6.4 Crypto & Hardening",
            "cloud": "6.13 Cloud",
            "iac": "6.4/6.14 Secure Config & SDLC",
            "kubernetes": "6.3/6.4/6.13 K8s & Cloud",
            "asm": "6.1/6.2/6.4 Inventory & Exposure",
            "api_security": "6.14 SDLC",
            "supply_chain": "6.3/6.14 Supply Chain",
        }
        df["control"] = df["module"].map(mod_to_ctrl).fillna("Other")
        ctrl = df.groupby("control").size().rename("Findings")
        st.dataframe(ctrl)

        st.subheader("CERT-In Reportable (P0)")
        p0 = df[df["risk_bucket"] == "P0"]
        if p0.empty:
            st.success("✅ No CERT-In reportable findings.")
        else:
            st.error(
                f"⚠️ {len(p0)} finding(s) require CERT-In reporting within "
                f"6 hours of detection."
            )
            st.dataframe(
                p0[["title", "tool", "risk_score", "cve", "first_seen"]],
                use_container_width=True,
            )

with tab5:
    st.caption(
        "Enrichment by Claude Fable 5 — advisory signals for analyst review. "
        "Deterministic risk scores remain authoritative."
    )
    if df.empty:
        st.info("No findings loaded.")
    else:
        # ---- live threat intel ----
        st.subheader("🔥 Live Threat Intelligence")
        hot = df[df["actively_exploited"] | df["kev_listed"]]
        if hot.empty:
            st.success("No scanned CVEs currently show in-the-wild exploitation or KEV listing.")
        else:
            st.dataframe(
                hot[["risk_bucket", "title", "cve", "actively_exploited",
                     "kev_listed", "risk_score", "status"]]
                .rename(columns={"actively_exploited": "exploited now", "kev_listed": "CISA KEV"}),
                use_container_width=True,
            )

        # ---- attack chains ----
        st.subheader("⛓️ Verified Attack Chains")
        seen_chains: set[tuple] = set()
        chains = []
        for chain_list in df["attack_chains"]:
            for c in chain_list:
                if not isinstance(c, dict):
                    continue
                key = (tuple(c.get("finding_ids", [])), c.get("narrative", ""))
                if key not in seen_chains:
                    seen_chains.add(key)
                    chains.append(c)
        if not chains:
            st.success("No multi-finding attack chains confirmed on current data.")
        else:
            titles = df.set_index(df["finding_id"].astype(str))["title"].to_dict()
            for i, c in enumerate(
                sorted(chains, key=lambda x: x.get("likelihood", 0), reverse=True), 1
            ):
                likelihood = float(c.get("likelihood", 0))
                with st.expander(
                    f"Chain {i}: {c.get('composite_severity', '?').upper()} — "
                    f"{c.get('kill_chain_stage', '?')} — {likelihood:.0%} likelihood — "
                    f"suggested {c.get('suggested_bucket', '?')}"
                ):
                    st.write(c.get("narrative", ""))
                    for n, fid in enumerate(c.get("finding_ids", []), 1):
                        st.markdown(f"{n}. {titles.get(fid, fid)}")

        # ---- escalations ----
        st.subheader("⬆️ AI-Suggested Escalations")
        esc = df[df["ai_suggested_bucket"].notna()]
        if esc.empty:
            st.success("No escalations suggested.")
        else:
            st.dataframe(
                esc[["risk_bucket", "ai_suggested_bucket", "title", "risk_score"]]
                .rename(columns={"risk_bucket": "current", "ai_suggested_bucket": "suggested"}),
                use_container_width=True,
            )

        # ---- triage: likely false positives ----
        st.subheader("🧹 Likely False Positives (AI Triage)")
        fp = df[df["ai_fp_likelihood"].notna() & (df["ai_fp_likelihood"] >= 0.8)]
        if fp.empty:
            st.info("No high-confidence false-positive candidates.")
        else:
            st.caption(f"{len(fp)} finding(s) flagged at ≥80% FP likelihood — review and dismiss to cut noise.")
            st.dataframe(
                fp[["ai_fp_likelihood", "title", "tool", "module", "risk_bucket", "ai_reasoning"]]
                .sort_values("ai_fp_likelihood", ascending=False),
                use_container_width=True,
            )

        # ---- remediation summaries ----
        st.subheader("🔧 AI Remediation Plans (P0/P1)")
        rem = df[df["ai_remediation"].notna()]
        if rem.empty:
            st.info("No AI remediation plans on current data.")
        else:
            st.dataframe(
                rem[["risk_bucket", "title", "ai_remediation"]],
                use_container_width=True,
            )

st.markdown("---")
st.caption(
    f"VulnSuite 0.1 | {settings.reporting.classification_banner}"
)
