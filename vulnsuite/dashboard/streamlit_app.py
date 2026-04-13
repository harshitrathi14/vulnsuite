"""VulnSuite - Streamlit CISO dashboard."""
from __future__ import annotations

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


@st.cache_data(ttl=60)
def load_findings(tenant_id: str) -> pd.DataFrame:
    with engine.connect() as conn:
        _set_tenant(conn, tenant_id)
        df = pd.read_sql(
            text("""
                SELECT finding_id, tool, module, title, severity,
                       cvss_base, epss, risk_score, risk_bucket,
                       status, first_seen, last_seen, cve
                FROM findings
                ORDER BY risk_score DESC
            """),
            conn,
        )
    return df


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

buckets = df["risk_bucket"].value_counts().to_dict() if not df.empty else {}
col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("P0 Critical", buckets.get("P0", 0))
col2.metric("P1 High", buckets.get("P1", 0))
col3.metric("P2 Medium", buckets.get("P2", 0))
col4.metric("P3 Low", buckets.get("P3", 0))
col5.metric("P4 Info", buckets.get("P4", 0))
col6.metric("Assets", len(assets_df))

# ---------- CERT-In clock ----------

p0_count = buckets.get("P0", 0)
if p0_count > 0:
    st.error(
        f"⏰ **{p0_count} P0 finding(s) — CERT-In 6-hour reporting clock is running.** "
        f"Review and file incident report via the Reports tab."
    )

st.markdown("---")

# ---------- tabs ----------

tab1, tab2, tab3, tab4 = st.tabs(
    ["📊 Risk Overview", "🔝 Top Risks", "🏷️ Modules", "🏛️ Compliance"]
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
    st.subheader("Top 25 Risks")
    if not df.empty:
        top = df.head(25)[
            ["risk_bucket", "risk_score", "tool", "module",
             "title", "severity", "cve"]
        ]
        st.dataframe(top, use_container_width=True)

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

st.markdown("---")
st.caption(
    f"VulnSuite 0.1 | {settings.reporting.classification_banner}"
)
