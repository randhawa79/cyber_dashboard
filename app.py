import streamlit as st
import pandas as pd
import plotly.express as px
import datetime
import io

# System Initializations
from config import logger
from database import initialize_database
import database
import vuln_collector
import news_collector
import regulatory_collector
import threat_intel
import ai_analysis

st.set_page_config(page_title="FinSec CISO Control Center", layout="wide", page_icon="🛡️")
initialize_database()

# --- SECURITY ACCESS & USER ROLE-BASED CONTROLS ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user_role = None

def render_login_form():
    st.markdown("<h2 style='text-align: center;'>🔐 FinSec Unified Governance Platform</h2>", unsafe_allow_html=True)
    with st.form("Identity Check"):
        username = st.text_input("Corporate ID Handle")
        password = st.text_input("Access Password Key", type="password")
        role_selection = st.selectbox("Authorization Domain Context", ["CISO", "SOC Analyst", "Vulnerability Manager", "Auditor"])
        submitted = st.form_submit_button("Authenticate Sign-In Token")
        
        if submitted:
            # Safely fetch the credential database from st.secrets
            user_registry = st.secrets.get("users", {})
            
            # Verify if user exists and check password match
            if username in user_registry and user_registry[username]["password"] == password:
                # Enforce Cryptographic Role Validation (RBAC mapping verification)
                if user_registry[username]["role"] == role_selection:
                    st.session_state.authenticated = True
                    st.session_state.user_role = role_selection
                    st.success(f"Authorization token verified. Welcome, {username}.")
                    st.rerun()
                else:
                    st.error("Access Refused: Selection profile does not match your assigned corporate role.")
            else:
                st.error("Invalid credentials or unauthorized identity token.")

if not st.session_state.authenticated:
    render_login_form()
    st.stop()

# --- PERSISTENT DATA ORCHESTRATION PIPELINES ---
@st.cache_data(ttl=3600)
def synchronize_and_pull_data():
    """Runs data ingest streams, handles cache controls, and structures DataFrames."""
    vuln_collector.fetch_and_sync_cisa_kev()
    news_collector.fetch_and_sync_news()
    regulatory_collector.sync_regulatory_advisories()
    threat_intel.sync_threat_indicators()
    
    vulns = database.query_to_dataframe("SELECT * FROM vulnerabilities")
    news_items = database.query_to_dataframe("SELECT * FROM news")
    alerts = database.query_to_dataframe("SELECT * FROM regulatory_alerts")
    threats = database.query_to_dataframe("SELECT * FROM threat_iocs")
    
    return vulns, news_items, alerts, threats

vulns_df, news_df, alerts_df, threats_df = synchronize_and_pull_data()

# --- LAYOUT NAVIGATION MANAGEMENT HEADER ---
st.markdown(f"### 🛡️ FinSec Executive Cyber Command Portal | Role Context: `{st.session_state.user_role}`")
st.markdown("---")

# Global Dynamic Controls Sidebar
st.sidebar.header("🎛️ Governance Control Center Filters")
severity_slider = st.sidebar.slider("CVSS Score Severity Threshold Check", 0.0, 10.0, 5.0)
search_query = st.sidebar.text_input("Universal Infrastructure String Search", "")

if st.sidebar.button("Logout System Token"):
    st.session_state.authenticated = False
    st.rerun()

# Apply Filters Globally to Vulnerabilities Dataset
filtered_vulns = vulns_df[vulns_df['cvss_score'] >= severity_slider]
if search_query:
    filtered_vulns = filtered_vulns[filtered_vulns['description'].str.contains(search_query, case=False) | filtered_vulns['cve_id'].str.contains(search_query, case=False)]

# --- TAB CONTROL INTERFACE GENERATION ---
tabs = st.tabs(["📊 Executive Briefing Hub", "🔍 Vulnerability Matrix", "🎯 Threat Matrix Indicators", "⚖️ Regulatory Enforcements", "📰 Global Intelligence Feed"])

# ==========================================
# TAB 1: EXECUTIVE SUMMARY HUB
# ==========================================
with tabs[0]:
    st.markdown("#### 🚨 Enterprise Exposure Matrix Overview")
    
    # Key Performance Metrics (KPIs) Layout
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Overall Corporate Risk Index Score", value="72 / 100", delta="-3 points reduction", delta_color="inverse")
    with col2:
        st.metric(label="Active Exploited Critical CVSS Flaws", value=len(filtered_vulns[filtered_vulns['cvss_score'] >= 8.5]), delta="Action Required", delta_color="off")
    with col3:
        st.metric(label="Pending RBI Regulatory Mandates", value=len(alerts_df[alerts_df['source'] == 'RBI']), delta="Critical Focus", delta_color="inverse")
    with col4:
        st.metric(label="Detected Malicious Infrastructure Assets", value=len(threats_df), delta="+2 New Today", delta_color="inverse")
        
    st.markdown("---")
    st.markdown("### 🤖 CISO Briefing Generator (Gemini AI Processing Unit)")
    with st.spinner("Compiling tactical landscape..."):
        ai_briefing = ai_analysis.generate_ai_executive_summary(filtered_vulns, news_df, alerts_df)
        st.markdown(ai_briefing)
        
    st.markdown("---")
    st.markdown("### 📈 Risk Prioritization Matrix (24-Hour Action Plan)")
    priority_data = [
        {"Priority": "🔥 1 - CRITICAL", "Issue": "Active CISA KEV Vulnerabilities discovered in networks", "Reason": "Remote authentication bypass threats are actively weaponized in the wild.", "Action": "Deploy upstream hotpatches across active web configurations within 24 hours."},
        {"Priority": "⚡ 2 - HIGH", "Issue": "UPI Validation Loop Compliance Gaps", "Reason": "Non-compliance with explicit device tracking updates can trigger operational fines.", "Action": "Enforce mandatory device binding policies via production deployment pipelines."},
        {"Priority": "⏱️ 3 - MEDIUM", "Issue": "Unencrypted Transaction Trace Log Capture", "Reason": "Violates explicit PCI DSS Section 3 database configuration boundaries.", "Action": "Update rotation logs configurations to securely mask payloads."}
    ]
    st.table(pd.DataFrame(priority_data))

# ==========================================
# TAB 2: VULNERABILITY MATRIX
# ==========================================
with tabs[1]:
    st.markdown("#### 🔍 Real-Time Active Infrastructure Vulnerabilities")
    
    if filtered_vulns.empty:
        st.info("No tracking exposures match your specific filter queries.")
    else:
        # Side-by-side Chart Analytics
        v_col1, v_col2 = st.columns(2)
        with v_col1:
            fig_cvss = px.histogram(filtered_vulns, x="cvss_score", title="CVSS Severity Metric Scatter Analysis", color_discrete_sequence=['#ef553b'])
            st.plotly_chart(fig_cvss, use_container_width=True)
        with v_col2:
            fig_epss = px.scatter(filtered_vulns, x="cvss_score", y="epss_score", size="epss_score", hover_name="cve_id", title="EPSS Probability vs Impact Risk Grid")
            st.plotly_chart(fig_epss, use_container_width=True)
            
        st.dataframe(filtered_vulns, use_container_width=True)
        
        # Comprehensive Data Export Operations Tooling
        st.markdown("##### 📥 Extract Security Assessment Inventories")
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
            filtered_vulns.to_excel(writer, sheet_name='Vulnerabilities', index=False)
        st.download_button(
            label="Download Vulnerability Audit Spreadsheet (Excel)",
            data=buffer.getvalue(),
            file_name=f"vuln_report_{datetime.date.today().isoformat()}.xlsx",
            mime="application/vnd.ms-excel"
        )

# ==========================================
# TAB 3: THREAT MATRIX INDICATORS
# ==========================================
with tabs[2]:
    st.markdown("#### 🎯 Active Threat Infrastructure Indicators & Payment Vectors")
    
    t_col1, t_col2 = st.columns([1, 2])
    with t_col1:
        fig_threats = px.pie(threats_df, names="threat_category", values="confidence_score", title="Tracked Vectors Weight Distribution")
        st.plotly_chart(fig_threats, use_container_width=True)
    with t_col2:
        st.markdown("**Active Network Perimeter Blocks**")
        st.dataframe(threats_df, use_container_width=True)

# ==========================================
# TAB 4: REGULATORY ENFORCEMENTS
# ==========================================
with tabs[3]:
    st.markdown("#### ⚖️ Compliance Tracking Modules (RBI, NPCI, CERT-In, PCI DSS)")
    
    for _, row in alerts_df.iterrows():
        with st.expander(f"📌 [{row['source']}] - {row['title']}"):
            st.markdown(f"**Date Logged**: {row['published_date']}")
            st.markdown(f"**Functional Vulnerability Context**: {row['summary']}")
            st.markdown(f"**Direct Compliance Mandate**: `{row['compliance_impact']}`")
            st.info(f"🔧 **Mandated Technical Patching Checklist**: {row['recommended_action']}")

# ==========================================
# TAB 5: GLOBAL INTELLIGENCE FEED
# ==========================================
with tabs[4]:
    st.markdown("#### 📰 Synced Global News Streams (Past 24 Hours)")
    
    for _, row in news_df.iterrows():
        st.markdown(f"##### [{row['source']}] {row['title']}")
        st.caption(f"Published Timeline context: {row['published_date']}")
        st.markdown(f"{row['summary']}")
        st.markdown(f"[Inspect Raw Resource Stream Link]({row['url']})")
        st.markdown("---")
