import os
import streamlit as st
import pandas as pd
from parser import get_engine, fetch_logs, get_risk_summary, get_top_violators
from seed_logs import seed_audit_logs

st.set_page_config(page_title="ITGC Audit Log Analyzer", layout="wide")

DB_HOST = os.getenv("DB_HOST", "localhost")

@st.cache_resource
def init_db():
    try:
        engine = get_engine(DB_HOST)
        df = pd.read_sql("SELECT COUNT(*) FROM information_schema.tables WHERE table_name='database_audit_logs'", engine)
        if df.iloc[0, 0] == 0:
            seed_audit_logs()
        return engine
    except Exception as e:
        return None

engine = init_db()

st.title("🔒 ITGC (IT General Controls) Audit Log Analyzer")
st.markdown("Automated security intelligence dashboard monitoring database access controls, authentication failures, and privilege escalations.")

if engine is None:
    st.error("Could not connect to PostgreSQL. Please ensure Docker containers are running.")
else:
    if st.button("🔄 Reset & Re-seed Log Data"):
        with st.spinner("Generating mock database audit logs..."):
            seed_audit_logs()
            st.success("Audit logs re-seeded successfully!")
            st.rerun()

    st.markdown("---")
    
    summary_df = get_risk_summary(engine)
    total_logs = pd.read_sql("SELECT COUNT(*) FROM database_audit_logs", engine).iloc[0, 0]
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Parsed Logs", total_logs)
    with col2:
        high_count = summary_df.loc[summary_df['risk_level'] == 'HIGH', 'count'].sum() if not summary_df.empty else 0
        st.metric("High Risks Flagged", high_count)
    with col3:
        crit_count = summary_df.loc[summary_df['risk_level'] == 'CRITICAL', 'count'].sum() if not summary_df.empty else 0
        st.metric("Critical Violations", crit_count)
    with col4:
        warn_count = summary_df.loc[summary_df['risk_level'] == 'WARNING', 'count'].sum() if not summary_df.empty else 0
        st.metric("Authentication Warnings", warn_count)

    st.markdown("### 📊 Security Insights & Analytics")
    
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Risk Distribution")
        if not summary_df.empty:
            st.bar_chart(summary_df.set_index("risk_level"))
    with c2:
        st.subheader("Top Risk Violators by User")
        violators_df = get_top_violators(engine)
        if not violators_df.empty:
            st.dataframe(violators_df, use_container_width=True)

    st.markdown("---")
    st.subheader("📋 Filterable Database Audit Logs")
    
    selected_risk = st.selectbox("Filter by Risk Level", ["ALL", "CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW"])
    logs_df = fetch_logs(engine, selected_risk)
    
    st.dataframe(logs_df, use_container_width=True)
