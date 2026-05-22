from ai_agent import generate_ai_summary
import streamlit as st
import pandas as pd

from wazuh_client import load_alerts
from alert_analyzer import analyze_alert


st.set_page_config(
    page_title="AI Security Analyst",
    layout="wide"
)

st.title("AI Security Analyst Dashboard")

alerts = load_alerts()
analyzed_alerts = [analyze_alert(alert) for alert in alerts]

df = pd.DataFrame(analyzed_alerts)

# =========================
# SIDEBAR FILTER
# =========================

st.sidebar.header("Filter")

selected_risk = st.sidebar.multiselect(
    "Risk Level",
    options=df["risk"].unique(),
    default=df["risk"].unique()
)

filtered_df = df[df["risk"].isin(selected_risk)]

# =========================
# EXECUTIVE SUMMARY
# =========================

st.subheader("Executive Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(filtered_df))
col2.metric("High Risk", len(filtered_df[filtered_df["risk"] == "HIGH"]))
col3.metric("Medium Risk", len(filtered_df[filtered_df["risk"] == "MEDIUM"]))
col4.metric("Low Risk", len(filtered_df[filtered_df["risk"] == "LOW"]))

# =========================
# RISK DISTRIBUTION
# =========================

st.subheader("Risk Distribution")

risk_counts = filtered_df["risk"].value_counts()

st.bar_chart(risk_counts)

# =========================
# TOP EVENTS
# =========================

st.subheader("Top Events")

top_events = filtered_df["event"].value_counts().head(10)

st.bar_chart(top_events)

# =========================
# TOP AGENTS
# =========================

st.subheader("Top Agents")

top_agents = filtered_df["agent"].value_counts()

st.bar_chart(top_agents)

# =========================
# MITRE ATT&CK
# =========================

st.subheader("MITRE ATT&CK Techniques")

mitre_counts = filtered_df["mitre"].value_counts()

st.bar_chart(mitre_counts)

# =========================
# ALERT TABLE
# =========================

st.subheader("Alerts")

st.dataframe(
    filtered_df[
        [
            "risk",
            "level",
            "agent",
            "event",
            "src_ip",
            "mitre",
            "recommendation"
        ]
    ],
    use_container_width=True
)

# =========================
# REPORT DOWNLOAD
# =========================

csv = filtered_df.to_csv(index=False)

st.download_button(
    label="Download CSV Report",
    data=csv,
    file_name="security_report.csv",
    mime="text/csv"
)

# =========================
# AI ANALYSIS
# =========================

st.subheader("AI Alert Analysis")

medium_high_df = filtered_df[filtered_df["risk"].isin(["HIGH", "MEDIUM"])]

unique_events = medium_high_df.drop_duplicates(subset=["event"]).head(5)

if unique_events.empty:
    st.info("Keine HIGH oder MEDIUM Alerts für die KI-Analyse gefunden.")
else:
    selected_event = st.selectbox(
        "Wähle ein Event für die KI-Analyse",
        unique_events["event"].tolist()
    )

    selected_alert = unique_events[unique_events["event"] == selected_event].iloc[0].to_dict()

    if st.button("KI-Analyse starten"):
        with st.spinner("Lokales LLM analysiert den Alert..."):
            ai_result = generate_ai_summary(selected_alert)

        st.markdown(ai_result)