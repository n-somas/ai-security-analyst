from ai_agent import generate_ai_summary
import pandas as pd
import streamlit as st

from alert_analyzer import analyze_alert
from correlation import detect_bruteforce
from wazuh_client import load_alerts


st.set_page_config(page_title="AI Security Analyst", layout="wide")
st.title("AI Security Analyst Dashboard")

alerts = load_alerts()

if not alerts:
    st.warning("Keine Wazuh-Alerts gefunden. Prüfe data/alerts_export.json.")
    st.stop()

analyzed_alerts = [analyze_alert(alert) for alert in alerts]
incidents = detect_bruteforce(analyzed_alerts)
df = pd.DataFrame(analyzed_alerts)

st.sidebar.header("Filter")
selected_risk = st.sidebar.multiselect(
    "Risk Level",
    options=sorted(df["risk"].dropna().unique()),
    default=sorted(df["risk"].dropna().unique()),
)
selected_agent = st.sidebar.multiselect(
    "Agent",
    options=sorted(df["agent"].dropna().unique()),
    default=sorted(df["agent"].dropna().unique()),
)
search_term = st.sidebar.text_input("Event oder Quell-IP suchen")

filtered_df = df[df["risk"].isin(selected_risk) & df["agent"].isin(selected_agent)]
if search_term:
    needle = search_term.lower()
    filtered_df = filtered_df[
        filtered_df["event"].astype(str).str.lower().str.contains(needle, na=False)
        | filtered_df["src_ip"].astype(str).str.lower().str.contains(needle, na=False)
    ]

st.subheader("Executive Summary")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Alerts", len(filtered_df))
col2.metric("High Risk", len(filtered_df[filtered_df["risk"] == "HIGH"]))
col3.metric("Medium Risk", len(filtered_df[filtered_df["risk"] == "MEDIUM"]))
col4.metric("Low Risk", len(filtered_df[filtered_df["risk"] == "LOW"]))
col5.metric("Correlated Incidents", len(incidents))

st.subheader("Correlated Incidents")
if not incidents:
    st.info("Keine Brute-Force-Muster erkannt.")
else:
    incident_df = pd.DataFrame(incidents)
    st.dataframe(
        incident_df[
            [
                "risk",
                "incident_type",
                "src_ip",
                "agent",
                "alert_count",
                "first_seen",
                "last_seen",
                "recommendation",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

st.subheader("Risk Distribution")
st.bar_chart(filtered_df["risk"].value_counts())

st.subheader("Top Events")
st.bar_chart(filtered_df["event"].value_counts().head(10))

st.subheader("Top Agents")
st.bar_chart(filtered_df["agent"].value_counts())

st.subheader("MITRE ATT&CK Techniques")
st.bar_chart(filtered_df["mitre"].value_counts())

st.subheader("Alerts")
st.dataframe(
    filtered_df[
        [
            "timestamp",
            "risk",
            "level",
            "agent",
            "event",
            "src_ip",
            "user",
            "mitre",
            "recommendation",
        ]
    ],
    use_container_width=True,
    hide_index=True,
)

csv = filtered_df.to_csv(index=False)
st.download_button(
    label="Download CSV Report",
    data=csv,
    file_name="security_report.csv",
    mime="text/csv",
)

st.subheader("AI Alert Analysis")
medium_high_df = filtered_df[filtered_df["risk"].isin(["HIGH", "MEDIUM"])]
unique_events = medium_high_df.drop_duplicates(subset=["event"]).head(5)

if unique_events.empty:
    st.info("Keine HIGH oder MEDIUM Alerts für die KI-Analyse gefunden.")
else:
    selected_event = st.selectbox(
        "Wähle ein Event für die KI-Analyse",
        unique_events["event"].tolist(),
    )
    selected_alert = unique_events[unique_events["event"] == selected_event].iloc[0].to_dict()

    if st.button("KI-Analyse starten"):
        with st.spinner("Lokales LLM analysiert den Alert..."):
            ai_result = generate_ai_summary(selected_alert)
        st.markdown(ai_result)
