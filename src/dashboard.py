from ai_agent import generate_ai_summary
import pandas as pd
import streamlit as st

from alert_analyzer import analyze_alert
from correlation import detect_bruteforce
from wazuh_client import load_alerts


st.set_page_config(
    page_title="AI Security Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("AI Security Analyst")
st.caption("Lokale SOC-Analyse für Wazuh-Alerts, Event-Korrelation und KI-gestützte Bewertung")

alerts = load_alerts()

if not alerts:
    st.warning("Keine Wazuh-Alerts gefunden. Prüfe die Datei data/alerts_export.json.")
    st.stop()

analyzed_alerts = [analyze_alert(alert) for alert in alerts]
incidents = detect_bruteforce(analyzed_alerts)
df = pd.DataFrame(analyzed_alerts)

# ---------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------

st.sidebar.title("Filter")

risk_options = sorted(df["risk"].dropna().unique().tolist())
agent_options = sorted(df["agent"].dropna().unique().tolist())

if "selected_risk" not in st.session_state:
    st.session_state.selected_risk = risk_options

if "selected_agent" not in st.session_state:
    st.session_state.selected_agent = agent_options

if "search_term" not in st.session_state:
    st.session_state.search_term = ""

selected_risk = st.sidebar.multiselect(
    "Risikostufe",
    options=risk_options,
    key="selected_risk",
)

selected_agent = st.sidebar.multiselect(
    "Agent",
    options=agent_options,
    key="selected_agent",
)

search_term = st.sidebar.text_input(
    "Event oder Quell-IP suchen",
    key="search_term",
)

if st.sidebar.button("Filter zurücksetzen", use_container_width=True):
    st.session_state.selected_risk = risk_options
    st.session_state.selected_agent = agent_options
    st.session_state.search_term = ""
    st.rerun()

filtered_df = df[
    df["risk"].isin(selected_risk)
    & df["agent"].isin(selected_agent)
].copy()

if search_term:
    needle = search_term.lower()
    filtered_df = filtered_df[
        filtered_df["event"].astype(str).str.lower().str.contains(needle, na=False)
        | filtered_df["src_ip"].astype(str).str.lower().str.contains(needle, na=False)
        | filtered_df["rule_id"].astype(str).str.lower().str.contains(needle, na=False)
        | filtered_df["user"].astype(str).str.lower().str.contains(needle, na=False)
    ]

risk_label_map = {
    "HIGH": "🔴 HIGH",
    "MEDIUM": "🟠 MEDIUM",
    "LOW": "🟢 LOW",
}

filtered_df["risk_display"] = filtered_df["risk"].map(risk_label_map).fillna(
    filtered_df["risk"]
)

# ---------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------

tab_overview, tab_alerts, tab_incidents, tab_analysis = st.tabs(
    ["Übersicht", "Alerts", "Incidents", "Analyse"]
)

# ---------------------------------------------------------------------
# Übersicht
# ---------------------------------------------------------------------

with tab_overview:
    st.subheader("Übersicht")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Alerts gesamt", len(filtered_df))
    col2.metric("Hohe Risiken", len(filtered_df[filtered_df["risk"] == "HIGH"]))
    col3.metric(
        "Mittlere Risiken",
        len(filtered_df[filtered_df["risk"] == "MEDIUM"]),
    )
    col4.metric("Niedrige Risiken", len(filtered_df[filtered_df["risk"] == "LOW"]))
    col5.metric("Korrelierte Incidents", len(incidents))

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("#### Risikoverteilung")
        risk_counts = filtered_df["risk"].value_counts()
        if risk_counts.empty:
            st.info("Für die aktuelle Filterauswahl sind keine Daten vorhanden.")
        else:
            st.bar_chart(risk_counts)

    with chart_col2:
        st.markdown("#### Häufigste Ereignisse")
        top_events = filtered_df["event"].value_counts().head(8)
        if top_events.empty:
            st.info("Keine Ereignisse verfügbar.")
        else:
            st.bar_chart(top_events)

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        st.markdown("#### Aktivste Agents")
        top_agents = filtered_df["agent"].value_counts().head(8)
        if top_agents.empty:
            st.info("Keine Agents verfügbar.")
        else:
            st.bar_chart(top_agents)

    with chart_col4:
        st.markdown("#### MITRE ATT&CK")
        mitre_counts = (
            filtered_df[filtered_df["mitre"] != "none"]["mitre"]
            .value_counts()
            .head(8)
        )
        if mitre_counts.empty:
            st.info("Keine MITRE-ATT&CK-Zuordnungen verfügbar.")
        else:
            st.bar_chart(mitre_counts)

# ---------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------

with tab_alerts:
    st.subheader("Security Alerts")
    st.caption(
        "Kompakte Übersicht aller gefilterten Alerts. "
        "Vollständige Details stehen im Tab Analyse."
    )

    if filtered_df.empty:
        st.info("Für die aktuelle Filterauswahl wurden keine Alerts gefunden.")
    else:
        alert_table = filtered_df[
            [
                "timestamp",
                "risk_display",
                "level",
                "agent",
                "event",
                "src_ip",
                "mitre",
            ]
        ].rename(
            columns={
                "timestamp": "Zeitstempel",
                "risk_display": "Risiko",
                "level": "Level",
                "agent": "Agent",
                "event": "Ereignis",
                "src_ip": "Quell-IP",
                "mitre": "MITRE ATT&CK",
            }
        )

        st.dataframe(
            alert_table,
            use_container_width=True,
            hide_index=True,
        )

        csv = filtered_df.drop(columns=["risk_display"]).to_csv(index=False)
        st.download_button(
            label="CSV-Bericht herunterladen",
            data=csv,
            file_name="security_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

# ---------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------

with tab_incidents:
    st.subheader("Korrelierte Incidents")

    if not incidents:
        st.success(
            "Keine korrelierten Incidents erkannt. "
            "Schwellenwert: mindestens 5 fehlgeschlagene Anmeldungen "
            "derselben Quell-IP innerhalb von 10 Minuten."
        )
    else:
        incident_df = pd.DataFrame(incidents)
        incident_df["risk_display"] = (
            incident_df["risk"].map(risk_label_map).fillna(incident_df["risk"])
        )

        incident_table = incident_df[
            [
                "risk_display",
                "incident_type",
                "src_ip",
                "agent",
                "alert_count",
                "first_seen",
                "last_seen",
            ]
        ].rename(
            columns={
                "risk_display": "Risiko",
                "incident_type": "Incident-Typ",
                "src_ip": "Quell-IP",
                "agent": "Agent",
                "alert_count": "Alerts",
                "first_seen": "Erstes Ereignis",
                "last_seen": "Letztes Ereignis",
            }
        )

        st.dataframe(
            incident_table,
            use_container_width=True,
            hide_index=True,
        )

        incident_labels = incident_df.apply(
            lambda row: (
                f"{row['incident_type']} | {row['src_ip']} | "
                f"{row['alert_count']} Alerts"
            ),
            axis=1,
        ).tolist()

        selected_incident_label = st.selectbox(
            "Incident auswählen",
            incident_labels,
        )

        selected_incident = incident_df.iloc[
            incident_labels.index(selected_incident_label)
        ]

        detail_col1, detail_col2, detail_col3 = st.columns(3)

        with detail_col1:
            st.markdown("**Risikostufe**")
            st.write(risk_label_map.get(selected_incident["risk"], selected_incident["risk"]))
            st.markdown("**Incident-Typ**")
            st.write(selected_incident["incident_type"])

        with detail_col2:
            st.markdown("**Quell-IP**")
            st.write(selected_incident["src_ip"])
            st.markdown("**Agent**")
            st.write(selected_incident["agent"])

        with detail_col3:
            st.markdown("**Anzahl Alerts**")
            st.write(selected_incident["alert_count"])
            st.markdown("**Zeitfenster**")
            st.write(
                f"{selected_incident['first_seen']} bis "
                f"{selected_incident['last_seen']}"
            )

        st.markdown("**Handlungsempfehlung**")
        st.warning(selected_incident["recommendation"])

# ---------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------

with tab_analysis:
    st.subheader("Alert-Analyse")

    if filtered_df.empty:
        st.info("Für die aktuelle Filterauswahl sind keine Alerts verfügbar.")
    else:
        detail_df = filtered_df.reset_index(drop=True).copy()
        detail_df["selection_label"] = detail_df.apply(
            lambda row: (
                f"{risk_label_map.get(row['risk'], row['risk'])} | "
                f"{row['event']} | {row['src_ip']} | {row['timestamp']}"
            ),
            axis=1,
        )

        selected_label = st.selectbox(
            "Alert auswählen",
            detail_df["selection_label"].tolist(),
        )

        selected_alert = detail_df[
            detail_df["selection_label"] == selected_label
        ].iloc[0]

        detail_col1, detail_col2, detail_col3 = st.columns(3)

        with detail_col1:
            st.markdown("**Risikostufe**")
            st.write(risk_label_map.get(selected_alert["risk"], selected_alert["risk"]))
            st.markdown("**Wazuh-Level**")
            st.write(selected_alert["level"])
            st.markdown("**Rule-ID**")
            st.write(selected_alert["rule_id"])

        with detail_col2:
            st.markdown("**Zeitstempel**")
            st.write(selected_alert["timestamp"])
            st.markdown("**Agent**")
            st.write(selected_alert["agent"])
            st.markdown("**Benutzer**")
            st.write(selected_alert["user"])

        with detail_col3:
            st.markdown("**Quell-IP**")
            st.write(selected_alert["src_ip"])
            st.markdown("**MITRE ATT&CK**")
            st.write(selected_alert["mitre"])
            st.markdown("**Ereignis**")
            st.write(selected_alert["event"])

        st.markdown("**Handlungsempfehlung**")
        st.info(selected_alert["recommendation"])

        if selected_alert["risk"] in ("HIGH", "MEDIUM"):
            if st.button(
                "Ausgewählten Alert mit KI analysieren",
                type="primary",
                use_container_width=True,
            ):
                with st.spinner("Lokales LLM analysiert den Alert..."):
                    ai_result = generate_ai_summary(selected_alert.to_dict())
                st.markdown("#### KI-Analyse")
                st.markdown(ai_result)
        else:
            st.caption(
                "Die KI-Analyse ist für MEDIUM- und HIGH-Alerts vorgesehen."
            )
