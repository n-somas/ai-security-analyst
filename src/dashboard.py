from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

from ai_agent import generate_ai_summary
from alert_analyzer import analyze_alert
from correlation import detect_bruteforce
from wazuh_client import load_alerts


st.set_page_config(
    page_title="AI Security Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root {
        --bg: #070b14;
        --surface: #0d1422;
        --surface-2: #111b2d;
        --surface-3: #16233a;
        --border: rgba(148, 163, 184, 0.16);
        --text: #f8fafc;
        --muted: #8fa0b8;
        --blue: #4f8cff;
        --cyan: #2dd4bf;
        --purple: #8b5cf6;
        --red: #ff5d73;
        --orange: #f7a94a;
        --green: #3ddc97;
    }

    html, body, [class*="css"] {
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .stApp {
        background:
            radial-gradient(circle at 18% -10%, rgba(79, 140, 255, .18), transparent 30%),
            radial-gradient(circle at 88% 4%, rgba(139, 92, 246, .12), transparent 25%),
            var(--bg);
        color: var(--text);
    }

    .block-container {
        max-width: 1480px;
        padding-top: 1.15rem;
        padding-bottom: 2.5rem;
    }

    header[data-testid="stHeader"] {
        background: transparent;
    }

    [data-testid="stToolbar"] {
        visibility: hidden;
        height: 0;
    }

    #MainMenu, footer {
        visibility: hidden;
    }

    [data-testid="stSidebar"] {
        background:
            linear-gradient(180deg, rgba(79, 140, 255, .055), transparent 22%),
            #09111e;
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.4rem;
    }

    .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 22px;
    }

    .brand-mark {
        width: 42px;
        height: 42px;
        border-radius: 13px;
        display: grid;
        place-items: center;
        background: linear-gradient(135deg, var(--blue), var(--purple));
        box-shadow: 0 12px 28px rgba(79, 140, 255, .28);
        font-size: 1.2rem;
    }

    .brand-title {
        color: var(--text);
        font-size: 1rem;
        font-weight: 800;
        line-height: 1.1;
    }

    .brand-sub {
        color: var(--muted);
        font-size: .74rem;
        margin-top: 4px;
    }

    .eyebrow {
        color: #7fa7ff;
        text-transform: uppercase;
        letter-spacing: .16em;
        font-size: .72rem;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .hero {
        position: relative;
        overflow: hidden;
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 28px 30px;
        background:
            linear-gradient(135deg, rgba(79, 140, 255, .13), rgba(139, 92, 246, .08)),
            var(--surface);
        box-shadow: 0 24px 70px rgba(0, 0, 0, .32);
        margin-bottom: 18px;
    }

    .hero::after {
        content: "";
        position: absolute;
        width: 260px;
        height: 260px;
        border-radius: 50%;
        right: -80px;
        top: -110px;
        background: radial-gradient(circle, rgba(79, 140, 255, .24), transparent 68%);
        pointer-events: none;
    }

    .hero h1 {
        margin: 0;
        color: var(--text);
        font-size: clamp(2rem, 3vw, 3.25rem);
        letter-spacing: -.045em;
        line-height: 1;
    }

    .hero p {
        margin: 12px 0 0;
        color: #a7b6ca;
        max-width: 760px;
        font-size: 1rem;
    }

    .status-line {
        display: flex;
        flex-wrap: wrap;
        gap: 9px;
        margin-top: 20px;
    }

    .pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border: 1px solid var(--border);
        border-radius: 999px;
        padding: 7px 11px;
        background: rgba(255, 255, 255, .035);
        color: #d9e4f2;
        font-size: .76rem;
        font-weight: 700;
    }

    .live-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--green);
        box-shadow: 0 0 0 4px rgba(61, 220, 151, .10), 0 0 14px rgba(61, 220, 151, .65);
    }

    div[data-testid="stSegmentedControl"] {
        margin: 0 0 18px;
    }

    div[data-testid="stSegmentedControl"] > div {
        background: rgba(13, 20, 34, .92);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 7px;
        box-shadow: 0 14px 34px rgba(0, 0, 0, .22);
    }

    div[data-testid="stSegmentedControl"] button {
        min-height: 46px;
        border-radius: 11px !important;
        border: 1px solid transparent !important;
        color: #9aaac0 !important;
        font-weight: 750 !important;
        transition: all .16s ease;
    }

    div[data-testid="stSegmentedControl"] button:hover {
        color: white !important;
        background: rgba(79, 140, 255, .10) !important;
        border-color: rgba(79, 140, 255, .28) !important;
    }

    div[data-testid="stSegmentedControl"] button[aria-pressed="true"] {
        color: white !important;
        background: linear-gradient(135deg, #386fe8, #6d4ce8) !important;
        border-color: rgba(255, 255, 255, .12) !important;
        box-shadow: 0 9px 24px rgba(79, 140, 255, .30);
    }

    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
        margin: 0 0 16px;
    }

    .kpi {
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
        background:
            linear-gradient(180deg, rgba(255,255,255,.025), transparent),
            var(--surface);
        box-shadow: 0 14px 36px rgba(0,0,0,.22);
        min-height: 132px;
    }

    .kpi-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
    }

    .kpi-icon {
        width: 34px;
        height: 34px;
        display: grid;
        place-items: center;
        border-radius: 11px;
        background: rgba(79, 140, 255, .10);
        color: #9bbcff;
        font-size: 1rem;
    }

    .kpi-label {
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: .08em;
        font-size: .71rem;
        font-weight: 800;
    }

    .kpi-value {
        color: var(--text);
        font-size: 2.15rem;
        line-height: 1;
        font-weight: 850;
        margin-top: 15px;
        letter-spacing: -.04em;
    }

    .kpi-foot {
        color: var(--muted);
        font-size: .75rem;
        margin-top: 10px;
    }

    .hero-score {
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 22px;
        background:
            linear-gradient(135deg, rgba(139, 92, 246, .12), rgba(79, 140, 255, .06)),
            var(--surface);
        box-shadow: 0 16px 42px rgba(0,0,0,.24);
        min-height: 100%;
    }

    .score-label {
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: .10em;
        font-size: .72rem;
        font-weight: 800;
    }

    .score-value {
        font-size: 3.3rem;
        font-weight: 900;
        letter-spacing: -.06em;
        margin: 12px 0 3px;
    }

    .score-caption {
        color: var(--muted);
        font-size: .8rem;
    }

    .score-track {
        height: 12px;
        border-radius: 999px;
        background: #080d17;
        border: 1px solid var(--border);
        overflow: hidden;
        margin-top: 18px;
    }

    .score-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(90deg, var(--green), var(--orange) 58%, var(--red));
        box-shadow: 0 0 18px rgba(79, 140, 255, .28);
    }

    .panel {
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 19px;
        background: var(--surface);
        box-shadow: 0 16px 42px rgba(0,0,0,.23);
        margin-bottom: 14px;
    }

    .panel-title {
        color: var(--text);
        font-size: 1rem;
        font-weight: 800;
    }

    .panel-sub {
        color: var(--muted);
        font-size: .78rem;
        margin-top: 4px;
        margin-bottom: 14px;
    }

    .risk-badge {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 6px 10px;
        font-size: .76rem;
        font-weight: 850;
        letter-spacing: .04em;
    }

    .high {
        color: #ffd0d7;
        background: rgba(255, 93, 115, .12);
        border: 1px solid rgba(255, 93, 115, .34);
    }

    .medium {
        color: #ffe2b3;
        background: rgba(247, 169, 74, .12);
        border: 1px solid rgba(247, 169, 74, .34);
    }

    .low {
        color: #bcf6dc;
        background: rgba(61, 220, 151, .12);
        border: 1px solid rgba(61, 220, 151, .34);
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 14px 34px rgba(0,0,0,.18);
    }

    .stButton > button,
    .stDownloadButton > button {
        border: 1px solid rgba(255,255,255,.12);
        border-radius: 12px;
        background: linear-gradient(135deg, #386fe8, #6d4ce8);
        color: white;
        font-weight: 800;
        min-height: 46px;
        box-shadow: 0 10px 24px rgba(79, 140, 255, .24);
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        transform: translateY(-1px);
        border-color: rgba(255,255,255,.24);
        box-shadow: 0 14px 30px rgba(79, 140, 255, .34);
    }

    @media (max-width: 1050px) {
        .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }

    @media (max-width: 650px) {
        .kpi-grid { grid-template-columns: 1fr; }
        .hero { padding: 22px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def risk_class(risk: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(risk, "low")


def make_bar_chart(data: pd.DataFrame, category: str, value: str, domain: list[str], colors: list[str]):
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
        .encode(
            x=alt.X(f"{category}:N", sort="-y", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y(f"{value}:Q", title=None),
            color=alt.Color(
                f"{category}:N",
                scale=alt.Scale(domain=domain, range=colors),
                legend=None,
            ),
            tooltip=[category, value],
        )
        .properties(height=285)
        .configure_view(strokeOpacity=0)
        .configure_axis(
            gridColor="#1f2a3a",
            domainColor="#2a3950",
            tickColor="#2a3950",
            labelColor="#9aaac0",
            titleColor="#9aaac0",
        )
    )


def render_kpis(dataframe: pd.DataFrame, incident_count: int) -> None:
    total = len(dataframe)
    high = len(dataframe[dataframe["risk"] == "HIGH"])
    medium = len(dataframe[dataframe["risk"] == "MEDIUM"])
    low = len(dataframe[dataframe["risk"] == "LOW"])

    st.markdown(
        f"""
        <div class="kpi-grid">
            <div class="kpi">
                <div class="kpi-top">
                    <div class="kpi-label">Alerts gesamt</div>
                    <div class="kpi-icon">◎</div>
                </div>
                <div class="kpi-value">{total}</div>
                <div class="kpi-foot">Aktuelle Filterauswahl</div>
            </div>
            <div class="kpi">
                <div class="kpi-top">
                    <div class="kpi-label">High Risk</div>
                    <div class="kpi-icon" style="color:#ff8da0;background:rgba(255,93,115,.10)">!</div>
                </div>
                <div class="kpi-value">{high}</div>
                <div class="kpi-foot">Sofortige Prüfung erforderlich</div>
            </div>
            <div class="kpi">
                <div class="kpi-top">
                    <div class="kpi-label">Medium Risk</div>
                    <div class="kpi-icon" style="color:#ffc978;background:rgba(247,169,74,.10)">◆</div>
                </div>
                <div class="kpi-value">{medium}</div>
                <div class="kpi-foot">Priorisierte Analyse</div>
            </div>
            <div class="kpi">
                <div class="kpi-top">
                    <div class="kpi-label">Incidents</div>
                    <div class="kpi-icon" style="color:#72e7bf;background:rgba(61,220,151,.10)">↗</div>
                </div>
                <div class="kpi-value">{incident_count}</div>
                <div class="kpi-foot">{low} Low-Risk-Alerts im Monitoring</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.sidebar.markdown(
    """
    <div class="brand">
        <div class="brand-mark">🛡️</div>
        <div>
            <div class="brand-title">AI Security Analyst</div>
            <div class="brand-sub">Local SOC Workspace</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

alerts = load_alerts()

if not alerts:
    st.warning("Keine Wazuh-Alerts gefunden. Prüfe data/alerts_export.json.")
    st.stop()

analyzed_alerts = [analyze_alert(alert) for alert in alerts]
incidents = detect_bruteforce(analyzed_alerts)
df = pd.DataFrame(analyzed_alerts)

risk_options = sorted(df["risk"].dropna().unique().tolist())
agent_options = sorted(df["agent"].dropna().unique().tolist())

st.sidebar.markdown("### Filter")
selected_risk = st.sidebar.multiselect("Risikostufe", risk_options, default=risk_options)
selected_agent = st.sidebar.multiselect("Agent", agent_options, default=agent_options)
search_term = st.sidebar.text_input(
    "Suche",
    placeholder="Event, IP, Rule-ID oder Benutzer",
)

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

latest_timestamp = filtered_df["timestamp"].max() if not filtered_df.empty else "Keine Daten"

st.markdown(
    f"""
    <div class="hero">
        <div class="eyebrow">Security Operations Workspace</div>
        <h1>Threats erkennen.<br>Incidents verstehen.</h1>
        <p>
            Lokale Analyse von Wazuh-Alerts mit Event-Korrelation,
            MITRE-ATT&CK-Zuordnung und KI-gestützter Untersuchung.
        </p>
        <div class="status-line">
            <span class="pill"><span class="live-dot"></span>Pipeline aktiv</span>
            <span class="pill">Wazuh verbunden</span>
            <span class="pill">Ollama lokal</span>
            <span class="pill">Letztes Event: {latest_timestamp}</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

nav_labels = {
    "Command Center": ":material/dashboard: Command Center",
    "Alerts": ":material/notifications: Alerts",
    "Incidents": ":material/crisis_alert: Incidents",
    "Investigation": ":material/search_insights: Investigation",
}

page = st.segmented_control(
    "Navigation",
    options=list(nav_labels.keys()),
    format_func=lambda item: nav_labels[item],
    default="Command Center",
    required=True,
    width="stretch",
    label_visibility="collapsed",
)

avg_score = round(filtered_df["threat_score"].mean(), 1) if not filtered_df.empty else 0

if page == "Command Center":
    render_kpis(filtered_df, len(incidents))

    hero_left, hero_right = st.columns([1.45, 1])

    with hero_left:
        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">Threat Landscape</div>
                <div class="panel-sub">Aktuelle Risikoverteilung der gefilterten Alerts</div>
            """,
            unsafe_allow_html=True,
        )
        risk_counts = (
            filtered_df["risk"]
            .value_counts()
            .rename_axis("Risiko")
            .reset_index(name="Anzahl")
        )
        if risk_counts.empty:
            st.info("Keine Daten vorhanden.")
        else:
            risk_chart = make_bar_chart(
                risk_counts,
                "Risiko",
                "Anzahl",
                ["LOW", "MEDIUM", "HIGH"],
                ["#3ddc97", "#f7a94a", "#ff5d73"],
            )
            st.altair_chart(risk_chart, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

    with hero_right:
        st.markdown(
            f"""
            <div class="hero-score">
                <div class="score-label">Average Threat Score</div>
                <div class="score-value">{avg_score}</div>
                <div class="score-caption">Durchschnittliche Risikobewertung auf einer Skala von 0 bis 100</div>
                <div class="score-track">
                    <div class="score-fill" style="width:{min(avg_score, 100)}%"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="panel" style="margin-top:14px">
                <div class="panel-title">Operational Snapshot</div>
                <div class="panel-sub">Aktive Systeme und erkannte Muster</div>
            """,
            unsafe_allow_html=True,
        )
        snap1, snap2 = st.columns(2)
        snap1.metric("Agents", filtered_df["agent"].nunique())
        snap2.metric("MITRE-Techniken", filtered_df[filtered_df["mitre"] != "none"]["mitre"].nunique())
        st.markdown("</div>", unsafe_allow_html=True)

    bottom_left, bottom_right = st.columns(2)

    with bottom_left:
        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">Top Events</div>
                <div class="panel-sub">Häufigste sicherheitsrelevante Ereignisse</div>
            """,
            unsafe_allow_html=True,
        )
        event_counts = (
            filtered_df["event"]
            .value_counts()
            .head(6)
            .rename_axis("Ereignis")
            .reset_index(name="Anzahl")
        )
        if not event_counts.empty:
            event_chart = (
                alt.Chart(event_counts)
                .mark_bar(cornerRadiusEnd=6)
                .encode(
                    y=alt.Y("Ereignis:N", sort="-x", title=None, axis=alt.Axis(labelLimit=180)),
                    x=alt.X("Anzahl:Q", title=None),
                    color=alt.value("#4f8cff"),
                    tooltip=["Ereignis", "Anzahl"],
                )
                .properties(height=285)
                .configure_view(strokeOpacity=0)
                .configure_axis(
                    gridColor="#1f2a3a",
                    domainColor="#2a3950",
                    tickColor="#2a3950",
                    labelColor="#9aaac0",
                )
            )
            st.altair_chart(event_chart, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

    with bottom_right:
        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">Agent Activity</div>
                <div class="panel-sub">Systeme mit dem höchsten Alert-Aufkommen</div>
            """,
            unsafe_allow_html=True,
        )
        agent_counts = (
            filtered_df["agent"]
            .value_counts()
            .head(6)
            .rename_axis("Agent")
            .reset_index(name="Anzahl")
        )
        if not agent_counts.empty:
            agent_chart = (
                alt.Chart(agent_counts)
                .mark_bar(cornerRadiusEnd=6)
                .encode(
                    y=alt.Y("Agent:N", sort="-x", title=None),
                    x=alt.X("Anzahl:Q", title=None),
                    color=alt.value("#8b5cf6"),
                    tooltip=["Agent", "Anzahl"],
                )
                .properties(height=285)
                .configure_view(strokeOpacity=0)
                .configure_axis(
                    gridColor="#1f2a3a",
                    domainColor="#2a3950",
                    tickColor="#2a3950",
                    labelColor="#9aaac0",
                )
            )
            st.altair_chart(agent_chart, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

elif page == "Alerts":
    render_kpis(filtered_df, len(incidents))

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Security Alerts</div>
            <div class="panel-sub">Gefilterte Ereignisse mit Threat Score und MITRE-Zuordnung</div>
        """,
        unsafe_allow_html=True,
    )

    table = filtered_df[
        ["timestamp", "risk", "threat_score", "level", "agent", "event", "src_ip", "mitre"]
    ].rename(
        columns={
            "timestamp": "Zeitstempel",
            "risk": "Risiko",
            "threat_score": "Threat Score",
            "level": "Level",
            "agent": "Agent",
            "event": "Ereignis",
            "src_ip": "Quell-IP",
            "mitre": "MITRE ATT&CK",
        }
    )

    st.dataframe(
        table,
        width="stretch",
        hide_index=True,
        column_config={
            "Threat Score": st.column_config.ProgressColumn(
                "Threat Score",
                min_value=0,
                max_value=100,
                format="%d",
            )
        },
    )
    st.markdown("</div>", unsafe_allow_html=True)

    csv = filtered_df.to_csv(index=False)
    st.download_button(
        "CSV-Bericht herunterladen",
        csv,
        "security_report.csv",
        "text/csv",
        width="stretch",
    )

elif page == "Incidents":
    render_kpis(filtered_df, len(incidents))

    if not incidents:
        st.success(
            "Keine korrelierten Incidents erkannt. "
            "Schwellenwert: mindestens 5 fehlgeschlagene Anmeldungen "
            "derselben Quell-IP innerhalb von 10 Minuten."
        )
    else:
        incident_df = pd.DataFrame(incidents)
        incident_labels = incident_df.apply(
            lambda row: f"{row['incident_type']} · {row['src_ip']} · {row['alert_count']} Alerts",
            axis=1,
        ).tolist()

        selected_label = st.selectbox("Incident auswählen", incident_labels)
        selected = incident_df.iloc[incident_labels.index(selected_label)]

        left, right = st.columns([1.25, 1])

        with left:
            st.markdown(
                f"""
                <div class="panel">
                    <div class="eyebrow">Correlated Incident</div>
                    <span class="risk-badge {risk_class(selected['risk'])}">{selected['risk']}</span>
                    <h2 style="margin:16px 0 10px">{selected['incident_type']}</h2>
                    <p style="color:#9aaac0;margin:0">
                        {selected['alert_count']} zusammengehörige Alerts wurden
                        innerhalb eines definierten Zeitfensters erkannt.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with right:
            st.markdown(
                f"""
                <div class="panel">
                    <div class="panel-title">Incident Context</div>
                    <div class="panel-sub">Technische Eckdaten</div>
                    <p><b>Quell-IP:</b> {selected['src_ip']}</p>
                    <p><b>Agent:</b> {selected['agent']}</p>
                    <p><b>Erstes Event:</b> {selected['first_seen']}</p>
                    <p><b>Letztes Event:</b> {selected['last_seen']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.warning(selected["recommendation"])

elif page == "Investigation":
    if filtered_df.empty:
        st.info("Keine Alerts für die aktuelle Filterauswahl.")
    else:
        detail_df = filtered_df.reset_index(drop=True).copy()
        detail_df["selection_label"] = detail_df.apply(
            lambda row: f"{row['risk']} · {row['event']} · {row['src_ip']} · {row['timestamp']}",
            axis=1,
        )

        selected_label = st.selectbox(
            "Alert auswählen",
            detail_df["selection_label"].tolist(),
        )
        selected = detail_df[detail_df["selection_label"] == selected_label].iloc[0]

        left, right = st.columns([1.35, 1])

        with left:
            st.markdown(
                f"""
                <div class="panel">
                    <div class="eyebrow">Alert Investigation</div>
                    <span class="risk-badge {risk_class(selected['risk'])}">{selected['risk']}</span>
                    <h2 style="margin:16px 0 14px">{selected['event']}</h2>
                    <p><b>Rule-ID:</b> {selected['rule_id']}</p>
                    <p><b>Wazuh-Level:</b> {selected['level']}</p>
                    <p><b>Agent:</b> {selected['agent']}</p>
                    <p><b>Benutzer:</b> {selected['user']}</p>
                    <p><b>Quell-IP:</b> {selected['src_ip']}</p>
                    <p><b>MITRE ATT&CK:</b> {selected['mitre']}</p>
                    <p><b>Zeitstempel:</b> {selected['timestamp']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with right:
            score = int(selected["threat_score"])
            st.markdown(
                f"""
                <div class="hero-score">
                    <div class="score-label">Threat Score</div>
                    <div class="score-value">{score}</div>
                    <div class="score-caption">Bewertung des ausgewählten Alerts</div>
                    <div class="score-track">
                        <div class="score-fill" style="width:{score}%"></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.expander("Score-Begründung"):
                for reason in selected.get("score_reasons", []):
                    st.write(f"• {reason}")

            st.info(selected["recommendation"])

        if selected["risk"] in ("HIGH", "MEDIUM"):
            if st.button(
                "Alert mit lokaler KI analysieren",
                type="primary",
                width="stretch",
            ):
                with st.spinner("Lokales LLM analysiert den Alert..."):
                    result = generate_ai_summary(selected.to_dict())
                st.markdown("### KI-Analyse")
                st.markdown(result)
        else:
            st.caption("KI-Analyse ist für MEDIUM- und HIGH-Alerts vorgesehen.")
