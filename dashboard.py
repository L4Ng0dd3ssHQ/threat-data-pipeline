from __future__ import annotations

from pathlib import Path
import traceback

import altair as alt
import pandas as pd
import streamlit as st

from src.threat_data_pipeline.config import load_settings
from src.threat_data_pipeline.pipeline import run_pipeline


st.set_page_config(
    page_title="Threat Intelligence Workstation",
    layout="wide",
    initial_sidebar_state="collapsed",
)


SOURCES = {
    "URLHaus": {
        "include_urlhaus": True,
        "accent": "#ff7a2f",
        "eyebrow": "Malware URL telemetry",
        "description": "Recent malicious URL activity with fast-moving infrastructure signals.",
    },
    "CISA KEV": {
        "include_kev": True,
        "accent": "#f2c14e",
        "eyebrow": "Exploited vulnerabilities",
        "description": "Known exploited CVEs curated for operational vulnerability monitoring.",
    },
    "ThreatFox": {
        "include_threatfox": True,
        "accent": "#10b981",
        "eyebrow": "IOC intelligence",
        "description": "High-volume indicators of compromise for delivery paths and active campaigns.",
    },
    "AlienVault OTX": {
        "include_alienvault": True,
        "accent": "#4f8cff",
        "eyebrow": "Threat pulse feed",
        "description": "Community pulse intelligence and campaign narratives from OTX subscriptions.",
    },
    "Feodo Tracker": {
        "include_feodo_tracker": True,
        "accent": "#ff4b57",
        "eyebrow": "Botnet C2 tracking",
        "description": "Command-and-control infrastructure linked to active malware operations.",
    },
}


CSS = """
<style>
@import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap");

:root {
    --room-a: #2a1d21;
    --room-b: #162738;
    --room-c: #0f1724;
    --shell: #d2c1b5;
    --shell-shadow: #a99687;
    --screen: #08121d;
    --screen-2: #102132;
    --panel: rgba(8, 18, 29, 0.86);
    --line: rgba(157, 188, 212, 0.18);
    --text: #ebf4ff;
    --muted: #a8bfd2;
    --mono: #7fd0ff;
}

.stApp {
    background:
        radial-gradient(circle at 18% 20%, rgba(255, 122, 47, 0.22), transparent 25%),
        radial-gradient(circle at 78% 12%, rgba(79, 140, 255, 0.22), transparent 24%),
        linear-gradient(135deg, var(--room-a) 0%, var(--room-b) 52%, var(--room-c) 100%);
}

html, body, [class*="css"] {
    font-family: "Space Grotesk", sans-serif;
}

section[data-testid="stSidebar"] {
    display: none;
}

.block-container {
    max-width: 1120px;
    margin-top: 2.6rem;
    margin-bottom: 0;
    padding: 1.8rem 1.8rem 2rem 1.8rem;
    background:
        linear-gradient(180deg, rgba(12, 22, 34, 0.96), rgba(7, 15, 24, 0.95)),
        linear-gradient(135deg, var(--screen), var(--screen-2));
    border-radius: 16px;
    border: 16px solid var(--shell);
    box-shadow:
        0 0 0 8px var(--shell-shadow),
        0 26px 80px rgba(0, 0, 0, 0.46),
        inset 0 0 0 1px rgba(255, 255, 255, 0.04);
    position: relative;
}

.block-container::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 4px;
    background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.05), transparent 22%),
        repeating-linear-gradient(
            180deg,
            rgba(255, 255, 255, 0.014) 0px,
            rgba(255, 255, 255, 0.014) 1px,
            transparent 2px,
            transparent 4px
        );
    pointer-events: none;
}

h1, h2, h3, h4 {
    color: var(--text);
    letter-spacing: -0.03em;
}

p, label, .stMarkdown, .stCaption {
    color: var(--muted);
}

.workstation-head {
    border: 1px solid var(--line);
    background: linear-gradient(135deg, rgba(7, 14, 24, 0.94), rgba(18, 35, 55, 0.78));
    border-radius: 20px;
    padding: 1.35rem 1.45rem 1.2rem 1.45rem;
}

.badge {
    display: inline-block;
    padding: 0.34rem 0.72rem;
    border-radius: 999px;
    background: linear-gradient(90deg, #ffe0aa, #f2c14e);
    color: #20140d;
    font-size: 0.74rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.09em;
}

.hero-title {
    margin: 0.95rem 0 0.75rem 0;
    font-size: clamp(2.2rem, 5vw, 3.8rem);
    line-height: 0.96;
    max-width: 9ch;
}

.hero-copy {
    max-width: 54rem;
    line-height: 1.7;
    font-size: 1rem;
}

.info-grid {
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: 1rem;
    margin-top: 1.1rem;
}

.panel, .source-card, .spotlight-card, .system-card, .active-card {
    border: 1px solid var(--line);
    border-radius: 20px;
    background: var(--panel);
    backdrop-filter: blur(8px);
}

.panel, .spotlight-card, .system-card, .active-card {
    padding: 1.1rem 1.15rem;
}

.source-card {
    min-height: 158px;
    padding: 1rem;
}

.source-accent {
    height: 6px;
    border-radius: 999px;
    margin-bottom: 0.9rem;
}

.mono {
    font-family: "IBM Plex Mono", monospace;
    color: var(--mono);
    font-size: 0.84rem;
}

.control-label {
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
}

div[role="radiogroup"] {
    gap: 0.7rem;
    justify-content: center;
}

div[role="radiogroup"] label {
    background: rgba(11, 20, 31, 0.82);
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 0.36rem 0.9rem;
}

div.stButton > button {
    background: linear-gradient(90deg, #ff6c2f, #ff944d);
    color: white;
    border: none;
    border-radius: 18px;
    min-height: 92px;
    width: 100%;
    padding: 1.1rem 1.3rem;
    font-size: 1.08rem;
    font-weight: 700;
    box-shadow: 0 16px 34px rgba(255, 108, 47, 0.24);
}

div.stButton > button:hover {
    filter: brightness(1.06);
}

div[data-testid="stMetric"] {
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 0.8rem 0.95rem;
    background: rgba(11, 19, 28, 0.62);
}

div[data-testid="stMetricValue"] {
    color: var(--text);
}

.metric-ribbon {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.metric-ribbon-card {
    border: 1px solid var(--line);
    border-radius: 20px;
    background: rgba(9, 17, 26, 0.7);
    padding: 1rem 1.1rem;
}

.metric-ribbon-title {
    color: var(--muted);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.metric-ribbon-value {
    color: var(--text);
    font-size: 1.7rem;
    font-weight: 700;
    margin-top: 0.3rem;
}

.error-panel {
    border: 1px solid rgba(255, 99, 99, 0.22);
    background: rgba(80, 26, 34, 0.68);
    color: #ffd8d8;
    border-radius: 20px;
    padding: 1rem 1.1rem;
}

.drive-base {
    max-width: 760px;
    margin: -4px auto 2.5rem auto;
    background: linear-gradient(180deg, #d3c2b7, #b9a79b);
    border: 1px solid rgba(77, 56, 46, 0.35);
    border-radius: 0 0 22px 22px;
    padding: 1.2rem 1.4rem 1rem 1.4rem;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.25);
}

.drive-row {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
}

.drive-slot {
    height: 78px;
    border-radius: 10px;
    background: linear-gradient(180deg, #8a96a5, #657181);
    border: 6px solid #aeb7c2;
    position: relative;
}

.drive-slot::before {
    content: "";
    position: absolute;
    top: 28px;
    left: 18px;
    width: 78%;
    height: 11px;
    border-radius: 3px;
    background: #2d343d;
}

.drive-slot::after {
    content: "";
    position: absolute;
    right: 14px;
    top: 20px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #435063;
}

.base-brand {
    margin-top: 0.9rem;
    text-align: center;
    font-family: "IBM Plex Mono", monospace;
    color: #334155;
    letter-spacing: 0.14em;
    font-size: 0.78rem;
}

[data-testid="stDataFrame"] {
    border-radius: 18px;
    overflow: hidden;
}


.stack-shell {
    max-width: 760px;
    margin: 0 auto;
}

.selector-strip {
    border: 1px solid var(--line);
    border-radius: 8px;
    background: rgba(8, 18, 29, 0.96);
    padding: 0.55rem 0.7rem;
    margin-top: 0.7rem;
}

.run-shell {
    border: 1px solid var(--line);
    border-radius: 8px;
    background: rgba(8, 18, 29, 0.96);
    padding: 0.7rem;
    margin-top: 0.9rem;
}

.active-card {
    margin-top: 0.9rem;
}

.standby-shell {
    margin-top: 1rem;
}

@media (max-width: 900px) {
    .block-container {
        border-width: 12px;
        padding: 1.2rem 1rem 1.5rem 1rem;
        margin-top: 1rem;
    }

    .info-grid, .metric-ribbon, .drive-row {
        grid-template-columns: 1fr;
    }
}
</style>
"""


alt.themes.enable("opaque")


def pick_column(columns: list[str], candidates: list[str]) -> str | None:
    lowered = {str(column).lower(): column for column in columns}
    for candidate in candidates:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    for column in columns:
        text = str(column).lower()
        for candidate in candidates:
            if candidate.lower() in text:
                return column
    return None


def get_date_column(df: pd.DataFrame) -> str | None:
    return pick_column(
        list(df.columns),
        ["dateAdded", "date_added", "reported", "dateReported", "date", "first_seen", "firstseen", "modified"],
    )


def get_threat_column(df: pd.DataFrame) -> str | None:
    return pick_column(list(df.columns), ["threat", "threat_type", "tags", "tag", "pulse_name", "malware"])


def get_indicator_column(df: pd.DataFrame) -> str | None:
    return pick_column(
        list(df.columns),
        ["ioc", "ioc_value", "ioc_url", "url", "indicator", "indicator_value", "host", "pulse_name", "name"],
    )


def normalize_datetime(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True)


def filter_dataframe(
    df: pd.DataFrame,
    keyword: str,
    threat_value: str,
    date_column: str | None,
    start_date,
    end_date,
) -> pd.DataFrame:
    filtered = df.copy()

    if keyword:
        mask = filtered.astype(str).apply(lambda column: column.str.contains(keyword, case=False, na=False))
        filtered = filtered[mask.any(axis=1)]

    threat_column = get_threat_column(filtered)
    if threat_column and threat_value != "All":
        filtered = filtered[filtered[threat_column].fillna("").astype(str) == threat_value]

    if date_column and start_date and end_date and date_column in filtered.columns:
        parsed = normalize_datetime(filtered[date_column])
        start_ts = pd.Timestamp(start_date).tz_localize("UTC")
        end_ts = pd.Timestamp(end_date).tz_localize("UTC") + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
        filtered = filtered[(parsed >= start_ts) & (parsed <= end_ts)]

    return filtered.reset_index(drop=True)


def build_spotlight(df: pd.DataFrame) -> tuple[str, str, str]:
    if df.empty:
        return (
            "No active spotlight",
            "The current filter set returned no records.",
            "Adjust the feed or filters to surface live intelligence.",
        )

    threat_column = get_threat_column(df)
    indicator_column = get_indicator_column(df)
    date_column = get_date_column(df)

    top_threat = "Mixed"
    if threat_column:
        counts = df[threat_column].fillna("Unknown").astype(str).value_counts()
        if not counts.empty:
            top_threat = counts.index[0]

    top_indicator = None
    if indicator_column:
        values = df[indicator_column].dropna().astype(str)
        if not values.empty:
            top_indicator = values.iloc[0]

    timing_note = "No date activity available."
    if date_column:
        parsed = normalize_datetime(df[date_column]).dropna()
        if not parsed.empty:
            latest = parsed.max().strftime("%Y-%m-%d")
            timing_note = f"Latest activity in the current view landed on {latest}."

    headline = f"Spotlight: {top_threat}"
    body = f"{len(df):,} records remain in focus after the current filters. {timing_note}"
    detail = top_indicator if top_indicator else "No single indicator field stood out in this feed."
    return headline, body, detail


def build_distribution_chart(df: pd.DataFrame, accent: str):
    threat_column = get_threat_column(df)
    if not threat_column or df.empty:
        return None
    chart_df = (
        df[threat_column]
        .fillna("Unknown")
        .astype(str)
        .value_counts()
        .head(10)
        .rename_axis("category")
        .reset_index(name="count")
    )
    return (
        alt.Chart(chart_df)
        .mark_bar(cornerRadiusTopRight=6, cornerRadiusBottomRight=6, color=accent)
        .encode(
            x=alt.X("count:Q", title="Records"),
            y=alt.Y("category:N", sort="-x", title=None),
            tooltip=["category", "count"],
        )
        .properties(height=360, title="Threat Distribution")
        .configure_view(strokeOpacity=0)
        .configure_axis(gridColor="rgba(255,255,255,0.08)", labelColor="#d7e7f5", titleColor="#d7e7f5")
        .configure_title(color="#eef6ff", font="Space Grotesk", fontSize=18, anchor="start")
    )


def build_timeline_chart(df: pd.DataFrame, date_column: str | None, rolling_window: int, accent: str):
    if not date_column or df.empty or date_column not in df.columns:
        return None, None
    parsed = normalize_datetime(df[date_column]).dropna()
    if parsed.empty:
        return None, None

    trend = (
        parsed.dt.floor("D")
        .value_counts()
        .sort_index()
        .rename_axis("date")
        .reset_index(name="count")
    )
    trend["rolling_mean"] = trend["count"].rolling(window=rolling_window, min_periods=1).mean()
    trend["rolling_std"] = trend["count"].rolling(window=rolling_window, min_periods=2).std().fillna(0)
    trend["threshold"] = trend["rolling_mean"] + 2 * trend["rolling_std"]
    trend["is_anomaly"] = trend["count"] > trend["threshold"]

    base = alt.Chart(trend).encode(x=alt.X("date:T", title="Date"))
    line = base.mark_line(color=accent, strokeWidth=3).encode(
        y=alt.Y("count:Q", title="Records"), tooltip=["date:T", "count:Q"]
    )
    rolling = base.mark_line(color="#f2c14e", strokeDash=[6, 4], strokeWidth=2).encode(
        y=alt.Y("rolling_mean:Q", title="Records")
    )
    anomalies = base.transform_filter(alt.datum.is_anomaly == True).mark_point(
        color="#ff5b6e", size=85, filled=True
    ).encode(y="count:Q", tooltip=["date:T", "count:Q"])
    chart = (line + rolling + anomalies).properties(height=360, title="Activity Pulse")
    chart = chart.configure_view(strokeOpacity=0).configure_axis(
        gridColor="rgba(255,255,255,0.08)", labelColor="#d7e7f5", titleColor="#d7e7f5"
    ).configure_title(color="#eef6ff", font="Space Grotesk", fontSize=18, anchor="start")
    return chart, trend


def render_source_cards(selected_label: str) -> None:
    cards = st.columns(len(SOURCES))
    for column, (label, meta) in zip(cards, SOURCES.items()):
        with column:
            active_style = "box-shadow: 0 0 0 1px rgba(255,255,255,0.10), 0 18px 42px rgba(0,0,0,0.22);" if label == selected_label else ""
            st.markdown(
                f"""
                <div class=\"source-card\" style=\"{active_style}\">
                    <div class=\"source-accent\" style=\"background:{meta['accent']};\"></div>
                    <div class=\"mono\">{meta['eyebrow']}</div>
                    <h4>{label}</h4>
                    <p>{meta['description']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_exports(artifact) -> None:
    export_rows = [{"output": name, "path": str(path)} for name, path in artifact.generated_files.items()]
    st.dataframe(pd.DataFrame(export_rows), use_container_width=True, hide_index=True)


st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
    <div class="workstation-head">
        <span class="badge">Retro analyst workstation</span>
        <div class="hero-title" style="width:100%; max-width:none; white-space:normal; word-break:keep-all; overflow-wrap:normal; text-align:center; font-size:clamp(2.4rem, 4.6vw, 4.8rem); line-height:1.02;">Threat Intelligence<br>Workstation.</div>
        <div class="hero-copy" style="margin-inline:auto;">
            A live intelligence console with a vintage desktop feel and a modern analyst workflow. Pull any feed, spotlight the strongest signal, and pivot through interactive charts without losing the visual drama.
        </div>
        <div class="info-grid">
            <div class="panel">
                <div class="mono">System profile</div>
                <h4>Built to demo like a product, not a homework script.</h4>
                <p>Use the feed pills to load live intelligence, then drill into the spotlight panel, preview rows, trend controls, and export-backed visuals from one place.</p>
            </div>
            <div class="panel">
                <div class="mono">Demo rhythm</div>
                <h4>Best first-click feeds</h4>
                <p>ThreatFox and AlienVault usually create the richest opening moment. KEV and Feodo are great second acts to show different intelligence shapes.</p>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")
selector_shell = st.columns([1, 6, 1])
with selector_shell[1]:
    selected_label = st.radio(
        "Choose a feed",
        options=list(SOURCES.keys()),
        horizontal=True,
        label_visibility="collapsed",
    )
render_source_cards(selected_label)
selected_source = SOURCES[selected_label]
accent = selected_source["accent"]

control_left, control_right = st.columns([2.0, 1.15])
with control_left:
    st.markdown(
        f"""
        <div class=\"active-card\" style=\"border: 2px solid {accent}; box-shadow: 0 0 0 1px rgba(255,255,255,0.04), 0 18px 38px rgba(0,0,0,0.18);\">
            <div class=\"mono\">Active feed</div>
            <h3 style=\"margin-top:0.35rem;\">{selected_label}</h3>
            <p>{selected_source['description']}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with control_right:
    st.markdown('<div class="control-label">Launch live run</div>', unsafe_allow_html=True)
    fetch_clicked = st.button("RUN LIVE SCAN", use_container_width=True)

if fetch_clicked:
    try:
        with st.spinner(f"Pulling live data from {selected_label}..."):
            settings = load_settings()
            run_flags = {key: value for key, value in selected_source.items() if key.startswith("include_")}
            artifact = run_pipeline(settings=settings, output_dir=Path("output"), **run_flags)
            st.session_state["dashboard_artifact"] = artifact
            st.session_state["dashboard_source"] = selected_label
            st.session_state["dashboard_error"] = None
    except Exception:
        st.session_state["dashboard_error"] = traceback.format_exc()

artifact = st.session_state.get("dashboard_artifact")
active_source = st.session_state.get("dashboard_source", selected_label)
error_trace = st.session_state.get("dashboard_error")

if error_trace:
    st.markdown(
        '<div class="error-panel"><strong>System fault</strong><br>The live run hit an exception. The trace is below so we can debug it fast.</div>',
        unsafe_allow_html=True,
    )
    st.code(error_trace)

if artifact is None:
    st.markdown(
        """
        <div class="stack-shell standby-shell">
            <div class="spotlight-card" style="text-align:center;">
                <div class="mono">Standby mode</div>
                <h3 style="margin-top:0.5rem;">No live intel loaded</h3>
                <p>Choose a feed and run the scan to wake up the workstation.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    accent = SOURCES.get(active_source, selected_source)["accent"]
    dataset = artifact.cleaned.copy()
    date_column = get_date_column(dataset)
    threat_column = get_threat_column(dataset)

    default_min = None
    default_max = None
    if date_column:
        parsed_dates = normalize_datetime(dataset[date_column]).dropna()
        if not parsed_dates.empty:
            default_min = parsed_dates.min().date()
            default_max = parsed_dates.max().date()

    filter_cols = st.columns([1.1, 1, 1, 0.9])
    with filter_cols[0]:
        keyword = st.text_input("Keyword Search", placeholder="Search URL, IOC, tag, vendor...")
    with filter_cols[1]:
        threat_options = ["All"]
        if threat_column:
            threat_options.extend(sorted(dataset[threat_column].dropna().astype(str).unique().tolist())[:50])
        threat_choice = st.selectbox("Threat Focus", threat_options)
    with filter_cols[2]:
        preview_rows = st.slider("Preview Rows", min_value=10, max_value=100, value=40, step=10)
    with filter_cols[3]:
        rolling_window = st.slider("Trend Window", min_value=3, max_value=14, value=7, step=1)

    if default_min and default_max:
        date_range = st.date_input("Date Range", value=(default_min, default_max))
        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date, end_date = date_range
        else:
            start_date, end_date = default_min, default_max
    else:
        start_date = end_date = None

    filtered = filter_dataframe(dataset, keyword, threat_choice, date_column, start_date, end_date)
    spotlight_title, spotlight_body, spotlight_detail = build_spotlight(filtered)

    metrics = st.columns(3)
    metrics[0].metric("Records Pulled", f"{artifact.quality_report.total_rows:,}")
    metrics[1].metric("Filtered View", f"{len(filtered):,}")
    metrics[2].metric("Exports", f"{len(artifact.generated_files):,}")

    st.markdown(
        f"""
        <div class=\"metric-ribbon\">
            <div class=\"metric-ribbon-card\">
                <div class=\"metric-ribbon-title\">Live source</div>
                <div class=\"metric-ribbon-value\">{active_source}</div>
            </div>
            <div class=\"metric-ribbon-card\">
                <div class=\"metric-ribbon-title\">Recommendations</div>
                <div class=\"metric-ribbon-value\">{len(artifact.recommendations)}</div>
            </div>
            <div class=\"metric-ribbon-card\">
                <div class=\"metric-ribbon-title\">Malformed rows</div>
                <div class=\"metric-ribbon-value\">{artifact.quality_report.malformed_rows:,}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_spotlight, tab_data, tab_charts, tab_exports = st.tabs([
        "Threat Spotlight",
        "Intel Grid",
        "Pulse Charts",
        "Exports",
    ])

    with tab_spotlight:
        left, right = st.columns([1.35, 1])
        with left:
            st.markdown(
                f"""
                <div class=\"spotlight-card\" style=\"border-left: 4px solid {accent};\">
                    <div class=\"mono\">Threat spotlight</div>
                    <h2 style=\"margin-top:0.45rem; color:{accent};\">{spotlight_title}</h2>
                    <p style=\"font-size:1.04rem; line-height:1.8; color:var(--text);\">{spotlight_body}</p>
                    <p><span class=\"mono\">Lead indicator</span><br>{spotlight_detail}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""
                <div class=\"spotlight-card\" style=\"margin-top:1rem;\">
                    <div class=\"mono\">Executive narrative</div>
                    <p style=\"font-size:1rem; line-height:1.85; color:var(--text); margin-top:0.65rem;\">{artifact.executive_summary}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with right:
            st.markdown(
                """
                <div class="spotlight-card">
                    <div class="mono">Analyst actions</div>
                    <h3 style="margin-top:0.45rem;">Next moves</h3>
                </div>
                """,
                unsafe_allow_html=True,
            )
            for item in artifact.recommendations:
                st.write(f"- {item}")

    with tab_data:
        st.dataframe(filtered.head(preview_rows), use_container_width=True, hide_index=True)
        quality_snapshot = pd.DataFrame(
            {
                "metric": ["duplicate_rows", "malformed_rows", "columns"],
                "value": [
                    artifact.quality_report.duplicate_rows,
                    artifact.quality_report.malformed_rows,
                    artifact.quality_report.total_columns,
                ],
            }
        )
        st.dataframe(quality_snapshot, use_container_width=True, hide_index=True)

    with tab_charts:
        distribution_chart = build_distribution_chart(filtered, accent)
        timeline_chart, trend_df = build_timeline_chart(filtered, date_column, rolling_window, accent)
        chart_left, chart_right = st.columns(2)
        with chart_left:
            if distribution_chart is not None:
                st.altair_chart(distribution_chart, use_container_width=True)
            else:
                st.info("No threat-category chart is available for this feed.")
        with chart_right:
            if timeline_chart is not None:
                st.altair_chart(timeline_chart, use_container_width=True)
            else:
                st.info("No timeline chart is available for this feed.")
        if trend_df is not None and not trend_df.empty:
            anomalies = trend_df[trend_df["is_anomaly"]]
            if not anomalies.empty:
                st.dataframe(
                    anomalies[["date", "count", "rolling_mean", "threshold"]],
                    use_container_width=True,
                    hide_index=True,
                )

    with tab_exports:
        render_exports(artifact)
        image_paths = [
            path for path in artifact.generated_files.values() if Path(path).suffix.lower() == ".png" and Path(path).exists()
        ]
        if image_paths:
            gallery = st.columns(2)
            for index, image_path in enumerate(image_paths):
                with gallery[index % 2]:
                    st.image(str(image_path), use_container_width=True)

st.markdown(
    """
    <div class="drive-base">
        <div class="drive-row">
            <div class="drive-slot"></div>
            <div class="drive-slot"></div>
        </div>
        <div class="base-brand">THREAT-STATION // MODEL 86</div>
    </div>
    """,
    unsafe_allow_html=True,
)
