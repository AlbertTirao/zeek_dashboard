# ui/pages/analytics.py
from datetime import datetime
import importlib
from contextlib import contextmanager

import streamlit as st
from pathlib import Path
from .header_layout import (
    inject_traffic_style_header_css,
    render_dashboard_loading_state,
    render_traffic_style_header,
)

ENABLE_HARDCODED_TRAFFIC_LOADERS = False  # Temporary: rely on per-module execution-trace loaders.


def inject_traffic_header_css():
    st.markdown(
        """
        <style>
        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
            --accent-red: #F63049;
            --tm-topbar-height: 2.35rem;
        }

        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0.05rem !important;
            padding-bottom: 1.05rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }

        header[data-testid="stHeader"] {
            height: var(--tm-topbar-height) !important;
            min-height: var(--tm-topbar-height) !important;
            background: #000 !important;
        }

        header[data-testid="stHeader"] > div {
            height: var(--tm-topbar-height) !important;
            min-height: var(--tm-topbar-height) !important;
            padding-top: 0 !important;
            padding-bottom: 0 !important;
        }

        [data-testid="stAppViewContainer"] > .main,
        [data-testid="stAppViewContainer"] .main,
        section.main {
            padding-left: 0 !important;
            padding-right: 0 !important;
            margin-left: 0 !important;
            margin-right: 0 !important;
            max-width: 100% !important;
        }

        .tm-page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 20px;
            margin-top: 0 !important;
            margin-bottom: 16px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid var(--panel-border);
            background:
              radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
              linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: var(--panel-shadow);
        }

        .tm-page-title {
            font-size: 46px;
            font-weight: 900;
            line-height: 1.0;
            letter-spacing: -0.5px;
        }

        .tm-page-sub {
            opacity: 0.74;
            font-size: 13px;
            margin-top: 6px;
        }

        .tm-header-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .tm-header-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0,247,255,0.8);
        }

        .tm-loading-shell {
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 18px;
            padding: 18px 20px 16px 20px;
            margin: 8px 0 16px 0;
            background:
                radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
                linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: var(--panel-shadow);
        }

        .tm-loading-shell::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(110deg, transparent 20%, rgba(255,255,255,0.08) 48%, transparent 72%);
            transform: translateX(-120%);
            animation: tm-loading-sweep 1.9s linear infinite;
            pointer-events: none;
        }

        .tm-loading-kicker {
            font-size: 0.72rem;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            font-weight: 800;
            color: #7EE7FF;
            margin-bottom: 0.32rem;
        }

        .tm-loading-title {
            font-size: 1.05rem;
            font-weight: 900;
            line-height: 1.2;
            color: #F5FAFF;
        }

        .tm-loading-copy {
            margin-top: 0.22rem;
            color: rgba(255,255,255,0.76);
            font-size: 0.88rem;
        }

        .tm-loading-steps {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 0.85rem;
        }

        .tm-loading-step {
            display: inline-flex;
            align-items: center;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.04);
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.74rem;
            font-weight: 700;
            color: #DCEAFB;
        }

        .tm-loading-bars {
            display: grid;
            gap: 7px;
            margin-top: 0.85rem;
        }

        .tm-loading-bar {
            position: relative;
            overflow: hidden;
            height: 8px;
            border-radius: 999px;
            background: rgba(255,255,255,0.09);
        }

        .tm-loading-bar::after {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            background: linear-gradient(90deg, rgba(0,247,255,0.12), rgba(0,247,255,0.95), rgba(246,48,73,0.28));
            transform: translateX(-55%);
            animation: tm-loading-pulse 1.25s ease-in-out infinite;
            animation-delay: var(--delay, 0s);
        }

        @keyframes tm-loading-sweep {
            to { transform: translateX(120%); }
        }

        @keyframes tm-loading-pulse {
            0%, 100% { transform: translateX(-55%); opacity: 0.78; }
            50% { transform: translateX(20%); opacity: 1; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


SECTION_LOADING_CONFIG = {
    "Shadow Apps": {
        "module": "ui.pages.shadow_apps",
        "func": "render_shadow_apps",
        "title": "Loading Shadow Apps",
        "subtitle": "Scanning parquet, resolving identity context, and preparing unauthorized application telemetry.",
        "steps": ["Scan parquet", "Resolve identity", "Build incidents"],
    },
    "Shadow Sharings": {
        "module": "ui.pages.shadow_sharings",
        "func": "render_shadow_uploads",
        "title": "Loading Shadow Sharings",
        "subtitle": "Correlating conn, http, ssl, and files telemetry into sharing incidents and scope caches.",
        "steps": ["Scan parquet", "Correlate evidence", "Build incidents"],
    },
    "Shadow AI": {
        "module": "ui.pages.shadow_ai",
        "func": "render_shadow_ai",
        "title": "Loading Shadow AI",
        "subtitle": "Matching provider signatures, analyzing telemetry, and preparing the AI activity scope.",
        "steps": ["Scan parquet", "Match providers", "Warm scope"],
    },
    "Anonymization Network": {
        "module": "ui.pages.anonymization_network",
        "func": "render_anonymization_network",
        "title": "Loading Anonymization Network",
        "subtitle": "Scoring proxy, VPN, and Tor signals and preparing the optimized anonymization view.",
        "steps": ["Score evidence", "Warm cache", "Render scope"],
    },
}


def _render_tm_loading_state(slot, *, title: str, subtitle: str, steps: list[str]) -> None:
    chips = "".join(
        [f"<span class='tm-loading-step'>{step}</span>" for step in steps if str(step).strip()]
    )
    bars = "".join(
        [f"<div class='tm-loading-bar' style='--delay:{idx * 0.15}s'></div>" for idx in range(3)]
    )
    slot.markdown(
        f"""
        <div class="tm-loading-shell">
            <div class="tm-loading-kicker">Traffic Monitoring</div>
            <div class="tm-loading-title">{title}</div>
            <div class="tm-loading-copy">{subtitle}</div>
            <div class="tm-loading-steps">{chips}</div>
            <div class="tm-loading-bars">{bars}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


@contextmanager
def _traffic_loading_ui(section: str, slot=None):
    config = SECTION_LOADING_CONFIG.get(section)
    if not config:
        yield
        return

    target = slot or st.empty()
    if ENABLE_HARDCODED_TRAFFIC_LOADERS:
        render_dashboard_loading_state(
            title=str(config["title"]),
            subtitle=str(config["subtitle"]),
            steps=[str(x) for x in config.get("steps", [])],
            kicker="Traffic Monitoring",
            container=target,
        )
    try:
        with st.spinner(f"Loading {section}..."):
            yield
    finally:
        if ENABLE_HARDCODED_TRAFFIC_LOADERS:
            target.empty()


def _render_traffic_section(section: str, parquet_root: Path, loading_slot=None) -> None:
    config = SECTION_LOADING_CONFIG.get(section)
    if not config:
        st.warning("Unknown traffic monitoring section selected.")
        return
    renderer = getattr(importlib.import_module(str(config["module"])), str(config["func"]))
    with _traffic_loading_ui(section, slot=loading_slot):
        renderer(parquet_root)

# ---------------------------------------------------------
# Main Render
# ---------------------------------------------------------
def render(parquet_root: Path):
    # REMOVED st.set_page_config() - This must be at the very top of app.py, not here
    inject_traffic_header_css()
    inject_traffic_style_header_css()
    updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    render_traffic_style_header(
        title="Traffic Monitoring",
        subtitle="Shadow Apps, Shadow Sharings, Shadow AI, and Anonymization Network telemetry",
        chip_label="Network Monitoring",
        updated_txt=updated_txt,
    )

    section_options = ["Shadow Apps", "Shadow Sharings", "Shadow AI", "Anonymization Network"]
    if st.session_state.get("traffic_monitoring_section") not in section_options:
        st.session_state["traffic_monitoring_section"] = section_options[0]
    loading_slot = st.empty()
    if ENABLE_HARDCODED_TRAFFIC_LOADERS:
        current_section = str(st.session_state.get("traffic_monitoring_section") or section_options[0])
        current_config = SECTION_LOADING_CONFIG.get(current_section, SECTION_LOADING_CONFIG[section_options[0]])
        render_dashboard_loading_state(
            title=str(current_config["title"]),
            subtitle=str(current_config["subtitle"]),
            steps=[str(x) for x in current_config.get("steps", [])],
            kicker="Traffic Monitoring",
            container=loading_slot,
        )

    section = st.radio(
        "Traffic monitoring section",
        section_options,
        horizontal=True,
        label_visibility="collapsed",
        key="traffic_monitoring_section",
    )

    _render_traffic_section(section, parquet_root, loading_slot=loading_slot)
