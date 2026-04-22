# ui/pages/analytics.py
from datetime import datetime
import importlib
from contextlib import contextmanager

import streamlit as st
from pathlib import Path
import contextlib
import time
from .header_layout import (
    dashboard_loading_ui,
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
    # --- TOGGLE SWITCH ---
    # Set to True to use the hardcoded animation, False to use the execution trace
    USE_HARDCODED_LOADING_UI = True 

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

    # Get current section config to feed into the hardcoded loader dynamically
    current_section = str(st.session_state.get("traffic_monitoring_section") or section_options[0])
    current_config = SECTION_LOADING_CONFIG.get(current_section, SECTION_LOADING_CONFIG.get(section_options[0], {"title": "Loading", "subtitle": "Please wait", "steps": []}))

    # --- Setup Trace State ---
    if "hide_analytics_trace" not in st.session_state:
        st.session_state.hide_analytics_trace = True

    trace_container = st.empty()
    show_trace = not st.session_state.hide_analytics_trace

    if show_trace:
        trace_box = trace_container.container()
        loading_slot = trace_box.empty()
    else:
        loading_slot = None
        trace_box = None

    upstream_trace = st.session_state.get("app_load_trace", [])

    # Custom trace steps for Traffic Monitoring
    local_processes = [
        {"name": "Scanning network traffic logs", "status": "pending", "duration": 0.0},
        {"name": f"Processing {current_section} datasets", "status": "pending", "duration": 0.0},
        {"name": "Rendering analytical charts", "status": "pending", "duration": 0.0},
    ]

    def update_loading_ui(complete=False):
        if USE_HARDCODED_LOADING_UI or not show_trace or loading_slot is None:
            return
        
        html_parts = [
            "<div class='dashboard-loading-shell' style='margin-bottom: 8px;'>",
            "  <div class='dashboard-loading-kicker'>Execution Trace</div>",
            f"  <div class='dashboard-loading-title'>Initializing {current_section}</div>",
            "  <div class='dashboard-loading-copy'>Tracking real-time data ingestion and processing...</div>",
            "  <div class='dashboard-loading-steps' style='display: flex; flex-direction: column; gap: 8px; margin-top: 16px;'>"
        ]

        if upstream_trace:
            html_parts.append("    <div style='font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 800; color: rgba(255,255,255,0.5); margin-top: 4px; margin-bottom: -2px; padding-left: 4px;'>Initial Load:</div>")
            for p in upstream_trace:
                time_str = f"{p.get('duration', 0.0):.2f}s"
                html_parts.append(
                    f"    <div class='dashboard-loading-step' style='width: 100%; display: flex; justify-content: space-between; background: rgba(46, 204, 113, 0.08); border: 1px solid rgba(46, 204, 113, 0.3); border-radius: 8px; color: #2ecc71; padding: 8px 14px;'>"
                    f"        <span style='font-weight: 700;'>✅ &nbsp;{p.get('name', 'Task')}</span>"
                    f"        <span style='font-family: monospace; font-size: 0.85rem; opacity: 0.9;'>{time_str}</span>"
                    f"    </div>"
                )

        html_parts.append("    <div style='font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 800; color: rgba(255,255,255,0.5); margin-top: 10px; margin-bottom: -2px; padding-left: 4px;'>Analytics Load:</div>")
        
        for p in local_processes:
            if p["status"] == "pending":
                icon, time_str, bg, border, color = "⏳", "Waiting...", "rgba(255,255,255,0.02)", "rgba(255,255,255,0.05)", "rgba(255,255,255,0.4)"
            elif p["status"] == "running":
                icon, time_str, bg, border, color = "🔄", "Processing...", "rgba(0, 247, 255, 0.08)", "rgba(0, 247, 255, 0.3)", "#00F7FF"
            else:
                icon, time_str, bg, border, color = "✅", f"{p['duration']:.2f}s", "rgba(46, 204, 113, 0.08)", "rgba(46, 204, 113, 0.3)", "#2ecc71"

            html_parts.append(
                f"    <div class='dashboard-loading-step' style='width: 100%; display: flex; justify-content: space-between; background: {bg}; border: 1px solid {border}; border-radius: 8px; color: {color}; padding: 8px 14px;'>"
                f"        <span style='font-weight: 700;'>{icon} &nbsp;{p['name']}</span>"
                f"        <span style='font-family: monospace; font-size: 0.85rem; opacity: 0.9;'>{time_str}</span>"
                f"    </div>"
            )

        html_parts.append("  </div>")
        if not complete:
            html_parts.append(
                "  <div class='dashboard-loading-bars' style='margin-top: 18px;'>"
                "      <div class='dashboard-loading-bar' style='--delay:0s'></div>"
                "      <div class='dashboard-loading-bar' style='--delay:0.15s'></div>"
                "      <div class='dashboard-loading-bar' style='--delay:0.3s'></div>"
                "  </div>"
            )
        html_parts.append("</div>")
        loading_slot.markdown("".join(html_parts), unsafe_allow_html=True)

    # --- Conditional Loader Wrapper ---
    @contextlib.contextmanager
    def analytics_loading_wrapper():
        if USE_HARDCODED_LOADING_UI:
            with dashboard_loading_ui(
                title=str(current_config["title"]),
                subtitle=str(current_config["subtitle"]),
                steps=[str(x) for x in current_config.get("steps", [])],
                container=trace_container,
            ):
                yield
        else:
            yield

    section = st.radio(
        "Traffic monitoring section",
        section_options,
        horizontal=True,
        label_visibility="collapsed",
        key="traffic_monitoring_section",
    )

    with analytics_loading_wrapper():
        
        # Track Step 1: Initial scanning (stubbed timer for flow)
        local_processes[0]["status"] = "running"
        update_loading_ui()
        t0 = time.time()
        time.sleep(0.05) # Brief pause so the UI transitions smoothly
        local_processes[0]["duration"] = time.time() - t0
        local_processes[0]["status"] = "done"

        # Track Step 2: Main Processing
        local_processes[1]["status"] = "running"
        update_loading_ui()
        t1 = time.time()
        
        # Execute the main section rendering
        _render_traffic_section(section, parquet_root, loading_slot=trace_container)
        
        local_processes[1]["duration"] = time.time() - t1
        local_processes[1]["status"] = "done"
        
        # Track Step 3: Finalizing Charts
        local_processes[2]["status"] = "running"
        update_loading_ui()
        t2 = time.time()
        local_processes[2]["duration"] = time.time() - t2
        local_processes[2]["status"] = "done"

    # Finalize UI and lock it in place
    update_loading_ui(complete=True)

    # Make sure the close trace button only shows if we are actually using the trace
    if not USE_HARDCODED_LOADING_UI and show_trace and trace_box:
        def close_trace():
            st.session_state.hide_analytics_trace = True
        trace_box.button("Close Execution Trace", key="close_analytics_trace_btn", on_click=close_trace)
