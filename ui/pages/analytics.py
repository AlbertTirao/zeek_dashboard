# ui/pages/analytics.py
from datetime import datetime

import streamlit as st
from pathlib import Path
from .shadow_apps import render_shadow_apps
from .shadow_sharings import render_shadow_uploads
from .shadow_ai import render_shadow_ai
from .anonymization_network import render_anonymization_network
from .header_layout import inject_traffic_style_header_css, render_traffic_style_header


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
        </style>
        """,
        unsafe_allow_html=True,
    )

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

    section = st.radio(
        "",
        ["Shadow Apps", "Shadow Sharings", "Shadow AI", "Anonymization Network"],
        horizontal=True,
        label_visibility="collapsed",
    )

    if section == "Shadow Apps":
        render_shadow_apps(parquet_root)
    elif section == "Shadow Sharings":
        render_shadow_uploads(parquet_root)
    elif section == "Shadow AI":
        render_shadow_ai(parquet_root)
    elif section == "Anonymization Network":
        render_anonymization_network(parquet_root)
