from contextlib import contextmanager
from datetime import datetime
import html
import time

import streamlit as st


def inject_traffic_style_header_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --tm-topbar-height: 0rem;
        }

        header[data-testid="stHeader"],
        [data-testid="stToolbar"],
        #MainMenu,
        footer,
        [data-testid="stDecoration"] {
            display: none !important;
            height: 0 !important;
            min-height: 0 !important;
        }

        header[data-testid="stHeader"] > div {
            display: none !important;
            height: 0 !important;
            min-height: 0 !important;
            padding: 0 !important;
        }

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0.0rem !important;
            margin-top: 0 !important;
        }

        [data-testid="stAppViewContainer"] {
            padding-top: 0 !important;
            margin-top: 0 !important;
            top: 0 !important;
        }

        [data-testid="stAppViewContainer"] > .main,
        [data-testid="stAppViewContainer"] .main,
        section.main,
        [data-testid="stMain"] {
            padding-top: 0 !important;
            margin-top: 0 !important;
            top: 0 !important;
        }

        .tm-page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 18px;
            margin-top: 0 !important;
            margin-bottom: 16px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid rgba(255,255,255,0.12);
            background:
              radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
              linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: 0 14px 38px rgba(0,0,0,0.25);
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
            background: #00F7FF;
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
            box-shadow: 0 14px 38px rgba(0,0,0,0.25);
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


def render_traffic_style_header(
    title: str,
    subtitle: str,
    chip_label: str,
    updated_txt: str | None = None,
    container=None,
) -> None:
    if updated_txt is None:
        updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    title_safe = html.escape(str(title or ""))
    subtitle_safe = html.escape(str(subtitle or ""))
    chip_safe = html.escape(str(chip_label or ""))
    target = container or st

    target.markdown(
        f"""
        <div class="tm-page-header">
          <div>
            <div class="tm-page-title">{title_safe}</div>
            <div class="tm-page-sub">{subtitle_safe} | Updated: <b>{updated_txt}</b></div>
          </div>
          <div class="tm-header-chip"><span class="tm-header-dot"></span>{chip_safe}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_dashboard_loading_state(
    *,
    title: str,
    subtitle: str,
    steps: list[str],
    kicker: str = "Dashboard",
    container=None,
) -> None:
    chips = "".join(
        [f"<span class='tm-loading-step'>{html.escape(str(step))}</span>" for step in steps if str(step).strip()]
    )
    bars = "".join(
        [f"<div class='tm-loading-bar' style='--delay:{idx * 0.15}s'></div>" for idx in range(3)]
    )
    target = container or st
    target.markdown(
        f"""
        <div class="tm-loading-shell">
          <div class="tm-loading-kicker">{html.escape(str(kicker or 'Dashboard'))}</div>
          <div class="tm-loading-title">{html.escape(str(title or 'Loading'))}</div>
          <div class="tm-loading-copy">{html.escape(str(subtitle or 'Preparing data...'))}</div>
          <div class="tm-loading-steps">{chips}</div>
          <div class="tm-loading-bars">{bars}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


@contextmanager
def dashboard_loading_ui(
    *,
    title: str,
    subtitle: str,
    steps: list[str],
    kicker: str = "Dashboard",
    container=None,
    minimum_seconds: float = 0.25,
):
    target = container or st.empty()
    render_dashboard_loading_state(
        title=title,
        subtitle=subtitle,
        steps=steps,
        kicker=kicker,
        container=target,
    )
    started_at = time.perf_counter()
    try:
        yield target
    finally:
        remaining = float(minimum_seconds or 0.0) - (time.perf_counter() - started_at)
        if remaining > 0:
            time.sleep(remaining)
        target.empty()
