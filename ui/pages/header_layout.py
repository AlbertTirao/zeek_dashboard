from datetime import datetime
import html

import streamlit as st


def inject_traffic_style_header_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --tm-topbar-height: 2.35rem;
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

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0.05rem !important;
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
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_traffic_style_header(title: str, subtitle: str, chip_label: str, updated_txt: str | None = None) -> None:
    if updated_txt is None:
        updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    title_safe = html.escape(str(title or ""))
    subtitle_safe = html.escape(str(subtitle or ""))
    chip_safe = html.escape(str(chip_label or ""))

    st.markdown(
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
