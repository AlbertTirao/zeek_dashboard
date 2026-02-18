from datetime import datetime

import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_option_menu import option_menu

MENU_OPTIONS = [
    "Device Inspection",
    "Traffic Monitoring",
    "Zeek Logs",
    "Alerts",
    "Authorization",
]

MENU_ICON_BY_PAGE = {
    "Device Inspection": "pc-display",
    "Traffic Monitoring": "activity",
    "Zeek Logs": "file-earmark-text",
    "Alerts": "bell",
    "Authorization": "shield-lock",
}

DEFAULT_PAGE = MENU_OPTIONS[0]


def render_sidebar(
    auto_refresh_interval=3600,
    menu_options=None,
    current_user: str = "",
    current_role: str = "",
):
    resolved_menu = list(menu_options) if menu_options else list(MENU_OPTIONS)
    if not resolved_menu:
        resolved_menu = [DEFAULT_PAGE]

    if "sidebar_page" not in st.session_state or st.session_state.sidebar_page not in resolved_menu:
        st.session_state.sidebar_page = resolved_menu[0]

    default_index = resolved_menu.index(st.session_state.sidebar_page)
    refresh_minutes = max(1, auto_refresh_interval // 60)

    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] > div:first-child {
            padding-top: 0rem;
            background: linear-gradient(180deg, #171b24 0%, #11151d 100%);
            border-right: 1px solid #242a35;
        }

        [data-testid="stSidebar"] .block-container {
            padding-top: 1rem;
            padding-bottom: 0.75rem;
            padding-left: 0.75rem;
            padding-right: 0.75rem;
        }

        .sidebar-brand {
            margin-bottom: 0.7rem;
            padding: 0.15rem 0.1rem 0.35rem 0.1rem;
        }

        .sidebar-brand-title {
            color: #f7fbff;
            font-size: 1.1rem;
            font-weight: 700;
            line-height: 1.2;
            margin: 0;
        }

        .sidebar-brand-subtitle {
            color: #a5b3c5;
            font-size: 0.8rem;
            margin-top: 0.2rem;
        }

        .sidebar-section-label {
            color: #8e9bb0;
            font-size: 0.74rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin: 0.4rem 0 0.45rem 0.2rem;
        }

        .option-menu {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            background: transparent;
        }

        .option-menu .nav-link {
            transition: all 0.18s ease;
            border: 1px solid transparent;
            background: #1a202c;
            color: #c0cbdb;
            margin: 0 !important;
            border-radius: 10px !important;
            font-weight: 500;
        }

        .option-menu .nav-link:hover {
            background: #222b39;
            color: #edf3ff;
            border-color: #2f3a4c;
        }

        .option-menu .nav-link-selected {
            background: #263246;
            color: #f4f8ff;
            border: 1px solid #3a4b66;
            font-weight: 600;
            box-shadow: inset 3px 0 0 #60a5fa;
        }

        .sidebar-meta {
            color: #a9bdd6;
            font-size: 0.78rem;
            margin-top: 0.85rem;
            margin-left: 0.2rem;
        }

        .sidebar-footer {
            color: #8f9eb2;
            font-size: 0.72rem;
            text-align: center;
            margin-top: 0.9rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="sidebar-brand-title">Zeek Dashboard</div>
                <div class="sidebar-brand-subtitle">SOC Monitoring Console</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div class='sidebar-section-label'>Navigation</div>", unsafe_allow_html=True)

        page = option_menu(
            menu_title=None,
            options=resolved_menu,
            icons=[MENU_ICON_BY_PAGE.get(x, "circle") for x in resolved_menu],
            menu_icon=None,
            default_index=default_index,
            orientation="vertical",
            styles={
                "container": {
                    "padding": "0!important",
                    "background-color": "transparent",
                    "width": "100%",
                    "border-radius": "0",
                },
                "icon": {"color": "#d6e4f8", "font-size": "17px"},
                "nav-link": {
                    "font-size": "15px",
                    "text-align": "left",
                    "padding": "9px 12px",
                    "margin": "0",
                    "border-radius": "10px",
                    "background-color": "#1a202c",
                    "color": "#c0cbdb",
                    "--hover-color": "#222b39",
                },
                "nav-link-selected": {
                    "background-color": "#263246",
                    "font-weight": "600",
                    "color": "#f4f8ff",
                    "border-radius": "10px",
                },
            },
            key="sidebar_option_menu",
        )

        st.session_state.sidebar_page = page

        st.markdown(
            f"<div class='sidebar-meta'>Auto-refresh every {refresh_minutes} min</div>",
            unsafe_allow_html=True,
        )

        if current_user:
            st.markdown(
                f"<div class='sidebar-meta'>Signed in as <b>{current_user}</b> ({current_role})</div>",
                unsafe_allow_html=True,
            )

        logout_clicked = st.button("Logout", key="sidebar_logout_btn", use_container_width=True)

        st_autorefresh(interval=auto_refresh_interval * 1000, key="auto_refresh_timer")

        today = datetime.now().strftime("%b %d, %Y")
        st.markdown(
            f"<div class='sidebar-footer'>&copy; 2026 Zeek SOC Dashboard<br>{today}</div>",
            unsafe_allow_html=True,
        )

    return st.session_state.sidebar_page, logout_clicked
