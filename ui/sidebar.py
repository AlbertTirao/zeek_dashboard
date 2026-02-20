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

MENU_ICONS = [
    "pc-display",
    "activity",
    "file-earmark-text",
    "bell",
    "shield-lock",
]

DEFAULT_PAGE = MENU_OPTIONS[0]


def render_sidebar(auto_refresh_interval=3600, menu_options=None, menu_icons=None):
    options = menu_options or MENU_OPTIONS
    icons = menu_icons or MENU_ICONS

    if "sidebar_page" not in st.session_state or st.session_state.sidebar_page not in options:
        st.session_state.sidebar_page = DEFAULT_PAGE

    default_index = options.index(st.session_state.sidebar_page)
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

        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="sidebar-brand-title">Zeek Dashboard</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        page = option_menu(
            menu_title=None,
            options=options,
            icons=icons,
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

        st_autorefresh(interval=auto_refresh_interval * 1000, key="auto_refresh_timer")

    return st.session_state.sidebar_page
