import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_option_menu import option_menu

MENU_OPTIONS = [
    "Device Inspection",
    "Traffic Monitoring",
    "Zeek Logs",
    "Alerts",
    "Authorization",
    "User Management",
]

MENU_ICONS = [
    "pc-display",
    "activity",
    "file-earmark-text",
    "bell",
    "shield-lock",
    "people",
]

DEFAULT_PAGE = MENU_OPTIONS[0]


def render_sidebar(auto_refresh_interval=3600, menu_options=None, menu_icons=None):
    options = menu_options or MENU_OPTIONS
    icons = menu_icons or MENU_ICONS

    if "sidebar_page" not in st.session_state or st.session_state.sidebar_page not in options:
        st.session_state.sidebar_page = DEFAULT_PAGE

    default_index = options.index(st.session_state.sidebar_page)

    # --- Global CSS: sidebar + kill option_menu grey wrapper ---
    st.markdown(
        """
        <style>
        :root{
            --sb:#151a28;
            --sb-text:#ffffff;
            --sb-dim:rgba(255,255,255,0.88);
            --sb-hover:rgba(255,255,255,0.06);
            --sb-selected:rgba(255,255,255,0.10);
        }

        /* Sidebar base color + remove divider */
        section[data-testid="stSidebar"],
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child{
            background: var(--sb) !important;
            border-right: 0 !important;
            box-shadow: none !important;
        }

        [data-testid="stSidebar"] .block-container{
            padding: 0.9rem 0.85rem 0.8rem 0.85rem;
            background: var(--sb) !important;
        }

        /* Some Streamlit versions add extra wrappers with their own background */
        [data-testid="stSidebar"] div,
        [data-testid="stSidebar"] aside{
            border: 0 !important;
            box-shadow: none !important;
        }

        /* ============================================================
           streamlit_option_menu is inside a custom-component iframe.
           The grey "card" is the wrapper/iframe background.
           Force wrapper + iframe to #151a28.
           ============================================================ */

        /* Wrapper that directly contains the iframe (Chromium supports :has()) */
        [data-testid="stSidebar"] div:has(> iframe[title="streamlit_option_menu.option_menu"]),
        [data-testid="stSidebar"] div:has(> iframe[title*="option_menu"]) {
            background: var(--sb) !important;
            background-color: var(--sb) !important;
            border: 0 !important;
            box-shadow: none !important;
            padding: 0 !important;
            margin: 0 !important;
            border-radius: 0 !important;
        }

        /* The iframe itself */
        [data-testid="stSidebar"] iframe[title="streamlit_option_menu.option_menu"],
        [data-testid="stSidebar"] iframe[title*="option_menu"]{
            background: var(--sb) !important;
            border: 0 !important;
            box-shadow: none !important;
        }

        /* Fallback wrapper testid some builds use */
        [data-testid="stSidebar"] [data-testid="stCustomComponentV1"]{
            background: var(--sb) !important;
            border: 0 !important;
            box-shadow: none !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            "<div style='color:#fff;font-weight:800;font-size:1.05rem;margin-bottom:0.75rem;'>Zeek Dashboard</div>",
            unsafe_allow_html=True,
        )

        # --- option_menu with solid container bg (#151a28) ---
        page = option_menu(
            menu_title=None,
            options=options,
            icons=icons,
            default_index=default_index,
            orientation="vertical",
            styles={
                "container": {
                    "padding": "0!important",
                    "background-color": "#151a28",
                    "border": "0",
                    "border-radius": "0",
                    "box-shadow": "none",
                    "margin": "0",
                },
                "nav-link": {
                    "background-color": "#151a28",
                    "color": "rgba(255,255,255,0.88)",
                    "margin": "0",
                    "padding": "0.55rem 0.2rem 0.55rem 0.6rem",
                    "border-radius": "0",
                    "border": "0",
                },
                # keep it non-gray: just a subtle white alpha highlight
                "nav-link-selected": {
                    "background-color": "rgba(255,255,255,0.10)",
                    "color": "#ffffff",
                    "font-weight": "800",
                    "border-radius": "0",
                    "border": "0",
                },
                "icon": {"color": "#ffffff", "font-size": "16px"},
            },
            key="sidebar_option_menu",
        )

        # Optional: make hover consistent (only affects non-iframe DOM if present)
        st.markdown(
            """
            <style>
            [data-testid="stSidebar"] a.nav-link:hover{
                background: rgba(255,255,255,0.06) !important;
                color: #fff !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.session_state.sidebar_page = page
        st_autorefresh(interval=auto_refresh_interval * 1000, key="auto_refresh_timer")

    return st.session_state.sidebar_page