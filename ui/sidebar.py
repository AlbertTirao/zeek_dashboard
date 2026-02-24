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

    # 1) Base sidebar theme (2 colors only)
    st.markdown(
        """
        <style>
        :root{
            --sb-top:#151a28;
            --sb-bot:#0f1422;
            --sb-text:#ffffff;
            --sb-dim:rgba(255,255,255,0.88);
        }

        /* Sidebar background only (no divider) */
        section[data-testid="stSidebar"],
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child{
            background: linear-gradient(180deg, var(--sb-top) 0%, var(--sb-bot) 100%) !important;
            border-right: 0 !important;
            box-shadow: none !important;
        }

        [data-testid="stSidebar"] .block-container{
            padding: 0.9rem 0.85rem 0.8rem 0.85rem;
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

        # 2) Render option_menu with “as transparent as possible”
        page = option_menu(
            menu_title=None,
            options=options,
            icons=icons,
            default_index=default_index,
            orientation="vertical",
            styles={
                "container": {
                    "padding": "0!important",
                    "background-color": "transparent",
                    "border": "0",
                    "border-radius": "0",
                },
                "nav-link": {
                    "background-color": "transparent",
                    "color": "rgba(255,255,255,0.88)",
                    "margin": "0",
                    "padding": "0.55rem 0.2rem 0.55rem 0.6rem",
                    "border-radius": "0",
                    "border": "0",
                },
                "nav-link-selected": {
                    "background-color": "transparent",
                    "color": "#ffffff",
                    "font-weight": "800",
                    "border-radius": "0",
                    "border": "0",
                },
                "icon": {"color": "#ffffff", "font-size": "16px"},
            },
            key="sidebar_option_menu",
        )

        # 3) HARD OVERRIDE AFTER render (this removes the grey box for real)
        st.markdown(
            """
            <style>
            /* Kill the grey rectangle: force ALL option_menu wrappers transparent */
            [data-testid="stSidebar"] .option-menu,
            [data-testid="stSidebar"] .option-menu > div,
            [data-testid="stSidebar"] .option-menu ul,
            [data-testid="stSidebar"] .option-menu li,
            [data-testid="stSidebar"] .option-menu .nav,
            [data-testid="stSidebar"] .option-menu .nav-pills,
            [data-testid="stSidebar"] ul.nav,
            [data-testid="stSidebar"] .nav,
            [data-testid="stSidebar"] .nav-pills,
            [data-testid="stSidebar"] .nav-item{
                background: transparent !important;
                background-color: transparent !important;
                border: 0 !important;
                border-radius: 0 !important;
                box-shadow: none !important;
                outline: none !important;
                padding: 0 !important;
                margin: 0 !important;
            }

            /* Remove bullets/indent that can look like a container */
            [data-testid="stSidebar"] .option-menu ul,
            [data-testid="stSidebar"] ul.nav{
                list-style: none !important;
            }

            /* Links: no box, no border, no focus ring */
            [data-testid="stSidebar"] .option-menu a.nav-link,
            [data-testid="stSidebar"] .option-menu a.nav-link-selected{
                background: transparent !important;
                background-color: transparent !important;
                border: 0 !important;
                border-radius: 0 !important;
                box-shadow: none !important;
                outline: none !important;
                text-decoration: none !important;
                color: var(--sb-dim) !important;
            }

            [data-testid="stSidebar"] .option-menu a.nav-link:hover{
                background: transparent !important;
                color: var(--sb-text) !important;
            }

            [data-testid="stSidebar"] .option-menu a.nav-link-selected{
                background: transparent !important;
                color: var(--sb-text) !important;
                font-weight: 800 !important;
            }

            [data-testid="stSidebar"] .option-menu a.nav-link:focus,
            [data-testid="stSidebar"] .option-menu a.nav-link:focus-visible,
            [data-testid="stSidebar"] .option-menu a.nav-link-selected:focus,
            [data-testid="stSidebar"] .option-menu a.nav-link-selected:focus-visible{
                outline: none !important;
                box-shadow: none !important;
            }

            /* Icons: no border/box */
            [data-testid="stSidebar"] .option-menu a.nav-link i,
            [data-testid="stSidebar"] .option-menu a.nav-link-selected i,
            [data-testid="stSidebar"] .option-menu a.nav-link svg,
            [data-testid="stSidebar"] .option-menu a.nav-link-selected svg{
                background: transparent !important;
                border: 0 !important;
                box-shadow: none !important;
                outline: none !important;
                color: var(--sb-text) !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.session_state.sidebar_page = page
        st_autorefresh(interval=auto_refresh_interval * 1000, key="auto_refresh_timer")

    return st.session_state.sidebar_page