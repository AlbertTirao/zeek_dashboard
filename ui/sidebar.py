import streamlit as st
from datetime import date
from streamlit_autorefresh import st_autorefresh
from streamlit_option_menu import option_menu

def render_sidebar(auto_refresh_interval=3600):
    # -------------------------
    # Inject CSS for full height, dark grey theme
    # -------------------------
    st.markdown(
        """
        <style>
        /* Sidebar full height and dark grey background */
        [data-testid="stSidebar"] > div:first-child {
            padding-top: 0rem;
            background-color: #1e1e1e;  /* dark grey */
        }

        /* Option menu container pinned top */
        .option-menu {
            display: flex;
            flex-direction: column;
            justify-content: flex-start !important;
            align-items: stretch;
        }

        /* Hover effect for nav links */
        .option-menu .nav-link {
            transition: all 0.2s ease;
        }

        .option-menu .nav-link:hover {
            background-color: #2a2a2a; /* slightly darker grey */
            color: #ffffff;
        }

        /* Sidebar title style */
        .sidebar-title {
            color: #ffffff;
            font-size: 20px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 20px;
            padding-top: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    with st.sidebar:
        # -------------------------
        # Sidebar Title
        # -------------------------
        st.markdown("<div class='sidebar-title'>Zeek SOC Dashboard</div>", unsafe_allow_html=True)

        # -------------------------
        # Navigation Drawer (pinned top)
        # -------------------------
        page = option_menu(
            menu_title=None,
            options=["Overview", "Devices", "Analytics", "Zeek Logs", "Alerts", "Authorization"],
            icons=["house", "pc-display", "bar-chart", "folder", "bell", "key"],
            menu_icon=None,
            default_index=0,
            orientation="vertical",
            styles={
                "container": {
                    "padding": "0!important",
                    "background-color": "#1e1e1e",  # dark grey
                    "width": "100%",
                },
                "icon": {"color": "#ffffff", "font-size": "18px"},
                "nav-link": {
                    "font-size": "16px",
                    "text-align": "left",
                    "margin": "4px 0px",
                    "color": "#cccccc",  # light grey text
                    "--hover-color": "#2a2a2a",
                    "padding": "10px 12px",
                    "border-radius": "5px",
                },
                "nav-link-selected": {
                    "background-color": "#333333",  # medium dark grey
                    "font-weight": "bold",
                }
            }
        )

        # -------------------------
        # Date Range Picker
        # -------------------------
        with st.expander("Date Range", expanded=True):
            start_date = st.date_input("Start Date", value=date.today(), key="start_date")
            end_date = st.date_input("End Date", value=date.today(), key="end_date")

        # -------------------------
        # Auto-refresh
        # -------------------------
        with st.expander("Auto-refresh", expanded=False):
            refresh = st.checkbox(f"Enable auto-refresh every {auto_refresh_interval//3600}h", key="auto_refresh")
            if refresh:
                st_autorefresh(interval=auto_refresh_interval*1000, key="auto_refresh_timer")
            st.button("Force Reload", on_click=lambda: (st.cache_data.clear(), st.experimental_rerun()))

        # -------------------------
        # Footer (clean, dark grey)
        # -------------------------
        st.markdown(
            "<div style='color:#888888;font-size:12px;text-align:center;margin-top:20px;'>© 2026 Zeek SOC Dashboard</div>",
            unsafe_allow_html=True
        )

    return page, start_date, end_date
