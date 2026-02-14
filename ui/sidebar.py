import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_option_menu import option_menu

def render_sidebar(auto_refresh_interval=3600):
    # -------------------------
    # Inject CSS for uniform dark-grey sidebar
    # -------------------------
    st.markdown(
        """
        <style>
        /* Sidebar container */
        [data-testid="stSidebar"] > div:first-child {
            padding-top: 0rem;
            background-color: #191919;
        }

        /* Option menu container */
        .option-menu {
            display: flex;
            flex-direction: column;
            justify-content: flex-start !important;
            align-items: stretch;
            background-color: #191919;
            border-radius: 0 !important;
        }

        /* Nav links */
        .option-menu .nav-link {
            transition: all 0.2s ease;
            border-bottom: 1px solid #191919;
            background-color: #191919;
            color: #cccccc;
            margin: 0 !important;
            border-radius: 0 !important;
        }

        /* Hover effect for nav links */
        .option-menu .nav-link:hover {
            background-color: #2a2a2a;
            color: #ffffff;
        }

        /* Selected nav link */
        .option-menu .nav-link-selected {
            background-color: #2a2a2a;
            font-weight: bold;
            color: #ffffff;
            border-radius: 0 !important;
        }

        /* Sidebar title */
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
        st.markdown("<div class='sidebar-title'>Zeek Dashboard</div>", unsafe_allow_html=True)

        # -------------------------
        # Navigation Drawer
        # -------------------------
        if "sidebar_page" not in st.session_state:
            st.session_state.sidebar_page = "Visual"

        # CORRECTED ICONS HERE  
        page = option_menu(
            menu_title=None,
            options=["Device Inspections", "Traffic Monitoring", "Zeek Logs", "Alerts", "Authorization"],
            icons=[
                "pc-display",        # Device Inspections (endpoint/device icon)
                "activity",          # Traffic Monitoring (network activity)
                "file-earmark-text", # Zeek Logs
                "bell",              # Alerts
                "shield-lock"        # Authorization
            ],
            menu_icon=None,
            default_index=0,
            orientation="vertical",
            styles={
                "container": {
                    "padding": "0!important",
                    "background-color": "#191919",
                    "width": "100%",
                    "border-radius": "0"
                },
                "icon": {"color": "#ffffff", "font-size": "18px"},
                "nav-link": {
                    "font-size": "16px",
                    "text-align": "left",
                    "padding": "10px 12px",
                    "margin": "0",
                    "border-radius": "0",
                    "border-bottom": "1px solid #191919",
                    "background-color": "#191919",
                    "color": "#cccccc",
                    "--hover-color": "#2a2a2a"
                },
                "nav-link-selected": {
                    "background-color": "#2a2a2a",
                    "font-weight": "bold",
                    "color": "#ffffff",
                    "border-radius": "0"
                }
            }, 
            key="sidebar_option_menu",  # CHANGED: prevents component_instance ID collisions
        )

        # Update session state with current selection
        st.session_state.sidebar_page = page

        # -------------------------
        # Auto-refresh every 1 hour
        # -------------------------
        st_autorefresh(interval=auto_refresh_interval*1000, key="auto_refresh_timer")

        # -------------------------
        # Footer
        # -------------------------
        st.markdown(
            "<div style='color:#aaaaaa;font-size:12px;text-align:center;margin-top:20px;'>© 2026 Zeek SOC Dashboard</div>",
            unsafe_allow_html=True
        )

    return st.session_state.sidebar_page