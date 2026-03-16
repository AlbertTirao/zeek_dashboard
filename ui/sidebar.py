import html
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
    "Logout",  # last (inside menu)
]

MENU_ICONS = [
    "pc-display",
    "activity",
    "file-earmark-text",
    "bell",
    "shield-lock",
    "people",
    "box-arrow-right",
]

DEFAULT_PAGE = MENU_OPTIONS[0]
SIDEBAR_COLLAPSE_STATE_KEY = "sidebar_collapsed"
SIDEBAR_EXPANDED_WIDTH_PX = 272
SIDEBAR_COLLAPSED_WIDTH_PX = 92
COLLAPSED_LABEL_TOKEN = "\u200b"


def _initials(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "U"
    parts = [p for p in name.split() if p]
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _collapsed_option_tokens(size: int) -> list[str]:
    return [COLLAPSED_LABEL_TOKEN * (i + 1) for i in range(size)]


def render_sidebar(auto_refresh_interval=3600, menu_options=None, menu_icons=None):
    options = menu_options or MENU_OPTIONS
    icons = menu_icons or MENU_ICONS
    collapsed = bool(st.session_state.get(SIDEBAR_COLLAPSE_STATE_KEY, False))

    if "sidebar_page" not in st.session_state or st.session_state.sidebar_page not in options:
        st.session_state.sidebar_page = DEFAULT_PAGE

    default_index = options.index(st.session_state.sidebar_page)

    # Profile info (best-effort from session)
    auth_user = st.session_state.get("auth_user") or st.session_state.get("user") or {}
    profile_name = str(
        auth_user.get("name")
        or st.session_state.get("current_name")
        or ""
    ).strip()
    if not profile_name:
        username_fallback = str(
            auth_user.get("username")
            or st.session_state.get("current_username")
            or ""
        ).strip()
        profile_name = username_fallback.split("@", 1)[0] if "@" in username_fallback else username_fallback
    if not profile_name:
        profile_name = "User"
    profile_role = (
        auth_user.get("role")
        or st.session_state.get("current_role")
        or st.session_state.get("role")
        or "Admin"
    )
    profile_name_safe = html.escape(str(profile_name))
    profile_role_safe = html.escape(str(profile_role))

    sidebar_width_px = SIDEBAR_COLLAPSED_WIDTH_PX if collapsed else SIDEBAR_EXPANDED_WIDTH_PX
    sidebar_block_padding = "0.22rem 0.56rem 0.68rem 0.56rem"
    toggle_justify = "center" if collapsed else "flex-end"
    st.markdown(
        f"""
        <style>
        section[data-testid="stSidebar"],
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child {{
            min-width: {sidebar_width_px}px !important;
            width: {sidebar_width_px}px !important;
            max-width: {sidebar_width_px}px !important;
        }}
        [data-testid="collapsedControl"],
        [data-testid="stSidebarCollapsedControl"],
        [data-testid="stSidebar"] [data-testid="baseButton-header"],
        [data-testid="stSidebar"] [data-testid="baseButton-headerNoPadding"],
        [data-testid="stSidebar"] button[kind="header"],
        [data-testid="stSidebar"] button[kind="headerNoPadding"],
        button[aria-label="Collapse sidebar"],
        button[aria-label="Expand sidebar"],
        [data-testid="stSidebar"] button[aria-label*="sidebar"],
        [data-testid="stSidebar"] button[title*="sidebar"] {{
            display: none !important;
            visibility: hidden !important;
            opacity: 0 !important;
            pointer-events: none !important;
        }}
        [data-testid="stSidebar"] .block-container{{
            padding: {sidebar_block_padding} !important;
        }}
        .st-key-sb_toggle {{
            display: flex;
            justify-content: {toggle_justify};
            align-items: center;
            width: 100%;
            margin: 0 0 0.55rem 0;
            padding: 0;
        }}
        .st-key-sb_toggle > div,
        .st-key-sb_toggle .stButton,
        .st-key-sb_toggle .st-key-sidebar_toggle_btn {{
            width: 100% !important;
            margin: 0 !important;
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: {toggle_justify} !important;
        }}
        .st-key-sb_toggle .stButton > button,
        .st-key-sb_toggle button {{
            min-height: 30px !important;
            width: 34px !important;
            height: 30px !important;
            padding: 0 !important;
            border-radius: 9px !important;
            border: 0 !important;
            background: #151a28 !important;
            color: #ffffff !important;
            font-weight: 800 !important;
            font-size: 18px !important;
            line-height: 1 !important;
            box-shadow: none !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            vertical-align: middle !important;
        }}
        .st-key-sb_toggle .stButton > button > div,
        .st-key-sb_toggle .stButton > button > div > p,
        .st-key-sb_toggle button > div,
        .st-key-sb_toggle button > div > p {{
            width: 100% !important;
            height: 100% !important;
            margin: 0 !important;
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            line-height: 1 !important;
        }}
        .st-key-sb_toggle .stButton > button:hover,
        .st-key-sb_toggle button:hover {{
            background: #151a28 !important;
            color: #ffffff !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    # --- Keep your exact color scheme ---
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

        section[data-testid="stSidebar"],
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child{
            background: var(--sb) !important;
            border-right: 0 !important;
            box-shadow: none !important;
        }

        [data-testid="stSidebar"] .block-container{
            background: var(--sb) !important;
        }

        [data-testid="stSidebar"] div,
        [data-testid="stSidebar"] aside{
            border: 0 !important;
            box-shadow: none !important;
        }

        /* Kill option_menu grey wrapper */
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

        [data-testid="stSidebar"] iframe[title="streamlit_option_menu.option_menu"],
        [data-testid="stSidebar"] iframe[title*="option_menu"]{
            background: var(--sb) !important;
            border: 0 !important;
            box-shadow: none !important;
        }

        [data-testid="stSidebar"] [data-testid="stCustomComponentV1"]{
            background: var(--sb) !important;
            border: 0 !important;
            box-shadow: none !important;
        }

        /* Profile header (no border ring) */
        .sb-profile{
            display:flex;
            align-items:center;
            gap:0.65rem;
            padding: 0.15rem 0 0.75rem 0;
        }
        .sb-profile-collapsed{
            display:flex;
            justify-content:center;
            padding: 0.05rem 0 0.6rem 0;
        }
        .sb-avatar{
            width: 42px;
            height: 42px;
            border-radius: 999px;
            border: 0 !important;
            outline: 0 !important;
            box-shadow: none !important;
            background: rgba(255,255,255,0.08);
            display:flex;
            align-items:center;
            justify-content:center;
            overflow:hidden;
            flex: 0 0 42px;
        }
        .sb-initials{
            color: var(--sb-text);
            font-weight: 800;
            letter-spacing: 0.4px;
            font-size: 0.95rem;
        }
        .sb-name{
            color: var(--sb-text);
            font-weight: 800;
            font-size: 0.95rem;
            margin: 0;
            line-height: 1.1;
        }
        .sb-role{
            color: rgba(255,255,255,0.70);
            font-weight: 600;
            font-size: 0.78rem;
            margin-top: 0.15rem;
        }
        .sb-divider{
            height: 1px;
            background: rgba(255,255,255,0.08);
            margin: 0.2rem 0 0.6rem 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if collapsed:
        nav_link_style = {
            "background-color": "#151a28",
            "color": "rgba(255,255,255,0.88)",
            "margin": "0.14rem 0",
            "padding": "0.68rem 0.22rem",
            "border-radius": "10px",
            "border": "0",
            "font-size": "0px",
            "display": "flex",
            "justify-content": "center",
            "align-items": "center",
        }
        nav_link_selected_style = {
            "background-color": "rgba(255,255,255,0.10)",
            "color": "#ffffff",
            "font-weight": "800",
            "border-radius": "10px",
            "border": "0",
            "font-size": "0px",
            "display": "flex",
            "justify-content": "center",
            "align-items": "center",
        }
        icon_style = {"color": "#ffffff", "font-size": "18px", "margin-right": "0"}
    else:
        nav_link_style = {
            "background-color": "#151a28",
            "color": "rgba(255,255,255,0.88)",
            "margin": "0.18rem 0",
            "padding": "0.68rem 0.62rem 0.68rem 0.72rem",
            "border-radius": "12px",
            "border": "0",
        }
        nav_link_selected_style = {
            "background-color": "rgba(255,255,255,0.10)",
            "color": "#ffffff",
            "font-weight": "800",
            "border-radius": "12px",
            "border": "0",
        }
        icon_style = {"color": "#ffffff", "font-size": "16px", "margin-right": "8px"}

    display_options = options
    selected_value_to_page = {name: name for name in options}
    if collapsed:
        collapsed_tokens = _collapsed_option_tokens(len(options))
        display_options = collapsed_tokens
        selected_value_to_page = dict(zip(collapsed_tokens, options))

    with st.sidebar:
        with st.container(key="sb_toggle"):
            toggle_label = "☰"
            if st.button(toggle_label, key="sidebar_toggle_btn"):
                st.session_state[SIDEBAR_COLLAPSE_STATE_KEY] = not collapsed
                st.rerun()

        if collapsed:
            st.markdown(
                f"""
                <div class="sb-profile-collapsed">
                    <div class="sb-avatar"><div class="sb-initials">{_initials(str(profile_name))}</div></div>
                </div>
                <div class="sb-divider"></div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="sb-profile">
                    <div class="sb-avatar"><div class="sb-initials">{_initials(str(profile_name))}</div></div>
                    <div>
                        <div class="sb-name">{profile_name_safe}</div>
                        <div class="sb-role">{profile_role_safe}</div>
                    </div>
                </div>
                <div class="sb-divider"></div>
                """,
                unsafe_allow_html=True,
            )

        selected_value = option_menu(
            menu_title=None,
            options=display_options,
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
                "nav-link": nav_link_style,
                "nav-link-selected": nav_link_selected_style,
                "icon": icon_style,
            },
            key="sidebar_option_menu",
        )

        page = selected_value_to_page.get(selected_value, st.session_state.sidebar_page)

        # Keep auto-refresh timer optional so app-level background refresh can own it.
        if int(auto_refresh_interval or 0) > 0:
            st_autorefresh(interval=int(auto_refresh_interval) * 1000, key="auto_refresh_timer")

    st.session_state.sidebar_page = page
    return page
