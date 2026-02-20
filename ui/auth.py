import streamlit as st
from pathlib import Path
import base64

from services.auth_service import authenticate_user


def current_user():
    user = st.session_state.get("auth_user")
    return user if isinstance(user, dict) else None


def is_authenticated() -> bool:
    return current_user() is not None


def require_authentication() -> None:
    if is_authenticated():
        return

    bg_image_path = Path(__file__).resolve().parent / "pages" / "Pic" / "bg.png"
    bg_image_data = ""
    if bg_image_path.exists():
        bg_image_data = base64.b64encode(bg_image_path.read_bytes()).decode("utf-8")

    right_panel_style = ""
    if bg_image_data:
        right_panel_style = (
            f"background-image: linear-gradient(0deg, rgba(3, 10, 28, 0.72), "
            f"rgba(3, 10, 28, 0.72)), url('data:image/png;base64,{bg_image_data}');"
        )

    st.markdown(
        f"""
        <style>
            .stApp {{
                background:
                    radial-gradient(circle at 14% 18%, rgba(0, 44, 104, 0.24) 0%, rgba(0, 18, 48, 0) 34%),
                    radial-gradient(circle at 86% 84%, rgba(0, 58, 138, 0.20) 0%, rgba(0, 18, 48, 0) 36%),
                    #020913;
            }}
            [data-testid="stSidebar"],
            [data-testid="collapsedControl"] {{
                display: none !important;
            }}
            section.main > div {{
                max-width: 1240px;
                padding-top: 2.0rem;
                padding-bottom: 2.0rem;
                margin-left: auto;
                margin-right: auto;
            }}
            [data-testid="stMainBlockContainer"] {{
                max-width: 1240px !important;
                padding-top: 2.0rem !important;
                padding-bottom: 2.0rem !important;
                width: 100% !important;
                margin-left: auto !important;
                margin-right: auto !important;
                min-height: calc(100vh - 7.2rem) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
            }}
            .st-key-login_shell {{
                border: 1px solid rgba(112, 146, 205, 0.30);
                border-radius: 20px;
                overflow: hidden;
                background: linear-gradient(180deg, rgba(2, 11, 32, 0.95), rgba(1, 9, 24, 0.96));
                box-shadow: 0 18px 60px rgba(0, 0, 0, 0.38);
                padding: 0.35rem;
                width: 100%;
                max-width: 1120px;
                margin: 0 auto;
            }}
            .st-key-login_form_panel {{
                min-height: 560px;
                max-width: 460px;
                margin: 0 auto;
                padding: 1.2rem 1rem;
                border: 1px solid rgba(112, 146, 205, 0.36);
                border-radius: 16px;
                padding: 1.25rem 1.25rem 1.35rem 1.25rem;
                background: linear-gradient(180deg, rgba(14, 24, 44, 0.72), rgba(7, 14, 29, 0.72));
                backdrop-filter: blur(3px);
            }}
            .st-key-login_image_panel {{
                min-height: 560px;
                background-color: #091223;
                background-repeat: no-repeat;
                background-size: cover;
                background-position: right center;
                border-radius: 14px;
                border: 1px solid rgba(112, 146, 205, 0.25);
                {right_panel_style}
            }}
            .st-key-login_form_panel h1 {{
                margin: 0 0 0.2rem 0;
                font-size: 1.9rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                color: #eef4ff;
            }}
            .st-key-login_form_panel p {{
                margin: 0 0 1rem 0;
                color: #b3c4e2;
                font-size: 0.95rem;
            }}
            .st-key-login_form_panel label {{
                color: #d5e1f7;
                font-weight: 600;
                letter-spacing: 0.01em;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div {{
                border: 1px solid rgba(148, 176, 219, 0.35);
                border-radius: 14px;
                background: rgba(239, 244, 255, 0.14);
                min-height: 48px;
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }}
            .st-key-login_form_panel div[data-baseweb="input"] > div:focus-within {{
                border-color: rgba(140, 182, 255, 0.85);
                box-shadow: 0 0 0 1px rgba(140, 182, 255, 0.45);
            }}
            .st-key-login_form_panel input {{
                color: #f0f5ff !important;
            }}
            .st-key-login_form_panel input::placeholder {{
                color: rgba(225, 236, 255, 0.64) !important;
            }}
            .st-key-login_form_panel button[kind="formSubmit"] {{
                margin-top: 0.35rem;
                min-height: 48px;
                border-radius: 12px;
                border: 1px solid rgba(160, 188, 228, 0.4);
                background: linear-gradient(180deg, rgba(8, 20, 43, 0.95), rgba(4, 13, 31, 0.95));
                color: #eef5ff;
                font-weight: 700;
                letter-spacing: 0.03em;
            }}
            .st-key-login_form_panel button[kind="formSubmit"]:hover {{
                border-color: rgba(175, 204, 242, 0.62);
            }}
            @media (max-width: 980px) {{
                [data-testid="stMainBlockContainer"] {{
                    min-height: auto !important;
                    display: block !important;
                }}
                .st-key-login_form_panel {{
                    min-height: auto;
                    max-width: 100%;
                    padding: 0.9rem 0.8rem;
                }}
                .st-key-login_image_panel {{
                    min-height: 300px;
                }}
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.container(key="login_shell"):
        col_form, col_image = st.columns([1, 1.18], gap="small")
        with col_form:
            with st.container(key="login_form_panel"):
                st.markdown("<h1>Log In</h1><p>Sign in with your assigned account.</p>", unsafe_allow_html=True)
                with st.form("login_form", clear_on_submit=False):
                    username = st.text_input("E-mail", placeholder="Enter your e-mail")
                    password = st.text_input("Password", type="password", placeholder="Password")
                    submitted = st.form_submit_button("LOG IN", use_container_width=True)
        with col_image:
            with st.container(key="login_image_panel"):
                st.markdown("&nbsp;", unsafe_allow_html=True)

    if submitted:
        try:
            user = authenticate_user(username=username, password=password)
        except Exception as e:
            st.error("Login service is unavailable.")
            st.caption(
                "Check AUTH_DATABASE_URL / DATABASE_URL and database connectivity."
            )
            st.code(str(e))
            st.stop()

        if user is None:
            st.error("Invalid username or password.")
            st.stop()
        st.session_state.auth_user = {
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
        }
        st.rerun()
    st.stop()


def require_role(*allowed_roles: str) -> None:
    user = current_user()
    if not user:
        st.error("Login is required.")
        st.stop()
    if user.get("role") not in set(allowed_roles):
        st.error("You do not have permission to access this page.")
        st.stop()

