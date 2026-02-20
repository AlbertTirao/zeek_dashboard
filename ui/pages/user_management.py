import pandas as pd
import streamlit as st

from services import auth_service


def _inject_user_management_css() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@500;700;800&display=swap');

        :root {
            --um-panel-border: rgba(255, 255, 255, 0.14);
            --um-panel-bg: rgba(255, 255, 255, 0.035);
            --um-panel-shadow: 0 16px 42px rgba(0, 0, 0, 0.28);
            --um-accent: #00f7ff;
        }

        html, body, [class*="css"] {
            font-family: 'Manrope', sans-serif;
        }

        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0.15rem !important;
            padding-bottom: 1rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }

        .um-page-header {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 18px;
            margin-top: 15px;
            margin-bottom: 14px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid var(--um-panel-border);
            background:
                radial-gradient(circle at top right, rgba(0, 247, 255, 0.08), transparent 40%),
                linear-gradient(135deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.015));
            box-shadow: var(--um-panel-shadow);
        }

        .um-title {
            font-size: 44px;
            font-weight: 800;
            line-height: 1.0;
            letter-spacing: -0.5px;
        }

        .um-sub {
            opacity: 0.78;
            font-size: 13px;
            margin-top: 6px;
        }

        .um-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.05);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .um-chip-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--um-accent);
            box-shadow: 0 0 10px rgba(0, 247, 255, 0.8);
        }

        .um-metric-card {
            height: 120px;
            padding: 15px;
            border-radius: 16px;
            border: 1px solid var(--um-panel-border);
            background: var(--um-panel-bg);
            box-shadow: var(--um-panel-shadow);
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
        }

        .um-metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.07em;
            opacity: 0.76;
        }

        .um-metric-value {
            margin-top: 6px;
            font-size: 35px;
            font-weight: 800;
            line-height: 1.0;
            letter-spacing: -0.4px;
        }

        .um-metric-note {
            margin-top: auto;
            font-size: 12px;
            opacity: 0.62;
        }

        .um-card {
            border: 1px solid var(--um-panel-border);
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.04), rgba(255, 255, 255, 0.015));
            border-radius: 16px;
            padding: 16px;
            box-shadow: var(--um-panel-shadow);
        }

        .um-card-title {
            font-size: 19px;
            font-weight: 800;
            margin-bottom: 3px;
            letter-spacing: -0.2px;
        }

        .um-card-sub {
            font-size: 12px;
            opacity: 0.72;
            margin-bottom: 10px;
        }

        .um-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2, 6, 23, 0.52), rgba(2, 6, 23, 0.34));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-top: 0.5rem;
        }

        .um-table-shell [data-testid="stDataFrame"] {
            border: 1px solid #2a466e !important;
            border-radius: 10px !important;
            overflow: hidden !important;
        }

        .um-table-shell [data-testid="stDataFrame"] table {
            background: #050b16 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_metric_card(label: str, value: str, note: str) -> None:
    st.markdown(
        f"""
        <div class="um-metric-card">
            <div class="um-metric-label">{label}</div>
            <div class="um-metric-value">{value}</div>
            <div class="um-metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render(current_username: str):
    _inject_user_management_css()

    users = auth_service.list_users()
    total_users = len(users)
    admin_count = sum(1 for u in users if str(u.get("role", "")).lower() == "admin")
    staff_count = sum(1 for u in users if str(u.get("role", "")).lower() == "staff")

    st.markdown(
        """
        <div class="um-page-header">
          <div>
            <div class="um-title">User Management</div>
            <div class="um-sub">Admin-only controls for account provisioning and access governance.</div>
          </div>
          <div class="um-chip"><span class="um-chip-dot"></span>Identity Access</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    m1, m2, m3 = st.columns(3, gap="large")
    with m1:
        _render_metric_card("Total Accounts", str(total_users), "All users in the authentication store")
    with m2:
        _render_metric_card("Admins", str(admin_count), "Privileged administrators")
    with m3:
        _render_metric_card("Staff", str(staff_count), "Operational dashboard users")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    st.markdown("<div class='um-card'>", unsafe_allow_html=True)
    st.markdown("<div class='um-card-title'>Create User</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='um-card-sub'>Provision a new account with role-based access.</div>",
        unsafe_allow_html=True,
    )

    with st.form("create_user_form", clear_on_submit=True):
        username = st.text_input("Username", placeholder="e.g. analyst1")
        password = st.text_input("Password", type="password", placeholder="At least 8 characters")
        role = st.selectbox("Role", options=["staff", "admin"], index=0)
        submit_create = st.form_submit_button("Create User", use_container_width=True)

    if submit_create:
        try:
            auth_service.create_user(
                username=username,
                password=password,
                role=role,
                created_by=current_username,
            )
            st.success(f"User '{username.strip().lower()}' created.")
            st.rerun()
        except Exception as e:
            st.error(str(e))

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='um-card'>", unsafe_allow_html=True)
    st.markdown("<div class='um-card-title'>Accounts</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='um-card-sub'>Live user directory with role and login history.</div>",
        unsafe_allow_html=True,
    )

    if users:
        df = pd.DataFrame(users)
        df = df.rename(
            columns={
                "username": "Username",
                "role": "Role",
                "is_active": "Status",
                "created_by": "Created By",
                "created_at": "Created At",
                "last_login_at": "Last Login",
            }
        )
        df["Status"] = df["Status"].map({True: "Active", False: "Inactive"})

        st.markdown("<div class='um-table-shell'>", unsafe_allow_html=True)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No accounts available.")

    st.markdown("</div>", unsafe_allow_html=True)
