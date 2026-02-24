import pandas as pd
import streamlit as st
from datetime import datetime

from services import auth_service
from .header_layout import inject_traffic_style_header_css, render_traffic_style_header


def _inject_user_management_css() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@500;700;800&display=swap');

        :root {
            /* === Devices theme (shared) === */
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
            --accent-red: #F63049;

            /* === UM aliases (keep existing class rules readable) === */
            --um-panel-border: var(--panel-border);
            --um-panel-bg: rgba(255,255,255,0.035);
            --um-panel-shadow: 0 16px 45px rgba(0,0,0,0.28);
            --um-accent: var(--accent-cyan);
        }

        html, body, [class*="css"] {
            font-family: 'Manrope', sans-serif;
        }

        /* Match Devices page background */
        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        /* Match Devices page container spacing */
        .block-container,
        .main .block-container,
        [data-testid="stMainBlockContainer"] {
            padding-top: 0 !important;
            padding-bottom: 1.05rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }

        [data-testid="stAppViewContainer"] > .main,
        [data-testid="stAppViewContainer"] .main,
        section.main {
            padding-left: 0 !important;
            padding-right: 0 !important;
            margin-left: 0 !important;
            margin-right: 0 !important;
            max-width: 100% !important;
        }

        /* --- User Management cards --- */
        .um-metric-card {
            height: 120px;
            padding: 15px;
            border-radius: 18px;
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
            background: var(--um-panel-bg);
            border-radius: 18px;
            padding: 16px;
            box-shadow: var(--panel-shadow);
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

        /* --- Table container (match Devices grid-card) --- */
        .um-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-top: 0.5rem;
        }

        /* Data editor uses stDataFrame markup under the hood */
        .um-table-shell [data-testid="stDataFrame"] {
            border: 1px solid #2A466E !important;
            border-radius: 10px !important;
            overflow: hidden !important;
            background: #061120 !important;
        }

        .um-table-shell [data-testid="stDataFrame"] table {
            background: #050B16 !important;
            color: #EAEAEA !important;
        }

        .um-table-shell [data-testid="stDataFrame"] thead tr th {
            background: #0A1730 !important;
            color: #EAF2FF !important;
            border-bottom: 1px solid #29406A !important;
        }

        .um-table-shell [data-testid="stDataFrame"] tbody tr:nth-child(odd) td {
            background: #071224 !important;
        }

        .um-table-shell [data-testid="stDataFrame"] tbody tr:nth-child(even) td {
            background: #050E1D !important;
        }

        .um-table-shell [data-testid="stDataFrame"] tbody tr td {
            color: #EAEAEA !important;
            border-color: #13233D !important;
        }

        /* Dialog surface (match Devices) */
        div[data-testid="stDialog"] > div {
            border: 1px solid rgba(255,255,255,0.16);
            border-radius: 20px;
            background:
                radial-gradient(700px 260px at 0% 0%, rgba(0,247,255,0.08), transparent 45%),
                linear-gradient(165deg, rgba(7,18,38,0.98), rgba(5,12,26,0.98));
            box-shadow: 0 20px 48px rgba(0,0,0,0.45);
        }

        div[data-testid="stDialog"] .block-container {
            padding-top: 0.45rem !important;
            padding-bottom: 0.55rem !important;
            padding-left: 0.25rem !important;
            padding-right: 0.25rem !important;
            max-width: 100% !important;
        }

        /* Inputs/buttons corner radius (match Devices) */
        div[data-testid="stTextInput"] input { border-radius: 14px !important; }
        div[data-testid="stSelectbox"] > div { border-radius: 14px !important; }
        button { border-radius: 14px !important; }

        /* ---- Password toggle icon fix (keep Streamlit design, correct state) ---- */
        div[data-baseweb="input"] button[aria-label*="Show password"],
        div[data-baseweb="input"] button[aria-label*="Hide password"],
        div[data-baseweb="input"] button[title*="Show password"],
        div[data-baseweb="input"] button[title*="Hide password"] {
            position: relative;
        }

        div[data-baseweb="input"] button[aria-label*="Show password"] svg,
        div[data-baseweb="input"] button[aria-label*="Hide password"] svg,
        div[data-baseweb="input"] button[title*="Show password"] svg,
        div[data-baseweb="input"] button[title*="Hide password"] svg {
            display: none !important;
        }

        div[data-baseweb="input"] button[aria-label*="Hide password"]::before,
        div[data-baseweb="input"] button[title*="Hide password"]::before {
            content: "";
            width: 18px;
            height: 18px;
            display: block;
            background: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI0VBRjJGRiI+PHBhdGggZD0iTTEyIDQuNUM3IDQuNSAyLjczIDcuNjEgMSAxMmMxLjczIDQuMzkgNiA3LjUgMTEgNy41czkuMjctMy4xMSAxMS03LjVjLTEuNzMtNC4zOS02LTcuNS0xMS03LjV6bTAgMTIuNWMtMi43NiAwLTUtMi4yNC01LTVzMi4yNC01IDUtNSA1IDIuMjQgNSA1LTIuMjQgNS01IDV6bTAtOGMtMS42NiAwLTMgMS4zNC0zIDNzMS4zNCAzIDMgMyAzLTEuMzQgMy0zLTEuMzQtMy0zLTN6Ii8+PC9zdmc+") center/18px 18px no-repeat;
        }

        div[data-baseweb="input"] button[aria-label*="Show password"]::before,
        div[data-baseweb="input"] button[title*="Show password"]::before {
            content: "";
            width: 18px;
            height: 18px;
            display: block;
            background: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI0VBRjJGRiI+PHBhdGggZD0iTTEyIDYuNWMzLjMgMCA2LjEgMS43IDcuOCA0LjUtLjcgMS4yLTEuNyAyLjItMi45IDNsMS40IDEuNGMxLjUtMS4xIDIuNy0yLjUgMy41LTQuNC0xLjczLTQuMzktNi03LjUtMTEtNy41LTEuNCAwLTIuNy4yLTQgLjZsMS43IDEuN2MuNy0uMiAxLjUtLjMgMi41LS4zem0tMTAtNC4xIDIuMyAyLjMuNS41QzMuNCA2LjYgMi4zIDkuMSAxIDEyYzEuNzMgNC4zOSA2IDcuNSAxMSA3LjUgMS43IDAgMy4zLS4zIDQuOC0uOGwuNC40IDIuOSAyLjkgMS4zLTEuM0wzLjMgMS4xIDIgMi40em01LjEgNS4xIDEuNSAxLjVjLS40LjctLjYgMS41LS42IDIuNSAwIDIuNzYgMi4yNCA1IDUgNSAxIDAgMS44LS4yIDIuNS0uNmwxLjUgMS41Yy0xLjEuNS0yLjMuOC00IC44LTMuMyAwLTYuMS0xLjctNy44LTQuNS45LTEuNiAyLjMtMi45IDMuOS0zLjd6bTQuOSA0LjkgMS43IDEuN2MtLjUuMi0xIC4zLTEuNy4zLTEuNjYgMC0zLTEuMzQtMy0zIDAtLjYuMS0xLjIuMy0xLjdsMS43IDEuN2MwIC4zLS4xLjQtLjEuNiAwIC42LjQgMSAxIDEgLjIgMCAuMyAwIC42LS4xeiIvPjwvc3ZnPg==") center/18px 18px no-repeat;
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


def _with_row_numbers(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy().reset_index(drop=True)
    out.insert(0, "#", pd.Series(range(1, len(out) + 1), dtype="int64"))
    return out


@st.dialog("Edit User")
def _render_edit_user_dialog(
    target_username: str,
    current_username: str,
) -> None:
    users = auth_service.list_users()
    user_map = {str(u.get("username", "")).strip().lower(): u for u in users}
    target = (target_username or "").strip().lower()
    current = (current_username or "").strip().lower()

    if target not in user_map:
        st.error("Selected user no longer exists.")
        if st.button("Close", use_container_width=True):
            st.session_state.pop("um_edit_target", None)
            st.rerun()
        return

    with st.form("um_edit_user_modal_form", clear_on_submit=False):
        new_username = st.text_input("E-mail", value=target, placeholder="name@gmail.com")
        new_password = st.text_input(
            "New Password",
            type="password",
            placeholder="Leave blank to keep current password",
        )
        st.caption("If set, password must be at least 8 characters and include a special character.")
        submit = st.form_submit_button("Save User Changes", use_container_width=True)

    if submit:
        try:
            clean_new_username = (new_username or "").strip().lower()
            auth_service.update_user(
                username=target,
                new_username=clean_new_username,
                password=(new_password.strip() if new_password.strip() else None),
            )

            if target == current and clean_new_username != current:
                if "auth_user" in st.session_state and isinstance(st.session_state["auth_user"], dict):
                    st.session_state["auth_user"]["username"] = clean_new_username

            st.success("User updated successfully.")
            st.rerun()
        except Exception as e:
            st.error(str(e))

    if st.button("Cancel", use_container_width=True, key="um_edit_cancel"):
        st.rerun()


def render(current_username: str):
    _inject_user_management_css()
    inject_traffic_style_header_css()

    users = auth_service.list_users()
    total_users = len(users)
    admin_count = sum(1 for u in users if str(u.get("role", "")).lower() == "admin")
    staff_count = sum(1 for u in users if str(u.get("role", "")).lower() == "staff")

    updated_txt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    render_traffic_style_header(
        title="User Management",
        subtitle="Admin-only controls for account provisioning and access governance",
        chip_label="Identity Access",
        updated_txt=updated_txt,
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
        username = st.text_input("E-mail", placeholder="name@gmail.com")
        password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 8 characters and 1 special character",
        )
        st.caption("Only @gmail.com e-mail accounts are allowed.")
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
        table_rows = []
        for row in users:
            username = str(row.get("username", "")).strip().lower()
            table_rows.append(
                {
                    "Username": username,
                    "Role": str(row.get("role", "staff")).strip().lower(),
                    "Created By": str(row.get("created_by", "") or ""),
                    "Created At": str(row.get("created_at", "") or ""),
                    "Last Login": str(row.get("last_login_at", "") or ""),
                    "Edit": False,
                }
            )

        df = pd.DataFrame(table_rows)
        editor_df = _with_row_numbers(
            df[["Username", "Role", "Created By", "Created At", "Last Login", "Edit"]].copy()
        )
        # Fit the table to actual rows so empty visual rows are not shown.
        table_height = min(420, max(140, 40 * (len(editor_df) + 1)))

        st.markdown("<div class='um-table-shell'>", unsafe_allow_html=True)
        edited_df = st.data_editor(
            editor_df,
            num_rows="fixed",
            use_container_width=True,
            hide_index=True,
            key="um_user_editor_v2",
            column_config={
                "#": st.column_config.NumberColumn("#", disabled=True, width="small"),
                "Username": st.column_config.TextColumn("Username", disabled=True, width="medium"),
                "Role": st.column_config.SelectboxColumn("Role", options=["staff", "admin"], required=True),
                "Created By": st.column_config.TextColumn("Created By", disabled=True, width="medium"),
                "Created At": st.column_config.TextColumn("Created At", disabled=True, width="medium"),
                "Last Login": st.column_config.TextColumn("Last Login", disabled=True, width="medium"),
                "Edit": st.column_config.CheckboxColumn(
                    "Edit",
                    help="Tick one user to open edit modal.",
                    width="small",
                ),
            },
            height=table_height,
        )
        st.markdown("</div>", unsafe_allow_html=True)

        st.caption("Tip: Tick Edit to open modal for username/password, then click Save Changes for role updates.")

        edit_candidates = []
        for row in edited_df.to_dict("records"):
            if bool(row.get("Edit", False)):
                username = str(row.get("Username", "")).strip().lower()
                if username:
                    edit_candidates.append(username)

        current_edit_set = sorted(set(edit_candidates))
        if "um_prev_edit_users" not in st.session_state:
            st.session_state["um_prev_edit_users"] = current_edit_set
        else:
            prev_edit_set = set(st.session_state.get("um_prev_edit_users", []))
            newly_checked = [u for u in current_edit_set if u not in prev_edit_set]
            if newly_checked:
                st.session_state["um_edit_target"] = newly_checked[0]
            st.session_state["um_prev_edit_users"] = current_edit_set

        if st.button("Save Changes", use_container_width=True, key="save_user_table_changes"):
            try:
                if "#" in edited_df.columns:
                    edited_df = edited_df.drop(columns=["#"], errors="ignore")

                updated_rows = {}
                for row in edited_df.to_dict("records"):
                    username = str(row.get("Username", "")).strip().lower()
                    if not username:
                        continue

                    role_value = str(row.get("Role", "staff")).strip().lower()
                    if role_value not in {"admin", "staff"}:
                        raise ValueError(f"Invalid role for '{username}'.")

                    updated_rows[username] = {
                        "role": role_value,
                    }

                before_map = {
                    str(u.get("username", "")).strip().lower(): {
                        "role": str(u.get("role", "staff")).strip().lower(),
                        "is_active": bool(u.get("is_active", True)),
                    }
                    for u in users
                }

                before_usernames = set(before_map.keys())
                after_usernames = set(updated_rows.keys())
                deleted_usernames = before_usernames - after_usernames
                common_usernames = before_usernames & after_usernames

                clean_current_user = (current_username or "").strip().lower()
                if clean_current_user in deleted_usernames:
                    raise ValueError("You cannot delete your own account.")

                final_admin_count = 0
                for username in after_usernames:
                    role_value = updated_rows[username]["role"]
                    if role_value == "admin":
                        final_admin_count += 1
                if final_admin_count == 0:
                    raise ValueError("At least one admin account must remain.")

                for username in sorted(deleted_usernames):
                    auth_service.delete_user(username=username)

                for username in sorted(common_usernames):
                    before = before_map[username]
                    after = updated_rows[username]
                    if before["role"] != after["role"]:
                        auth_service.update_user(
                            username=username,
                            role=after["role"],
                        )

                st.success("User table updated successfully.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        edit_target = st.session_state.pop("um_edit_target", None)
        if edit_target:
            _render_edit_user_dialog(
                target_username=str(edit_target),
                current_username=current_username,
            )
    else:
        st.info("No accounts available.")

    st.markdown("</div>", unsafe_allow_html=True)
