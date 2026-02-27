import pandas as pd
import streamlit as st
from datetime import datetime

from services import auth_service
from .header_layout import inject_traffic_style_header_css, render_traffic_style_header

try:
    from st_aggrid import AgGrid, DataReturnMode, GridOptionsBuilder, GridUpdateMode, JsCode
except Exception:  # pragma: no cover - optional dependency at runtime
    AgGrid = None
    DataReturnMode = None
    GridOptionsBuilder = None
    GridUpdateMode = None
    JsCode = None


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


def _aggrid_payload_to_df(payload) -> pd.DataFrame:
    if isinstance(payload, pd.DataFrame):
        return payload.copy()
    if isinstance(payload, list):
        return pd.DataFrame(payload)
    return pd.DataFrame()


def _user_table_aggrid_theme_and_css() -> tuple[str, dict]:
    custom_css = {
        ".ag-root-wrapper": {
            "background-color": "#061120",
            "color": "#EAF2FF",
            "border": "1px solid #2A466E",
        },
        ".ag-header": {
            "background-color": "#0A1730",
            "color": "#EAF2FF",
            "border-bottom": "1px solid #29406A",
        },
        ".ag-header-cell, .ag-header-group-cell": {
            "background-color": "#0A1730",
            "color": "#EAF2FF",
            "border-right": "1px solid #20365A",
        },
        ".ag-header-cell-label": {
            "font-weight": "800",
            "letter-spacing": "0.02em",
        },
        ".ag-cell": {
            "background-color": "#050B16",
            "color": "#EAEAEA",
            "border-color": "#13233D",
            "display": "flex",
            "align-items": "center",
        },
        ".ag-row-odd": {
            "background-color": "#071224",
        },
        ".ag-row-even": {
            "background-color": "#050E1D",
        },
        ".ag-row-hover": {
            "background-color": "#0F203D",
        },
        ".ag-row-selected": {
            "background-color": "#102540",
        },
        ".ag-cell[col-id='Action']": {
            "justify-content": "center",
        },
        ".ag-header-cell[col-id='Action'] .ag-header-cell-label": {
            "justify-content": "center",
        },
        ".ag-header-cell[col-id='Action'] .ag-header-cell-text": {
            "font-size": "17px",
            "font-weight": "800",
        },
        ".ag-center-cols-viewport": {
            "overflow-x": "hidden !important",
        },
    }
    return "alpine-dark", custom_css


_UM_ACTION_CELL_STYLE = (
    JsCode(
        """
        function() {
            return {
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                textAlign: 'center',
                fontSize: '22px',
                lineHeight: '1',
                letterSpacing: '0.12em',
                color: '#F6FAFF',
                cursor: 'pointer',
                paddingTop: '3px',
                paddingBottom: '3px'
            };
        }
        """
    )
    if JsCode
    else None
)

_UM_ACTION_CLICK_JS = (
    JsCode(
        """
        function(params) {
            if (!params || !params.column || !params.event) return;
            const colId = params.column.getColId ? params.column.getColId() : '';
            if (colId !== 'Action') return;

            const username = ((params.data && params.data.Username) || '').toString().trim().toLowerCase();
            if (!username) return;

            let actionType = 'edit';
            let cellEl = null;
            if (params.event.target && params.event.target.closest) {
                cellEl = params.event.target.closest('.ag-cell');
            }
            if (cellEl && cellEl.getBoundingClientRect) {
                const rect = cellEl.getBoundingClientRect();
                const clickX = params.event.clientX - rect.left;
                if (clickX > (rect.width * 0.5)) {
                    actionType = 'delete';
                }
            }

            const token = actionType + '|' + username + '|' + Date.now().toString();
            if (params.node && params.node.setDataValue) {
                params.node.setDataValue('_ActionToken', token);
            } else if (params.setValue) {
                params.setValue(token);
            }
        }
        """
    )
    if JsCode
    else None
)


@st.dialog("Delete User")
def _render_delete_user_dialog(target_username: str, current_username: str) -> None:
    users = auth_service.list_users()
    user_map = {str(u.get("username", "")).strip().lower(): u for u in users}
    target = (target_username or "").strip().lower()
    current = (current_username or "").strip().lower()

    if target not in user_map:
        st.error("Selected user no longer exists.")
        if st.button("Close", use_container_width=True, key="um_delete_missing_close"):
            st.session_state.pop("um_delete_target", None)
            st.rerun()
        return

    target_role = str(user_map[target].get("role", "staff")).strip().lower()
    st.warning(f"Delete user '{target}'? This action cannot be undone.")
    if target_role == "admin":
        st.caption("This account currently has admin role.")

    c1, c2 = st.columns(2, gap="small")
    with c1:
        do_delete = st.button(
            "Delete User",
            use_container_width=True,
            key=f"um_confirm_delete_{target}",
            type="primary",
        )
    with c2:
        cancel = st.button(
            "Cancel",
            use_container_width=True,
            key=f"um_cancel_delete_{target}",
        )

    if do_delete:
        try:
            if target == current:
                raise ValueError("You cannot delete your own account.")

            admin_count = sum(1 for u in users if str(u.get("role", "")).strip().lower() == "admin")
            if target_role == "admin" and admin_count <= 1:
                raise ValueError("At least one admin account must remain.")

            auth_service.delete_user(username=target)
            st.session_state.pop("um_delete_target", None)
            st.success("User deleted successfully.")
            st.rerun()
        except Exception as e:
            st.error(str(e))

    if cancel:
        st.session_state.pop("um_delete_target", None)
        st.rerun()


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

    current_name = str(user_map[target].get("name", "") or "").strip()

    with st.form("um_edit_user_modal_form", clear_on_submit=False):
        new_name = st.text_input("Name", value=current_name, placeholder="Full name")
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
            clean_new_name = " ".join(str(new_name or "").strip().split())
            clean_new_username = (new_username or "").strip().lower()
            auth_service.update_user(
                username=target,
                name=clean_new_name,
                new_username=clean_new_username,
                password=(new_password.strip() if new_password.strip() else None),
            )

            if target == current:
                if "auth_user" in st.session_state and isinstance(st.session_state["auth_user"], dict):
                    st.session_state["auth_user"]["name"] = clean_new_name
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

    if AgGrid is None:
        st.error("streamlit-aggrid is required for the Action column UI.")
        return

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
        name = st.text_input("Name", placeholder="Full name")
        username = st.text_input("E-mail", placeholder="name@gmail.com")
        password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 8 characters and 1 special character",
        )
        st.caption("Name is required. Only @gmail.com e-mail accounts are allowed.")
        role = st.selectbox("Role", options=["staff", "admin"], index=0)
        submit_create = st.form_submit_button("Create User", use_container_width=True)

    if submit_create:
        try:
            auth_service.create_user(
                name=name,
                username=username,
                password=password,
                role=role,
                created_by=current_username,
            )
            created_name = " ".join(str(name or "").strip().split())
            st.success(f"User '{created_name or username.strip().lower()}' created.")
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
            display_name = str(row.get("name", "") or "").strip()
            username = str(row.get("username", "")).strip().lower()
            table_rows.append(
                {
                    "Name": display_name,
                    "Username": username,
                    "Role": str(row.get("role", "staff")).strip().lower(),
                    "Created By": str(row.get("created_by", "") or ""),
                    "Created At": str(row.get("created_at", "") or ""),
                    "Last Login": str(row.get("last_login_at", "") or ""),
                }
            )

        df = pd.DataFrame(table_rows)
        editor_df = _with_row_numbers(df[["Name", "Username", "Role", "Created By", "Created At", "Last Login"]].copy())
        editor_df["Action"] = "✎  🗑"
        editor_df["_ActionToken"] = ""
        # Fit the table to actual rows so empty visual rows are not shown.
        table_height = min(520, max(170, 52 * (len(editor_df) + 1)))

        st.markdown("<div class='um-table-shell'>", unsafe_allow_html=True)
        gb = GridOptionsBuilder.from_dataframe(editor_df)
        gb.configure_default_column(
            sortable=True,
            filter=True,
            resizable=True,
            minWidth=95,
            editable=False,
        )
        gb.configure_column("#", header_name="#", width=56, pinned="left", suppressMovable=True)
        gb.configure_column("Name", minWidth=180, flex=1.2, editable=False, tooltipField="Name")
        gb.configure_column("Username", minWidth=220, flex=1.4, editable=False, tooltipField="Username")
        gb.configure_column(
            "Role",
            width=110,
            editable=True,
            cellEditor="agSelectCellEditor",
            cellEditorParams={"values": ["staff", "admin"]},
            singleClickEdit=True,
        )
        gb.configure_column("Created By", minWidth=150, flex=1.05, editable=False, tooltipField="Created By")
        gb.configure_column("Created At", minWidth=175, flex=1.1, editable=False, tooltipField="Created At")
        gb.configure_column("Last Login", minWidth=175, flex=1.1, editable=False, tooltipField="Last Login")
        gb.configure_column(
            "Action",
            width=128,
            editable=False,
            sortable=False,
            filter=False,
            suppressMenu=True,
            suppressMovable=True,
            cellStyle=_UM_ACTION_CELL_STYLE,
        )
        gb.configure_column("_ActionToken", hide=True)
        grid_options = gb.build()
        grid_options["stopEditingWhenCellsLoseFocus"] = True
        grid_options["singleClickEdit"] = True
        grid_options["suppressRowClickSelection"] = True
        grid_options["rowSelection"] = "single"
        grid_options["rowMultiSelectWithClick"] = False
        grid_options["enableCellTextSelection"] = True
        grid_options["ensureDomOrder"] = True
        grid_options["rowHeight"] = 54
        grid_options["headerHeight"] = 50
        grid_options["onCellClicked"] = _UM_ACTION_CLICK_JS

        ag_theme, ag_css = _user_table_aggrid_theme_and_css()
        grid_response = AgGrid(
            editor_df,
            gridOptions=grid_options,
            update_mode=GridUpdateMode.MODEL_CHANGED,
            data_return_mode=DataReturnMode.AS_INPUT,
            server_sync_strategy="server_wins",
            height=table_height,
            theme=ag_theme,
            custom_css=ag_css,
            allow_unsafe_jscode=True,
            fit_columns_on_grid_load=True,
            key="um_user_editor_v5",
        )
        edited_df = _aggrid_payload_to_df(grid_response.get("data", None))
        if edited_df.empty:
            edited_df = editor_df.copy()
        st.markdown("</div>", unsafe_allow_html=True)

        st.caption("Tip: Use Action icons to edit/delete users. Update roles in the Role column, then click Save Changes.")

        for row in edited_df.to_dict("records"):
            raw_action = str(row.get("_ActionToken", "") or "").strip()
            if "|" not in raw_action:
                continue
            last_action_token = str(st.session_state.get("um_last_action_token", "") or "").strip()
            if raw_action == last_action_token:
                continue

            parts = raw_action.split("|", 2)
            action_type = str(parts[0] if len(parts) > 0 else "").strip().lower()
            action_user = str(parts[1] if len(parts) > 1 else "").strip().lower()
            if action_type not in {"edit", "delete"} or not action_user:
                continue

            st.session_state["um_last_action_token"] = raw_action
            if action_type == "edit":
                st.session_state["um_edit_target"] = action_user
            else:
                st.session_state["um_delete_target"] = action_user
            st.rerun()

        if st.button("Save Changes", use_container_width=True, key="save_user_table_changes"):
            try:
                clean_df = edited_df.drop(columns=["#", "Action", "_ActionToken"], errors="ignore")

                updated_rows = {}
                for row in clean_df.to_dict("records"):
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
                    }
                    for u in users
                }

                before_usernames = set(before_map.keys())
                after_usernames = set(updated_rows.keys())
                common_usernames = before_usernames & after_usernames

                final_admin_count = 0
                for username in after_usernames:
                    role_value = updated_rows[username]["role"]
                    if role_value == "admin":
                        final_admin_count += 1
                if final_admin_count == 0:
                    raise ValueError("At least one admin account must remain.")

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

        delete_target = str(st.session_state.get("um_delete_target", "") or "").strip().lower()
        if delete_target:
            _render_delete_user_dialog(
                target_username=delete_target,
                current_username=current_username,
            )

        edit_target = st.session_state.pop("um_edit_target", None)
        if edit_target:
            _render_edit_user_dialog(
                target_username=str(edit_target),
                current_username=current_username,
            )
    else:
        st.info("No accounts available.")

    st.markdown("</div>", unsafe_allow_html=True)
