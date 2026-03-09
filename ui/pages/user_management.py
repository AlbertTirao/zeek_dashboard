import pandas as pd
import streamlit as st
from datetime import datetime
import time

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


UM_USERS_CACHE_ROWS_KEY = "um_users_cache_rows"
UM_USERS_CACHE_AT_KEY = "um_users_cache_at"
UM_USERS_CACHE_TTL_SECONDS = 8.0
UM_CREATE_CLEAR_FIELDS_FLAG_KEY = "um_create_clear_fields"


def _normalize_username(value: str) -> str:
    return str(value or "").strip().lower()


def _users_contains_username(rows: list[dict], username: str) -> bool:
    target = _normalize_username(username)
    if not target:
        return False
    for row in rows or []:
        row_username = _normalize_username(str((row or {}).get("username", "") or ""))
        if row_username == target:
            return True
    return False


def _clone_users(rows) -> list[dict]:
    out = []
    for row in (rows or []):
        if isinstance(row, dict):
            out.append(dict(row))
    return out


def _set_cached_users(rows: list[dict]) -> None:
    st.session_state[UM_USERS_CACHE_ROWS_KEY] = _clone_users(rows)
    st.session_state[UM_USERS_CACHE_AT_KEY] = float(time.time())


def _get_cached_users(*, force: bool = False) -> list[dict]:
    now = float(time.time())
    if not force:
        cached_rows = st.session_state.get(UM_USERS_CACHE_ROWS_KEY)
        cached_at = float(st.session_state.get(UM_USERS_CACHE_AT_KEY, 0.0) or 0.0)
        if isinstance(cached_rows, list) and cached_at > 0 and (now - cached_at) <= UM_USERS_CACHE_TTL_SECONDS:
            return _clone_users(cached_rows)

    users = auth_service.list_users()
    _set_cached_users(users)
    return _clone_users(users)


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


def _users_signature(users: list[dict]) -> str:
    parts = []
    for row in users or []:
        parts.append(
            "|".join(
                [
                    str(row.get("username", "")).strip().lower(),
                    str(row.get("name", "")).strip(),
                    str(row.get("role", "")).strip().lower(),
                    str(row.get("created_at", "")).strip(),
                    str(row.get("last_login_at", "")).strip(),
                ]
            )
        )
    return "||".join(parts)


def _bump_user_table_version() -> None:
    st.session_state["um_user_editor_version"] = int(st.session_state.get("um_user_editor_version", 0)) + 1


def _looks_like_credential_text(value: str) -> bool:
    clean = str(value or "").strip()
    if not clean:
        return False
    has_letter = any(ch.isalpha() for ch in clean)
    has_digit = any(ch.isdigit() for ch in clean)
    has_special = any((not ch.isalnum()) and (not ch.isspace()) for ch in clean)
    return (not has_letter) and (has_digit or has_special)


def _fallback_name_from_username(username: str) -> str:
    clean_username = str(username or "").strip().lower()
    if not clean_username:
        return "Unspecified"
    local = clean_username.split("@", 1)[0].strip()
    if not local:
        return "Unspecified"
    local = local.replace(".", " ").replace("_", " ").replace("-", " ")
    local = " ".join(local.split())
    if not local:
        return "Unspecified"
    if any(ch.isalpha() for ch in local):
        return local.title()
    return local


def _safe_display_name(raw_name: str, username: str) -> str:
    clean_name = str(raw_name or "").strip()
    if not clean_name or _looks_like_credential_text(clean_name):
        return _fallback_name_from_username(username)
    return clean_name


def _um_table_height_for_rows(row_count: int) -> int:
    visible_rows = max(4, min(int(row_count or 0), 8))
    return 50 + (visible_rows * 54) + 4


def _user_table_aggrid_theme_and_css() -> tuple[str, dict]:
    custom_css = {
        ".ag-root-wrapper": {
            "background-color": "#061120",
            "color": "#EAF2FF",
            "border": "1px solid #2A466E",
            "border-radius": "10px",
            "overflow": "hidden",
        },
        ".ag-root, .ag-body, .ag-body-viewport, .ag-body-clipper, .ag-center-cols-clipper, .ag-center-cols-viewport, .ag-center-cols-container": {
            "background-color": "#050B16",
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
        ".ag-body-horizontal-scroll": {
            "display": "none !important",
            "height": "0 !important",
            "min-height": "0 !important",
            "max-height": "0 !important",
            "overflow": "hidden !important",
        },
        ".ag-horizontal-left-spacer, .ag-horizontal-right-spacer": {
            "display": "none !important",
            "width": "0 !important",
            "min-width": "0 !important",
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

_UM_GRID_SIZE_CHANGED_JS = (
    JsCode(
        """
        function(params) {
            if (!params || !params.api || !params.columnApi) return;
            const fit = () => {
                try {
                    params.api.sizeColumnsToFit();
                } catch (e) {}
            };
            fit();
            setTimeout(fit, 0);
            setTimeout(fit, 60);
        }
        """
    )
    if JsCode
    else None
)


@st.dialog("Delete User")
def _render_delete_user_dialog(target_username: str, current_username: str) -> None:
    users = _get_cached_users(force=False)
    user_map = {str(u.get("username", "")).strip().lower(): u for u in users}
    target = (target_username or "").strip().lower()
    current = (current_username or "").strip().lower()

    if target not in user_map:
        st.error("Selected user no longer exists.")
        if st.button("Close", width="stretch", key="um_delete_missing_close"):
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
            width="stretch",
            key=f"um_confirm_delete_{target}",
            type="primary",
        )
    with c2:
        cancel = st.button(
            "Cancel",
            width="stretch",
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
            refreshed_users = _get_cached_users(force=True)
            if _users_contains_username(refreshed_users, target):
                raise RuntimeError("Delete operation completed, but the account is still present. Please retry.")
            _bump_user_table_version()
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
    users = _get_cached_users(force=False)
    user_map = {str(u.get("username", "")).strip().lower(): u for u in users}
    target = (target_username or "").strip().lower()
    current = (current_username or "").strip().lower()

    if target not in user_map:
        st.error("Selected user no longer exists.")
        if st.button("Close", width="stretch"):
            st.session_state.pop("um_edit_target", None)
            st.rerun()
        return

    stored_name = str(user_map[target].get("name", "") or "").strip()
    current_name = _safe_display_name(stored_name, target)
    if _looks_like_credential_text(stored_name):
        st.warning("Stored display name looked like credentials. Set a proper name and save.")

    with st.form("um_edit_user_modal_form", clear_on_submit=False):
        new_name = st.text_input("Name", value=current_name, placeholder="Full name")
        new_username = st.text_input("E-mail", value=target, placeholder="name@gmail.com")
        new_password = st.text_input(
            "New Password",
            type="password",
            placeholder="Leave blank to keep current password",
        )
        st.caption("If set, password must be at least 8 characters and include a special character.")
        submit = st.form_submit_button("Save User Changes", width="stretch")

    if submit:
        try:
            clean_new_name = " ".join(str(new_name or "").strip().split())
            clean_new_username = (new_username or "").strip().lower()
            clean_new_password = new_password.strip() if new_password.strip() else None
            auth_service.update_user(
                username=target,
                name=clean_new_name,
                new_username=clean_new_username,
                password=clean_new_password,
            )
            refreshed_users = _get_cached_users(force=True)
            if not _users_contains_username(refreshed_users, clean_new_username):
                raise RuntimeError("Update operation completed, but the account could not be loaded. Please retry.")
            _bump_user_table_version()

            if target == current:
                if "auth_user" in st.session_state and isinstance(st.session_state["auth_user"], dict):
                    st.session_state["auth_user"]["name"] = clean_new_name
                    st.session_state["auth_user"]["username"] = clean_new_username

            st.success("User updated successfully.")
            st.rerun()
        except Exception as e:
            st.error(str(e))

    if st.button("Cancel", width="stretch", key="um_edit_cancel"):
        st.rerun()


def render(current_username: str):
    _inject_user_management_css()
    inject_traffic_style_header_css()

    if AgGrid is None:
        st.error("streamlit-aggrid is required for the Action column UI.")
        return

    users = _get_cached_users(force=False)

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

    create_feedback = st.session_state.pop("um_create_feedback", None)
    if isinstance(create_feedback, dict):
        feedback_level = str(create_feedback.get("level", "") or "").strip().lower()
        feedback_message = str(create_feedback.get("message", "") or "").strip()
        feedback_detail = str(create_feedback.get("detail", "") or "").strip()
        if feedback_message:
            if feedback_level == "success":
                st.success(feedback_message)
            elif feedback_level == "warning":
                st.warning(feedback_message)
            elif feedback_level == "error":
                st.error(feedback_message)
            else:
                st.info(feedback_message)
        if feedback_detail:
            st.caption(feedback_detail)

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
    if bool(st.session_state.pop(UM_CREATE_CLEAR_FIELDS_FLAG_KEY, False)):
        for key in ("um_create_name", "um_create_username", "um_create_password", "um_create_role"):
            st.session_state.pop(key, None)

    with st.form("create_user_form", clear_on_submit=False):
        name = st.text_input("Name", placeholder="Full name", key="um_create_name")
        username = st.text_input("E-mail", placeholder="name@gmail.com", key="um_create_username")
        password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 8 characters and 1 special character",
            key="um_create_password",
        )
        st.caption("Name is required and must include letters. Only @gmail.com e-mail accounts are allowed.")
        st.caption("The new user receives this e-mail and default password, then must verify OTP and change it on first login.")
        role_options = ["staff", "admin"]
        current_role = str(st.session_state.get("um_create_role", "staff") or "staff").strip().lower()
        role_index = role_options.index(current_role) if current_role in role_options else 0
        role = st.selectbox("Role", options=role_options, index=role_index, key="um_create_role")
        submit_create = st.form_submit_button("Create User", width="stretch", type="primary")

    if submit_create:
        try:
            clean_name = auth_service.validate_display_name_policy(name)
            clean_username = auth_service.validate_username_policy(username)
            auth_service.validate_password_policy(password)
            clean_role = str(role or "").strip().lower()
            auth_service.create_user(
                name=clean_name,
                username=clean_username,
                password=password,
                role=clean_role,
                created_by=current_username,
            )
            refreshed_users = _get_cached_users(force=True)
            if not _users_contains_username(refreshed_users, clean_username):
                raise RuntimeError("User creation succeeded, but the new account could not be loaded from the database.")
            _bump_user_table_version()
            email_warning = ""
            try:
                auth_service.send_new_user_credentials_email(
                    username=clean_username,
                    default_password=password,
                    created_by=current_username,
                )
            except Exception as email_exc:
                email_warning = str(email_exc)

            if email_warning:
                st.session_state["um_create_feedback"] = {
                    "level": "warning",
                    "message": (
                        f"User '{clean_name or clean_username}' created, but the credentials e-mail was not sent."
                    ),
                    "detail": email_warning,
                }
            else:
                st.session_state["um_create_feedback"] = {
                    "level": "success",
                    "message": (
                        f"User '{clean_name or clean_username}' created and credentials e-mail sent."
                    ),
                    "detail": "",
                }
            # Keep failed submissions intact; clear fields safely on next rerun.
            st.session_state[UM_CREATE_CLEAR_FIELDS_FLAG_KEY] = True
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
        current_users_signature = _users_signature(users)
        if st.session_state.get("um_users_signature") != current_users_signature:
            st.session_state["um_users_signature"] = current_users_signature
            st.session_state["um_user_editor_version"] = int(st.session_state.get("um_user_editor_version", 0)) + 1
        grid_component_key = f"um_user_editor_v7_{int(st.session_state.get('um_user_editor_version', 0))}"

        table_rows = []
        for row in users:
            username = str(row.get("username", "")).strip().lower()
            display_name = _safe_display_name(str(row.get("name", "") or "").strip(), username)
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
        gb.configure_column("Name", minWidth=140, flex=1.2, editable=False, tooltipField="Name")
        gb.configure_column("Username", minWidth=170, flex=1.35, editable=False, tooltipField="Username")
        gb.configure_column(
            "Role",
            width=96,
            editable=True,
            cellEditor="agSelectCellEditor",
            cellEditorParams={"values": ["staff", "admin"]},
            singleClickEdit=True,
        )
        gb.configure_column("Created By", minWidth=125, flex=1.0, editable=False, tooltipField="Created By")
        gb.configure_column("Created At", minWidth=140, flex=1.0, editable=False, tooltipField="Created At")
        gb.configure_column("Last Login", minWidth=140, flex=1.0, editable=False, tooltipField="Last Login")
        gb.configure_column(
            "Action",
            width=104,
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
        grid_options["suppressHorizontalScroll"] = True
        grid_options["alwaysShowHorizontalScroll"] = False
        grid_options["alwaysShowVerticalScroll"] = True
        grid_options["domLayout"] = "normal"
        grid_options["onCellClicked"] = _UM_ACTION_CLICK_JS
        grid_options["onGridSizeChanged"] = _UM_GRID_SIZE_CHANGED_JS
        grid_options["onFirstDataRendered"] = _UM_GRID_SIZE_CHANGED_JS

        ag_theme, ag_css = _user_table_aggrid_theme_and_css()
        grid_response = AgGrid(
            editor_df,
            gridOptions=grid_options,
            update_mode=GridUpdateMode.VALUE_CHANGED,
            data_return_mode=DataReturnMode.AS_INPUT,
            server_sync_strategy="server_wins",
            theme=ag_theme,
            custom_css=ag_css,
            height=_um_table_height_for_rows(len(editor_df)),
            reload_data=False,
            allow_unsafe_jscode=True,
            fit_columns_on_grid_load=True,
            key=grid_component_key,
        )
        edited_df = _aggrid_payload_to_df(grid_response.get("data", None))
        if edited_df.empty:
            edited_df = editor_df.copy()
        st.markdown("</div>", unsafe_allow_html=True)

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

            role_changes = []
            for username in sorted(common_usernames):
                before = before_map[username]
                after = updated_rows[username]
                if before["role"] != after["role"]:
                    role_changes.append((username, after["role"]))

            if role_changes:
                for username, new_role in role_changes:
                    auth_service.update_user(
                        username=username,
                        role=new_role,
                    )
                _get_cached_users(force=True)
                _bump_user_table_version()
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

