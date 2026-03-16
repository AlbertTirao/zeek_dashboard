import streamlit as st
from pathlib import Path
from typing import Optional
import pandas as pd
import datetime
import duckdb
import re
import inspect
import requests
import time
import yaml
from uuid import uuid4
from .header_layout import (
    dashboard_loading_ui,
    inject_traffic_style_header_css,
    render_traffic_style_header,
)
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode


def _is_dark_theme() -> bool:
    try:
        base = st.get_option("theme.base")
        if isinstance(base, str) and base.lower() in {"light", "dark"}:
            return base.lower() == "dark"
    except Exception:
        pass
    return True


def get_aggrid_theme_and_css():
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
        ".ag-header-cell-label": {"font-weight": "800", "letter-spacing": "0.02em"},
        ".ag-cell": {
            "background-color": "#050B16",
            "color": "#EAEAEA",
            "border-color": "#13233D",
            "display": "flex",
            "align-items": "center",
        },
        ".ag-row-odd": {"background-color": "#071224"},
        ".ag-row-even": {"background-color": "#050E1D"},
        ".ag-row-hover": {"background-color": "#0F203D"},
        ".ag-row-selected": {"background-color": "#102540"},
        ".ag-cell[col-id='Actions']": {"justify-content": "center"},
        ".ag-header-cell[col-id='Actions'] .ag-header-cell-label": {"justify-content": "center"},
        ".ag-header-cell[col-id='Actions'] .ag-header-cell-text": {"font-size": "17px", "font-weight": "800"},
        ".auth-action-group": {
            "display": "flex",
            "align-items": "center",
            "justify-content": "center",
            "gap": "12px",
            "width": "100%",
            "height": "100%",
        },
        ".auth-action-btn": {
            "border": "none",
            "background": "transparent",
            "padding": "0",
            "margin": "0",
            "font-size": "22px",
            "line-height": "1",
            "color": "#F6FAFF",
            "cursor": "pointer",
        },
        ".auth-action-btn:hover": {
            "filter": "brightness(1.15)",
            "transform": "translateY(-1px)",
        },
        ".auth-action-btn:focus": {
            "outline": "none",
        },
        ".auth-action-btn-delete": {"color": "#FFDADA"},
        ".ag-center-cols-viewport": {"overflow-x": "hidden !important"},
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


def _table_height_for_rows(
    n_rows: int,
    *,
    row_px: int = 28,
    header_px: int = 42,
    min_px: int = 190,
    max_px: int = 520,
) -> int:
    try:
        rows = max(int(n_rows), 1)
    except Exception:
        rows = 1
    return max(min_px, min(max_px, header_px + rows * row_px))


def _apply_shadow_grid_filter_sort(grid_options: dict) -> dict:
    opts = dict(grid_options or {})
    default_col_def = dict(opts.get("defaultColDef") or {})

    default_col_def["sortable"] = True
    default_col_def["filter"] = "agSetColumnFilter"
    default_col_def["floatingFilter"] = False
    default_col_def.setdefault("minWidth", 96)
    default_col_def["menuTabs"] = ["filterMenuTab", "generalMenuTab"]
    default_col_def["suppressMenu"] = False

    filter_params = dict(default_col_def.get("filterParams") or {})
    filter_params.setdefault("excelMode", "windows")
    filter_params.setdefault("suppressMiniFilter", False)
    default_col_def["filterParams"] = filter_params

    opts["defaultColDef"] = default_col_def
    opts["suppressMenuHide"] = False
    opts["enableCellTextSelection"] = True
    opts["ensureDomOrder"] = True
    opts["enableRtl"] = False
    opts["suppressColumnVirtualisation"] = True
    opts.setdefault("pagination", True)
    if opts.get("pagination"):
        opts.setdefault("paginationAutoPageSize", False)
        opts.setdefault("paginationPageSize", 25)
        opts.setdefault("paginationPageSizeSelector", [25, 50, 100])
    opts.pop("autoSizeStrategy", None)
    return opts

AUTH_ACTION_DISPLAY = "\u270E  \U0001F5D1"
AUTH_ACTION_TOKEN_COL = "_ActionToken"

AUTH_ACTION_CELL_STYLE = (
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

AUTH_ACTIONS_RENDERER = (
    JsCode(
        """
        class AuthActionsRenderer {
            init(params) {
                this.params = params;
                this.eGui = document.createElement('div');
                this.eGui.className = 'auth-action-group';

                const triggerAction = (action, event) => {
                    if (event) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    if (this.params && this.params.node && this.params.node.setDataValue) {
                        this.params.node.setDataValue('__row_action', action);
                        this.params.node.setDataValue('__action_nonce', Date.now().toString());
                        if (this.params.api && this.params.api.refreshCells) {
                            this.params.api.refreshCells({ rowNodes: [this.params.node], force: true });
                        }
                    }
                };

                this.editHandler = (event) => triggerAction('edit', event);
                this.deleteHandler = (event) => triggerAction('delete', event);

                this.editBtn = document.createElement('button');
                this.editBtn.type = 'button';
                this.editBtn.className = 'auth-action-btn auth-action-btn-edit';
                this.editBtn.title = 'Edit';
                this.editBtn.setAttribute('aria-label', 'Edit');
                this.editBtn.setAttribute('data-auth-action', 'edit');
                this.editBtn.textContent = String.fromCharCode(0x270E);
                this.editBtn.addEventListener('click', this.editHandler);

                this.deleteBtn = document.createElement('button');
                this.deleteBtn.type = 'button';
                this.deleteBtn.className = 'auth-action-btn auth-action-btn-delete';
                this.deleteBtn.title = 'Delete';
                this.deleteBtn.setAttribute('aria-label', 'Delete');
                this.deleteBtn.setAttribute('data-auth-action', 'delete');
                this.deleteBtn.textContent = String.fromCodePoint(0x1F5D1);
                this.deleteBtn.addEventListener('click', this.deleteHandler);

                this.eGui.appendChild(this.editBtn);
                this.eGui.appendChild(this.deleteBtn);
            }

            getGui() {
                return this.eGui;
            }

            refresh() {
                return false;
            }

            destroy() {
                if (this.editBtn && this.editHandler) {
                    this.editBtn.removeEventListener('click', this.editHandler);
                }
                if (this.deleteBtn && this.deleteHandler) {
                    this.deleteBtn.removeEventListener('click', this.deleteHandler);
                }
            }
        }
        """
    )
    if JsCode
    else None
)

AUTH_ACTION_CLICK_JS = (
    JsCode(
        """
        function(params) {
            if (!params || !params.column || !params.event) return;
            const colId = params.column.getColId ? params.column.getColId() : '';
            if (colId !== 'Actions') return;

            const rowId = ((params.data && params.data._id) || '').toString().trim();
            if (!rowId) return;

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

            const token = actionType + '|' + rowId + '|' + Date.now().toString();

            if (params.node && params.node.setDataValue) {
                params.node.setDataValue('_ActionToken', token);
                if (params.api && params.api.refreshCells) {
                    params.api.refreshCells({ rowNodes: [params.node], force: true });
                }
            }
        }
        """
    )
    if JsCode
    else None
)

# -----------------------------
# Timezone Configuration
# -----------------------------
LOCAL_TZ = "Asia/Manila"

def get_local_now():
    """Returns the current local time as a naive datetime object."""
    return pd.Timestamp.now(tz=LOCAL_TZ).tz_localize(None)

# -----------------------------
# Configuration & Constants
# -----------------------------
MAC_REGEX_PATTERN = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
DOMAIN_REGEX_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
PARQUET_ROOT = Path("data/parquet")
MAC_HEX_RE = re.compile(r"[^0-9a-fA-F]")
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# -----------------------------
# Styling & Assets
# -----------------------------
def inject_custom_css():
    """Injects styling and aligns authorization tables with Shadow table shells."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        :root {
            --panel-border: rgba(255,255,255,0.12);
            --panel-bg: rgba(255,255,255,0.03);
            --panel-shadow: 0 14px 38px rgba(0,0,0,0.25);
            --accent-cyan: #00F7FF;
        }

        .stApp {
            background:
                radial-gradient(1200px 550px at 10% -5%, rgba(0, 247, 255, 0.08), transparent 45%),
                radial-gradient(900px 460px at 90% 8%, rgba(246, 48, 73, 0.08), transparent 42%),
                #040B18;
        }

        /* Metric Styling */
        [data-testid="stMetric"] {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 0.55rem 0.75rem;
        }

        div[data-testid="stMetricValue"] {
            font-size: 28px;
            font-weight: 600;
            line-height: 1.1;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 14px;
            font-weight: 500;
            color: #888;
        }
        [data-testid="stMetricLabel"] p {
            font-size: 0.75rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-weight: 600;
        }

        /* Inputs & Tables */
        .stTextInput input, .stTextArea textarea, .stSelectbox, div[data-testid="stDataEditor"] {
            border-radius: 4px !important;
        }

        /* Shadow-style table shell (align with shadow pages) */
        .shadow-table-shell {
            border: 1px solid rgba(148, 163, 184, 0.24);
            background: linear-gradient(180deg, rgba(2,6,23,0.5), rgba(2,6,23,0.35));
            border-radius: 12px;
            padding: 0.56rem 0.62rem 0.46rem 0.62rem;
            margin-bottom: 0.75rem;
        }

        .shadow-table-shell [data-testid="stDataEditor"],
        .shadow-table-shell [data-testid="stDataFrame"] {
            border: 1px solid #2A466E !important;
            border-radius: 10px !important;
            overflow: hidden !important;
            background: #061120 !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] table,
        .shadow-table-shell [data-testid="stDataFrame"] table {
            background: #050B16 !important;
            color: #EAEAEA !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] thead tr th,
        .shadow-table-shell [data-testid="stDataFrame"] thead tr th {
            background: #0A1730 !important;
            color: #EAF2FF !important;
            border-bottom: 1px solid #29406A !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] tbody tr:nth-child(odd) td,
        .shadow-table-shell [data-testid="stDataFrame"] tbody tr:nth-child(odd) td {
            background: #071224 !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] tbody tr:nth-child(even) td,
        .shadow-table-shell [data-testid="stDataFrame"] tbody tr:nth-child(even) td {
            background: #050E1D !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] tbody tr td,
        .shadow-table-shell [data-testid="stDataFrame"] tbody tr td {
            color: #EAEAEA !important;
            border-color: #13233D !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] [role="grid"],
        .shadow-table-shell [data-testid="stDataFrame"] [role="grid"] {
            background: #061120 !important;
        }

        .shadow-table-shell [data-testid="stDataEditor"] input {
            background: rgba(8, 20, 40, 0.8) !important;
            border: 1px solid #35517d !important;
            color: #e5eefc !important;
        }

        .auth-inline-modal-backdrop {
            position: fixed;
            inset: 0;
            background:
                radial-gradient(900px 420px at 18% 8%, rgba(0, 247, 255, 0.08), transparent 48%),
                radial-gradient(760px 360px at 86% 14%, rgba(246, 48, 73, 0.08), transparent 46%),
                rgba(3, 8, 18, 0.58);
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            pointer-events: none;
            z-index: 50;
        }

        [class*="st-key-auth_modal_shell_"] {
            position: relative;
            z-index: 60;
            margin: 0.2rem auto 1.1rem auto;
        }

        [class*="st-key-auth_modal_shell_"] > div[data-testid="stVerticalBlockBorderWrapper"] {
            border: 1px solid rgba(148, 163, 184, 0.22) !important;
            border-radius: 22px !important;
            background:
                radial-gradient(circle at top right, rgba(0,247,255,0.05), transparent 34%),
                linear-gradient(180deg, rgba(10, 16, 30, 0.98), rgba(8, 13, 24, 0.98)) !important;
            box-shadow:
                0 28px 68px rgba(0, 0, 0, 0.48),
                0 0 0 1px rgba(255,255,255,0.02) inset !important;
            padding: 0.2rem 0.35rem 0.55rem 0.35rem !important;
        }

        [class*="st-key-auth_modal_shell_"] h3 {
            font-size: 20px !important;
            font-weight: 800 !important;
            margin-bottom: 0.2rem !important;
        }

        [class*="st-key-auth_modal_shell_"] p {
            margin-bottom: 0.35rem;
        }

        [class*="st-key-auth_modal_shell_"] [data-testid="stTextInputRoot"],
        [class*="st-key-auth_modal_shell_"] [data-testid="stTextAreaRoot"] {
            margin-top: 0.15rem;
        }

        @media (max-width: 900px) {
            [class*="st-key-auth_modal_shell_"] {
                margin-left: 0;
                margin-right: 0;
            }
        }

        /* Headers */
        h1, h2, h3 {
            font-weight: 600 !important;
            letter-spacing: -0.5px;
        }

        .alerts-page-header {
            display:flex;
            align-items:flex-end;
            justify-content:space-between;
            gap: 20px;
            margin-top: 15px;
            margin-bottom: 14px;
            padding: 18px 20px;
            border-radius: 18px;
            border: 1px solid var(--panel-border);
            background:
              radial-gradient(circle at top right, rgba(0,247,255,0.08), transparent 40%),
              linear-gradient(135deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
            box-shadow: var(--panel-shadow);
        }

        .alerts-page-title {
            font-size: 44px;
            font-weight: 900;
            line-height: 1.0;
            letter-spacing: -0.4px;
        }

        .alerts-page-sub {
            opacity: 0.74;
            font-size: 13px;
            margin-top: 6px;
        }

        .alerts-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(255,255,255,0.18);
            background: rgba(255,255,255,0.05);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .alerts-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0,247,255,0.8);
        }

        .auth-metric-card {
            height: 146px;
            padding: 16px 16px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.12);
            background: rgba(255,255,255,0.035);
            box-shadow: 0 16px 45px rgba(0,0,0,0.28);
            width: 100%;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            justify-content: flex-start;
            text-align: left;
        }

        .auth-metric-label {
            width: 100%;
            font-size: 14px;
            opacity: 0.82;
            text-align: left;
        }

        .auth-metric-value {
            width: 100%;
            font-size: 44px;
            font-weight: 800;
            line-height: 1.05;
            margin-top: 2px;
            letter-spacing: -0.6px;
            text-align: left;
        }

        .auth-metric-note {
            width: 100%;
            font-size: 12px;
            opacity: 0.55;
            margin-top: auto;
            padding-top: 6px;
            text-align: left;
        }

        /* User Management-style add buttons */
        .st-key-btn_import_mac,
        .st-key-btn_import_domain,
        .st-key-ban_add_btn,
        .st-key-ai_sig_add_row {
            display: flex;
            align-items: flex-start;
            justify-content: flex-end;
            margin-top: 1px;
        }

        .st-key-btn_import_mac button,
        .st-key-btn_import_domain button,
        .st-key-ban_add_btn button,
        .st-key-ai_sig_add_row button {
            min-height: 44px;
            border-radius: 13px !important;
            border: 1px solid rgba(148, 163, 184, 0.44) !important;
            background: linear-gradient(135deg, #0A1428 0%, #1E2A44 100%) !important;
            color: #E6F0FF !important;
            font-weight: 800 !important;
            letter-spacing: 0.01em;
            box-shadow: 0 12px 30px rgba(2, 6, 23, 0.62);
            transition: transform 0.16s ease, box-shadow 0.16s ease, filter 0.16s ease;
        }

        .st-key-btn_import_mac button:hover,
        .st-key-btn_import_domain button:hover,
        .st-key-ban_add_btn button:hover,
        .st-key-ai_sig_add_row button:hover {
            transform: translateY(-1px);
            filter: brightness(1.09);
            box-shadow: 0 16px 34px rgba(2, 6, 23, 0.72);
        }

        .st-key-btn_import_mac button:active,
        .st-key-btn_import_domain button:active,
        .st-key-ban_add_btn button:active,
        .st-key-ai_sig_add_row button:active {
            transform: translateY(0px);
        }

        /* Spacing */
        .block-container {
            padding-top: 0.2rem !important;
            padding-bottom: 1.05rem !important;
            padding-left: 30px !important;
            padding-right: 30px !important;
            max-width: 100% !important;
        }
        </style>
    """, unsafe_allow_html=True)

# -----------------------------
# Streamlit Compatibility Helpers
# -----------------------------
_DATA_EDITOR_SUPPORTS_HIDE_INDEX = "hide_index" in inspect.signature(st.data_editor).parameters
_DATAFRAME_SUPPORTS_HIDE_INDEX = "hide_index" in inspect.signature(st.dataframe).parameters

def _st_data_editor(df, **kwargs):
    """Wrapper to enforce hide_index=True when supported."""
    if _DATA_EDITOR_SUPPORTS_HIDE_INDEX:
        kwargs.setdefault("hide_index", True)
    return st.data_editor(df, **kwargs)

def _st_dataframe(df, **kwargs):
    """Wrapper to enforce hide_index=True when supported."""
    if _DATAFRAME_SUPPORTS_HIDE_INDEX:
        kwargs.setdefault("hide_index", True)
    return st.dataframe(df, **kwargs)

def _with_row_numbers(df: pd.DataFrame) -> pd.DataFrame:
    """Returns a copy of df with a disabled display-only '#' column inserted first."""
    out = df.copy().reset_index(drop=True)
    out.insert(0, "#", pd.Series(range(1, len(out) + 1), dtype="int64"))
    return out


def _with_action_columns(df: pd.DataFrame, action_cols: list[str]) -> pd.DataFrame:
    out = df.copy()
    existing = list(out.columns)
    for col in action_cols:
        if col not in out.columns:
            out[col] = ""
    ordered = [c for c in existing if c not in action_cols] + action_cols
    return out[ordered].copy()


def _with_table_action_state(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "Actions" not in out.columns:
        out["Actions"] = AUTH_ACTION_DISPLAY
    else:
        out["Actions"] = AUTH_ACTION_DISPLAY
    if AUTH_ACTION_TOKEN_COL not in out.columns:
        out[AUTH_ACTION_TOKEN_COL] = ""
    ordered = [c for c in out.columns if c not in {"Actions", AUTH_ACTION_TOKEN_COL}]
    ordered.extend(["Actions", AUTH_ACTION_TOKEN_COL])
    return out[ordered].copy()


def _normalize_auth_editor_df(df: pd.DataFrame, template_df: pd.DataFrame) -> pd.DataFrame:
    base = template_df.copy()
    if not isinstance(df, pd.DataFrame) or df.empty:
        out = base
    else:
        out = df.copy()
    expected_cols = list(base.columns)
    for col in expected_cols:
        if col not in out.columns:
            out[col] = base[col] if col in base.columns else ""
    out = out[[c for c in expected_cols if c in out.columns]].copy()
    if "#" in out.columns:
        out = out.reset_index(drop=True)
        out["#"] = range(1, len(out) + 1)
    if "Actions" in out.columns:
        out["Actions"] = AUTH_ACTION_DISPLAY
    if AUTH_ACTION_TOKEN_COL in out.columns:
        out[AUTH_ACTION_TOKEN_COL] = out[AUTH_ACTION_TOKEN_COL].astype(str).where(out[AUTH_ACTION_TOKEN_COL].notna(), "")
    return out


def _aggrid_response_get(grid_response, key: str, default=None):
    if grid_response is None:
        return default
    getter = getattr(grid_response, "get", None)
    if callable(getter):
        try:
            return getter(key, default)
        except TypeError:
            try:
                return getter(key)
            except Exception:
                return default
        except Exception:
            return default
    if isinstance(grid_response, dict):
        return grid_response.get(key, default)
    return default


def _aggrid_to_df(grid_response, fallback_df: pd.DataFrame) -> pd.DataFrame:
    data = _aggrid_response_get(grid_response, "data")
    if isinstance(data, pd.DataFrame):
        return data.copy()
    if isinstance(data, list):
        return pd.DataFrame(data)
    return fallback_df.copy()


def _aggrid_selected_rows(grid_response) -> list[dict]:
    rows = _aggrid_response_get(grid_response, "selected_rows")
    if isinstance(rows, pd.DataFrame):
        return rows.to_dict("records")
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    return []


def _consume_grid_action(df: pd.DataFrame) -> tuple[Optional[dict], pd.DataFrame]:
    if not isinstance(df, pd.DataFrame) or df.empty or AUTH_ACTION_TOKEN_COL not in df.columns:
        return None, df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame()

    out = df.copy()
    tokens = out[AUTH_ACTION_TOKEN_COL].astype(str).str.strip()
    pending_mask = tokens.str.count(r"\|") >= 2
    if not bool(pending_mask.any()):
        return None, out

    pending = out.loc[pending_mask].copy()
    pending["_action_ts"] = pd.to_numeric(
        pending[AUTH_ACTION_TOKEN_COL].astype(str).str.rsplit("|", n=1).str[-1],
        errors="coerce",
    ).fillna(0)
    target_idx = pending["_action_ts"].idxmax()

    raw_token = str(out.at[target_idx, AUTH_ACTION_TOKEN_COL]).strip()
    last_action_token = str(st.session_state.get("_auth_last_action_token", "") or "").strip()
    out[AUTH_ACTION_TOKEN_COL] = ""
    if not raw_token or raw_token == last_action_token:
        return None, out

    action_name = str(raw_token.split("|", 1)[0]).strip().lower()
    if action_name not in {"edit", "delete"}:
        return None, out

    st.session_state["_auth_last_action_token"] = raw_token
    row_payload = out.loc[target_idx].to_dict()
    return {"action": action_name, "row": row_payload}, out


AUTH_DIALOG_REQUEST_KEY = "_auth_dialog_request"
AUTH_DIALOG_INPUT_KEYS = (
    "auth_edit_device_mac",
    "auth_edit_domain_name",
    "auth_edit_ai_provider",
    "auth_edit_ai_patterns",
    "auth_edit_ban_mac",
)


def _clear_auth_dialog_widget_state() -> None:
    for key in AUTH_DIALOG_INPUT_KEYS:
        st.session_state.pop(key, None)


def _reset_auth_interaction_state() -> None:
    st.session_state["_auth_last_action_token"] = ""
    st.session_state["_auth_grid_epoch"] = int(st.session_state.get("_auth_grid_epoch", 0) or 0) + 1
    for keys in AUTH_SECTION_GRID_CACHE_KEYS.values():
        _clear_auth_grid_cache(*keys)


def _open_auth_table_dialog(kind: str, section: str, row: dict) -> None:
    _clear_auth_dialog_widget_state()
    st.session_state[AUTH_DIALOG_REQUEST_KEY] = {
        "kind": str(kind or "").strip().lower(),
        "section": str(section or "").strip().lower(),
        "row": dict(row or {}),
    }


def _close_auth_table_dialog() -> None:
    st.session_state.pop(AUTH_DIALOG_REQUEST_KEY, None)
    _clear_auth_dialog_widget_state()
    _reset_auth_interaction_state()


def _rerun_app() -> None:
    try:
        st.rerun(scope="app")
    except TypeError:
        st.rerun()


def _get_auth_dialog_request() -> dict:
    payload = st.session_state.get(AUTH_DIALOG_REQUEST_KEY, None)
    if isinstance(payload, dict):
        return dict(payload)
    return {}


def _auth_grid_key(base: str) -> str:
    epoch = int(st.session_state.get("_auth_grid_epoch", 0) or 0)
    return f"{base}_{epoch}"


def _auth_modal_shell(shell_id: str):
    st.markdown("<div class='auth-inline-modal-backdrop'></div>", unsafe_allow_html=True)
    left_col, center_col, right_col = st.columns([0.65, 4.8, 0.65], gap="large")
    return center_col.container(key=f"auth_modal_shell_{shell_id}", border=True)


def _clear_auth_grid_cache(*keys: str) -> None:
    for key in keys:
        if key:
            st.session_state.pop(key, None)


def _render_shadow_aggrid(
    df: pd.DataFrame,
    *,
    key: str,
    editable_cols: set[str] | None = None,
    hidden_cols: set[str] | None = None,
    col_headers: dict[str, str] | None = None,
    column_widths: dict[str, int] | None = None,
    column_flexes: dict[str, int] | None = None,
    height: int = 420,
    selection_mode: str = "single",
    action_config: dict[str, dict] | None = None,
) -> dict:
    editable_cols = editable_cols or set()
    hidden_cols = hidden_cols or set()
    col_headers = col_headers or {}
    column_widths = column_widths or {}
    column_flexes = column_flexes or {}

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(filter=True, sortable=True, resizable=True, editable=False)
    gb.configure_selection(selection_mode=selection_mode, use_checkbox=False)

    if "#" in df.columns:
        gb.configure_column("#", header_name="#", width=70, pinned="left", suppressMovable=True, resizable=False, editable=False)
    for col in df.columns:
        cfg: dict = {}
        if col in hidden_cols:
            cfg["hide"] = True
        header = col_headers.get(col)
        width = column_widths.get(col)
        flex = column_flexes.get(col)
        if header:
            cfg["header_name"] = header
        if flex:
            cfg["minWidth"] = width or 96
            cfg["flex"] = flex
            cfg["suppressSizeToFit"] = True
        elif width:
            cfg["width"] = width
        if col in editable_cols:
            cfg["editable"] = True
        if cfg:
            gb.configure_column(col, **cfg)

    if action_config:
        action_click_handler = None
        for col, cfg in action_config.items():
            params = cfg.get("params") or {}
            if cfg.get("clickHandler") is not None:
                action_click_handler = cfg.get("clickHandler")
            gb.configure_column(
                col,
                header_name=cfg.get("header", col),
                editable=False,
                filter=False,
                sortable=False,
                resizable=False,
                width=cfg.get("width", 96),
                pinned=cfg.get("pinned", "right"),
                suppressMenu=True,
                suppressSizeToFit=cfg.get("suppressSizeToFit", True),
                cellStyle=cfg.get("cellStyle"),
                cellRenderer=cfg.get("renderer"),
                cellRendererParams=params,
            )
    else:
        action_click_handler = None

    grid_options = _apply_shadow_grid_filter_sort(gb.build())
    grid_options["pagination"] = False
    grid_options["rowSelection"] = selection_mode
    grid_options["suppressRowClickSelection"] = True
    grid_options["rowMultiSelectWithClick"] = False
    grid_options["rowHeight"] = 42
    grid_options["headerHeight"] = 42
    grid_options["domLayout"] = "normal"
    grid_options["alwaysShowVerticalScroll"] = True
    grid_options["suppressHorizontalScroll"] = True
    grid_options["alwaysShowHorizontalScroll"] = False
    grid_options["maintainColumnOrder"] = True
    grid_options["suppressMovableColumns"] = True
    if action_click_handler is not None:
        grid_options["onCellClicked"] = action_click_handler

    ag_theme, ag_css = get_aggrid_theme_and_css()
    return AgGrid(
        df,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.VALUE_CHANGED,
        data_return_mode=DataReturnMode.AS_INPUT,
        server_sync_strategy="server_wins",
        height=height,
        theme=ag_theme,
        custom_css=ag_css,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        fit_columns_on_grid_load=False,
        reload_data=False,
        key=key,
    )


def _open_shadow_table_shell() -> None:
    st.markdown("<div class='shadow-table-shell'>", unsafe_allow_html=True)


def _close_shadow_table_shell() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


def render_auth_metric_card(label: str, value, note: str = "") -> None:
    st.markdown(
        f"""
        <div class="auth-metric-card">
            <div class="auth-metric-label">{label}</div>
            <div class="auth-metric-value">{value}</div>
            <div class="auth-metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------
# Helpers
# -----------------------------
def _now_str():
    return get_local_now().strftime("%Y-%m-%d %H:%M:%S")

def _parse_dt(s: str):
    if not s:
        return None
    try:
        return datetime.datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def _file_mtime_str(p: Path):
    try:
        ts = p.stat().st_mtime
        # Use strictly localized fallback for file modified timestamps
        return pd.Timestamp(ts, unit='s', tz='UTC').tz_convert(LOCAL_TZ).tz_localize(None).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return _now_str()


def _path_stat_sig(path: Path | None) -> tuple[float, int]:
    if path is None or not path.exists():
        return (0.0, 0)
    try:
        st_ = path.stat()
        return (float(st_.st_mtime_ns), int(st_.st_size))
    except Exception:
        return (0.0, 0)


def _clean_device_text(value: object) -> str:
    text = str(value or "").strip()
    if text.lower() in {"", "-", "nan", "none", "<na>", "null"}:
        return ""
    return text


def _clean_text_series(series: pd.Series | None, index) -> pd.Series:
    if series is None:
        return pd.Series(pd.NA, index=index, dtype="string")
    out = series.astype("string")
    out = out.str.strip()
    out = out.replace(["", "-", "nan", "None", "none", "<NA>", "null"], pd.NA)
    return out


def _normalize_dhcp_host_name(dhcp: pd.DataFrame) -> pd.DataFrame:
    if dhcp is None or dhcp.empty:
        return dhcp
    host_name = _clean_text_series(dhcp.get("host_name"), dhcp.index)
    fqdn = _clean_text_series(dhcp.get("client_fqdn"), dhcp.index)
    dhcp = dhcp.copy()
    dhcp["host_name"] = host_name.where(host_name.notna(), fqdn)
    return dhcp

def normalize_mac(value) -> str:
    """
    Canonicalize MAC to lowercase colon form: aa:bb:cc:dd:ee:ff
    Supports:
      - bytes length 6
      - aa-bb-cc-dd-ee-ff
      - aabb.ccdd.eeff
      - aabbccddeeff
      - aa:bb:cc:dd:ee:ff
    Returns "" if invalid.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if len(b) == 6:
            return ":".join(f"{x:02x}" for x in b)
        try:
            value = b.decode("utf-8", errors="ignore")
        except Exception:
            value = str(b)

    s = str(value).strip().lower()
    if not s:
        return ""

    hx = MAC_HEX_RE.sub("", s)
    if len(hx) != 12:
        return ""
    return ":".join(hx[i:i+2] for i in range(0, 12, 2))


def _extract_date_from_dirname(name: str):
    if DATE_DIR_RE.match(name):
        return name
    if name.startswith("date="):
        tail = name.split("date=", 1)[1]
        if DATE_DIR_RE.match(tail):
            return tail
    return None


def iter_date_dirs(parquet_root: Path):
    """Yield (date_str, path_to_date_dir). Only includes real date folders."""
    if not parquet_root.exists():
        return
    for p in sorted((x for x in parquet_root.iterdir() if x.is_dir()), key=lambda z: z.name):
        n = p.name.lower()
        if n.startswith("_") or "cache" in n:
            continue
        d = _extract_date_from_dirname(p.name)
        if d:
            yield d, p


def _duckdb_read_parquet_columns(path: Path, columns: tuple[str, ...]) -> pd.DataFrame:
    if path is None or not path.exists():
        return pd.DataFrame()
    wanted = tuple(str(c) for c in (columns or tuple()) if str(c).strip())
    if not wanted:
        return pd.DataFrame()
    con = duckdb.connect(database=":memory:")
    try:
        schema_df = con.execute(
            "DESCRIBE SELECT * FROM read_parquet(?)",
            [str(path)],
        ).df()
        available = {str(c) for c in schema_df.get("column_name", pd.Series(dtype="object")).tolist()}
        selected = [c for c in wanted if c in available]
        if not selected:
            return pd.DataFrame()
        select_sql = ", ".join(f'"{c}"' for c in selected)
        return con.execute(
            f"SELECT {select_sql} FROM read_parquet(?)",
            [str(path)],
        ).df()
    except Exception:
        try:
            return pd.read_parquet(path, columns=list(wanted))
        except Exception:
            return pd.DataFrame()
    finally:
        try:
            con.close()
        except Exception:
            pass


def _duckdb_read_parquet_union_columns(paths: list[Path], columns: tuple[str, ...]) -> pd.DataFrame:
    valid_paths = [str(p) for p in (paths or []) if isinstance(p, Path) and p.exists()]
    if not valid_paths:
        return pd.DataFrame()
    wanted = tuple(str(c) for c in (columns or tuple()) if str(c).strip())
    if not wanted:
        return pd.DataFrame()
    con = duckdb.connect(database=":memory:")
    try:
        schema_df = con.execute(
            "DESCRIBE SELECT * FROM read_parquet(?, union_by_name=true)",
            [valid_paths],
        ).df()
        available = {str(c) for c in schema_df.get("column_name", pd.Series(dtype="object")).tolist()}
        selected = [c for c in wanted if c in available]
        if not selected:
            return pd.DataFrame()
        select_sql = ", ".join(f'"{c}"' for c in selected)
        return con.execute(
            f"SELECT {select_sql} FROM read_parquet(?, union_by_name=true)",
            [valid_paths],
        ).df()
    except Exception:
        dfs = []
        for p in valid_paths:
            try:
                dfs.append(pd.read_parquet(Path(p), columns=list(wanted)))
            except Exception:
                continue
        return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    finally:
        try:
            con.close()
        except Exception:
            pass


def _coerce_ts_any(series: pd.Series) -> pd.Series:
    """Robust timestamp coercion (seconds/ms/us/ns, datetime, string)."""
    if series is None or len(series) == 0:
        return pd.to_datetime(series, errors="coerce")

    if pd.api.types.is_datetime64_any_dtype(series):
        return series

    if pd.api.types.is_object_dtype(series):
        parsed = pd.to_datetime(series, errors="coerce", utc=False, format="mixed")
        if parsed.notna().any():
            return parsed

    num = pd.to_numeric(series, errors="coerce")
    if not num.notna().any():
        return pd.to_datetime(series, errors="coerce", format="mixed")

    m = float(num.dropna().abs().max())
    if m > 1e17:
        unit = "ns"
    elif m > 1e14:
        unit = "us"
    elif m > 1e11:
        unit = "ms"
    else:
        unit = "s"
    return pd.to_datetime(num, unit=unit, errors="coerce")

def _mac_is_valid(mac: str) -> bool:
    mac = normalize_mac(mac)
    return bool(re.match(MAC_REGEX_PATTERN, mac))

def _domain_is_valid(domain: str) -> bool:
    return bool(re.match(DOMAIN_REGEX_PATTERN, (domain or "").strip()))

def _dedupe_keep_last(rows: list[dict], key: str) -> list[dict]:
    """Dedupe list of dicts by key, keep the last occurrence."""
    out = {}
    for r in rows:
        k = str(r.get(key, "")).strip().lower()
        if k:
            out[k] = r
    return list(out.values())

# -----------------------------
# Data Logic - Structured (Devices)
# -----------------------------
# -----------------------------
# Robust Editor State Helpers (fix add/delete when filtered)
# -----------------------------
def _ensure_ids(rows: list[dict], id_key="_id") -> list[dict]:
    out = []
    for r in rows:
        rr = dict(r)
        if not rr.get(id_key):
            rr[id_key] = str(uuid4())
        out.append(rr)
    return out

def _rows_to_df(rows: list[dict], cols: list[str]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols].copy()


AUTH_SECTION_GRID_CACHE_KEYS = {
    "device": ("device_editor_cache", "device_editor_filter"),
    "domain": ("domain_editor_cache", "domain_editor_filter"),
    "ai": ("ai_sig_editor_cache",),
    "ban": ("ban_editor_cache", "ban_editor_filter"),
}


def _invalidate_auth_section(section: str) -> None:
    for key in AUTH_SECTION_GRID_CACHE_KEYS.get(str(section or "").strip().lower(), ()):
        st.session_state.pop(key, None)


def _ordered_unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


# -----------------------------
# Device Access Data & UI
# -----------------------------
def load_devices(filepath: Path) -> list[dict]:

    default_structure = {"mac": "", "ip": "", "hostname": "", "vendor": "", "date_modified": ""}

    if filepath.suffix == ".txt":
        yaml_path = filepath.with_suffix(".yaml")
        if yaml_path.exists():
            filepath = yaml_path

    if not filepath.exists():
        return []

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []

        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            target_key = filepath.stem
            if target_key in data and isinstance(data[target_key], list):
                raw_list = data[target_key]
            else:
                for val in data.values():
                    if isinstance(val, list):
                        raw_list = val
                        break

        structured = []
        file_stamp = _file_mtime_str(filepath)

        for item in raw_list:
            if isinstance(item, str):
                m = normalize_mac(item)
                if not m:
                    continue
                structured.append(
                    {"mac": m, "ip": "", "hostname": "", "vendor": "", "date_modified": file_stamp}
                )
            elif isinstance(item, dict):
                entry = default_structure.copy()
                clean_item = {str(k).lower(): v for k, v in item.items()}
                entry.update(clean_item)

                mac_raw = entry.get("mac")
                if not mac_raw:
                    for alt in (
                        "mac_address",
                        "mac address",
                        "macaddress",
                        "device_mac",
                        "device mac",
                        "client_mac",
                        "client mac",
                    ):
                        if alt in entry and entry.get(alt):
                            mac_raw = entry.get(alt)
                            break
                m = normalize_mac(mac_raw)
                if not m:
                    continue

                host_raw = (
                    entry.get("hostname")
                    or entry.get("host_name")
                    or entry.get("host name")
                    or entry.get("client_fqdn")
                )
                vendor_raw = entry.get("vendor") or entry.get("manufacturer")
                entry["mac"] = m
                entry["ip"] = _clean_device_text(entry.get("ip", "") or entry.get("host", "") or entry.get("client_addr", ""))
                entry["hostname"] = _clean_device_text(host_raw)
                entry["vendor"] = _clean_device_text(vendor_raw)
                entry["date_modified"] = str(entry.get("date_modified") or file_stamp).strip()
                structured.append(entry)

        structured = _dedupe_keep_last(structured, "mac")
        structured.sort(key=lambda x: x.get("mac", ""))
        return structured
    except Exception as e:
        st.error(f"Error loading devices: {e}")
        return []


def save_devices(filepath: Path, device_list: list[dict]) -> None:

    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    cleaned = []
    for d in device_list:
        m = normalize_mac(d.get("mac", ""))
        if not m or not _mac_is_valid(m):
            continue
        cleaned.append(
            {
                "mac": m,
                "ip": _clean_device_text(d.get("ip", "")),
                "hostname": _clean_device_text(d.get("hostname", "")),
                "vendor": _clean_device_text(d.get("vendor", "")),
                "date_modified": str(d.get("date_modified") or _now_str()).strip(),
            }
        )

    cleaned = _dedupe_keep_last(cleaned, "mac")
    cleaned.sort(key=lambda x: x.get("mac", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)


@st.cache_data(show_spinner=False)
def get_mac_vendor(mac: str) -> str:

    mac = normalize_mac(mac)
    if not mac:
        return "Unknown"
    try:
        time.sleep(0.25)
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"


@st.cache_data(show_spinner=False, ttl=30)
def get_latest_network_info() -> pd.DataFrame:

    known_host_paths: list[Path] = []
    dhcp_paths: list[Path] = []

    if not PARQUET_ROOT.exists():
        return pd.DataFrame()

    day_dirs = [p for _, p in iter_date_dirs(PARQUET_ROOT)]
    if not day_dirs:
        day_dirs = sorted((p for p in PARQUET_ROOT.iterdir() if p.is_dir()), key=lambda z: z.name)

    for day_dir in day_dirs:
        kh = day_dir / "known_hosts.parquet"
        dh = day_dir / "dhcp.parquet"
        if kh.exists():
            known_host_paths.append(kh)
        if dh.exists():
            dhcp_paths.append(dh)

    known_hosts = _duckdb_read_parquet_union_columns(
        known_host_paths,
        ("mac", "ts", "host", "id.orig_h", "client_addr", "ip", "addr"),
    )
    dhcp = _duckdb_read_parquet_union_columns(
        dhcp_paths,
        ("mac", "client_addr", "host_name", "client_fqdn", "domain"),
    )
    dhcp = _normalize_dhcp_host_name(dhcp)

    if known_hosts.empty or "mac" not in known_hosts.columns:
        return pd.DataFrame()

    known_hosts = known_hosts.copy()
    known_hosts["mac"] = known_hosts["mac"].map(normalize_mac)
    known_hosts = known_hosts[known_hosts["mac"] != ""]
    if known_hosts.empty:
        return pd.DataFrame()

    if "ts" in known_hosts.columns:
        known_hosts["ts"] = _coerce_ts_any(known_hosts["ts"])

    ip_col = None
    for c in ["host", "id.orig_h", "client_addr", "ip", "addr"]:
        if c in known_hosts.columns:
            ip_col = c
            break
    if ip_col is None:
        known_hosts["host"] = ""
        ip_col = "host"

    if not dhcp.empty:
        if "mac" in dhcp.columns:
            dhcp = dhcp.copy()
            dhcp["mac"] = dhcp["mac"].map(normalize_mac)
            dhcp = dhcp[dhcp["mac"] != ""]
            dhcp_cols = [c for c in ["mac", "host_name"] if c in dhcp.columns]
            if "mac" in dhcp_cols:
                dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["mac"], keep="last")
                merged = pd.merge(known_hosts, dhcp_norm, how="left", on="mac")
            else:
                merged = known_hosts.copy()
        else:
            dhcp_cols = [c for c in ["client_addr", "host_name"] if c in dhcp.columns]
            if "client_addr" in dhcp_cols:
                dhcp_norm = dhcp[dhcp_cols].drop_duplicates(subset=["client_addr"], keep="last")
                merged = pd.merge(known_hosts, dhcp_norm, how="left", left_on=ip_col, right_on="client_addr")
            else:
                merged = known_hosts.copy()
    else:
        merged = known_hosts.copy()

    if "host_name" not in merged.columns:
        merged["host_name"] = ""
    merged["host_name"] = _clean_text_series(merged.get("host_name"), merged.index).fillna("").astype(str)

    if "ts" in merged.columns:
        merged = merged.copy()
        merged["ts"] = _coerce_ts_any(merged["ts"])
        merged = merged.sort_values("ts", na_position="last")

    final_info = merged.groupby("mac").agg({ip_col: "last", "host_name": "last"}).reset_index()
    final_info.rename(columns={ip_col: "latest_ip", "host_name": "latest_host"}, inplace=True)
    return final_info


def auto_enrich_devices(device_list):

    net_df = get_latest_network_info()
    net_map = {}
    if not net_df.empty:
        net_map = net_df.set_index("mac").to_dict(orient="index")

    changes_detected = False

    for device in device_list:
        mac = normalize_mac(device.get("mac", ""))
        if not mac:
            continue
        device_changed = False
        device["mac"] = mac
        clean_ip = _clean_device_text(device.get("ip", ""))
        clean_host = _clean_device_text(device.get("hostname", ""))
        clean_vendor = _clean_device_text(device.get("vendor", ""))
        if clean_ip != str(device.get("ip", "") or "").strip():
            device_changed = True
        if clean_host != str(device.get("hostname", "") or "").strip():
            device_changed = True
        if clean_vendor != str(device.get("vendor", "") or "").strip():
            device_changed = True
        device["ip"] = clean_ip
        device["hostname"] = clean_host
        device["vendor"] = clean_vendor

        if mac in net_map:
            found_ip = _clean_device_text(net_map[mac].get("latest_ip", "") or "")
            found_host = _clean_device_text(net_map[mac].get("latest_host", "") or "")

            if found_ip and found_ip != device.get("ip", ""):
                device["ip"] = found_ip
                device_changed = True

            if found_host and found_host != device.get("hostname", ""):
                device["hostname"] = found_host
                device_changed = True

        if not device.get("vendor") or str(device.get("vendor", "")).strip().lower() == "unknown":
            found_vendor = _clean_device_text(get_mac_vendor(mac))
            if found_vendor and found_vendor.lower() != "unknown" and found_vendor != device.get("vendor", ""):
                device["vendor"] = found_vendor
                device_changed = True

        if device_changed or not _parse_dt(str(device.get("date_modified", "") or "").strip()):
            device["date_modified"] = _now_str()
        changes_detected = changes_detected or device_changed

    device_list = _dedupe_keep_last(device_list, "mac")
    return device_list, changes_detected


def _get_device_rows_state(filepath: Path) -> list[dict]:
    source_key = _path_stat_sig(filepath)
    rows = st.session_state.get("device_rows_state")
    if not isinstance(rows, list) or st.session_state.get("_device_rows_source_key") != source_key:
        rows = _ensure_ids(load_devices(filepath))
    rows = _ensure_ids(rows)
    st.session_state.device_rows_state = rows
    st.session_state["_device_rows_source_key"] = source_key
    return rows


def _update_device_row(filepath: Path, row_id: str, mac: str, ip: str, hostname: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_device_rows_state(filepath)
    target_index = next((i for i, row in enumerate(rows) if str(row.get("_id", "")).strip() == row_id), None)
    if target_index is None:
        raise ValueError("The selected device no longer exists.")

    mac_norm = normalize_mac(mac)
    if not mac_norm or not _mac_is_valid(mac_norm):
        raise ValueError("Enter a valid MAC address.")
    if any(normalize_mac(row.get("mac", "")) == mac_norm and str(row.get("_id", "")).strip() != row_id for row in rows):
        raise ValueError("That MAC address already exists in Device Access.")

    old_row = dict(rows[target_index])
    old_mac = normalize_mac(old_row.get("mac", ""))
    vendor = str(old_row.get("vendor", "") or "").strip()
    if old_mac != mac_norm:
        vendor = get_mac_vendor(mac_norm)
        if not vendor or vendor == "Unknown":
            vendor = str(old_row.get("vendor", "") or "").strip()

    rows[target_index] = {
        "_id": row_id,
        "mac": mac_norm,
        "ip": str(ip or "").strip(),
        "hostname": str(hostname or "").strip(),
        "vendor": vendor,
        "date_modified": _now_str(),
    }
    rows = _ensure_ids(_dedupe_keep_last(rows, "mac"))
    st.session_state.device_rows_state = rows
    save_devices(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    st.session_state["_device_rows_source_key"] = _path_stat_sig(filepath)
    item_text = f"{old_mac} -> {mac_norm}" if old_mac and old_mac != mac_norm else mac_norm
    log_activity(filepath, "Edited", "Device", [item_text])
    _invalidate_auth_section("device")


def _delete_device_row(filepath: Path, row_id: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_device_rows_state(filepath)
    removed = next((row for row in rows if str(row.get("_id", "")).strip() == row_id), None)
    if removed is None:
        raise ValueError("The selected device no longer exists.")
    rows = [row for row in rows if str(row.get("_id", "")).strip() != row_id]
    st.session_state.device_rows_state = rows
    save_devices(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    st.session_state["_device_rows_source_key"] = _path_stat_sig(filepath)
    removed_mac = normalize_mac(removed.get("mac", ""))
    if removed_mac:
        log_activity(filepath, "Deleted", "Device", [removed_mac])
    _invalidate_auth_section("device")


def show_device_edit_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    with _auth_modal_shell("device_edit"):
        st.markdown("### Edit Device Access")
        st.markdown("**Device Access**")
        st.caption("Update the selected record and save the changes.")

        mac_value = st.text_input("MAC Address", value=str((row or {}).get("mac", "") or ""), key="auth_edit_device_mac")
        save_col, cancel_col = st.columns(2, gap="small")
        with save_col:
            if st.button("Save Device", type="primary", width="stretch", key="auth_edit_device_save"):
                try:
                    _update_device_row(
                        mac_file,
                        row_id,
                        mac_value,
                        str((row or {}).get("ip", "") or ""),
                        str((row or {}).get("hostname", "") or ""),
                    )
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Device updated.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_edit_device_cancel"):
                _close_auth_table_dialog()
                _rerun_app()


def show_device_delete_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    target_text = str((row or {}).get("mac", "") or "").strip()
    with _auth_modal_shell("device_delete"):
        st.markdown("### Delete Device Access")
        st.markdown("**Device Access**")
        st.warning(f"Delete this entry?\n\n`{target_text or 'Unknown'}`")
        confirm_col, cancel_col = st.columns(2, gap="small")
        with confirm_col:
            if st.button("Delete Device", type="primary", width="stretch", key="auth_delete_confirm_device"):
                try:
                    _delete_device_row(mac_file, row_id)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Entry deleted.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_delete_cancel_device"):
                _close_auth_table_dialog()
                _rerun_app()


def render_device_access_section(device_list: list[dict], filepath: Path) -> None:

    st.markdown("**Device Access**")
    dialog_payload = _get_auth_dialog_request()
    if str(dialog_payload.get("section", "") or "").strip().lower() == "device":
        kind = str(dialog_payload.get("kind", "") or "").strip().lower()
        row = dict(dialog_payload.get("row") or {})
        if kind == "edit":
            show_device_edit_dialog(row, filepath, filepath.parent / "whitelist_domains.yaml", filepath.parent / "ai_signatures.yaml", filepath.parent / "banned_macs.yaml")
        elif kind == "delete":
            show_device_delete_dialog(row, filepath, filepath.parent / "whitelist_domains.yaml", filepath.parent / "ai_signatures.yaml", filepath.parent / "banned_macs.yaml")

    current_rows = _get_device_rows_state(filepath)
    updated_list, changes = auto_enrich_devices(current_rows)
    if changes:
        st.session_state.device_rows_state = _ensure_ids(updated_list)
        save_devices(filepath, [{k: v for k, v in d.items() if k != "_id"} for d in updated_list])
        st.session_state["_device_rows_source_key"] = _path_stat_sig(filepath)

    f1, _ = st.columns([2, 3])
    with f1:
        date_filter = st.selectbox(
            "Filter by Date Modified",
            ["All", "Today", "Last 7 Days", "Last 30 Days"],
            index=0,
        )

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Quick Add Device",
            placeholder="Paste MAC Address (you can paste multiple, separated by space/comma/newline)",
            label_visibility="collapsed",
            key="device_quick_add",
        )
    with col_btn:
        if st.button("+ Add Device", key="btn_import_mac", type="primary", width="stretch"):
            entries = [x for x in re.split(r"[,\s\n]+", (new_text or "")) if x.strip()]
            entries = [normalize_mac(x) for x in entries]
            entries = [m for m in entries if m and _mac_is_valid(m)]

            existing = {normalize_mac(d.get("mac")) for d in st.session_state.device_rows_state}
            added = []
            for m in entries:
                if m in existing:
                    continue
                st.session_state.device_rows_state.append(
                    {
                        "_id": str(uuid4()),
                        "mac": m,
                        "ip": "",
                        "hostname": "",
                        "vendor": "",
                        "date_modified": _now_str(),
                    }
                )
                existing.add(m)
                added.append(m)

            if added:
                save_devices(
                    filepath,
                    [{k: v for k, v in d.items() if k != "_id"} for d in st.session_state.device_rows_state],
                )
                log_activity(filepath, "Added", "Device", added)
                _invalidate_auth_section("device")
                st.toast(f"Added {len(added)} device(s)")
                st.rerun()
            else:
                st.info("No new valid MACs were added (duplicates/invalid).")

    st.divider()

    device_search_state_key = "device_search"
    if device_search_state_key not in st.session_state:
        st.session_state[device_search_state_key] = ""
    st.text_input(
        "Search Devices",
        placeholder="Search MAC / IP / Hostname..",
        label_visibility="collapsed",
        key=device_search_state_key,
    )
    search_query = str(st.session_state.get(device_search_state_key, "") or "").strip()

    rows = _get_device_rows_state(filepath)
    cols_all = ["_id", "mac", "ip", "hostname", "vendor", "date_modified"]
    df = _rows_to_df(rows, cols_all)

    if date_filter != "All" and not df.empty:
        df["_dt"] = df["date_modified"].apply(_parse_dt)
        now = get_local_now()
        if date_filter == "Today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif date_filter == "Last 7 Days":
            start = now - datetime.timedelta(days=7)
        else:
            start = now - datetime.timedelta(days=30)
        df = df[df["_dt"].notna() & (df["_dt"] >= start)].copy()
        df.drop(columns=["_dt"], inplace=True, errors="ignore")

    if search_query:
        q = search_query.strip()
        mask = df.apply(lambda r: r.astype(str).str.contains(q, case=False).any(), axis=1)
        df = df[mask].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    display_cols = ["_id", "mac", "ip", "hostname", "vendor", "date_modified"]
    editor_df = _with_table_action_state(_with_row_numbers(df[display_cols].copy()))

    view_key = (date_filter, search_query)
    device_editor_key = "device_editor_cache"
    device_filter_key = "device_editor_filter"
    if st.session_state.get(device_filter_key) != view_key or device_editor_key not in st.session_state:
        st.session_state[device_filter_key] = view_key
        st.session_state[device_editor_key] = _normalize_auth_editor_df(editor_df, editor_df)
    else:
        st.session_state[device_editor_key] = _normalize_auth_editor_df(
            st.session_state[device_editor_key], editor_df
        )

    _open_shadow_table_shell()
    action_config = {
        "Actions": {
            "header": "Actions",
            "width": 126,
            "cellStyle": AUTH_ACTION_CELL_STYLE,
            "clickHandler": AUTH_ACTION_CLICK_JS,
            "pinned": "right",
        },
    }

    grid_response = _render_shadow_aggrid(
        st.session_state[device_editor_key],
        key=_auth_grid_key("device_editor_grid"),
        hidden_cols={"_id", AUTH_ACTION_TOKEN_COL},
        col_headers={
            "mac": "MAC Address",
            "ip": "IP Address",
            "hostname": "Host Name",
            "vendor": "Vendor",
            "date_modified": "Date Modified",
        },
        column_widths={
            "mac": 180,
            "ip": 150,
            "hostname": 220,
            "vendor": 220,
            "date_modified": 190,
            "Actions": 126,
        },
        column_flexes={"hostname": 1, "vendor": 1},
        height=_table_height_for_rows(len(st.session_state[device_editor_key]), min_px=240, max_px=520),
        action_config=action_config,
    )
    _close_shadow_table_shell()
    edited_df = _normalize_auth_editor_df(
        _aggrid_to_df(grid_response, st.session_state[device_editor_key]), editor_df
    )
    pending_action, cleaned_df = _consume_grid_action(edited_df)
    st.session_state[device_editor_key] = _normalize_auth_editor_df(cleaned_df, editor_df)
    if pending_action:
        _open_auth_table_dialog(str(pending_action.get("action", "")), "device", pending_action.get("row") or {})
        st.rerun()


# -----------------------------
# Domain Whitelist Data & UI
# -----------------------------
def load_domain_whitelist(filepath: Path) -> list[dict]:

    if not filepath.exists():
        return []
    default_row = {"domain": "", "date_modified": ""}

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []

        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            target_key = filepath.stem
            if target_key in data and isinstance(data[target_key], list):
                raw_list = data[target_key]
            else:
                for v in data.values():
                    if isinstance(v, list):
                        raw_list = v
                        break

        file_stamp = _file_mtime_str(filepath)
        out = []
        for it in raw_list:
            if isinstance(it, str):
                dom = it.strip().lower()
                if dom:
                    out.append({"domain": dom, "date_modified": file_stamp})
            elif isinstance(it, dict):
                row = default_row.copy()
                clean = {str(k).lower(): v for k, v in it.items()}
                row.update(clean)

                dom = str(row.get("domain", "")).strip().lower()
                if not dom and "domain name" in clean:
                    dom = str(clean.get("domain name", "")).strip().lower()
                if not dom:
                    continue
                dm = str(row.get("date_modified") or file_stamp).strip()
                out.append({"domain": dom, "date_modified": dm})

        out = _dedupe_keep_last(out, "domain")
        out.sort(key=lambda x: x.get("domain", ""))
        return out
    except Exception:
        return []


def save_domain_whitelist(filepath: Path, rows: list[dict]) -> None:

    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    cleaned = []
    for r in rows:
        dom = str(r.get("domain", "")).strip().lower()
        if not dom or not _domain_is_valid(dom):
            continue
        cleaned.append({"domain": dom, "date_modified": str(r.get("date_modified") or _now_str()).strip()})

    cleaned = _dedupe_keep_last(cleaned, "domain")
    cleaned.sort(key=lambda x: x.get("domain", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)


def _get_domain_rows_state(filepath: Path) -> list[dict]:

    rows = st.session_state.get("domain_rows_state")
    if not isinstance(rows, list):
        rows = []
        for row in load_domain_whitelist(filepath):
            row_copy = dict(row)
            row_copy["_id"] = row_copy.get("_id") or str(uuid4())
            rows.append(row_copy)
    st.session_state.domain_rows_state = rows
    return rows


def _update_domain_row(filepath: Path, row_id: str, domain: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_domain_rows_state(filepath)
    target_index = next((i for i, row in enumerate(rows) if str(row.get("_id", "")).strip() == row_id), None)
    if target_index is None:
        raise ValueError("The selected domain no longer exists.")

    clean_domain = str(domain or "").strip().lower()
    if not clean_domain or not _domain_is_valid(clean_domain):
        raise ValueError("Enter a valid domain.")
    if any(str(row.get("domain", "")).strip().lower() == clean_domain and str(row.get("_id", "")).strip() != row_id for row in rows):
        raise ValueError("That domain already exists in the whitelist.")

    old_domain = str(rows[target_index].get("domain", "") or "").strip().lower()
    rows[target_index] = {"_id": row_id, "domain": clean_domain, "date_modified": _now_str()}
    rows = _dedupe_keep_last(rows, "domain")
    st.session_state.domain_rows_state = rows
    save_domain_whitelist(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    item_text = f"{old_domain} -> {clean_domain}" if old_domain and old_domain != clean_domain else clean_domain
    log_activity(filepath, "Edited", "Domain", [item_text])
    _invalidate_auth_section("domain")


def _delete_domain_row(filepath: Path, row_id: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_domain_rows_state(filepath)
    removed = next((row for row in rows if str(row.get("_id", "")).strip() == row_id), None)
    if removed is None:
        raise ValueError("The selected domain no longer exists.")
    rows = [row for row in rows if str(row.get("_id", "")).strip() != row_id]
    st.session_state.domain_rows_state = rows
    save_domain_whitelist(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    removed_domain = str(removed.get("domain", "") or "").strip().lower()
    if removed_domain:
        log_activity(filepath, "Deleted", "Domain", [removed_domain])
    _invalidate_auth_section("domain")


def show_domain_edit_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    with _auth_modal_shell("domain_edit"):
        st.markdown("### Edit Domain Whitelist")
        st.markdown("**Domain Whitelist**")
        st.caption("Update the selected record and save the changes.")

        domain_value = st.text_input("Domain", value=str((row or {}).get("domain", "") or ""), key="auth_edit_domain_name")
        save_col, cancel_col = st.columns(2, gap="small")
        with save_col:
            if st.button("Save Domain", type="primary", width="stretch", key="auth_edit_domain_save"):
                try:
                    _update_domain_row(domain_file, row_id, domain_value)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Domain updated.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_edit_domain_cancel"):
                _close_auth_table_dialog()
                _rerun_app()


def show_domain_delete_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    target_text = str((row or {}).get("domain", "") or "").strip()
    with _auth_modal_shell("domain_delete"):
        st.markdown("### Delete Domain Whitelist")
        st.markdown("**Domain Whitelist**")
        st.warning(f"Delete this entry?\n\n`{target_text or 'Unknown'}`")
        confirm_col, cancel_col = st.columns(2, gap="small")
        with confirm_col:
            if st.button("Delete Domain", type="primary", width="stretch", key="auth_delete_confirm_domain"):
                try:
                    _delete_domain_row(domain_file, row_id)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Entry deleted.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_delete_cancel_domain"):
                _close_auth_table_dialog()
                _rerun_app()


def render_domain_whitelist_section(domain_rows: list[dict], filepath: Path) -> None:

    st.markdown("**Domain Whitelist**")
    dialog_payload = _get_auth_dialog_request()
    if str(dialog_payload.get("section", "") or "").strip().lower() == "domain":
        kind = str(dialog_payload.get("kind", "") or "").strip().lower()
        row = dict(dialog_payload.get("row") or {})
        mac_file = filepath.parent / "authorized_macs.yaml"
        if kind == "edit":
            show_domain_edit_dialog(row, mac_file, filepath, filepath.parent / "ai_signatures.yaml", filepath.parent / "banned_macs.yaml")
        elif kind == "delete":
            show_domain_delete_dialog(row, mac_file, filepath, filepath.parent / "ai_signatures.yaml", filepath.parent / "banned_macs.yaml")

    if "domain_rows_state" not in st.session_state:
        rows = []
        for r in domain_rows:
            rr = dict(r)
            rr["_id"] = rr.get("_id") or str(uuid4())
            rows.append(rr)
        st.session_state.domain_rows_state = rows

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_domain = st.text_input("Add Domain", placeholder="example.com", label_visibility="collapsed", key="dom_add")
    with col_btn:
        if st.button("+ Add Domain", key="btn_import_domain", type="primary", width="stretch"):
            entries = [x.strip().lower() for x in re.split(r"[,\s\n]+", (new_domain or "")) if x.strip()]
            entries = [d for d in entries if _domain_is_valid(d)]

            existing = {str(r.get("domain", "")).strip().lower() for r in st.session_state.domain_rows_state}
            added = []
            for dom in entries:
                if dom in existing:
                    continue
                st.session_state.domain_rows_state.append(
                    {"_id": str(uuid4()), "domain": dom, "date_modified": _now_str()}
                )
                existing.add(dom)
                added.append(dom)

            if added:
                save_domain_whitelist(
                    filepath,
                    [{k: v for k, v in r.items() if k != "_id"} for r in st.session_state.domain_rows_state],
                )
                log_activity(filepath, "Added", "Domain", added)
                _invalidate_auth_section("domain")
                st.toast(f"Added {len(added)} domain(s)")
                st.rerun()
            else:
                st.info("No new valid domains were added (duplicates/invalid).")

    st.divider()

    domain_search_state_key = "dom_search"
    if domain_search_state_key not in st.session_state:
        st.session_state[domain_search_state_key] = ""
    st.text_input(
        "Search Whitelist",
        placeholder="Filter domains...",
        label_visibility="collapsed",
        key=domain_search_state_key,
    )
    search_query = str(st.session_state.get(domain_search_state_key, "") or "").strip().lower()

    df = pd.DataFrame(st.session_state.domain_rows_state)
    if df.empty:
        df = pd.DataFrame(columns=["_id", "domain", "date_modified"])

    for c in ["_id", "domain", "date_modified"]:
        if c not in df.columns:
            df[c] = ""

    if search_query:
        df = df[df["domain"].astype(str).str.lower().str.contains(search_query, na=False)].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    editor_df = _with_table_action_state(_with_row_numbers(df[["_id", "domain", "date_modified"]].copy()))

    _open_shadow_table_shell()
    view_key = search_query
    domain_editor_key = "domain_editor_cache"
    domain_filter_key = "domain_editor_filter"
    if st.session_state.get(domain_filter_key) != view_key or domain_editor_key not in st.session_state:
        st.session_state[domain_filter_key] = view_key
        st.session_state[domain_editor_key] = _normalize_auth_editor_df(editor_df, editor_df)
    else:
        st.session_state[domain_editor_key] = _normalize_auth_editor_df(
            st.session_state[domain_editor_key], editor_df
        )

    action_config = {
        "Actions": {
            "header": "Actions",
            "width": 126,
            "cellStyle": AUTH_ACTION_CELL_STYLE,
            "clickHandler": AUTH_ACTION_CLICK_JS,
            "pinned": "right",
        },
    }

    grid_response = _render_shadow_aggrid(
        st.session_state[domain_editor_key],
        key=_auth_grid_key("domain_editor_grid"),
        hidden_cols={"_id", AUTH_ACTION_TOKEN_COL},
        col_headers={
            "domain": "Domain Name",
            "date_modified": "Date Modified",
        },
        column_widths={
            "domain": 300,
            "date_modified": 190,
            "Actions": 126,
        },
        column_flexes={"domain": 1},
        height=_table_height_for_rows(len(st.session_state[domain_editor_key]), min_px=240, max_px=520),
        action_config=action_config,
    )
    _close_shadow_table_shell()
    edited_df = _normalize_auth_editor_df(
        _aggrid_to_df(grid_response, st.session_state[domain_editor_key]), editor_df
    )
    pending_action, cleaned_df = _consume_grid_action(edited_df)
    st.session_state[domain_editor_key] = _normalize_auth_editor_df(cleaned_df, editor_df)
    if pending_action:
        _open_auth_table_dialog(str(pending_action.get("action", "")), "domain", pending_action.get("row") or {})
        st.rerun()


# -----------------------------
# AI Policies Data & UI
# -----------------------------
def load_ai_config(filepath: Path):
    if not filepath.exists():
        return {"authorized_providers": [], "ai_signatures": {}}
    try:
        config = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        return config if config else {"authorized_providers": [], "ai_signatures": {}}
    except Exception:
        return {"authorized_providers": [], "ai_signatures": {}}


def save_ai_config(filepath: Path, config_dict: dict) -> None:
    filepath.parent.mkdir(exist_ok=True, parents=True)
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_dict, f, sort_keys=False)


def _ai_signature_source_key(config: dict) -> tuple:
    pairs: list[tuple[str, tuple[str, ...]]] = []
    raw = config.get("ai_signatures", {}) if isinstance(config, dict) else {}
    if isinstance(raw, dict):
        for provider, patterns in raw.items():
            provider_name = str(provider or "").strip()
            pattern_list = tuple(str(p).strip() for p in (patterns or []) if str(p).strip())
            if provider_name:
                pairs.append((provider_name, pattern_list))
    authorized = tuple(
        sorted(
            _ordered_unique(
                [str(value or "").strip() for value in ((config or {}).get("authorized_providers", []) or [])]
            ),
            key=str.lower,
        )
    )
    return (
        tuple(sorted(pairs, key=lambda item: item[0].lower())),
        authorized,
    )


def _ai_policy_provider_count(config: dict) -> int:
    values = [str(value or "").strip() for value in ((config or {}).get("authorized_providers", []) or [])]
    values.extend(str(value or "").strip() for value in ((config or {}).get("ai_signatures", {}) or {}).keys())
    return len(_ordered_unique(values))


def _get_ai_signature_rows_state(filepath: Path) -> tuple[dict, list[dict]]:
    config = load_ai_config(filepath)
    source_key = _ai_signature_source_key(config)
    current_rows = st.session_state.get("ai_sig_rows_state")
    if not isinstance(current_rows, list) or st.session_state.get("_ai_sig_source_key") != source_key:
        rows: list[dict] = []
        seen_providers: set[str] = set()
        for provider, patterns in (config.get("ai_signatures", {}) or {}).items():
            provider_name = str(provider or "").strip()
            if not provider_name:
                continue
            pattern_text = ", ".join(str(p).strip() for p in (patterns or []) if str(p).strip())
            rows.append({"_id": str(uuid4()), "Provider": provider_name, "Patterns": pattern_text})
            seen_providers.add(provider_name.lower())
        for provider in _ordered_unique(
            [str(value or "").strip() for value in (config.get("authorized_providers", []) or [])]
        ):
            if provider.lower() in seen_providers:
                continue
            rows.append({"_id": str(uuid4()), "Provider": provider, "Patterns": ""})
            seen_providers.add(provider.lower())
        st.session_state["ai_sig_rows_state"] = rows
        st.session_state["_ai_sig_source_key"] = source_key
    return config, st.session_state.get("ai_sig_rows_state", [])


def _persist_ai_signature_rows(
    filepath: Path,
    rows: list[dict],
    *,
    old_provider: str | None = None,
    new_provider: str | None = None,
    deleted_provider: str | None = None,
    action_label: str = "Edited",
    item_label: str | None = None,
) -> None:

    config = load_ai_config(filepath)
    signatures: dict[str, list[str]] = {}
    for row in rows:
        provider_name = str(row.get("Provider", "") or "").strip()
        if not provider_name:
            continue
        pattern_text = str(row.get("Patterns", "") or "").strip()
        patterns = [part.strip() for part in pattern_text.split(",") if part.strip()]
        signatures[provider_name] = patterns

    config["ai_signatures"] = signatures
    auth_list = [str(x).strip() for x in (config.get("authorized_providers", []) or []) if str(x).strip()]
    if old_provider and new_provider and old_provider != new_provider:
        auth_list = [new_provider if value == old_provider else value for value in auth_list]
    if deleted_provider:
        auth_list = [value for value in auth_list if value != deleted_provider]
    config["authorized_providers"] = [value for value in _ordered_unique(auth_list) if value in signatures]
    save_ai_config(filepath, config)
    st.session_state["ai_sig_rows_state"] = rows
    st.session_state["_ai_sig_source_key"] = _ai_signature_source_key(config)
    log_activity(
        filepath,
        action_label,
        "AI Signature",
        [str(item_label or new_provider or deleted_provider or old_provider or "").strip()],
    )
    _invalidate_auth_section("ai")


def _update_ai_signature_row(filepath: Path, row_id: str, provider: str, patterns_text: str) -> None:
    row_id = str(row_id or "").strip()
    _, rows = _get_ai_signature_rows_state(filepath)
    clean_provider = str(provider or "").strip()
    if not clean_provider:
        raise ValueError("Provider name is required.")
    if any(str(row.get("Provider", "")).strip().lower() == clean_provider.lower() and str(row.get("_id", "")).strip() != row_id for row in rows):
        raise ValueError("That provider already exists in AI Policies.")

    target_index = next((i for i, row in enumerate(rows) if str(row.get("_id", "")).strip() == row_id), None)
    old_provider = ""
    action_label = "Added"
    item_label = clean_provider
    if target_index is None:
        rows.append({"_id": row_id or str(uuid4()), "Provider": clean_provider, "Patterns": str(patterns_text or "").strip()})
    else:
        old_provider = str(rows[target_index].get("Provider", "") or "").strip()
        rows[target_index] = {
            "_id": row_id,
            "Provider": clean_provider,
            "Patterns": str(patterns_text or "").strip(),
        }
        action_label = "Edited"
        item_label = f"{old_provider} -> {clean_provider}" if old_provider and old_provider != clean_provider else clean_provider

    _persist_ai_signature_rows(
        filepath,
        rows,
        old_provider=old_provider or None,
        new_provider=clean_provider,
        action_label=action_label,
        item_label=item_label,
    )


def _delete_ai_signature_row(filepath: Path, row_id: str) -> None:
    row_id = str(row_id or "").strip()
    _, rows = _get_ai_signature_rows_state(filepath)
    removed = next((row for row in rows if str(row.get("_id", "")).strip() == row_id), None)
    if removed is None:
        raise ValueError("The selected AI policy no longer exists.")
    rows = [row for row in rows if str(row.get("_id", "")).strip() != row_id]
    deleted_provider = str(removed.get("Provider", "") or "").strip()
    _persist_ai_signature_rows(
        filepath,
        rows,
        deleted_provider=deleted_provider,
        action_label="Deleted",
        item_label=deleted_provider,
    )


def show_ai_edit_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    with _auth_modal_shell("ai_edit"):
        st.markdown("### Edit AI Policy")
        st.markdown("**AI Policies**")
        st.caption("Update the selected record and save the changes.")

        provider_value = st.text_input("AI Provider Name", value=str((row or {}).get("Provider", "") or ""), key="auth_edit_ai_provider")
        patterns_value = st.text_area(
            "Regex Patterns (Comma Separate)",
            value=str((row or {}).get("Patterns", "") or ""),
            placeholder="pattern1, pattern2, pattern3",
            key="auth_edit_ai_patterns",
            height=160,
        )
        save_label = "Add Policy" if not row_id else "Save Policy"
        save_col, cancel_col = st.columns(2, gap="small")
        with save_col:
            if st.button(save_label, type="primary", width="stretch", key="auth_edit_ai_save"):
                try:
                    _update_ai_signature_row(ai_yaml_file, row_id, provider_value, patterns_value)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("AI policy updated.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_edit_ai_cancel"):
                _close_auth_table_dialog()
                _rerun_app()


def show_ai_delete_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    target_text = str((row or {}).get("Provider", "") or "").strip()
    with _auth_modal_shell("ai_delete"):
        st.markdown("### Delete AI Policy")
        st.markdown("**AI Policies**")
        st.warning(f"Delete this entry?\n\n`{target_text or 'Unknown'}`")
        confirm_col, cancel_col = st.columns(2, gap="small")
        with confirm_col:
            if st.button("Delete AI Policy", type="primary", width="stretch", key="auth_delete_confirm_ai"):
                try:
                    _delete_ai_signature_row(ai_yaml_file, row_id)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Entry deleted.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_delete_cancel_ai"):
                _close_auth_table_dialog()
                _rerun_app()


def render_ai_policies_section(yaml_path: Path) -> None:

    config, sig_rows = _get_ai_signature_rows_state(yaml_path)
    dialog_payload = _get_auth_dialog_request()
    if str(dialog_payload.get("section", "") or "").strip().lower() == "ai":
        kind = str(dialog_payload.get("kind", "") or "").strip().lower()
        row = dict(dialog_payload.get("row") or {})
        mac_file = yaml_path.parent / "authorized_macs.yaml"
        domain_file = yaml_path.parent / "whitelist_domains.yaml"
        ban_file = yaml_path.parent / "banned_macs.yaml"
        if kind == "edit":
            show_ai_edit_dialog(row, mac_file, domain_file, yaml_path, ban_file)
        elif kind == "delete":
            show_ai_delete_dialog(row, mac_file, domain_file, yaml_path, ban_file)

    st.subheader("Sanctioned AI Providers")
    auth_list = config.get("authorized_providers", [])
    sigs_dict = config.get("ai_signatures", {})
    available_providers = _ordered_unique(
        [str(value or "").strip() for value in auth_list] + [str(value or "").strip() for value in sigs_dict.keys()]
    )
    valid_defaults = [x for x in auth_list if x in available_providers]

    auth_select_col, auth_add_col = st.columns([4, 1], gap="small")
    with auth_select_col:
        new_auth = st.multiselect("Select Authorized Providers", options=available_providers, default=valid_defaults)
    with auth_add_col:
        st.markdown("<div style='height: 1.9rem;'></div>", unsafe_allow_html=True)
        if st.button("+ Add Policy", key="ai_sig_add_row", type="primary", width="stretch"):
            _open_auth_table_dialog("edit", "ai", {"_id": "", "Provider": "", "Patterns": ""})
            st.rerun()

    if set(new_auth) != set(auth_list):
        if st.button("Update Sanctioned List"):
            config["authorized_providers"] = new_auth
            save_ai_config(yaml_path, config)
            st.toast("Sanctioned list updated")
            st.rerun()

    st.divider()
    st.subheader("Detection Signatures")

    sig_df = pd.DataFrame(sig_rows)
    if sig_df.empty:
        sig_df = pd.DataFrame(columns=["_id", "Provider", "Patterns"])

    sig_df = _with_table_action_state(_with_row_numbers(sig_df[["_id", "Provider", "Patterns"]].copy()))

    _open_shadow_table_shell()
    ai_editor_key = "ai_sig_editor_cache"
    ai_source_key = st.session_state.get("_ai_sig_source_key")
    if ai_editor_key not in st.session_state or st.session_state.get("_ai_sig_editor_source_key") != ai_source_key:
        st.session_state[ai_editor_key] = _normalize_auth_editor_df(sig_df, sig_df)
        st.session_state["_ai_sig_editor_source_key"] = ai_source_key
    else:
        st.session_state[ai_editor_key] = _normalize_auth_editor_df(st.session_state[ai_editor_key], sig_df)

    action_config = {
        "Actions": {
            "header": "Actions",
            "width": 126,
            "cellStyle": AUTH_ACTION_CELL_STYLE,
            "clickHandler": AUTH_ACTION_CLICK_JS,
            "pinned": "right",
        },
    }

    grid_response = _render_shadow_aggrid(
        st.session_state[ai_editor_key],
        key=_auth_grid_key("ai_sig_editor_grid"),
        hidden_cols={"_id", AUTH_ACTION_TOKEN_COL},
        col_headers={
            "Provider": "AI Provider Name",
            "Patterns": "Regex Patterns (Comma Separate)",
        },
        column_widths={
            "Provider": 220,
            "Patterns": 520,
            "Actions": 126,
        },
        column_flexes={"Patterns": 1},
        height=_table_height_for_rows(len(st.session_state[ai_editor_key]), min_px=240, max_px=520),
        action_config=action_config,
    )
    _close_shadow_table_shell()
    edited_sigs = _normalize_auth_editor_df(_aggrid_to_df(grid_response, st.session_state[ai_editor_key]), sig_df)
    pending_action, cleaned_df = _consume_grid_action(edited_sigs)
    st.session_state[ai_editor_key] = _normalize_auth_editor_df(cleaned_df, sig_df)
    if pending_action:
        _open_auth_table_dialog(str(pending_action.get("action", "")), "ai", pending_action.get("row") or {})
        st.rerun()


# -----------------------------
# Audit Log Data & UI
# -----------------------------
def log_activity(filepath: Path, action: str, item_type: str, items: list[str]) -> None:

    if not items:
        return
    log_file = filepath.parent / "activity_log.csv"
    timestamp = _now_str()
    new_rows = [{"Timestamp": timestamp, "Action": action, "Type": item_type, "Item": item} for item in items]
    df_new = pd.DataFrame(new_rows)
    header_needed = not log_file.exists()
    df_new.to_csv(log_file, mode="a", header=header_needed, index=False)


def load_history(mac_file: Path) -> pd.DataFrame:
    log_file = mac_file.parent / "activity_log.csv"
    if not log_file.exists():
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])
    try:
        df = pd.read_csv(log_file)
        return df.drop_duplicates().sort_values(by="Timestamp", ascending=False)
    except Exception:
        return pd.DataFrame(columns=["Timestamp", "Action", "Type", "Item"])


def render_audit_log_section(mac_file: Path) -> None:

    st.subheader("System Audit Log")
    history_df = load_history(mac_file)
    if not history_df.empty:
        hist_view = _with_row_numbers(history_df).reset_index(drop=True).copy()
        if "Timestamp" in hist_view.columns:
            hist_view["Timestamp"] = pd.to_datetime(hist_view["Timestamp"], errors="coerce").dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            ).fillna("-")

        _open_shadow_table_shell()
        _render_shadow_aggrid(
            hist_view,
            key="auth_audit_grid",
            col_headers={
                "Timestamp": "Timestamp",
                "Action": "Action",
                "Type": "Type",
                "Item": "Item",
            },
            column_widths={
                "Timestamp": 190,
                "Action": 140,
                "Type": 150,
                "Item": 360,
            },
            column_flexes={"Item": 1},
            height=_table_height_for_rows(len(hist_view), min_px=240, max_px=520),
        )
        _close_shadow_table_shell()
        if st.button("Clear Audit Log", type="secondary"):
            (mac_file.parent / "activity_log.csv").unlink(missing_ok=True)
            st.rerun()
    else:
        st.info("No activity recorded yet.")


# -----------------------------
# Ban List Data & UI
# -----------------------------
def load_ban_list(filepath: Path) -> list[dict]:

    if not filepath.exists():
        return []
    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not data:
            return []
        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            if filepath.stem in data and isinstance(data[filepath.stem], list):
                raw_list = data[filepath.stem]
            else:
                for v in data.values():
                    if isinstance(v, list):
                        raw_list = v
                        break

        out = []
        file_stamp = _file_mtime_str(filepath)
        for it in raw_list:
            if isinstance(it, str):
                m = normalize_mac(it)
                if m:
                    out.append({"mac": m, "date_modified": file_stamp})
            elif isinstance(it, dict):
                m = normalize_mac(it.get("mac", ""))
                if m:
                    out.append({"mac": m, "date_modified": str(it.get("date_modified") or file_stamp)})

        out = _dedupe_keep_last(out, "mac")
        out.sort(key=lambda x: x.get("mac", ""))
        return out
    except Exception:
        return []


def save_ban_list(filepath: Path, ban_list: list[dict]) -> None:

    filepath.parent.mkdir(exist_ok=True, parents=True)
    key_name = filepath.stem

    cleaned = []
    for r in ban_list:
        m = normalize_mac(r.get("mac", ""))
        if not m or not _mac_is_valid(m):
            continue
        cleaned.append({"mac": m, "date_modified": str(r.get("date_modified") or _now_str()).strip()})

    cleaned = _dedupe_keep_last(cleaned, "mac")
    cleaned.sort(key=lambda x: x.get("mac", ""))

    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump({key_name: cleaned}, f, sort_keys=False)


def _get_ban_rows_state(filepath: Path) -> list[dict]:

    rows = st.session_state.get("ban_rows_state")
    if not isinstance(rows, list):
        rows = []
        for row in load_ban_list(filepath):
            row_copy = dict(row)
            row_copy["_id"] = row_copy.get("_id") or str(uuid4())
            row_copy["mac"] = normalize_mac(row_copy.get("mac", ""))
            rows.append(row_copy)
    st.session_state.ban_rows_state = rows
    return rows


def _update_ban_row(filepath: Path, row_id: str, mac: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_ban_rows_state(filepath)
    target_index = next((i for i, row in enumerate(rows) if str(row.get("_id", "")).strip() == row_id), None)
    if target_index is None:
        raise ValueError("The selected banned MAC no longer exists.")

    mac_norm = normalize_mac(mac)
    if not mac_norm or not _mac_is_valid(mac_norm):
        raise ValueError("Enter a valid MAC address.")
    if any(normalize_mac(row.get("mac", "")) == mac_norm and str(row.get("_id", "")).strip() != row_id for row in rows):
        raise ValueError("That MAC address is already in the ban list.")

    old_mac = normalize_mac(rows[target_index].get("mac", ""))
    rows[target_index] = {"_id": row_id, "mac": mac_norm, "date_modified": _now_str()}
    rows = _dedupe_keep_last(rows, "mac")
    st.session_state.ban_rows_state = rows
    save_ban_list(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    item_text = f"{old_mac} -> {mac_norm}" if old_mac and old_mac != mac_norm else mac_norm
    log_activity(filepath, "Edited", "Banned MAC", [item_text])
    _invalidate_auth_section("ban")


def _delete_ban_row(filepath: Path, row_id: str) -> None:

    row_id = str(row_id or "").strip()
    rows = _get_ban_rows_state(filepath)
    removed = next((row for row in rows if str(row.get("_id", "")).strip() == row_id), None)
    if removed is None:
        raise ValueError("The selected banned MAC no longer exists.")
    rows = [row for row in rows if str(row.get("_id", "")).strip() != row_id]
    st.session_state.ban_rows_state = rows
    save_ban_list(filepath, [{k: v for k, v in row.items() if k != "_id"} for row in rows])
    removed_mac = normalize_mac(removed.get("mac", ""))
    if removed_mac:
        log_activity(filepath, "Deleted", "Banned MAC", [removed_mac])
    _invalidate_auth_section("ban")


def show_ban_edit_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    with _auth_modal_shell("ban_edit"):
        st.markdown("### Edit Ban Entry")
        st.markdown("**Ban List**")
        st.caption("Update the selected record and save the changes.")

        mac_value = st.text_input("MAC Address", value=str((row or {}).get("mac", "") or ""), key="auth_edit_ban_mac")
        save_col, cancel_col = st.columns(2, gap="small")
        with save_col:
            if st.button("Save Ban Entry", type="primary", width="stretch", key="auth_edit_ban_save"):
                try:
                    _update_ban_row(ban_file, row_id, mac_value)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Ban list entry updated.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_edit_ban_cancel"):
                _close_auth_table_dialog()
                _rerun_app()


def show_ban_delete_dialog(row: dict, mac_file: Path, domain_file: Path, ai_yaml_file: Path, ban_file: Path) -> None:
    row_id = str((row or {}).get("_id", "") or "").strip()
    target_text = str((row or {}).get("mac", "") or "").strip()
    with _auth_modal_shell("ban_delete"):
        st.markdown("### Delete Ban Entry")
        st.markdown("**Ban List**")
        st.warning(f"Delete this entry?\n\n`{target_text or 'Unknown'}`")
        confirm_col, cancel_col = st.columns(2, gap="small")
        with confirm_col:
            if st.button("Delete Entry", type="primary", width="stretch", key="auth_delete_confirm_ban"):
                try:
                    _delete_ban_row(ban_file, row_id)
                except ValueError as exc:
                    st.error(str(exc))
                    return
                _close_auth_table_dialog()
                st.success("Entry deleted.")
                _rerun_app()
        with cancel_col:
            if st.button("Cancel", width="stretch", key="auth_delete_cancel_ban"):
                _close_auth_table_dialog()
                _rerun_app()


def render_ban_list_section(ban_file: Path) -> None:

    st.markdown("**Ban List**")
    dialog_payload = _get_auth_dialog_request()
    if str(dialog_payload.get("section", "") or "").strip().lower() == "ban":
        kind = str(dialog_payload.get("kind", "") or "").strip().lower()
        row = dict(dialog_payload.get("row") or {})
        mac_file = ban_file.parent / "authorized_macs.yaml"
        domain_file = ban_file.parent / "whitelist_domains.yaml"
        ai_yaml_file = ban_file.parent / "ai_signatures.yaml"
        if kind == "edit":
            show_ban_edit_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif kind == "delete":
            show_ban_delete_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)

    if "ban_rows_state" not in st.session_state:
        rows = []
        for r in load_ban_list(ban_file):
            rr = dict(r)
            rr["_id"] = rr.get("_id") or str(uuid4())
            rr["mac"] = normalize_mac(rr.get("mac", ""))
            rows.append(rr)
        st.session_state.ban_rows_state = rows

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        new_text = st.text_input(
            "Add MAC to Ban List",
            placeholder="Paste MAC Address (supports multiple)",
            label_visibility="collapsed",
            key="ban_add_input",
        )
    with col_btn:
        if st.button("+ Add MAC", type="primary", key="ban_add_btn", width="stretch"):
            entries = [x for x in re.split(r"[,\s\n]+", (new_text or "")) if x.strip()]
            entries = [normalize_mac(x) for x in entries]
            entries = [m for m in entries if m and _mac_is_valid(m)]

            existing = {normalize_mac(d.get("mac")) for d in st.session_state.ban_rows_state}
            added = []
            for m in entries:
                if m in existing:
                    continue
                st.session_state.ban_rows_state.append({"_id": str(uuid4()), "mac": m, "date_modified": _now_str()})
                existing.add(m)
                added.append(m)

            if added:
                save_ban_list(
                    ban_file,
                    [{k: v for k, v in r.items() if k != "_id"} for r in st.session_state.ban_rows_state],
                )
                log_activity(ban_file, "Added", "Banned MAC", added)
                _invalidate_auth_section("ban")
                st.toast(f"Banned {len(added)} MAC(s)")
                st.rerun()
            else:
                st.info("No new valid MACs were added (duplicates/invalid).")

    st.divider()

    ban_search_state_key = "ban_search"
    if ban_search_state_key not in st.session_state:
        st.session_state[ban_search_state_key] = ""
    st.text_input(
        "Search Banned MACs",
        placeholder="Search MAC Address..",
        label_visibility="collapsed",
        key=ban_search_state_key,
    )
    search_query = str(st.session_state.get(ban_search_state_key, "") or "").strip().lower()

    df = pd.DataFrame(st.session_state.ban_rows_state)
    if df.empty:
        df = pd.DataFrame(columns=["_id", "mac", "date_modified"])

    for c in ["_id", "mac", "date_modified"]:
        if c not in df.columns:
            df[c] = ""

    if search_query:
        df = df[df["mac"].astype(str).str.contains(search_query, case=False, na=False)].copy()

    df["_dt_sort"] = df["date_modified"].apply(_parse_dt)
    df = df.sort_values(by="_dt_sort", ascending=False, na_position="last").drop(columns=["_dt_sort"])

    editor_df = _with_table_action_state(_with_row_numbers(df[["_id", "mac", "date_modified"]].copy()))

    _open_shadow_table_shell()
    view_key = search_query
    ban_editor_key = "ban_editor_cache"
    ban_filter_key = "ban_editor_filter"
    if st.session_state.get(ban_filter_key) != view_key or ban_editor_key not in st.session_state:
        st.session_state[ban_filter_key] = view_key
        st.session_state[ban_editor_key] = _normalize_auth_editor_df(editor_df, editor_df)
    else:
        st.session_state[ban_editor_key] = _normalize_auth_editor_df(st.session_state[ban_editor_key], editor_df)

    action_config = {
        "Actions": {
            "header": "Actions",
            "width": 126,
            "cellStyle": AUTH_ACTION_CELL_STYLE,
            "clickHandler": AUTH_ACTION_CLICK_JS,
            "pinned": "right",
        },
    }

    grid_response = _render_shadow_aggrid(
        st.session_state[ban_editor_key],
        key=_auth_grid_key("ban_editor_grid"),
        hidden_cols={"_id", AUTH_ACTION_TOKEN_COL},
        col_headers={
            "mac": "MAC Address",
            "date_modified": "Date Modified",
        },
        column_widths={
            "mac": 180,
            "date_modified": 190,
            "Actions": 126,
        },
        column_flexes={"mac": 1},
        height=_table_height_for_rows(len(st.session_state[ban_editor_key]), min_px=240, max_px=520),
        action_config=action_config,
    )
    _close_shadow_table_shell()
    edited_df = _normalize_auth_editor_df(
        _aggrid_to_df(grid_response, st.session_state[ban_editor_key]), editor_df
    )
    pending_action, cleaned_df = _consume_grid_action(edited_df)
    st.session_state[ban_editor_key] = _normalize_auth_editor_df(cleaned_df, editor_df)
    if pending_action:
        _open_auth_table_dialog(str(pending_action.get("action", "")), "ban", pending_action.get("row") or {})
        st.rerun()


def render_pending_auth_dialog(
    payload: dict,
    mac_file: Path,
    domain_file: Path,
    ai_yaml_file: Path,
    ban_file: Path,
) -> None:
    kind = str((payload or {}).get("kind", "") or "").strip().lower()
    section = str((payload or {}).get("section", "") or "").strip().lower()
    row = dict((payload or {}).get("row") or {})

    if kind == "edit":
        if section == "device":
            show_device_edit_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "domain":
            show_domain_edit_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "ai":
            show_ai_edit_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "ban":
            show_ban_edit_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
    elif kind == "delete":
        if section == "device":
            show_device_delete_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "domain":
            show_domain_delete_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "ai":
            show_ai_delete_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)
        elif section == "ban":
            show_ban_delete_dialog(row, mac_file, domain_file, ai_yaml_file, ban_file)

# -----------------------------
# Main Render
# -----------------------------
def render(mac_file: Path):
    inject_custom_css()
    inject_traffic_style_header_css()

    if mac_file.suffix == ".txt":
        yaml_path = mac_file.with_suffix(".yaml")
        if yaml_path.exists():
            mac_file = yaml_path

    mac_file = mac_file.resolve()
    domain_file = (mac_file.parent / "whitelist_domains.yaml").resolve()
    ai_yaml_file = (mac_file.parent / "ai_signatures.yaml").resolve()
    ban_file = (mac_file.parent / "banned_macs.yaml").resolve()

    updated_txt = get_local_now().strftime("%Y-%m-%d %H:%M:%S")
    render_traffic_style_header(
        title="Authorization Overview",
        subtitle="Device, domain, and AI policy controls",
        chip_label="Live monitoring",
        updated_txt=updated_txt,
    )
    with dashboard_loading_ui(
        title="Loading Authorization",
        subtitle="Preparing device, domain, AI policy, and ban-list controls for administration.",
        steps=["Read policies", "Prepare tables", "Render controls"],
        container=st.empty(),
    ):
        saved_devices = load_devices(mac_file)
        saved_domains = load_domain_whitelist(domain_file)
        ai_config = load_ai_config(ai_yaml_file)
        saved_bans = load_ban_list(ban_file)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_auth_metric_card("Device Whitelist", len(saved_devices), "Authorized MAC entries")
    with m2:
        render_auth_metric_card("Domain Whitelist", len(saved_domains), "Allowed domain entries")
    with m3:
        render_auth_metric_card("AI Policies", _ai_policy_provider_count(ai_config), "Configured AI providers")
    with m4:
        render_auth_metric_card("Banned MACs", len(saved_bans), "Blocked devices")

    st.write("")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Device Access", "Domain Whitelist", "AI Policies", "Audit Log", "Ban List"]
    )

    with tab1:
        render_device_access_section(saved_devices, mac_file)

    with tab2:
        render_domain_whitelist_section(saved_domains, domain_file)

    with tab3:
        render_ai_policies_section(ai_yaml_file)

    with tab4:
        render_audit_log_section(mac_file)

    with tab5:
        render_ban_list_section(ban_file)
