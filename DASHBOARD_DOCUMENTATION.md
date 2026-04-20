# Zeek Dashboard - Accurate Functional Documentation
Last validated against source code: 2026-04-21

## 1) Scope
This document describes how the current dashboard implementation works in this repository.
It is based on active code paths in:
- `app.py`
- `config/client.py`
- `ui/auth.py`
- `ui/sidebar.py`
- `ui/pages/*`
- selected helpers in `services/auth_service.py` and `services/drive_services.py`

## 2) What This System Does
Zeek Dashboard is a Streamlit application that reads Zeek parquet logs from `data/parquet` and provides:
- Device inventory and trust posture.
- Alerts for verified and unauthorized devices.
- Traffic Monitoring modules for:
  - Shadow Apps
  - Shadow Sharings
  - Shadow AI
  - Anonymization Network
- Raw Zeek parquet log exploration.
- Admin controls for allowlists, policies, bans, audit history, and user accounts.

## 3) Runtime and Data Prerequisites
1. Python environment and dependencies from `requirements.txt`.
2. Local parquet logs under `data/parquet/YYYY-MM-DD/*.parquet`.
3. Authentication backend configured in `.streamlit/secrets.toml` (`mongodb` or `mysql`).
4. SMTP configured for OTP and new-user e-mail delivery.
5. Optional Google OAuth settings if OAuth mode is enabled.
6. Optional Google Drive credentials if automatic Drive-to-parquet sync is used.

## 4) Application Lifecycle and Background Services
Current behavior in `app.py`:
1. `st.set_page_config(...)` is set once at app startup.
2. `data/parquet` is created if it does not exist.
3. Authentication schema initialization runs on startup through `auth_service.init_auth_schema()`.
4. Bootstrap admin seeding runs on startup through `auth_service.seed_bootstrap_admin()`.
5. A background Drive sync manager is created with a single-worker executor.
6. On each rerun, the app:
- polls any in-flight Drive sync job
- schedules a new background sync when enough time has passed
- computes target dates from `DRIVE_SYNC_LOOKBACK_DAYS`; when this is `<= 0`, it passes an empty target tuple and lets Drive sync use scoped policy
7. Default timing from `config/client.py`:
- `AUTO_REFRESH_INTERVAL = 3600` seconds
- `DRIVE_SYNC_INTERVAL = 3600` seconds
- `DRIVE_SYNC_LOOKBACK_DAYS = 0` (scoped policy)
8. Background refresh behavior:
- `st_autorefresh(...)` currently runs on a fixed hourly cadence (`HOURLY_SYNC_INTERVAL_SECONDS = 3600`)
- user interactions also cause normal Streamlit reruns
9. If a Drive sync completes successfully:
- `_parquet_sync_token` is incremented
- `st.cache_data.clear()` is called
- the app reruns so pages pick up the new parquet data
10. Several Traffic Monitoring pages watch `_parquet_sync_token` and reset page-local caches when new parquet arrives.

Important current-state note:
- There is no user-visible manual Drive sync button in the current sidebar code.

## 5) Authentication Flow (Exact Behavior)
Current behavior in `ui/auth.py`:
1. Persistent auth is restored first from:
- URL query param `auth`
- `.streamlit/auth_session_store.json`
2. If Google OAuth is configured, OAuth callback handling runs before showing the login form.
3. The login form requires:
- Gmail-format username
- password
- arithmetic captcha
4. The entered e-mail must pass:
- Gmail-only validation
- optional allowed-e-mail validation when configured
5. The entered password must include at least one special character before credential verification continues.
6. Credential verification uses `verify_user_credentials_for_otp(...)`.
7. Branching on `password_reset_required`:
- If `false`:
  - login completes immediately with `complete_login_after_otp(...)`
  - OTP is not sent
- If `true`:
  - a 6-digit OTP is sent to e-mail
  - OTP expires in 60 seconds
  - after OTP verification, the user must change the default password
8. If Google OAuth is enabled:
- after OTP verification, or after password reset, the user is redirected to Google sign-in
- Google account verification must match the typed e-mail
9. Successful login stores a persistent HMAC-signed auth token with a configurable TTL.
10. Logout clears:
- persistent auth session
- query params
- session state (except auth schema bootstrap state)

## 6) Roles and Access Control
Routing behavior from `app.py`:
- `admin` menu:
  - Device Inspection
  - Traffic Monitoring
  - Zeek Logs
  - Alerts
  - Authorization
  - User Management
  - Logout
- `staff` menu:
  - Device Inspection
  - Traffic Monitoring
  - Zeek Logs
  - Alerts
  - Logout

Important accuracy note:
- `Authorization` and `User Management` are protected both by menu visibility and by server-side role checks inside page routing.

## 7) Sidebar and Shared Page Behavior
From `ui/sidebar.py` and `app.py`:
- The sidebar is a custom collapsible option-menu sidebar.
- It shows user initials, display name, and role.
- Selected page state is stored in session.
- The app renders the sidebar once per run and routes from the selected menu item.
- If any dialog is open, the sidebar stays pinned to the current page instead of following incidental reruns.
- Major pages use shared dashboard-style headers and loading shells before data-heavy content is rendered.

## 8) Data Ingestion, Caches, and State
### 8.1 Local Data Contract
Expected local layout:
- `data/parquet/YYYY-MM-DD/*.parquet`

### 8.2 Google Drive Sync Capability
Drive sync backend exists in `services/drive_services.py`.
Current implementation wiring:
- background sync is scheduled automatically by `app.py`
- it refreshes local parquet files under `data/parquet`
- there is no current manual sidebar trigger

### 8.3 Page Cache Locations
Current cache directories under `data/parquet` include:
- `data/parquet/_cache_alerts`
- `data/parquet/_shadow_cache_apps`
- `data/parquet/_shadow_cache_sharing`
- `data/parquet/_shadow_cache_ai`
- `data/parquet/_shadow_cache_anonymization_network`

The anonymization module also keeps feed and scored-cache artifacts inside its cache tree.

### 8.4 Policy and State Files
Authorization and policy files:
- `authorized_macs.yaml` or legacy `authorized_macs.txt`
- `whitelist_domains.yaml`
- `ai_signatures.yaml`
- `banned_macs.yaml`
- `risk_policy.yaml`
- `config/anonymization_network_allowlist.yaml` or legacy anonymization allowlist candidates

Operational state and logs:
- `activity_log.csv`
- `authorized_macs_history.json`
- `device_metrics_store.json`
- `.streamlit/auth_session_store.json`

## 9) Page Playbooks

### 9.1 Device Inspection (`Device Overview` header)
Purpose: Device inventory, authorization posture, and device-level forensics.

Operator flow:
1. Open `Device Inspection`.
2. Review metric cards:
- Total Devices
- Active Devices
- Authorized
- Unauthorized
- Risk Ratio
3. Click `Active Devices`, `Authorized`, or `Unauthorized` cards to open dialogs.
4. In Authorized/Unauthorized dialogs, use:
- MAC search
- Time Range (`Last 7 Days`, `Last 30 Days`, `Specific Date`, `All Time`)
- History filter (`Hide`, `Last 7 Days`, `All`)
5. Export Authorized/Unauthorized dialog CSV when needed.
6. Click a MAC cell to open device forensics.
7. In Forensics, choose:
- Time Range
- Service filter (`All Services`, `DNS`, `HTTP`, `SSL`)

Primary outputs:
- Metric cards with daily delta tracking.
- Hourly Authorized vs Unauthorized activity chart.
- Risk gauge with thresholds:
  - `Healthy` when risk `<= 20`
  - `Warning` when risk `<= 50`
  - `High Risk` when risk `> 50`
- Active Devices dialog.
- Authorized Devices dialog with `Authorized Date` and `Last Seen`.
- Unauthorized Devices dialog with MAC spoofing status.
- Optional authorization history table inside the list dialog.
- Forensics traffic-volume chart.
- Forensics top-destinations table.

Read sources:
- Alerts latest-per-MAC cache when available.
- `known_hosts` and DHCP-derived parquet data.
- authorization records and authorization history.
- ban list.

Write side effects:
- updates `device_metrics_store.json`
- if a MAC exists in both allowlist and ban list, the ban entry is removed and `banned_macs.yaml` is rewritten

Important data behavior:
- inventory prefers the latest Alerts cache view, then enriches from DHCP and authorization metadata
- banned MACs are excluded from page-level counts and tables

### 9.2 Traffic Monitoring (Container Page)
Purpose: Shared container page that switches between four traffic modules.

Current section selector values:
- Shadow Apps
- Shadow Sharings
- Shadow AI
- Anonymization Network

Shared behavior across the traffic modules:
- the selected date is often loaded together with adjacent day folders
- after loading, rows are strictly filtered back to the selected date by timestamp
- this avoids missing midnight-spillover events stored in neighboring day folders

### 9.3 Traffic Monitoring - Shadow Apps
Purpose: Detect unauthorized application behavior from correlated Zeek telemetry.

Operator flow:
1. Select `Dataset Scope`.
2. Open `Detection basis` to review risk-policy-driven logic.
3. Review top metrics.
4. Review charts:
- Activity Over Time
- Source Distribution
5. Filter the incidents grid by:
- Search
- Risk Level
- Source Logs
6. Click MAC to open device/app forensics.
7. Allow a destination when needed.
8. Export CSV.

Primary outputs:
- Total Events
- Authorized Events
- Unauthorized Events
- Critical / High Risk
- execution trace panel with `Initial Load` and `Shadow Apps Load` step timings
- timeline chart
- source pie chart
- risk-ranked incidents grid

Read sources:
- `_shadow_cache_apps`
- `risk_policy.yaml`
- `whitelist_domains.yaml`

Write side effects:
- allow actions update `whitelist_domains.yaml`

### 9.4 Traffic Monitoring - Shadow Sharings
Purpose: Detect suspicious sharing and upload behavior from correlated conn/ssl/http/files telemetry.

Operator flow:
1. Select `Dataset Scope`.
2. Review `Detection basis`.
3. Review top metrics:
- Selected Events
- Total Volume
- Automation / SDK
- Top Offender
- Unique devices in scope
4. Review the incident-confidence timeline.
5. Filter the incidents table by:
- Search
- Confidence Level
- Source Logs
6. Click a MAC row to open the device sharing incidents dialog.
7. Edit `Allowed` decisions to whitelist destination domains when appropriate.
8. Export CSV.

Primary outputs:
- scope metrics and unique-device count
- confidence-over-time view with adaptive time buckets
- grouped daily incident table by MAC + Destination
- per-device incidents dialog

Read sources:
- `_shadow_cache_sharing`
- selected day plus adjacent day folders
- `whitelist_domains.yaml`

Write side effects:
- allow decisions update `whitelist_domains.yaml`

Important accuracy note:
- in code, Traffic Monitoring currently routes `Shadow Sharings` through `render_shadow_uploads(...)`, which is a compatibility alias for the active sharing renderer

### 9.5 Traffic Monitoring - Shadow AI
Purpose: Detect AI usage and potential leakage risk from signatures, policy context, and Zeek telemetry.

Operator flow:
1. Select `Dataset Scope`.
2. Review `Detection basis`.
3. Apply page filters:
- Search
- Risk Level
- Evidence Type
4. Review top metrics:
- Selected Events
- Shadow AI Events
- Critical Incidents
- Unique MACs
- Unique Hosts
- Data Leakage
5. Use the main tab selector:
- Overview
- Trends
- Shadow AI Incidents
6. In `Shadow AI Incidents`, review:
- provider summary table
- top destinations/domains
- Shadow AI by MAC
- signature fragments causing matches
7. Toggle provider `Allowed` when needed.
8. Click MAC in the MAC table to open the device AI incidents dialog.
9. Export CSV from the current table views.

Primary outputs:
- scope metrics and unique source-IP count
- overview scatter timeline
- trend visualizations
- provider grid with grouped risk basis
- top destinations/domains grid
- MAC summary grid with dialog drilldown
- signature-match summary grid

Read sources:
- `_shadow_cache_ai`
- `ai_signatures.yaml`
- selected day plus adjacent day folders

Write side effects:
- provider allow actions update `authorized_providers` in `ai_signatures.yaml`

Important current-state note:
- the current UI only exposes Search, Risk Level, and Evidence Type filters to operators
- older provider/verdict/match-field filter concepts still exist in code paths but are not surfaced as page controls

### 9.6 Traffic Monitoring - Anonymization Network
Purpose: Detect Proxy, VPN, and Tor behavior with scoring, feed enrichment, and summarized triage tables.

Operator flow:
1. Select `Dataset Scope`.
2. Review `Detection basis`.
3. Apply filters:
- Search
- Confidence
- Source
- Category
4. Review metric cards.
5. Review charts:
- Events By Category
- Top Source IP (Max Risk)
6. Review `Top destinations/reasons`.
7. Review `Proxy/VPN/Tor Incidents`.
8. Export CSV from the summary and incident tables.

Primary outputs:
- Events
- High
- Proxy
- VPN
- Tor
- High Evidence
- destination/reason SOC rollup
- event-level Proxy/VPN/Tor incidents table

Read sources:
- `_shadow_cache_anonymization_network`
- cached external feeds for Tor/open proxy logic
- optional `data/ip2proxy_lookup.parquet` or `IP2PROXY_LOOKUP_FILE`
- anonymization allowlist YAML candidates

Important current-state note:
- the module contains anonymization allowlist helper code and dialog code
- the current render path is focused on scoring, filtering, and export; it does not expose an active allowlist action in the main operator flow

### 9.7 Zeek Logs (`Raw Log Explorer` header)
Purpose: Browse raw Zeek parquet rows for a selected day and log type.

Operator flow:
1. Pick `Dataset Day`.
2. Pick `Log Type`.
3. Search all columns with free text.
4. Optionally use datetime-like search input (`YYYY-MM-DD[ HH[:MM[:SS[.ffffff]]]]`).
5. Browse the resulting grid.

Primary outputs:
- raw row explorer for the selected parquet-backed log
- full-column search
- datetime-aware filtering behavior

Read sources:
- `data/parquet/YYYY-MM-DD/*.parquet`

Important current-state note:
- if no parquet data exists, the page still shows a legacy message suggesting `Force Refresh Data` in the sidebar
- that sidebar control is not present in the current app

### 9.8 Alerts (`Alerts Overview` header)
Purpose: Time-scoped device trust monitoring for verified and unauthorized devices.

Operator flow:
1. Choose `Filter Scope`:
- Last 7 Days
- Last 30 Days
- Specific Date
- All Time
2. Click a metric card to choose the active table view:
- Total Devices
- Verified Devices
- Unauthorized Devices
3. Use table filters:
- Search table
- Source
4. Export CSV.

Primary outputs:
- scope-aware metric cards
- prioritized status banner:
  - allowlist removal alert first
  - unauthorized-device warning second
  - secure success banner otherwise
- filterable device table with row counts

Read sources:
- `_cache_alerts`
- authorization allowlist
- ban list
- inferred private-IP fallback on specific-date scopes when primary capture logs are missing

Important accuracy note:
- the current Alerts cards are calculated from the selected time scope, not from a static all-time inventory

### 9.9 Authorization (Admin)
Purpose: Manage allowlists, signatures, bans, and audit history.

Current header: `Authorization Overview`

Top metrics:
- Device Whitelist
- Domain Whitelist
- AI Policies
- Banned MACs

Tabs and behavior:
- `Device Access`
  - auto-enriches saved device rows from latest network metadata when possible
  - filters by Date Modified
  - supports quick-add of one or multiple MAC addresses
  - supports search
  - uses Action controls for edit/delete
- `Domain Whitelist`
  - quick-add domains
  - search
  - Action controls for edit/delete
- `AI Policies`
  - updates sanctioned providers
  - maintains detection signatures per provider
  - Action controls for add/edit/delete policy rows
- `Audit Log`
  - shows activity history table
  - supports `Clear Audit Log`
- `Ban List`
  - quick-add MACs
  - Action controls for edit/delete

Write side effects:
- updates policy and allowlist YAML files
- appends activity to `activity_log.csv`
- can delete `activity_log.csv` when clearing the audit log

### 9.10 User Management (Admin)
Purpose: Manage dashboard user accounts and roles in the configured auth backend.

Current header: `User Management`

Operator flow:
1. Review account metrics:
- Total Accounts
- Admins
- Staff
2. Open `+ Add User` to create a new account.
3. Enter:
- Full Name
- Gmail address
- Temporary Password
- Role
4. Edit or delete users from the Action column.
5. Change roles inline in the `Role` column.

Displayed account columns:
- Name
- Username
- Role
- Created By
- Created At
- Last Login

Validation and behavior:
- Gmail-only usernames
- password policy enforcement
- created users are marked with `password_reset_required=True`
- add-user flow attempts to send credentials by e-mail
- current user cannot delete their own account
- at least one admin must remain after delete or role changes
- when a user edits their own name or e-mail, session display info is updated

## 10) File and Configuration Map
Core runtime files:
- `app.py`: app entrypoint, background sync orchestration, routing, logout handling
- `config/client.py`: parquet path, Drive settings, refresh intervals
- `ui/auth.py`: login, OTP, password reset, persistent auth handling
- `ui/sidebar.py`: custom collapsible sidebar and navigation

Primary page modules:
- `ui/pages/devices.py`
- `ui/pages/analytics.py`
- `ui/pages/shadow_apps.py`
- `ui/pages/shadow_sharings.py`
- `ui/pages/shadow_ai.py`
- `ui/pages/anonymization_network.py`
- `ui/pages/zeek_logs.py`
- `ui/pages/alerts.py`
- `ui/pages/authorization.py`
- `ui/pages/user_management.py`

Service helpers:
- `services/auth_service.py`
- `services/drive_services.py`

## 11) Important Accuracy Notes
- Background Google Drive sync is active in `app.py`, but it is automatic and not exposed as a manual sidebar action.
- The Device menu item is labeled `Device Inspection`, while the page header currently renders as `Device Overview`.
- The Zeek Logs page header currently renders as `Raw Log Explorer`.
- Traffic Monitoring modules intentionally load adjacent date folders for midnight boundary coverage, then strictly filter back to the selected date.
- Alerts `Specific Date` mode can fall back to inferred device events from private-IP activity if direct DHCP/ARP/CONN evidence is missing for that day.
- Legacy `.txt` authorization file paths are still supported in some places, but YAML is the active source format when present.
- The Zeek Logs empty-state message still references `Force Refresh Data`, which does not exist in the current sidebar.

## 12) Quick Verification Checklist
Use this checklist after deployment or dashboard changes:
1. Login works for both admin and staff.
2. Staff cannot access `Authorization` or `User Management`.
3. Background Drive sync can run without breaking page routing or caching.
4. Device card dialogs open and MAC clicks open Forensics.
5. Authorized dialog shows `Authorized Date` separately from `Last Seen`.
6. Alerts cards change when switching between `Last 7 Days`, `Last 30 Days`, `Specific Date`, and `All Time`.
7. Traffic Monitoring section switcher loads all four modules.
8. Shadow Apps, Shadow Sharings, Shadow AI, and Anonymization Network all respect selected-date scoping.
9. CSV export works on Alerts and the active monitoring tables.
10. Authorization edits persist and appear in the audit log.
11. User add/edit/delete and inline role updates persist in the auth backend.
12. Logout clears the session and returns to the login page.

## 13) Execution Trace Timing Notes
Why seconds can reset or change between runs:
1. Streamlit reruns the script top-to-bottom on interactions. Every click, page switch, or dialog action reruns the app, so trace durations are recalculated for that specific rerun.
2. Timers are live-run measurements. The trace uses `time.time() - start_time`, so values represent current-run cost, not a single lifetime startup value.
3. `@st.cache_data` reduces repeated work. First pass does heavy parquet/aggregation reads; subsequent reruns often return cached data and appear near-zero.
4. Auto refresh triggers reruns. `st_autorefresh` in `app.py` fires on an hourly interval, which recalculates trace timings even without manual clicks.
5. Python module import caching matters. First import of a page module can be slower; later navigations reuse `sys.modules` and usually load faster.

Practical interpretation:
- fluctuating trace numbers are expected and usually indicate caching is working correctly.

## 14) Manifest-Driven Verification Blueprint (Proposed)
Status:
- this section is an implementation blueprint for integrity automation, not the current shipped behavior.
- design goal: no manual checksum work in production operations.

### 14.1 Architecture
1. Zeek server is the source of truth and writes a per-date `manifest.json`.
2. Dashboard server consumes that manifest and performs lightweight verification during download and render.

### 14.2 Zeek Server Verification Pipeline
1. Validate log -> parquet -> csv conversion consistency:
- load raw log-derived frame, parquet frame, and csv frame
- assert row counts match (`len(df_log) == len(df_parquet) == len(df_csv)`)
- abort upload on mismatch
2. Validate upload integrity programmatically (no manual checks):
- compute local hash before upload
- upload file via Drive API
- compare local hash with checksum metadata returned by API (for example `md5Checksum`)
- store verification result in manifest
3. Publish manifest:
- include date, log type, expected row count, checksum, source timestamps, and verification status
- upload manifest beside data artifacts

### 14.3 Dashboard Verification Pipeline
1. Verify downloaded parquet automatically:
- fetch Drive metadata checksum for each file
- hash downloaded local file
- compare checksums in worker code
- on mismatch, delete corrupted local copy and queue re-download
2. Verify parquet retrieval completeness:
- read expected row count from manifest
- compare with DuckDB `COUNT(*)` on local parquet
- fail closed when mismatch is detected
3. Verify UI render integrity visibly:
- expose a `Data Health` status in UI
- example: `Data Integrity: Verified (Loaded 14,502 of 14,502 expected records)`

## 15) Component Notes and FAQ
### 15.1 What `ui/auth.py` does
1. Implements login UX state machine (`credentials`, `otp`, `password_reset`) with captcha and feedback handling.
2. Restores/persists auth sessions via signed token (`?auth=...`) plus local session store (`.streamlit/auth_session_store.json`).
3. Handles Google OAuth callback routing and expected-email state validation.
4. Finalizes authenticated session state in Streamlit session.
5. Exposes gatekeepers:
- `require_authentication()` to block app pages until login succeeds
- `require_role(*allowed_roles)` for role-based page restrictions

### 15.2 What `services/auth_service.py` does
1. Initializes auth backend schema and seeds bootstrap admin.
2. Implements user CRUD and account listing across supported backends.
3. Handles password policy, PBKDF2 hashing, and credential verification.
4. Generates and validates OTP flow support primitives.
5. Sends OTP/credential emails through SMTP.
6. Validates Google OAuth auth codes against Google endpoints and maps them to local users.

### 15.3 What `config/client.py` does
1. Defines local data/log directories and parquet paths.
2. Resolves service account credentials with fallback discovery in `secrets/*.json`.
3. Stores Drive auth mode and credential paths.
4. Defines refresh/sync knobs:
- `AUTO_REFRESH_INTERVAL = 3600`
- `DRIVE_SYNC_INTERVAL = 3600`
- `DRIVE_SYNC_LOOKBACK_DAYS = 0` (scoped sync policy instead of fixed N-day lookback)

### 15.4 When data sync is triggered
1. On each rerun, `app.py` polls sync state and may schedule background sync if minimum interval has elapsed.
2. `st_autorefresh` forces periodic reruns on the configured interval (hourly in current code).
3. User interactions trigger reruns too, but sync does not restart unless schedule conditions are met.
4. In OAuth mode, reauth flow can be triggered when stored credentials expire.

### 15.5 Cache layers used in this app
1. Python function cache (`@lru_cache`) in Drive auth helpers.
2. Disk sync ledger cache (`data/parquet/_drive_sync_state.json`) for incremental Drive pulls.
3. Streamlit data cache (`@st.cache_data`) for heavy dataframe/query reuse (for example `ttl=600` in `load_single_log`).
4. Page-level parquet cache directories:
- `_cache_alerts`
- `_shadow_cache_apps`
- `_shadow_cache_sharing`
- `_shadow_cache_ai`
- `_shadow_cache_anonymization_network`
5. Streamlit resource cache (`@st.cache_resource`) for long-lived resources such as in-memory DB connections and manager objects.

### 15.6 Difference between 1 hour and 10 minutes
1. 1-hour interval controls cloud sync cadence (Drive polling/download behavior).
2. 10-minute cache TTL controls in-memory dataframe reuse for UI/query speed.
3. They operate at different layers:
- cloud-to-disk sync cadence vs RAM cache retention

### 15.7 What `services/drive_services.py` does
1. Authenticates to Google Drive (`service`, `oauth`, or `auto` mode).
2. Syncs Drive logs to local parquet cache with incremental logic and state tracking.
3. Enforces parquet-only ingestion from Drive sources.
4. Organizes data by resolved date and log type, with deterministic candidate selection.
5. Exposes quick read helpers (`load_single_log`, `run_duckdb_query`, catalog scan) for dashboard pages.
