## developer notes

This is a python project by: Macam, Marvin John; Sebastian, Joshua; Sison, Sweet Lana; Tirao Albert

# zeek_dashboard

Dashboard for visualizing Zeek logs uploaded to Google Drive.

## Prerequisites

1. Python 3.10+ installed
2. `pip` available
3. (Optional) Docker Desktop if you want local MongoDB instead of Atlas

## Setup For New Clone

1. Clone repository:

```bash
git clone https://github.com/AlbertTirao/zeek_dashboard.git
cd zeek_dashboard
```

2. Create and activate virtual environment:

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create local secrets file:

```bash
Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
```

5. Configure authentication in `.streamlit/secrets.toml` using one of the options below.
6. Run app:

```bash
streamlit run app.py
```

## Setup After Pull (Existing Collaborators)

1. Pull latest code:

```bash
git pull
```

2. Reinstall dependencies (important after auth changes):

```bash
pip install -r requirements.txt
```

3. Verify `.streamlit/secrets.toml` still has valid values for your environment.
4. Restart Streamlit:

```bash
streamlit run app.py
```

## Authentication (Python + MongoDB/MySQL)

Authentication is implemented directly in Python (no Node auth service).
Set `auth.db_backend` to choose the login store:

1. `mongodb` (default)
2. `mysql`

### Option A: MongoDB Atlas (Recommended)

1. In Atlas, create a cluster.
2. Create a database user (username/password).
3. Add your IP in Atlas Network Access.
4. Put your Atlas connection in `.streamlit/secrets.toml`:

```toml
[auth]
db_backend = "mongodb"
mongodb_uri = "mongodb+srv://<db_user>:<db_password>@<cluster-host>/?appName=Cluster0"
mongodb_db = "zeek_auth"
bootstrap_admin_username = "admin@gmail.com"
bootstrap_admin_password = "AdminPass123!"
allowed_google_emails = ["admin@gmail.com"]
google_oauth_enabled = false
google_client_id = "your-google-oauth-client-id.apps.googleusercontent.com"
google_client_secret = "your-google-oauth-client-secret"
google_redirect_uri = "http://localhost:8501"
session_secret = "replace-with-a-long-random-secret"
session_ttl_seconds = 604800
```

Notes:

1. URL-encode special characters in password.
2. `mongodb_db` is the database name used by the app.
3. `session_secret` enables login persistence across browser reloads.
4. `allowed_google_emails` (optional) restricts login only when Google OAuth is enabled.
5. Set Google Cloud OAuth authorized redirect URI to `google_redirect_uri`.

### Option B: Local MongoDB With Docker

1. Start local MongoDB:

```bash
docker compose up -d auth-mongo
```

2. Use local URI in `.streamlit/secrets.toml`:

```toml
[auth]
db_backend = "mongodb"
mongodb_uri = "mongodb://zeek_root:zeek_root_dev@localhost:27017/?authSource=admin"
mongodb_db = "zeek_auth"
bootstrap_admin_username = "admin@gmail.com"
bootstrap_admin_password = "AdminPass123!"
allowed_google_emails = ["admin@gmail.com"]
google_oauth_enabled = false
google_client_id = "your-google-oauth-client-id.apps.googleusercontent.com"
google_client_secret = "your-google-oauth-client-secret"
google_redirect_uri = "http://localhost:8501"
session_secret = "replace-with-a-long-random-secret"
session_ttl_seconds = 604800
```

3. Stop local MongoDB:

```bash
docker compose down
```

4. Reset local Mongo data:

```bash
docker compose down -v
```

### Option C: MySQL (Supervisor/Remote Server)

1. Prepare `.streamlit/secrets.toml` with MySQL settings:

```toml
[auth]
db_backend = "mysql"
mysql_host = "<server-host-or-ip>"
mysql_port = 3306
mysql_user = "<db_user>"
mysql_password = "<db_password>"
mysql_database = "zeek_auth"
bootstrap_admin_username = "admin@gmail.com"
bootstrap_admin_password = "AdminPass123!"
allowed_google_emails = ["admin@gmail.com"]
google_oauth_enabled = false
google_client_id = "your-google-oauth-client-id.apps.googleusercontent.com"
google_client_secret = "your-google-oauth-client-secret"
google_redirect_uri = "http://localhost:8501"
session_secret = "replace-with-a-long-random-secret"
session_ttl_seconds = 604800
```

2. Validate connectivity and auto-create auth tables on the target MySQL server:

```bash
python scripts/check_auth_mysql.py
```

3. If current login users are stored in MongoDB, migrate users:

```bash
python scripts/migrate_auth_users_mongo_to_mysql.py
```

4. Start/restart the app:

```bash
streamlit run app.py
```

### SMTP (Required for OTP E-mail)

Add SMTP settings in `.streamlit/secrets.toml`:

```toml
[auth]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your-sender@gmail.com"
smtp_password = "your-16-char-app-password"
smtp_from_email = "your-sender@gmail.com"
smtp_from_name = "Zeek Dashboard"
smtp_use_tls = true
smtp_use_ssl = false
```

Quick check from project root:

```bash
python -c "from services import auth_service; print(auth_service._get_smtp_config())"
```

## First Login

1. On first startup, if `app_users` is empty, the app creates the bootstrap admin from `.streamlit/secrets.toml`.
2. Default bootstrap login from example config:
   - Username: `admin@gmail.com`
   - Password: `AdminPass123!`
3. If users already exist, bootstrap is skipped.

## Roles

1. `admin`: full access including User Management
2. `staff`: operational dashboard pages only

## Google Drive Note

On first run/rerun, app asks for Google authentication in browser.
Make sure your Google account is a collaborator on the Zeek logs Drive folder.

## Troubleshooting

1. `MongoDB is not configured`:
   - Missing `auth.mongodb_uri` while `auth.db_backend="mongodb"`
2. `MySQL is not configured`:
   - Missing one or more of `auth.mysql_host`, `auth.mysql_port`, `auth.mysql_user`, `auth.mysql_password`, `auth.mysql_database` while `auth.db_backend="mysql"`
3. DB authentication/connection failure:
   - Wrong DB username/password
   - DB user has no access to the selected database
   - server/network/firewall/IP allowlist blocks access
4. `Invalid username or password` on first login:
   - `app_users` already contains users and bootstrap was skipped
5. `Google sign-in is unavailable`:
   - check `auth.google_client_id`, `auth.google_client_secret`, `auth.google_redirect_uri`
   - ensure the same redirect URI is configured in Google Cloud
6. `Google account verification failed for the entered e-mail`:
   - sign in using the exact same email typed in the form
7. `This e-mail is not approved for login`:
   - this check applies when Google OAuth is enabled
   - add the address to `auth.allowed_google_emails` in `.streamlit/secrets.toml`

## Security

1. Do not commit `.streamlit/secrets.toml` or `.env`
2. Rotate credentials if secrets were exposed
3. User accounts must use `@gmail.com` addresses.
4. Passwords must be at least 8 characters and include at least one special character.
5. When `allowed_google_emails` is set, only listed Google emails can authenticate in OAuth mode.
6. With Google OAuth enabled, login requires a verified Google account (`email_verified=true`).
