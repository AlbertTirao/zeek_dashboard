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

## Authentication (Python + MongoDB)

Authentication is implemented directly in Python (no Node auth service).

### Option A: MongoDB Atlas (Recommended)

1. In Atlas, create a cluster.
2. Create a database user (username/password).
3. Add your IP in Atlas Network Access.
4. Put your Atlas connection in `.streamlit/secrets.toml`:

```toml
[auth]
mongodb_uri = "mongodb+srv://<db_user>:<db_password>@<cluster-host>/?appName=Cluster0"
mongodb_db = "zeek_auth"
bootstrap_admin_username = "admin"
bootstrap_admin_password = "AdminPass123!"
```

Notes:

1. URL-encode special characters in password.
2. `mongodb_db` is the database name used by the app.

### Option B: Local MongoDB With Docker

1. Start local MongoDB:

```bash
docker compose up -d auth-mongo
```

2. Use local URI in `.streamlit/secrets.toml`:

```toml
[auth]
mongodb_uri = "mongodb://zeek_root:zeek_root_dev@localhost:27017/?authSource=admin"
mongodb_db = "zeek_auth"
bootstrap_admin_username = "admin"
bootstrap_admin_password = "AdminPass123!"
```

3. Stop local MongoDB:

```bash
docker compose down
```

4. Reset local Mongo data:

```bash
docker compose down -v
```

## First Login

1. On first startup, if `app_users` is empty, the app creates the bootstrap admin from `.streamlit/secrets.toml`.
2. Default bootstrap login from example config:
   - Username: `admin`
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
   - Missing `auth.mongodb_uri` in `.streamlit/secrets.toml`
2. Atlas authentication/connection failure:
   - Wrong DB username/password
   - IP not allowlisted
   - malformed URI
3. `Invalid username or password` on first login:
   - `app_users` already contains users and bootstrap was skipped

## Security

1. Do not commit `.streamlit/secrets.toml` or `.env`
2. Rotate credentials if secrets were exposed
