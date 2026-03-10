# Zeek Dashboard Server Deployment Guide (Step-by-Step)

This guide deploys the project on an Ubuntu Linux server and runs it as a persistent service.

## Deployment Target

- OS: Ubuntu 22.04/24.04
- App path: `/opt/zeek-dashboard`
- Process manager: `systemd`
- Web endpoint: Nginx reverse proxy to Streamlit on `127.0.0.1:8501`

## 1) Prepare the Server

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3 python3-venv python3-pip nginx ufw
```

Open firewall rules:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## 2) Clone the Project

```bash
sudo mkdir -p /opt/zeek-dashboard
sudo chown $USER:$USER /opt/zeek-dashboard
git clone https://github.com/AlbertTirao/zeek_dashboard.git /opt/zeek-dashboard
cd /opt/zeek-dashboard
```

If your repository is private, use your SSH/HTTPS private URL instead.

## 3) Create Python Environment and Install Dependencies

```bash
cd /opt/zeek-dashboard
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 4) Create Required Runtime Files and Folders

```bash
cd /opt/zeek-dashboard
mkdir -p .streamlit secrets data logs
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
```

## 5) Configure Google Drive Authentication

Your project supports `service`, `oauth`, and `auto` modes in `config/client.py`.
For server deployments, use `service` mode to avoid browser login prompts.

Set this in `config/client.py`:

```python
DRIVE_AUTH_MODE = "service"
```

Place your service account key file at:

`/opt/zeek-dashboard/secrets/service_account.json`

Important:

1. Share the Google Drive folder with the service account e-mail.
2. Keep `secrets/service_account.json` out of Git.

## 6) Configure App Auth Backend in `.streamlit/secrets.toml`

Edit:

`/opt/zeek-dashboard/.streamlit/secrets.toml`

### Option A: MongoDB

```toml
[auth]
db_backend = "mongodb"
mongodb_uri = "mongodb+srv://<db_user>:<db_password>@<cluster-host>/zeek_auth?retryWrites=true&w=majority&appName=<app-name>"
mongodb_db = "zeek_auth"

bootstrap_admin_username = "admin@gmail.com"
bootstrap_admin_password = "ChangeMe123!"
session_secret = "replace-with-a-long-random-secret"
session_ttl_seconds = 604800

smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your-sender@gmail.com"
smtp_password = "your-16-char-app-password"
smtp_from_email = "your-sender@gmail.com"
smtp_from_name = "Zeek Dashboard"
smtp_use_tls = true
smtp_use_ssl = false
```

### Option B: MySQL

```toml
[auth]
db_backend = "mysql"
mysql_host = "<mysql-host>"
mysql_port = 3306
mysql_user = "zeek_auth_user"
mysql_password = "<strong-password>"
mysql_database = "zeek_auth"

bootstrap_admin_username = "admin@gmail.com"
bootstrap_admin_password = "ChangeMe123!"
session_secret = "replace-with-a-long-random-secret"
session_ttl_seconds = 604800

smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your-sender@gmail.com"
smtp_password = "your-16-char-app-password"
smtp_from_email = "your-sender@gmail.com"
smtp_from_name = "Zeek Dashboard"
smtp_use_tls = true
smtp_use_ssl = false
```

## 7) MySQL Initialization (Only If Using MySQL Backend)

Run database and user creation:

```bash
cd /opt/zeek-dashboard
mysql -u root -p < "mysql/Create DATABASE and TABLE.sql"
```

Validate connectivity and schema:

```bash
cd /opt/zeek-dashboard
source .venv/bin/activate
python scripts/check_auth_mysql.py
```

If old users exist in MongoDB and you want to migrate them:

```bash
cd /opt/zeek-dashboard
source .venv/bin/activate
python scripts/migrate_auth_users_mongo_to_mysql.py
```

## 8) Manual Smoke Test

Run once before creating a system service:

```bash
cd /opt/zeek-dashboard
source .venv/bin/activate
streamlit run app.py --server.address 0.0.0.0 --server.port 8501 --server.headless true
```

Open `http://SERVER_IP:8501` and confirm login works, then stop with `Ctrl+C`.

## 9) Create systemd Service

Create service file:

```bash
sudo tee /etc/systemd/system/zeek-dashboard.service > /dev/null << 'EOF'
[Unit]
Description=Zeek Dashboard (Streamlit)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/zeek-dashboard
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/zeek-dashboard/.venv/bin/streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Replace `User=ubuntu` with your actual server username.

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zeek-dashboard
sudo systemctl status zeek-dashboard --no-pager
```

Live logs:

```bash
journalctl -u zeek-dashboard -f
```

## 10) Configure Nginx Reverse Proxy

```bash
sudo tee /etc/nginx/sites-available/zeek-dashboard > /dev/null << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8501/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
EOF
```

Enable config:

```bash
sudo ln -s /etc/nginx/sites-available/zeek-dashboard /etc/nginx/sites-enabled/zeek-dashboard
sudo nginx -t
sudo systemctl reload nginx
```

## 11) Enable HTTPS (Recommended)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
sudo systemctl status certbot.timer --no-pager
```

## 12) Post-Deploy Verification

```bash
sudo systemctl status zeek-dashboard --no-pager
sudo systemctl status nginx --no-pager
curl -I http://127.0.0.1:8501
```

Check login using bootstrap admin credentials from `secrets.toml`.

## 13) Update / Redeploy Procedure

```bash
cd /opt/zeek-dashboard
git pull
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart zeek-dashboard
sudo systemctl status zeek-dashboard --no-pager
```

## 14) Backup Important Files

Back up these files before upgrades or server changes:

1. `/opt/zeek-dashboard/.streamlit/secrets.toml`
2. `/opt/zeek-dashboard/secrets/service_account.json`
3. `/opt/zeek-dashboard/secrets/drive_credentials.json` (if OAuth mode is used)

## 15) Common Troubleshooting

1. App fails to start:
   - `journalctl -u zeek-dashboard -n 100 --no-pager`
2. MySQL errors:
   - verify `mysql_*` values in `.streamlit/secrets.toml`
   - run `python scripts/check_auth_mysql.py`
3. MongoDB errors:
   - verify `mongodb_uri` and allowlist server IP in Atlas
4. Google Drive sync errors:
   - confirm Drive folder is shared to service account e-mail
   - confirm `secrets/service_account.json` exists and is valid
5. OTP e-mail not sending:
   - verify SMTP host/user/password and app password settings

## Quick Checklist

1. Dependencies installed
2. Virtualenv created
3. `.streamlit/secrets.toml` configured
4. `secrets/service_account.json` uploaded
5. `DRIVE_AUTH_MODE = "service"` set
6. Manual `streamlit run` test passed
7. `systemd` service active
8. Nginx reverse proxy active
9. HTTPS enabled
