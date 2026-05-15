# Linux Deployment Guide

This guide covers deploying NetScan on Ubuntu/Debian using systemd for service management.

## Prerequisites

```bash
sudo apt update
sudo apt install python3.11 python3.11-venv nmap redis-server -y

# Enable Redis on boot
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Verify
nmap --version
redis-cli ping    # Expected: PONG
```

---

## Step 1 — Deploy Project Files

```bash
sudo mkdir -p /opt/NetScan
sudo chown $USER:$USER /opt/NetScan

# Clone or copy your files
git clone https://github.com/Blackout-26/NetScan.git /opt/NetScan
cd /opt/NetScan
```

---

## Step 2 — Virtual Environment and Dependencies

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 3 — Configure .env

```bash
cp .env.example .env
nano .env
```

```env
DATABASE_URL=sqlite+aiosqlite:///./netscan.db
NMAP_PATH=/usr/bin/nmap
REDIS_URL=redis://localhost:6379/0
ALLOWED_ORIGINS=["http://YOUR-SERVER-IP:8000"]
LOG_LEVEL=INFO
LOG_FILE=./logs/netscan.log
```

---

## Step 4 — Test Manually

```bash
source venv/bin/activate

# Terminal 1
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2
celery -A app.scanner.tasks.celery_app worker --loglevel=info --concurrency=3
```

Confirm login page loads at `http://localhost:8000`, then `Ctrl+C` both.

---

## Step 5 — Create systemd Services

**`/etc/systemd/system/netscan-api.service`:**

```ini
[Unit]
Description=NetScan API Server
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/opt/NetScan
ExecStart=/opt/NetScan/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
Environment=PATH=/opt/NetScan/venv/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

**`/etc/systemd/system/netscan-worker.service`:**

```ini
[Unit]
Description=NetScan Celery Worker
After=network.target redis-server.service

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/opt/NetScan
ExecStart=/opt/NetScan/venv/bin/celery -A app.scanner.tasks.celery_app worker --loglevel=info --concurrency=3
Restart=always
RestartSec=5
Environment=PATH=/opt/NetScan/venv/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_USERNAME` with your Linux username.

**Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable netscan-api netscan-worker
sudo systemctl start netscan-api netscan-worker

# Verify
sudo systemctl status netscan-api
sudo systemctl status netscan-worker
```

---

## Step 6 — Firewall

```bash
sudo ufw allow 8000/tcp
sudo ufw allow OpenSSH
sudo ufw enable
```

---

## Step 7 — Nmap Privileges

OS detection requires elevated network privileges. Grant them without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

---

## Service Management

```bash
# Status
sudo systemctl status netscan-api
sudo systemctl status netscan-worker

# Restart
sudo systemctl restart netscan-api netscan-worker

# Live logs
sudo journalctl -u netscan-api -f
sudo journalctl -u netscan-worker -f
```
