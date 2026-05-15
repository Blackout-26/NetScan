# Windows Deployment Guide

This guide covers deploying NetScan as a persistent Windows Service that starts automatically on boot.

## Prerequisites

| Software | Version | Download |
|----------|---------|----------|
| Python | 3.11.x | https://www.python.org/downloads/release/python-3119/ |
| Nmap | 7.95+ | https://nmap.org/dist/nmap-7.95-setup.exe |
| Redis for Windows | 5.0.14.1 | https://github.com/tporadowski/redis/releases |
| NSSM | 2.24 | https://nssm.cc/release/nssm-2.24.zip |

> **Important:** Use Python 3.11 specifically. Python 3.12+ has incompatible pre-built wheels for some dependencies.

---

## Step 1 — Install Prerequisites

**Python 3.11:** Run the installer, check "Add python.exe to PATH".

**Nmap:** Run the installer with all defaults. Verify:
```cmd
nmap --version
```

**Redis:** Run the `.msi` installer. Verify:
```cmd
redis-cli ping
```
Expected: `PONG`

**NSSM:** Extract the ZIP. Copy `nssm.exe` from the `win64` folder:
```cmd
mkdir C:\nssm
copy path\to\win64\nssm.exe C:\nssm\nssm.exe
```

---

## Step 2 — Deploy Project Files

Copy the NetScan project folder to `C:\NetScan`.

```cmd
mkdir C:\NetScan
# copy your project files here
```

---

## Step 3 — Virtual Environment and Dependencies

```cmd
cd C:\NetScan
python -m venv venv
venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify:
```cmd
python -c "import fastapi, nmap, sqlalchemy, celery; print('All good')"
```

---

## Step 4 — Configure .env

```cmd
copy .env.example .env
notepad .env
```

Set these values:

```env
APP_NAME=NetScan
APP_VERSION=1.0.0
DEBUG=false
SECRET_KEY=replace-with-long-random-string

DATABASE_URL=sqlite+aiosqlite:///./netscan.db
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
DEFAULT_SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=3

REDIS_URL=redis://localhost:6379/0

REPORTS_DIR=./reports
ALLOWED_ORIGINS=["http://YOUR-SERVER-IP:8000","http://localhost:8000"]

LOG_LEVEL=INFO
LOG_FILE=./logs/netscan.log
```

Replace `YOUR-SERVER-IP` with the machine's actual IP address (`ipconfig` to find it).

---

## Step 5 — Test Manually First

Before creating services, confirm everything works.

**Terminal 1:**
```cmd
cd C:\NetScan && venv\Scripts\activate.bat
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Expected output:
```
INFO     Database tables initialised.
INFO     Default admin account created. Username: 'admin'
INFO     NetScan ready - v1.0.0
INFO     Uvicorn running on http://0.0.0.0:8000
```

**Terminal 2:**
```cmd
cd C:\NetScan && venv\Scripts\activate.bat
celery -A app.scanner.tasks.celery_app worker --loglevel=info --pool=solo
```

Expected: `celery@HOSTNAME ready.`

Open `http://localhost:8000` — login page should appear. Press `Ctrl+C` in both terminals when confirmed.

---

## Step 6 — Create Startup Batch Files

**`C:\NetScan\start_api.bat`:**
```batch
@echo off
cd /d C:\NetScan
call venv\Scripts\activate.bat
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**`C:\NetScan\start_worker.bat`:**
```batch
@echo off
cd /d C:\NetScan
call venv\Scripts\activate.bat
celery -A app.scanner.tasks.celery_app worker --loglevel=info --pool=solo
```

---

## Step 7 — Register as Windows Services

Run all commands as **Administrator**.

**API Service:**
```cmd
C:\nssm\nssm.exe install NetScanAPI "C:\Windows\System32\cmd.exe" "/c C:\NetScan\start_api.bat"
C:\nssm\nssm.exe set NetScanAPI DisplayName "NetScan API Server"
C:\nssm\nssm.exe set NetScanAPI Start SERVICE_AUTO_START
C:\nssm\nssm.exe set NetScanAPI AppDirectory C:\NetScan
C:\nssm\nssm.exe set NetScanAPI AppStdout C:\NetScan\logs\api.log
C:\nssm\nssm.exe set NetScanAPI AppStderr C:\NetScan\logs\api_error.log
C:\nssm\nssm.exe set NetScanAPI AppStdoutCreationDisposition 4
C:\nssm\nssm.exe set NetScanAPI AppStderrCreationDisposition 4
```

**Celery Worker Service:**
```cmd
C:\nssm\nssm.exe install NetScanWorker "C:\Windows\System32\cmd.exe" "/c C:\NetScan\start_worker.bat"
C:\nssm\nssm.exe set NetScanWorker DisplayName "NetScan Celery Worker"
C:\nssm\nssm.exe set NetScanWorker Start SERVICE_AUTO_START
C:\nssm\nssm.exe set NetScanWorker AppDirectory C:\NetScan
C:\nssm\nssm.exe set NetScanWorker AppStdout C:\NetScan\logs\worker.log
C:\nssm\nssm.exe set NetScanWorker AppStderr C:\NetScan\logs\worker_error.log
C:\nssm\nssm.exe set NetScanWorker AppStdoutCreationDisposition 4
C:\nssm\nssm.exe set NetScanWorker AppStderrCreationDisposition 4
```

**Start both:**
```cmd
sc start NetScanAPI
sc start NetScanWorker
```

---

## Step 8 — Open Firewall

```cmd
netsh advfirewall firewall add rule name="NetScan" dir=in action=allow protocol=TCP localport=8000
```

---

## Step 9 — Verify Auto-Start

```cmd
shutdown /r /t 5
```

Wait 60 seconds after reboot. Open `http://YOUR-SERVER-IP:8000` in a browser. The login page should load without any manual steps.

---

## Service Management

```cmd
# Check status
sc query NetScanAPI
sc query NetScanWorker

# Restart after code changes
sc stop NetScanAPI && sc start NetScanAPI
sc stop NetScanWorker && sc start NetScanWorker

# View logs
type C:\NetScan\logs\api_error.log
type C:\NetScan\logs\worker_error.log

# Remove services
C:\nssm\nssm.exe remove NetScanAPI confirm
C:\nssm\nssm.exe remove NetScanWorker confirm
```

---

## Troubleshooting

**Login gives "Network Error":**
- Check `sc query NetScanAPI` — state must be `4 RUNNING`
- Check `type C:\NetScan\logs\api_error.log` for errors
- If log shows `no such table: users` — delete `C:\NetScan\netscan.db` and restart the service

**Scan stays pending forever:**
- Check `sc query NetScanWorker` — must be `4 RUNNING`
- Check `redis-cli ping` — must return `PONG`. If not: `net start Redis`

**Nmap not found:**
- Run `where nmap` — copy the path to NMAP_PATH in `.env`
- Restart both services after changing `.env`

**Cannot access from other machines:**
- Confirm firewall rule: `netsh advfirewall firewall show rule name="NetScan"`
- Re-run the firewall command in Step 8 if not shown
