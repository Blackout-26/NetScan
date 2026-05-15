# 🔍 NetScan — Network Port Scanner & Risk Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square&logo=fastapi" />
  <img src="https://img.shields.io/badge/Nmap-7.95+-red?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" />
</p>

<p align="center">
  A self-hosted network security scanning platform built with FastAPI and Nmap.<br/>
  Discover devices, detect open ports, classify security risks, and generate professional reports — all from a clean web dashboard.
</p>

---

## 📸 Screenshots

| Dashboard | Scan Detail | Report |
|-----------|-------------|--------|
| Live stats, risk breakdown chart, scan launcher | Discovered devices with port-level risk breakdown | PDF report with CVEs and recommendations |

---

## ✨ Features

- **Full port scanning** — Quick (top 1000), Full (all 65,535), or Service (version detection) modes
- **Service detection** — Identifies software running on every open port (Apache, SSH, PostgreSQL, etc.)
- **Risk classification** — 40+ built-in rules rating each service High / Medium / Low / Info
- **CVE hints** — Maps dangerous services to known vulnerabilities
- **Live dashboard** — Auto-updating web UI showing all devices and findings
- **PDF / JSON / CSV reports** — One-click export with actionable recommendations
- **Authentication** — Login-protected with forced credential change on first use
- **Background scanning** — Celery workers mean scans never block the UI
- **Auto-start** — Runs as a system service, starts on boot

---

## 🏗 Architecture

```
Browser  ──►  FastAPI (port 8000)  ──►  SQLite DB
                     │
               Redis Queue
                     │
              Celery Worker  ──►  Nmap  ──►  Target Network
```

| Component | Technology |
|-----------|-----------|
| Web framework | FastAPI + Uvicorn |
| Background tasks | Celery + Redis |
| Scanner engine | Nmap + python-nmap |
| Database | SQLite (async via aiosqlite) |
| ORM | SQLAlchemy 2.0 (async) |
| Templates | Jinja2 + Bootstrap 5 |
| PDF generation | ReportLab |
| Auth | PBKDF2-SHA256 + HttpOnly cookies |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- [Nmap](https://nmap.org/download.html)
- [Redis](https://redis.io/downloads/) (or [Windows port](https://github.com/tporadowski/redis/releases))

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Blackout-26/NetScan.git
cd NetScan

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate.bat       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — set NMAP_PATH to your nmap executable
```

### Configure `.env`

```env
DATABASE_URL=sqlite+aiosqlite:///./netscan.db
NMAP_PATH=/usr/bin/nmap                          # Linux
# NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe  # Windows
REDIS_URL=redis://localhost:6379/0
ALLOWED_ORIGINS=["http://localhost:8000"]
```

### Run

Open **two terminals** with the venv activated:

**Terminal 1 — API server:**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Background worker:**
```bash
# Linux/Mac
celery -A app.scanner.tasks.celery_app worker --loglevel=info

# Windows
celery -A app.scanner.tasks.celery_app worker --loglevel=info --pool=solo
```

Open your browser at `http://localhost:8000`

**Default credentials:** `admin` / `NetScan@Admin1`
> You will be forced to change these on first login.

---

## 🔐 Authentication

NetScan uses a single-admin model — one account with full access.

On first startup, a default admin account is created. The system **forces a credential change** before granting access to the dashboard. Once changed, the defaults are permanently discarded.

Password requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one digit

Passwords are stored using **PBKDF2-HMAC-SHA256** with 260,000 iterations and a unique random salt per password (OWASP 2023 recommendation).

---

## 📡 Scan Types

| Type | Ports | Speed | Use Case |
|------|-------|-------|----------|
| Quick | Top 1,000 | ~2 min/host | Regular scheduled checks |
| Full | All 65,535 | ~15-30 min/host | Deep security audit |
| Service | Top 1,000 + aggressive version detection | ~5 min/host | Software inventory |

### Scan Targets

```
192.168.1.1          # Single IP
192.168.1.0/24       # Entire subnet
192.168.1.1-50       # IP range
hostname.local       # Hostname
```

---

## ⚠️ Risk Levels

| Level | Score | Description |
|-------|-------|-------------|
| 🔴 High | 3 | Immediate risk — plaintext protocols, exposed databases, dangerous services |
| 🟡 Medium | 2 | Security concern — SSH exposure, HTTP, file sharing |
| 🟢 Low | 1 | Low risk — HTTPS, DNS, NTP |
| ⚪ Info | 0 | Unknown service — investigate whether it should be running |

**High risk examples:** Telnet (23), FTP (21), exposed MySQL/PostgreSQL/MongoDB, RDP (3389), Redis (6379)

---

## 🗂 Project Structure

```
NetScan/
├── app/
│   ├── main.py                 # FastAPI app, startup, page routing
│   ├── api/
│   │   └── routes/
│   │       ├── auth.py         # Login, logout, update credentials
│   │       ├── scans.py        # Scan lifecycle endpoints
│   │       ├── devices.py      # Device and port query endpoints
│   │       ├── reports.py      # Report generation and download
│   │       └── dashboard.py    # Stats and health check
│   ├── core/
│   │   ├── config.py           # Pydantic-settings (.env driven)
│   │   ├── logging.py          # Rotating file + console logging
│   │   ├── risk.py             # Risk classification engine (40+ rules)
│   │   ├── security.py         # Password hashing, session tokens
│   │   └── deps.py             # FastAPI auth dependency
│   ├── database/
│   │   └── session.py          # Async SQLAlchemy engine
│   ├── models/                 # SQLAlchemy ORM models
│   │   ├── user.py             # Single admin user
│   │   ├── scan.py             # Scan job
│   │   ├── device.py           # Discovered host
│   │   ├── port.py             # Open port with risk data
│   │   └── report.py           # Generated report
│   ├── schemas/                # Pydantic v2 request/response schemas
│   ├── scanner/
│   │   ├── engine.py           # Nmap wrapper + result parser
│   │   └── tasks.py            # Celery background task
│   └── services/
│       ├── scan_service.py     # Scan CRUD and business logic
│       ├── auth_service.py     # Auth seeding, login, updates
│       └── report_service.py   # PDF/JSON/CSV generation
├── templates/                  # Jinja2 HTML templates (Bootstrap 5)
├── tests/                      # Pytest unit tests
├── .env.example                # Environment variable template
├── requirements.txt
└── README.md
```

---

## 🌐 API Reference

All endpoints require authentication (session cookie) except `/health` and `/api/v1/auth/login`.

Interactive API docs available at `http://localhost:8000/api/docs` when running.

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login — sets session cookie |
| POST | `/api/v1/auth/logout` | Logout — clears session |
| GET | `/api/v1/auth/me` | Current user info |
| POST | `/api/v1/auth/update-credentials` | Change username and password |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scans/` | Launch a new scan |
| GET | `/api/v1/scans/` | List all scans (paginated) |
| GET | `/api/v1/scans/{uuid}` | Get scan status |
| DELETE | `/api/v1/scans/{uuid}` | Cancel a scan |

### Devices & Ports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/devices/` | List devices (filter by scan or risk level) |
| GET | `/api/v1/devices/{id}` | Get device with all ports |
| GET | `/api/v1/devices/{id}/ports` | Get ports for a device |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/reports/` | Generate report (pdf/json/csv) |
| GET | `/api/v1/reports/{uuid}/download` | Download report file |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/api/v1/dashboard/stats` | Aggregated statistics |

---

## 🧪 Tests

```bash
pytest tests/ -v
```

Current coverage: risk engine (13 tests) + authentication (8 tests) = 21 tests.

---

## 🖥 Production Deployment (Windows)

For running NetScan as a Windows Service that starts automatically on boot, see the full guide:

👉 [docs/windows-deployment.md](docs/windows-deployment.md)

For Linux deployment with systemd, see:

👉 [docs/linux-deployment.md](docs/linux-deployment.md)

---

## 🛡 Security Notes

> **Legal:** Only scan networks and devices you own or have explicit written authorisation to scan. Unauthorised scanning is illegal.

> **Endpoint Protection:** Nmap's aggressive timing (`-T4`) may be flagged by antivirus/IDS software. See [docs/endpoint-protection.md](docs/endpoint-protection.md) for how to handle this.

> **HTTPS:** NetScan currently runs on HTTP. For production deployments, place it behind a reverse proxy (Nginx) with a TLS certificate.

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests where appropriate
4. Run the test suite: `pytest tests/ -v`
5. Commit and push: `git push origin feature/my-feature`
6. Open a pull request

### Adding a Custom Risk Rule

Open `app/core/risk.py` and add to `_PORT_RULES`:

```python
9090: RiskRule(
    name="Custom Service",
    level=RiskLevel.MEDIUM,
    description="Description of the risk.",
    recommendation="What the admin should do about it.",
),
```

No other changes needed — the rule is applied to all future scans automatically.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Prince** ([@Blackout-26](https://github.com/Blackout-26))

Built as part of an IT internship project focused on network security tooling.

---

<p align="center">
  <sub>Built with FastAPI, Nmap, Celery, Redis, SQLAlchemy, and ReportLab</sub>
</p>
