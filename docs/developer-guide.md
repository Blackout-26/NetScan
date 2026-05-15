# Developer Guide

## Local Development Setup

```bash
git clone https://github.com/Blackout-26/NetScan.git
cd NetScan

python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate.bat on Windows

pip install -r requirements.txt
cp .env.example .env       # edit as needed
```

Start Redis, then in two terminals:

```bash
# Terminal 1
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2
celery -A app.scanner.tasks.celery_app worker --loglevel=info --pool=solo
```

The `--reload` flag auto-restarts the API when you save a file.

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## Code Structure

### Adding a New API Endpoint

1. Open (or create) the relevant file in `app/api/routes/`
2. Define the function with FastAPI decorators
3. Add `_: User = Depends(require_auth)` to protect it
4. Add the corresponding Pydantic schema in `app/schemas/__init__.py`
5. Register the router in `app/api/__init__.py` if it is a new file
6. Write a test

Minimal example:

```python
from app.core.deps import require_auth
from app.models.user import User

@router.get("/example", response_model=MySchema)
async def my_endpoint(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> MySchema:
    result = await my_service.get_something(db)
    return MySchema.model_validate(result)
```

---

### Adding a Custom Risk Rule

Open `app/core/risk.py` and add to `_PORT_RULES`:

```python
9090: RiskRule(
    name="My Service",
    level=RiskLevel.MEDIUM,
    description="What makes this port risky.",
    recommendation="What the admin should do.",
),
```

To add CVE hints for the port:

```python
_CVE_HINTS: Dict[int, List[str]] = {
    # existing entries...
    9090: ["CVE-2023-XXXX (Description)"],
}
```

No other changes needed. The rule applies to all future scans automatically.

---

### Adding a New Database Model

1. Create the model file in `app/models/`
2. Import it in `app/models/__init__.py` so SQLAlchemy registers it
3. The table will be created automatically on next startup via `init_db()`
4. Create corresponding Pydantic schemas in `app/schemas/__init__.py`

---

### Modifying the Dashboard UI

Templates are in `templates/`. They use vanilla JavaScript and Bootstrap 5 loaded from CDN — no build step required.

To add a new page:
1. Create the HTML template in `templates/`
2. Add a route in `app/main.py` that renders it
3. Add authentication check: `user = await _get_user(request); if not user: return RedirectResponse("/login")`

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | Async SQLAlchemy URL |
| `NMAP_PATH` | Yes | — | Full path to nmap executable |
| `REDIS_URL` | Yes | — | Redis connection URL |
| `ALLOWED_ORIGINS` | Yes | — | JSON array of allowed CORS origins |
| `SECRET_KEY` | No | hardcoded | Secret key (change in production) |
| `DEBUG` | No | false | Enable SQLAlchemy query logging |
| `DEFAULT_SCAN_TIMEOUT` | No | 300 | Max seconds per scan |
| `MAX_CONCURRENT_SCANS` | No | 3 | Celery worker concurrency |
| `REPORTS_DIR` | No | ./reports | Generated reports directory |
| `LOG_LEVEL` | No | INFO | Logging level |
| `LOG_FILE` | No | ./logs/netscan.log | Log file path |

---

## Pull Request Guidelines

- One feature or fix per PR
- Include tests for new functionality
- Run `pytest tests/ -v` before submitting — all tests must pass
- Follow the existing code style (type hints, docstrings on public functions)
- Update the relevant docs if your change affects behaviour or configuration
