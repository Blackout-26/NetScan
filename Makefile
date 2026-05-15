# NetScan Makefile
.PHONY: install dev worker test lint clean

install:
	python3 -m venv venv
	. venv/bin/activate && pip install -r requirements.txt
	cp -n .env.example .env || true

dev:
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

worker:
	celery -A app.scanner.tasks.celery_app worker --loglevel=info -c 3

test:
	pytest tests/ -v --cov=app --cov-report=term-missing

lint:
	ruff check app/ tests/
	mypy app/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache reports/*.pdf reports/*.json reports/*.csv
