.PHONY: setup-db

setup-db:
	@if ! command -v pg_isready >/dev/null 2>&1; then \
		echo "pg_isready is not available. Install PostgreSQL client tools first."; \
		exit 1; \
	fi
	@if ! command -v psql >/dev/null 2>&1; then \
		echo "psql is not available. Install PostgreSQL client tools first."; \
		exit 1; \
	fi
	@if ! command -v createdb >/dev/null 2>&1; then \
		echo "createdb is not available. Install PostgreSQL client tools first."; \
		exit 1; \
	fi
	@if ! pg_isready >/dev/null 2>&1; then \
		echo "PostgreSQL does not appear to be running."; \
		echo "Start it with: brew services start postgresql@18"; \
		exit 1; \
	fi
	@if psql -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname='webscanner'" | grep -q 1; then \
		echo "Database 'webscanner' already exists."; \
	else \
		echo "Creating database 'webscanner'..."; \
		createdb webscanner; \
		echo "Database 'webscanner' created."; \
	fi
	@echo
	@echo "Next steps:"
	@echo "1. cd /Users/muba/Desktop/webscanner/services/scanner"
	@echo "2. cp .env.example .env"
	@echo "3. Edit .env and set DATABASE_URL to use your macOS username"
	@echo "4. python3.12 -m venv .venv"
	@echo "5. source .venv/bin/activate"
	@echo "6. pip install -r requirements.txt"
	@echo "7. alembic upgrade head"
	@echo "8. uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
