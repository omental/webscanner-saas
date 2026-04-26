# Web Vulnerability Scanner Monorepo

Minimal initial monorepo scaffold for a Web Vulnerability Scanner SaaS.

## Structure

```text
webscanner/
  Makefile
  apps/
    web/
  services/
    scanner/
```

## Prerequisites

- Node.js 20+
- npm 10+
- Python 3.12
- PostgreSQL 18 via Homebrew on macOS

## Local PostgreSQL setup on Mac

Homebrew PostgreSQL on macOS commonly authenticates with your macOS username, not `postgres/postgres`.

Check your local username:

```bash
whoami
```

Use that username in the scanner service database URL:

```env
DATABASE_URL=postgresql+asyncpg://YOUR_LOCAL_USERNAME@localhost:5432/webscanner
```

## Local backend bootstrap sequence

1. Start PostgreSQL:

```bash
brew services start postgresql@18
```

2. Confirm PostgreSQL is running:

```bash
brew services list
```

3. Bootstrap the local database:

```bash
cd /Users/muba/Desktop/webscanner
make setup-db
```

4. Configure the scanner service environment:

```bash
cd /Users/muba/Desktop/webscanner/services/scanner
cp .env.example .env
```

Then edit `.env` so `DATABASE_URL` uses your local macOS username.

5. Create a virtual environment and install dependencies:

```bash
cd /Users/muba/Desktop/webscanner/services/scanner
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

6. Run database migrations:

```bash
cd /Users/muba/Desktop/webscanner/services/scanner
source .venv/bin/activate
alembic upgrade head
```

7. Start FastAPI:

```bash
cd /Users/muba/Desktop/webscanner/services/scanner
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at [http://localhost:8000](http://localhost:8000).

## Verification

Check your username:

```bash
whoami
```

List databases:

```bash
psql -l
```

Connect to the local development database:

```bash
psql -d webscanner
```

Apply migrations:

```bash
cd /Users/muba/Desktop/webscanner/services/scanner
source .venv/bin/activate
alembic upgrade head
```

## Run the web app

```bash
cd /Users/muba/Desktop/webscanner/apps/web
npm install
npm run dev
```

The web app will be available at [http://localhost:3000](http://localhost:3000).

## API health check

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```
