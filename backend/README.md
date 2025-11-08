# Cerberus Backend (FastAPI)

## Setup

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows
pip install -r backend/requirements.txt
```

2. Set environment variables (PowerShell example) or create a `.env` file in the project root:

```bash
# Using PowerShell environment variables:
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
# Optional if you want AI narratives
$env:OPENAI_API_KEY="your_openai_key"
```

Or create a `.env` file in the project root with:
```
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
REPORT_DB_PATH=./data/reports.db
REPORT_RETENTION_DAYS=7
REPORT_RETENTION_LIMIT=1000
```

**Get API Keys:**
- AbuseIPDB: https://www.abuseipdb.com/pricing (Sign up and get your API key from your account) - **Required**
- OpenAI: https://platform.openai.com/api-keys (Optional, for AI-generated narratives)

3. Run the server:

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints
- GET `/api/health` – health check
- POST `/api/v1/analyze` – analyze IP (body: `{ "ip_address": "1.2.3.4" }`)
- GET `/api/v1/reports/recent` – paginated recent stored analyses (`limit` query parameter)
- GET `/api/v1/reports/stats` – aggregate dashboard metrics (`hours` query parameter)


