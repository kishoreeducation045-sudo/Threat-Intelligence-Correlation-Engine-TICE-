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
$env:VIRUSTOTAL_API_KEY="your_vt_key"
$env:OTX_API_KEY="your_otx_key"
# Optional if you want AI narratives
$env:OPENAI_API_KEY="your_openai_key"
```

Or create a `.env` file in the project root with:
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_alienvault_otx_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

**Get API Keys:**
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AlienVault OTX: https://otx.alienvault.com/api (Sign up and get your API key from your profile)
- OpenAI: https://platform.openai.com/api-keys (Optional, for AI-generated narratives)

3. Run the server:

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints
- GET `/api/health` – health check
- POST `/api/v1/analyze` – analyze IP (body: `{ "ip_address": "1.2.3.4" }`)


