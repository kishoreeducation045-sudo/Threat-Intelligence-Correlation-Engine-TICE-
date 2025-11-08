# Cerberus - Threat Intelligence Correlation Engine

A comprehensive threat intelligence platform that correlates data from multiple sources to provide detailed IP address analysis.

## Project Structure

```
.
├── backend/          # FastAPI backend service
├── frontend/         # React + Vite frontend application
└── .env             # Environment variables (create this file)
```

## Quick Start

### Prerequisites

- Python 3.8+ (for backend)
- Node.js 16+ and npm (for frontend)
- API Keys:
  - **AbuseIPDB API Key** (required): https://www.abuseipdb.com/pricing
  - OpenAI API Key (optional): https://platform.openai.com/api-keys

### Backend Setup

1. Navigate to the project root and create a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
```

2. Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

3. Create a `.env` file in the project root with your API keys:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=
```

**Note:** Only the AbuseIPDB API key is required. The system uses AbuseIPDB for all threat intelligence data. OpenAI API key is optional and only needed if you want AI-generated threat narratives.

**Get AbuseIPDB API Key:**
- Visit https://www.abuseipdb.com/pricing to sign up for a free or paid plan
- Get your API key from https://www.abuseipdb.com/account/api

**Quick Setup:** Run `setup.bat` (Windows) or `./setup.sh` (Linux/Mac) to automatically set up everything.

Optional persistence settings (defaults shown):
```
REPORT_DB_PATH=./data/reports.db
REPORT_RETENTION_DAYS=7
REPORT_RETENTION_LIMIT=1000
```
Set these in `.env` if you want to change the storage location or retention policy.

4. Start the backend server:

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the frontend directory:

```bash
cd frontend
```

2. Install frontend dependencies:

```bash
npm install
```

3. Start the development server:

```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Usage

1. Make sure both backend and frontend servers are running
2. Open your browser and navigate to `http://localhost:3000`
3. Use the **Analyzer** tab to enter an IPv4 address and click "Analyze"
4. Review the detailed report (threat score, risk level, categories, geolocation, triggered rules, narrative)
5. Switch to the **Dashboard** tab to view the live threat feed wall:
   - Auto-refreshing cards of recent analyses with severity badges
   - Top risk list, activity trend sparkline, and common category chips
   - Stored analyses sourced from the on-disk report repository

## API Endpoints

### Backend API

- `GET /api/health` - Health check endpoint
- `POST /api/v1/analyze` - Analyze an IP address
  - Request body: `{ "ip_address": "1.2.3.4" }`
  - Returns: Detailed threat analysis
- `GET /api/v1/reports/recent` - Fetch recent stored analyses (supports `limit` query parameter)
- `GET /api/v1/reports/stats` - Aggregate dashboard statistics (supports `hours` window parameter)

## Development

### Backend

The backend is built with FastAPI and includes:
- Threat intelligence collection from AbuseIPDB
- Geolocation data from ip-api.com (free, no API key required)
- Data normalization and scoring
- AI-powered narrative generation (optional, requires OpenAI API key)
- Persistent report repository for the live threat feed dashboard

### Frontend

The frontend is built with React and Vite, featuring:
- Modern, responsive UI
- Real-time backend health monitoring
- Visual threat indicators
- Detailed analysis results display
- War-room style dashboard with auto-refreshing feed, trend charts, and category insights

## Building for Production

### Backend

The backend can be deployed using any ASGI server (uvicorn, gunicorn, etc.)

### Frontend

```bash
cd frontend
npm run build
```

The production build will be in the `frontend/dist` directory.

## License

This project is for demonstration purposes.

