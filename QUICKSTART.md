# Quick Start Guide

## Prerequisites
- Python 3.8+ installed
- Node.js 16+ and npm installed

## Step 1: Create .env File

Create a `.env` file in the project root directory with the following content:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=
```

**Note:** 
- Replace `your_abuseipdb_api_key_here` with your actual AbuseIPDB API key
- Get your API key from: https://www.abuseipdb.com/account/api
- The OPENAI_API_KEY is optional. Leave it empty if you don't have one.

## Step 2: Setup (Automatic)

### Windows:
```bash
setup.bat
```

### Linux/Mac:
```bash
chmod +x setup.sh
./setup.sh
```

## Step 2: Setup (Manual)

### Backend Setup:
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### Frontend Setup:
```bash
cd frontend
npm install
cd ..
```

## Step 3: Run the Application

### Terminal 1 - Start Backend:
```bash
# Windows:
start_backend.bat

# Linux/Mac:
chmod +x start_backend.sh
./start_backend.sh

# Or manually:
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2 - Start Frontend:
```bash
# Windows:
start_frontend.bat

# Linux/Mac:
chmod +x start_frontend.sh
./start_frontend.sh

# Or manually:
cd frontend
npm run dev
```

## Step 4: Access the Application

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

Optional persistence configuration (set in `.env`):
```
REPORT_DB_PATH=./data/reports.db
REPORT_RETENTION_DAYS=7
REPORT_RETENTION_LIMIT=1000
```

## Testing

1. Open http://localhost:3000 in your browser
2. Enter an IP address (e.g., `8.8.8.8`)
3. Click "Analyze"
4. View the threat intelligence results
5. Navigate to the Dashboard tab to inspect the live threat feed and summary widgets

## Troubleshooting

### Backend won't start:
- Make sure `.env` file exists in the project root
- Check that `ABUSEIPDB_API_KEY` is set correctly
- Verify Python virtual environment is activated
- Ensure all dependencies are installed: `pip install -r backend/requirements.txt`

### Frontend won't start:
- Make sure you're in the `frontend` directory or use the provided scripts
- Verify Node.js and npm are installed: `node --version` and `npm --version`
- Install dependencies: `cd frontend && npm install`
- Check that backend is running on port 8000
- Ensure the report database path is writable (default `./data/reports.db`)

### API Connection Errors:
- Verify backend is running on http://localhost:8000
- Check the browser console for CORS errors
- Ensure the backend health check works: http://localhost:8000/api/health

