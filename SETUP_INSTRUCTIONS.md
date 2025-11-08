# Setup Instructions

## Automatic Setup (Recommended)

### Windows:
1. Double-click `setup.bat` or run in terminal:
   ```bash
   setup.bat
   ```

### Linux/Mac:
1. Make script executable and run:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

The setup script will:
- Create Python virtual environment
- Install all Python dependencies
- Create `.env` file with your ABUSEIPDB_API_KEY
- Install frontend dependencies

## Manual Setup

### Step 1: Create .env File

Create a `.env` file in the project root directory with:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=
REPORT_DB_PATH=./data/reports.db
REPORT_RETENTION_DAYS=7
REPORT_RETENTION_LIMIT=1000
```

**Get your AbuseIPDB API key:**
- Visit https://www.abuseipdb.com/pricing to sign up
- Get your API key from https://www.abuseipdb.com/account/api

### Step 2: Backend Setup

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

### Step 3: Frontend Setup

```bash
cd frontend
npm install
cd ..
```

## Running the Application

### Option 1: Use Provided Scripts

**Terminal 1 - Backend:**
- Windows: Double-click `start_backend.bat` or run `start_backend.bat`
- Linux/Mac: `./start_backend.sh`

**Terminal 2 - Frontend:**
- Windows: Double-click `start_frontend.bat` or run `start_frontend.bat`
- Linux/Mac: `./start_frontend.sh`

### Option 2: Manual Commands

**Terminal 1 - Backend:**
```bash
# Activate virtual environment first
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

# Start backend
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

## Access the Application

- **Frontend UI**: http://localhost:3000 (Analyzer & Dashboard tabs)
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/health

## Verification

1. Check backend is running:
   - Open http://localhost:8000/api/health in browser
   - Should see: `{"status":"healthy","service":"Cerberus TICE","version":"1.0.0"}`

2. Check frontend is running:
   - Open http://localhost:3000 in browser
   - Should see the Cerberus interface

3. Test IP analysis:
   - Enter an IP address (e.g., `8.8.8.8`)
   - Click "Analyze"
   - View threat intelligence results
4. View the live dashboard:
   - Switch to the Dashboard tab
   - Confirm cards, summary widgets, and trend chart populate from stored analyses

## Troubleshooting

### Backend Issues

**Error: "ABUSEIPDB_API_KEY missing"**
- Make sure `.env` file exists in project root
- Verify `ABUSEIPDB_API_KEY` is set correctly in `.env` file
- Restart the backend server after creating/updating `.env`

**Error: "Module not found"**
- Activate virtual environment: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)
- Install dependencies: `pip install -r backend/requirements.txt`

**Error: "Port 8000 already in use"**
- Stop other services on port 8000
- Or change port: `uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8001`

### Frontend Issues

**Error: "Cannot connect to backend"**
- Verify backend is running on http://localhost:8000
- Check backend health: http://localhost:8000/api/health
- Check browser console for CORS errors
- Ensure the report database path (`REPORT_DB_PATH`) points to a writable location

**Error: "Module not found"**
- Install dependencies: `cd frontend && npm install`
- Delete `node_modules` and `package-lock.json`, then run `npm install` again

### API Key Issues

**AbuseIPDB API returns errors:**
- Verify API key is correct in your `.env` file
- Check API key is active at: https://www.abuseipdb.com/account/api
- Ensure `.env` file has no extra spaces or quotes around the key
- Make sure your AbuseIPDB account has API access enabled

## File Structure

```
.
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py          # Configuration (loads .env)
│   │   ├── main.py            # FastAPI application
│   │   ├── models.py          # Data models
│   │   └── services/
│   │       ├── collector.py   # AbuseIPDB API integration
│   │       ├── normalizer.py  # Data normalization
│   │       ├── repository/    # Report persistence layer
│   │       ├── scorer.py      # Threat scoring
│   │       ├── narrative.py   # Narrative generation
│   │       └── utils.py       # Utility functions
│   ├── requirements.txt
│   └── README.md
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── components/
│   │   │   └── IPAnalyzer.jsx
│   │   └── services/
│   │       └── api.js
│   ├── package.json
│   └── vite.config.js
├── .env                       # Environment variables (create this)
├── setup.bat / setup.sh       # Automatic setup scripts
├── start_backend.bat / .sh    # Backend startup scripts
├── start_frontend.bat / .sh   # Frontend startup scripts
└── README.md

```

## Next Steps

1. Run `setup.bat` (Windows) or `./setup.sh` (Linux/Mac)
2. Start backend: `start_backend.bat` or `./start_backend.sh`
3. Start frontend: `start_frontend.bat` or `./start_frontend.sh`
4. Open http://localhost:3000 and start analyzing IP addresses!

