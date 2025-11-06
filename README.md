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
  - VirusTotal API Key: https://www.virustotal.com/gui/my-apikey
  - AlienVault OTX API Key: https://otx.alienvault.com/api
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
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_alienvault_otx_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

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
3. Enter an IPv4 address in the input field
4. Click "Analyze" to get comprehensive threat intelligence data
5. View the detailed analysis including:
   - Threat score (0-100)
   - Risk level (LOW, MEDIUM, HIGH, CRITICAL)
   - Threat categories
   - Country and ASN information
   - Malicious sources count
   - Abuse confidence score
   - AI-generated threat narrative
   - Triggered security rules

## API Endpoints

### Backend API

- `GET /api/health` - Health check endpoint
- `POST /api/v1/analyze` - Analyze an IP address
  - Request body: `{ "ip_address": "1.2.3.4" }`
  - Returns: Detailed threat analysis

## Development

### Backend

The backend is built with FastAPI and includes:
- Threat intelligence collection from VirusTotal and AlienVault OTX
- Data normalization and scoring
- AI-powered narrative generation (optional, requires OpenAI API key)

### Frontend

The frontend is built with React and Vite, featuring:
- Modern, responsive UI
- Real-time backend health monitoring
- Visual threat indicators
- Detailed analysis results display

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

