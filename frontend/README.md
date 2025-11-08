# Cerberus Frontend

Modern React-based frontend for the Cerberus Threat Intelligence Correlation Engine.

## Features

- 🎨 Modern, responsive UI design
- 🔍 IP address threat analysis
- 📊 Visual threat score and risk level indicators
- 📝 Detailed threat narratives
- 🏷️ Threat category tags
- 📈 Real-time backend health monitoring
- 🧱 Live threat feed dashboard with auto-refreshing cards, top risk list, and trend sparkline

## Setup

1. Install dependencies:

```bash
cd frontend
npm install
```

2. Start the development server:

```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Configuration

The frontend is configured to connect to the backend at `http://localhost:8000` by default. This is handled via the Vite proxy configuration in `vite.config.js`.

To change the backend URL, you can:
- Set the `VITE_API_URL` environment variable
- Modify the `API_BASE_URL` in `src/services/api.js`

## Build for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

## Preview Production Build

```bash
npm run preview
```

## Requirements

- Node.js 16+ 
- npm or yarn

## Usage

1. Make sure the backend server is running on port 8000
2. Start the frontend development server
3. Enter an IPv4 address in the input field
4. Click "Analyze" to get threat intelligence data
5. View the detailed analysis results including threat score, risk level, categories, and narrative
6. Switch to the Dashboard tab to monitor recent analyses and aggregate insights

