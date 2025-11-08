@echo off
echo Starting Cerberus Frontend...
echo.
echo Make sure you have:
echo 1. Installed dependencies: cd frontend && npm install
echo 2. Backend server is running on http://localhost:8000
echo.
pause
cd frontend
npm run dev

