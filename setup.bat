@echo off
echo ========================================
echo Cerberus Threat Intelligence Setup
echo ========================================
echo.

echo Step 1: Creating Python virtual environment...
python -m venv .venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo.
echo Step 2: Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo Step 3: Installing Python dependencies...
pip install -r backend/requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo Step 4: Creating .env file...
if not exist .env (
    echo ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here > .env
    echo OPENAI_API_KEY= >> .env
    echo .env file created - Please add your AbuseIPDB API key
) else (
    echo .env file already exists, skipping...
)

echo.
echo Step 5: Installing Frontend dependencies...
cd frontend
call npm install
if errorlevel 1 (
    echo ERROR: Failed to install frontend dependencies
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To start the backend:
echo    start_backend.bat
echo.
echo To start the frontend (in a new terminal):
echo    start_frontend.bat
echo.
pause

