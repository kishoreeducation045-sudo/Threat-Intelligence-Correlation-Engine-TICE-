#!/bin/bash
echo "Starting Cerberus Backend Server..."
echo ""
echo "Make sure you have:"
echo "1. Created a .env file in the project root with ABUSEIPDB_API_KEY"
echo "2. Activated your Python virtual environment"
echo "3. Installed dependencies: pip install -r backend/requirements.txt"
echo ""
read -p "Press enter to continue..."
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

