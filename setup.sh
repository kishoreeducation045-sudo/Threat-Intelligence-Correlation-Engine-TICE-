#!/bin/bash
echo "========================================"
echo "Cerberus Threat Intelligence Setup"
echo "========================================"
echo ""

echo "Step 1: Creating Python virtual environment..."
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create virtual environment"
    exit 1
fi

echo ""
echo "Step 2: Activating virtual environment..."
source .venv/bin/activate

echo ""
echo "Step 3: Installing Python dependencies..."
pip install -r backend/requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install Python dependencies"
    exit 1
fi

echo ""
echo "Step 4: Creating .env file..."
if [ ! -f .env ]; then
    cat > .env << EOF
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=
EOF
    echo ".env file created - Please add your AbuseIPDB API key"
else
    echo ".env file already exists, skipping..."
fi

echo ""
echo "Step 5: Installing Frontend dependencies..."
cd frontend
npm install
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install frontend dependencies"
    cd ..
    exit 1
fi
cd ..

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "To start the backend:"
echo "   ./start_backend.sh"
echo ""
echo "To start the frontend (in a new terminal):"
echo "   ./start_frontend.sh"
echo ""

