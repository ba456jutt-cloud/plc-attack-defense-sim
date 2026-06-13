#!/bin/bash
echo "Starting CPSS Water Treatment Plant Simulation (Linux Native)"
echo "IMPORTANT: Make sure OpenPLC is already running and listening on localhost:502!"
echo ""

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Warning: venv not found. Using system python."
fi

export PLC_HOST="127.0.0.1"
export PLC_PORT="502"

echo "Starting Physics Engine..."
python3 water_treatment/physics.py &

echo "Starting Safety Instrumented System (SIS)..."
python3 defense/sis.py &

echo "Starting Digital Twin Countermeasures (CM-6)..."
python3 defense/countermeasures.py &

echo "Starting Modbus Firewall..."
python3 defense/modbus_firewall.py &

echo "Starting Web Dashboard..."
export PLC_PORT="5502" # Dashboard connects to firewall
python3 dashboard/server.py &

echo "All services started in the background! Dashboard available at http://127.0.0.1:5000"
echo "To stop them, use the 'pkill -f python3' command or kill their PIDs."
