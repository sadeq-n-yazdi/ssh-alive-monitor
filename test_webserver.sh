#!/bin/bash

# Port to run the server on
PORT=8082
API_URL="http://localhost:$PORT"
API_KEY="master-key-123"

# Check if config.json exists and try to extract a master key
if [ -f "webserver/config.json" ]; then
    FOUND_KEY=$(grep -oP '"master_keys":\s*\[\s*"\K[^"]+' webserver/config.json | head -n 1)
    if [ ! -z "$FOUND_KEY" ]; then
        API_KEY="$FOUND_KEY"
    fi
fi

echo "Building webserver..."
cd webserver
go build -o ssh-monitor
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Starting webserver on port $PORT..."
./ssh-monitor -port $PORT &
SERVER_PID=$!
# Give it a second to start
sleep 2

echo "---------------------------------------------------"
echo "Test 1: Add Hosts"
echo "Adding 127.0.0.1:22..."
curl -s -X POST -H "X-API-Key: $API_KEY" -d "127.0.0.1:22" "$API_URL/api/hosts"
echo ""
echo "Adding google.com (should default to 22)..."
curl -s -X POST -H "X-API-Key: $API_KEY" -d "google.com" "$API_URL/api/hosts"
echo ""
echo "Adding scanme.nmap.org..."
curl -s -X POST -H "X-API-Key: $API_KEY" -d "scanme.nmap.org" "$API_URL/api/hosts"
echo ""

echo "---------------------------------------------------"
echo "Waiting 5 seconds for initial check to potentially run/complete..."
sleep 8

echo "---------------------------------------------------"
echo "Test 2: Get Results (Default Text)"
curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/results"

echo "---------------------------------------------------"
echo "Test 3: Get Results (JSON)"
curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/results?format=json" | jq . 2>/dev/null || curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/results?format=json"

echo "---------------------------------------------------"
echo "Test 4: Get Results (YAML)"
curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/results?format=yaml"

echo "---------------------------------------------------"
echo "Test 5: Get Results with limit=1"
curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/results?limit=1"

echo "---------------------------------------------------"
echo "Test 6: Delete Host"
echo "Deleting google.com:22..."
curl -s -X DELETE -H "X-API-Key: $API_KEY" -d "google.com:22" "$API_URL/api/hosts"
echo ""
echo "Verifying host list..."
curl -s -H "X-API-Key: $API_KEY" "$API_URL/api/hosts"

echo "---------------------------------------------------"
echo "Test completed. Killing server..."
kill $SERVER_PID
echo "Done."
