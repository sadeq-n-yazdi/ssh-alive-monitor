#!/bin/bash

# Comprehensive test script for SSH Alive Monitor

# Get absolute path to project root
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
WEBSERVER_DIR="$ROOT_DIR/webserver"

# Ensure we are in the root directory for consistency
cd "$ROOT_DIR"

PORT=8083
API_URL="http://localhost:$PORT"
MASTER_KEY="master-key-123"
NORMAL_KEY="normal-key-456"

echo "Building webserver..."
cd "$WEBSERVER_DIR"
go build -o ssh-monitor .
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Starting webserver on port $PORT..."
./ssh-monitor -port $PORT &
SERVER_PID=$!
sleep 2

function cleanup {
    echo "Killing server..."
    kill $SERVER_PID
    rm -f ssh-monitor
}
trap cleanup EXIT

echo "---------------------------------------------------"
echo "Test 1: Access without API Key (Should fail)"
curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/results"
echo ""

echo "---------------------------------------------------"
echo "Test 2: Master Key - Add a Normal Key"
curl -s -X POST -H "X-API-Key: $MASTER_KEY" -H "Content-Type: application/json" \
     -d "{\"key\": \"$NORMAL_KEY\", \"type\": \"normal\"}" "$API_URL/api/keys"
echo ""

echo "---------------------------------------------------"
echo "Test 3: Normal Key - Add Host (Immediate check)"
curl -s -X POST -H "X-API-Key: $NORMAL_KEY" -d "127.0.0.1:22" "$API_URL/api/hosts"
echo ""
echo "Waiting 1 second for check to complete..."
sleep 1

echo "---------------------------------------------------"
echo "Test 4: Normal Key - Get Results (Plain Text)"
curl -s -H "X-API-Key: $NORMAL_KEY" "$API_URL/api/results"

echo "---------------------------------------------------"
echo "Test 5: Get Results (JSON via Accept Header)"
curl -s -H "X-API-Key: $NORMAL_KEY" -H "Accept: application/json" "$API_URL/api/results" | jq .

echo "---------------------------------------------------"
echo "Test 6: Get Results (YAML via format param)"
curl -s -H "X-API-Key: $NORMAL_KEY" "$API_URL/api/results?format=yaml"

echo "---------------------------------------------------"
echo "Test 7: Add another host with custom interval and timeout"
curl -s -X POST -H "X-API-Key: $NORMAL_KEY" -H "Content-Type: application/json" \
     -d "{\"host\": \"google.com:22\", \"interval\": \"1s\", \"timeout\": \"1s\"}" "$API_URL/api/hosts"
echo ""
sleep 2
echo "Latest results (should see multiple checks for google.com):"
curl -s -H "X-API-Key: $NORMAL_KEY" "$API_URL/api/results?limit=5"

echo "---------------------------------------------------"
echo "Test 8: Filter results by host"
echo "Filtering for 127.0.0.1:"
curl -s -H "X-API-Key: $NORMAL_KEY" "$API_URL/api/results?host=127.0.0.1"

echo "---------------------------------------------------"
echo "Test 9: Master Key - List all keys"
curl -s -H "X-API-Key: $MASTER_KEY" "$API_URL/api/keys" | jq .

echo "---------------------------------------------------"
echo "Tests completed."
