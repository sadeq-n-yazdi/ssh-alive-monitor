#!/bin/bash

# Get absolute path to project root
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
WEBSERVER_DIR="$ROOT_DIR/webserver"

# Ensure we are in the root directory for consistency
cd "$ROOT_DIR"

# Port to run the server on
PORT=8083
API_URL="http://localhost:$PORT"
MASTER_KEY="master-key-123"

# Cleanup previous run
rm -f "$WEBSERVER_DIR/ssh-monitor"

echo "Building webserver..."
cd "$WEBSERVER_DIR"
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
echo "Setup: Create a Normal User Key"
KEY_RESPONSE=$(curl -s -X POST -H "X-API-Key: $MASTER_KEY" -H "Accept: application/json" -H "Content-Type: application/json" -d '{"generate":true, "type":"normal"}' "$API_URL/api/keys")
echo "Raw Key Response: $KEY_RESPONSE"
NORMAL_KEY=$(echo "$KEY_RESPONSE" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
echo "Generated Normal Key: $NORMAL_KEY"

if [ -z "$NORMAL_KEY" ]; then
    echo "Failed to generate normal key"
    kill $SERVER_PID
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 1: Normal User - Add /24 CIDR (Should Succeed)"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "X-API-Key: $NORMAL_KEY" -d "192.168.1.0/24" "$API_URL/api/hosts")
if [ "$RESPONSE" -eq 200 ]; then
    echo "PASS: Added /24 successfully"
else
    echo "FAIL: Failed to add /24. HTTP Code: $RESPONSE"
fi

echo "---------------------------------------------------"
echo "Test 2: Normal User - Add /23 CIDR (Should Fail)"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "X-API-Key: $NORMAL_KEY" -d "192.168.0.0/23" "$API_URL/api/hosts")
if [ "$RESPONSE" -eq 403 ]; then
    echo "PASS: Blocked /23 as expected (Forbidden)"
else
    echo "FAIL: Should have blocked /23. HTTP Code: $RESPONSE"
fi

echo "---------------------------------------------------"
echo "Test 3: Master User - Add /23 CIDR (Should Succeed)"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "X-API-Key: $MASTER_KEY" -d "192.168.2.0/23" "$API_URL/api/hosts")
if [ "$RESPONSE" -eq 200 ]; then
    echo "PASS: Added /23 successfully as Master"
else
    echo "FAIL: Master failed to add /23. HTTP Code: $RESPONSE"
fi

echo "---------------------------------------------------"
echo "Test 4: Verify Hosts were added"
# We added 192.168.1.0/24 (256 hosts) and 192.168.2.0/23 (512 hosts) = ~768 hosts
# Let's count hosts
RESPONSE=$(curl -s -H "Accept: application/json" -H "X-API-Key: $MASTER_KEY" "$API_URL/api/hosts")
echo "Head of response: ${RESPONSE:0:100}..."
HOST_COUNT=$(echo "$RESPONSE" | grep -o "\"host\"" | wc -l)
echo "Total hosts found: $HOST_COUNT"
if [ "$HOST_COUNT" -gt 700 ]; then
    echo "PASS: Host count seems correct (>700)"
else
    echo "FAIL: Expected >700 hosts, got $HOST_COUNT"
fi

echo "---------------------------------------------------"
echo "Test completed. Killing server..."
kill $SERVER_PID
rm -f ssh-monitor
echo "Done."
