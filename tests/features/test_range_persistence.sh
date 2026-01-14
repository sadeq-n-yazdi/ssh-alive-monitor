#!/bin/bash

# Determine project structure
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
WEBSERVER_DIR="$ROOT_DIR/webserver"

PORT=8084
API_URL="http://localhost:$PORT"
MASTER_KEY="master-key-123"
CONFIG_FILE="$WEBSERVER_DIR/config.json"
BACKUP_FILE="$WEBSERVER_DIR/config.json.bak"

echo "Project Root: $ROOT_DIR"
echo "Webserver Dir: $WEBSERVER_DIR"

# Cleanup and Backup config
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$BACKUP_FILE"
fi

# Ensure a clean config for testing
echo '{"master_keys":["master-key-123"]}' > "$CONFIG_FILE"

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
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null
    if [ -f "$BACKUP_FILE" ]; then
        mv "$BACKUP_FILE" "$CONFIG_FILE"
    else
        rm -f "$CONFIG_FILE"
    fi
    rm -f "$WEBSERVER_DIR/ssh-monitor"
}
trap cleanup EXIT

echo "---------------------------------------------------"
echo "Test 1: Add a CIDR Range"
CIDR="10.0.0.0/24"
ADD_RESPONSE=$(curl -s -X POST -H "X-API-Key: $MASTER_KEY" -d "$CIDR" "$API_URL/api/hosts")
echo "Response: $ADD_RESPONSE"

echo "---------------------------------------------------"
echo "Test 2: Verify Persistence in config.json"
if grep -q "network_ranges" "$CONFIG_FILE" && grep -q "$CIDR" "$CONFIG_FILE"; then
    echo "PASS: Range found in config.json"
else
    echo "FAIL: Range NOT found in config.json"
    cat "$CONFIG_FILE"
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 3: List Ranges via API"
RANGES_LIST=$(curl -s -H "Accept: application/json" -H "X-API-Key: $MASTER_KEY" "$API_URL/api/ranges")
echo "Ranges: $RANGES_LIST"
if echo "$RANGES_LIST" | grep -q "$CIDR"; then
    echo "PASS: Range listed correctly"
else
    echo "FAIL: Range missing from API list"
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 4: Restart Server and Verify Reload"
echo "Killing server..."
kill $SERVER_PID
sleep 1
echo "Starting server again..."
./ssh-monitor -port $PORT &
SERVER_PID=$!
sleep 2

# Verify hosts are re-added
HOST_COUNT=$(curl -s -H "Accept: application/json" -H "X-API-Key: $MASTER_KEY" "$API_URL/api/hosts" | grep -o "\"host\"" | wc -l)
echo "Total hosts after reload: $HOST_COUNT"
if [ "$HOST_COUNT" -ge 256 ]; then
    echo "PASS: Hosts reloaded from config"
else
    echo "FAIL: Expected at least 256 hosts, got $HOST_COUNT"
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 5: Delete Range"
DEL_RESPONSE=$(curl -s -X DELETE -H "X-API-Key: $MASTER_KEY" -d "$CIDR" "$API_URL/api/ranges")
echo "Delete Response: $DEL_RESPONSE"

# Check config again
if grep -q "$CIDR" "$CONFIG_FILE"; then
    echo "FAIL: Range still exists in config.json"
    exit 1
else
    echo "PASS: Range removed from config.json"
fi

# Check monitor
HOST_COUNT=$(curl -s -H "Accept: application/json" -H "X-API-Key: $MASTER_KEY" "$API_URL/api/hosts" | grep -o "\"host\"" | wc -l)
echo "Total hosts after deletion: $HOST_COUNT"
if [ "$HOST_COUNT" -eq 0 ]; then
    echo "PASS: Hosts removed from monitor"
else
    echo "FAIL: Hosts still in monitor"
    exit 1
fi

echo "---------------------------------------------------"
echo "All Persistence Tests Passed!"
