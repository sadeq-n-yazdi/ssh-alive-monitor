#!/bin/bash

# Test script to add random hosts every 10 seconds
# This helps verify WebSocket real-time updates are working

API_KEY="master-key-123"
PORT=8080
BASE_URL="http://localhost:$PORT"

echo "Starting WebSocket test - adding random hosts every 10 seconds"
echo "Press Ctrl+C to stop"
echo ""

# Counter for test hosts
counter=1

while true; do
    # Generate random IP in 10.0.0.x range
    random_ip="10.0.0.$((RANDOM % 255 + 1))"

    echo "[$(date '+%H:%M:%S')] Adding test host: $random_ip:22"

    # Add host via API
    response=$(curl -s -X POST \
        -H "X-API-Key: $API_KEY" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "host=$random_ip&port=22&interval=5m&timeout=3s&public=true" \
        "$BASE_URL/api/hosts" 2>&1)

    if [ $? -eq 0 ]; then
        echo "  ✓ Host added successfully"
    else
        echo "  ✗ Failed to add host: $response"
    fi

    echo ""

    # Wait 10 seconds
    sleep 10

    counter=$((counter + 1))
done
