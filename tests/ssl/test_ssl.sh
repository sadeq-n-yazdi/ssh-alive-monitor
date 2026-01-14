#!/bin/bash

# Test script for SSL Certificate Generation and HTTPS Support

# Get absolute path to project root
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
WEBSERVER_DIR="$ROOT_DIR/webserver"

# Ensure we are in the root directory for consistency
cd "$ROOT_DIR"

PORT=8443
API_URL="https://localhost:$PORT"
MASTER_KEY="master-key-123"
TEST_DOMAIN="vps03.famcdn.net"
CERT_FILE="test_server.crt"
KEY_FILE="test_server.key"
CONFIG_FILE="test_config_ssl.json"

echo "Building webserver..."
cd "$WEBSERVER_DIR"
go build -o ssh-monitor .
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi
cd "$ROOT_DIR"

# Create a test config
cat <<EOF > $CONFIG_FILE
{
    "port": "$PORT",
    "log_level": "info",
    "log_components": ["requests", "response"],
    "log_format": "text",
    "default_interval": "10m",
    "default_timeout": "5s",
    "ssl_enabled": true,
    "cert_path": "$CERT_FILE",
    "key_path": "$KEY_FILE",
    "ssl_cert_domains": ["$TEST_DOMAIN"],
    "master_keys": ["$MASTER_KEY"]
}
EOF

# Ensure clean state
rm -f $CERT_FILE $KEY_FILE

echo "Starting webserver on port $PORT (SSL Enabled)..."
# We run from root so it picks up the config file via path or we can overwrite config.json, 
# but the server looks for config.json in CWD. 
# Let's move the binary here or run from here.
./webserver/ssh-monitor -port $PORT &
# Wait, the server reads config.json from CWD. We need to rename our test config or pass it (server doesn't accept config path flag yet, uses hardcoded config.json).
# Workaround: Symlink or rename.
mv config.json config.json.bak 2>/dev/null
mv config-override.json config-override.json.bak 2>/dev/null
cp $CONFIG_FILE config.json

SERVER_PID=$!

function cleanup {
    echo "Cleaning up..."
    kill $SERVER_PID
    rm -f config.json
    mv config.json.bak config.json 2>/dev/null
    mv config-override.json.bak config-override.json 2>/dev/null
    rm -f $CONFIG_FILE $CERT_FILE $KEY_FILE
}
trap cleanup EXIT

echo "Waiting for server to start and generate certs..."
sleep 3

echo "---------------------------------------------------"
echo "Test 1: Verify Certificate Files Exist"
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "PASS: Certificate and Key files generated."
else
    echo "FAIL: Certificate or Key files missing."
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 2: Verify Certificate Domain (Subject Alternative Name or Common Name)"
# Check for the domain in the text output of the cert
if openssl x509 -in $CERT_FILE -text -noout | grep -q "$TEST_DOMAIN"; then
    echo "PASS: Domain $TEST_DOMAIN found in certificate."
else
    echo "FAIL: Domain $TEST_DOMAIN NOT found in certificate."
    openssl x509 -in $CERT_FILE -text -noout
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 3: Verify HTTPS Connection (curl -k)"
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" "$API_URL/")
if [ "$HTTP_CODE" -eq "200" ]; then
    echo "PASS: Server responded with 200 OK over HTTPS."
else
    echo "FAIL: Server responded with $HTTP_CODE over HTTPS."
    exit 1
fi

echo "---------------------------------------------------"
echo "Test 4: Verify Auth over HTTPS"
RESP=$(curl -k -s -H "X-API-Key: $MASTER_KEY" "$API_URL/api/keys")
if echo "$RESP" | grep -q "$MASTER_KEY"; then
    echo "PASS: API Key auth worked over HTTPS."
else
    echo "FAIL: API Key auth failed over HTTPS."
    echo "Response: $RESP"
    exit 1
fi

echo "Tests completed successfully."
