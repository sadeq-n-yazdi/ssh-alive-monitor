#!/bin/bash

# Get absolute path to project root (this script is in webserver/)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

# Generate a secure 32-character hex API key
KEY=$(openssl rand -hex 32 2>/dev/null || LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 64 | head -n 1)

echo "Generated Master API Key:"
echo "$KEY"
echo ""
echo "To use this key:"
echo "1. Copy webserver/config.json.sample to webserver/config.json (if not already exists)"
echo "2. Add the generated key to the \"master_keys\" array in webserver/config.json"
echo ""
echo "Example config.json entry:"
echo "  \"master_keys\": [\"$KEY\"]"
