#!/bin/bash

# SSH Alive Monitor Install Script

# Get absolute path to project root (this script is in root)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR="$SCRIPT_DIR"
WEBSERVER_DIR="$ROOT_DIR/webserver"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

INSTALL_DIR="/opt/ssh-monitor"
mkdir -p $INSTALL_DIR

echo "Building ssh-monitor..."
cd "$WEBSERVER_DIR"
go build -o ssh-monitor .

echo "Installing files..."
cp ssh-monitor "$INSTALL_DIR/"
cp generate_key.sh "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/generate_key.sh"
cp ssh-monitor.service /etc/systemd/system/

# Create default config if not exists
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    cat > "$INSTALL_DIR/config.json" <<EOF
{
    "port": "8080",
    "log_level": "info",
    "log_components": ["requests", "response", "checks"],
    "log_format": "color",
    "default_interval": "10m",
    "default_timeout": "5s",
    "master_keys": ["master-key-123"]
}
EOF
fi

echo "Reloading systemd and starting service..."
systemctl daemon-reload
systemctl enable ssh-monitor
# systemctl start ssh-monitor # Don't start it during installation if not wanted, but usually we do.

echo "Installation complete!"
echo "Service is installed and enabled. You can start it with: systemctl start ssh-monitor"
echo "Don't forget to generate a secure API key using: $INSTALL_DIR/generate_key.sh and update $INSTALL_DIR/config.json"
