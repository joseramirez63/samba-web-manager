#!/bin/bash

# Samba Web Manager Installation Script
# MIT License

set -e

echo "=================================="
echo "Samba Web Manager Installation"
echo "=================================="
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (sudo ./install.sh)"
    exit 1
fi

# Determine source directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/samba-manager"

# System update
echo "📦 Updating system..."
apt update

# Install required packages
echo "📦 Installing required packages..."
apt install -y python3 python3-pip python3-venv samba samba-common-bin nmbd wsdd2

# Copy project files to install directory
echo "📁 Copying files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}/." "${INSTALL_DIR}/"

cd "${INSTALL_DIR}"

# Python virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

# Install Python packages
echo "📦 Installing Python packages..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install flask werkzeug flask-limiter

# Generate SECRET_KEY and write config
echo "🔑 Generating SECRET_KEY..."
mkdir -p /etc/samba-manager
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
cat > /etc/samba-manager/config.env << EOFENV
SECRET_KEY="${SECRET_KEY}"
EOFENV
chmod 600 /etc/samba-manager/config.env

# Data directory
echo "📁 Creating data directory..."
mkdir -p "${INSTALL_DIR}/data"

# Systemd service
echo "⚙️  Creating systemd service..."
cat > /etc/systemd/system/samba-manager.service << 'EOFSERVICE'
[Unit]
Description=Samba Web Manager
After=network.target smbd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/samba-manager
EnvironmentFile=/etc/samba-manager/config.env
Environment="PATH=/opt/samba-manager/venv/bin"
ExecStart=/opt/samba-manager/venv/bin/python /opt/samba-manager/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFSERVICE

# Reload systemd
systemctl daemon-reload

# Start and enable services
echo "🚀 Starting services..."
systemctl start samba-manager
systemctl enable samba-manager

echo "🗂️  Starting Samba (smbd + nmbd)..."
systemctl start smbd nmbd
systemctl enable smbd nmbd

echo "🔍 Starting wsdd2 (Windows network discovery)..."
systemctl start wsdd2
systemctl enable wsdd2

# Sudoers configuration
echo "🔐 Configuring sudo permissions..."
if ! grep -q "samba-manager" /etc/sudoers; then
    cat >> /etc/sudoers << 'EOFSUDOERS'

# Samba Web Manager
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart smbd
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl status smbd
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wsdd2
root ALL=(ALL) NOPASSWD: /usr/bin/smbpasswd
root ALL=(ALL) NOPASSWD: /usr/sbin/useradd
root ALL=(ALL) NOPASSWD: /usr/sbin/userdel
root ALL=(ALL) NOPASSWD: /usr/bin/chown
root ALL=(ALL) NOPASSWD: /usr/bin/chmod
root ALL=(ALL) NOPASSWD: /usr/bin/mkdir
root ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/samba/smb.conf
EOFSUDOERS
fi

# Get IP address
IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=================================="
echo "✅ Installation Complete!"
echo "=================================="
echo ""
echo "🌐 Web Panel: http://$IP:5000"
echo ""
echo "🔐 Default Login:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "⚠️  Change the default password on your first login!"
echo ""
echo "📊 Service Status:"
systemctl status samba-manager --no-pager
echo ""
echo "🛠️  Useful Commands:"
echo "   sudo systemctl status samba-manager   # Status"
echo "   sudo systemctl restart samba-manager  # Restart"
echo "   sudo systemctl stop samba-manager     # Stop"
echo "   sudo journalctl -u samba-manager -f   # Follow logs"
echo ""
