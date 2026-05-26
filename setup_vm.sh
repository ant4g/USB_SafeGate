#!/bin/bash

# Exit on error
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Starting SafeGate setup..."

# 1. Install Python 3 and dependencies
echo "Installing Python 3 and dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv build-essential libudev-dev

# 2. Setup directory and virtual environment
INSTALL_DIR="/opt/safegate"
mkdir -p $INSTALL_DIR
cp safegate.py requirements.txt $INSTALL_DIR/

echo "Creating virtual environment in $INSTALL_DIR..."
python3 -m venv $INSTALL_DIR/venv
$INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt

# 3. Handle API Key
if [ -z "$VIRUSTOTAL_API_KEY" ]; then
    read -p "Enter your VirusTotal API Key: " VT_API_KEY
else
    VT_API_KEY=$VIRUSTOTAL_API_KEY
fi

echo "VIRUSTOTAL_API_KEY=$VT_API_KEY" > /etc/safegate.env
chmod 600 /etc/safegate.env

# 4. SSH Setup for callbacks
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo "Reminder: You must copy the id_rsa_safegate from the Host to /root/.ssh/ on this VM."

# 5. Create Systemd Service
echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/safegate.service
[Unit]
Description=USB SafeGate Scanner
After=network.target

[Service]
Environment=PYTHONUNBUFFERED=1
Type=simple
User=root
WorkingDirectory=/opt/safegate
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/safegate.py
EnvironmentFile=/etc/safegate.env
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and start service
echo "Enabling and starting SafeGate service..."
systemctl daemon-reload
systemctl enable safegate.service
systemctl start safegate.service

echo "--------------------------------------------------"
echo "Setup complete! SafeGate is now running as a daemon."
echo "You can check status with: systemctl status safegate"
echo "To view logs: journalctl -u safegate -f"
echo "--------------------------------------------------"
