#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Setting up Host Gatekeeper..."

# 1. Install dependencies
apt-get update
apt-get install -y python3-pyudev python3-libvirt libvirt-clients udev

# 2. Create restricted user for VM callbacks
USER="safegate-gatekeeper"
if ! id "$USER" &>/dev/null; then
    useradd -m -s /bin/bash $USER
    echo "Created user $USER"
fi

# 3. Setup SSH for VM
SSH_DIR="/home/$USER/.ssh"
mkdir -p $SSH_DIR
chmod 700 $SSH_DIR

# We will generate a key that you should copy TO THE VM
ssh-keygen -t rsa -b 4096 -f "$SSH_DIR/id_rsa_safegate" -N "" -q
chown -R $USER:$USER $SSH_DIR

# Restricted authorized_keys
PUB_KEY=$(cat "$SSH_DIR/id_rsa_safegate.pub")
echo "command=\"python3 /opt/safegate/host_gate.py \$SSH_ORIGINAL_COMMAND\",no-port-forwarding,no-x11-forwarding,no-agent-forwarding $PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown $USER:$USER "$SSH_DIR/authorized_keys"

# 4. Udev Rule to ignore USBs on Host initially
echo 'ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"' > /etc/udev/rules.d/99-safegate.rules
udevadm control --reload-rules
udevadm trigger

# 5. Allow restricted user to use virsh for the scanner-vm
# Note: This might require adding the user to 'libvirt' group
usermod -aG libvirt $USER

echo "--------------------------------------------------"
echo "Host Setup Complete!"
echo "1. Ensure your VM is named 'scanner-vm' in libvirt."
echo "2. Copy the PRIVATE KEY to your VM's /root/.ssh/id_rsa_safegate:"
cat "$SSH_DIR/id_rsa_safegate"
echo "--------------------------------------------------"
