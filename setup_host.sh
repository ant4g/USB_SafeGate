#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Setting up Host Gatekeeper..."

# 1. Install dependencies
dnf update
dnf install -y python3-pyudev python3-libvirt libvirt-client udev

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

# 4. Udev Rule to block USBs on Host (disks + partitions)
cat > /etc/udev/rules.d/99-safegate.rules <<'EOF'
# SafeGate: block all USB block devices on host (disks + partitions)
ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", \
    ENV{UDISKS_IGNORE}="1", \
    ENV{UDISKS_AUTO}="0", \
    ENV{UDISKS_PRESENTATION_HIDE}="1", \
    ENV{SYSTEMD_READY}="0", \
    OWNER="root", GROUP="root", MODE="0000"
EOF
udevadm control --reload-rules
udevadm trigger

# 5. Allow restricted user to use virsh for the scanner-vm
# Note: This might require adding the user to 'libvirt' group
usermod -aG libvirt $USER

# 5b. Polkit rule so libvirt group can manage system VMs without auth prompt
cat > /etc/polkit-1/rules.d/50-safegate-libvirt.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage" && subject.isInGroup("libvirt")) {
        return polkit.Result.YES;
    }
});
EOF

# 5c. Sudoers entry: let gatekeeper run notify-send as any user without password
cat > /etc/sudoers.d/safegate <<EOF
$USER ALL=(ALL) NOPASSWD: /usr/bin/env, /usr/bin/notify-send, /usr/bin/wall, /usr/bin/mount, /usr/bin/umount
EOF
chmod 440 /etc/sudoers.d/safegate

# 5d. Mount root owned by gatekeeper so it can mkdir per-serial subdirs
mkdir -p /media/safe_usb
chown $USER:$USER /media/safe_usb
chmod 755 /media/safe_usb

echo "--------------------------------------------------"
echo "Host Setup Complete!"
echo "1. Ensure your VM is named 'scanner-vm' in libvirt."
echo "2. Copy the PRIVATE KEY to your VM's /root/.ssh/id_rsa_safegate:"
cat "$SSH_DIR/id_rsa_safegate"
echo "--------------------------------------------------"
