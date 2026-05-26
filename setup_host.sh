#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Setting up Host Gatekeeper..."

# 1. Install dependencies
dnf update -y
dnf install -y python3-pyudev python3-libvirt libvirt-client udev python3-tkinter

# 2. Restricted user that the VM uses for the SSH callback
USER="safegate-gatekeeper"
if ! id "$USER" &>/dev/null; then
    useradd -m -s /bin/bash $USER
    echo "Created user $USER"
fi

# 3. Group whose members may read/write the IPC socket
groupadd -f safegate
# add the SSH callback user (must talk to daemon socket)
usermod -aG safegate "$USER"

# Detect the desktop user even when invoked via 'sudo su' / 'sudo -i'
# (where $SUDO_USER may be unset or 'root'). Fall back to logname, then ask.
DESKTOP_USER="${SAFEGATE_DESKTOP_USER:-}"
if [[ -z "$DESKTOP_USER" || "$DESKTOP_USER" == "root" ]]; then
    DESKTOP_USER="${SUDO_USER:-}"
fi
if [[ -z "$DESKTOP_USER" || "$DESKTOP_USER" == "root" ]]; then
    DESKTOP_USER="$(logname 2>/dev/null || true)"
fi
if [[ -z "$DESKTOP_USER" || "$DESKTOP_USER" == "root" ]]; then
    # Last resort: pick the first non-system human user with a real shell
    DESKTOP_USER="$(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1; exit}' /etc/passwd)"
fi
if [[ -z "$DESKTOP_USER" || "$DESKTOP_USER" == "root" ]]; then
    read -rp "Which user runs the desktop session (will be added to 'safegate' group)? " DESKTOP_USER
fi
if id "$DESKTOP_USER" &>/dev/null; then
    usermod -aG safegate "$DESKTOP_USER"
    echo "Added $DESKTOP_USER to group 'safegate' (full logout required)."
else
    echo "WARNING: could not determine desktop user. Run manually:"
    echo "    sudo usermod -aG safegate <your-username>"
fi

# 4. SSH keypair for the VM → Host callback
SSH_DIR="/home/$USER/.ssh"
mkdir -p $SSH_DIR
chmod 700 $SSH_DIR
if [[ ! -f "$SSH_DIR/id_rsa_safegate" ]]; then
    ssh-keygen -t rsa -b 4096 -f "$SSH_DIR/id_rsa_safegate" -N "" -q
fi
chown -R $USER:$USER $SSH_DIR

# Restricted authorized_keys: forced command, no port/x11/agent forwarding
PUB_KEY=$(cat "$SSH_DIR/id_rsa_safegate.pub")
echo "command=\"python3 /opt/safegate/host_gate.py \$SSH_ORIGINAL_COMMAND\",no-port-forwarding,no-x11-forwarding,no-agent-forwarding $PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown $USER:$USER "$SSH_DIR/authorized_keys"

# 5. Udev rule: hide every USB block device from the host
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

# 6. Mount root (daemon runs as root, so root owns it)
mkdir -p /media/safe_usb
chmod 755 /media/safe_usb

# 7. Deploy code to /opt/safegate
install -d /opt/safegate
install -m 0755 host_gate.py  /opt/safegate/host_gate.py
install -m 0755 dashboard.py  /opt/safegate/dashboard.py

# 8. Systemd service: daemon runs as root, supplementary group "safegate"
#    so the IPC socket can be chown'd root:safegate.
cat > /etc/systemd/system/safegate-host.service <<'EOF'
[Unit]
Description=SafeGate USB Host Gatekeeper
After=virtqemud.socket virtnetworkd.service libvirtd.service
Wants=virtqemud.socket virtnetworkd.service

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/safegate/host_gate.py
Restart=on-failure
RestartSec=3
RuntimeDirectory=safegate
RuntimeDirectoryMode=0770
SupplementaryGroups=safegate

[Install]
WantedBy=multi-user.target
EOF

# Make sure libvirt default network is up + auto-starts (creates virbr0)
systemctl enable --now virtnetworkd.socket virtnetworkd.service 2>/dev/null || true
if virsh -c qemu:///system net-list --all 2>/dev/null | grep -q '^ default'; then
    virsh -c qemu:///system net-autostart default 2>/dev/null || true
    virsh -c qemu:///system net-start    default 2>/dev/null || true
fi
# And make scanner-vm itself autostart on boot (optional but matches dashboard UX)
virsh -c qemu:///system list --all 2>/dev/null | grep -q 'scanner-vm' \
    && virsh -c qemu:///system autostart scanner-vm 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now safegate-host.service

# 9. XDG autostart for the dashboard — every desktop login spawns it
cat > /etc/xdg/autostart/safegate-dashboard.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=SafeGate Dashboard
Exec=/usr/bin/python3 /opt/safegate/dashboard.py
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF

echo "--------------------------------------------------"
echo "Host Setup Complete!"
echo " - safegate-host.service is enabled and running."
echo " - dashboard.py will autostart on next desktop login (XDG-aware DEs)."
echo "   On Hyprland / Sway / minimal WMs, add to your config:"
echo "     exec-once = /usr/bin/python3 /opt/safegate/dashboard.py"
echo " - ${DESKTOP_USER:-<desktop user>} must log out and back in to pick up group 'safegate'."
echo ""
echo "1. Ensure your VM is named 'scanner-vm' in libvirt."
echo "2. Copy the PRIVATE KEY to your VM's /root/.ssh/id_rsa_safegate:"
cat "$SSH_DIR/id_rsa_safegate"
echo "--------------------------------------------------"
