#!/bin/bash
# Reverts changes made by setup_host.sh
set +e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Tearing down Host Gatekeeper..."

USER="safegate-gatekeeper"
RULE_FILE="/etc/udev/rules.d/99-safegate.rules"
POLKIT_FILE="/etc/polkit-1/rules.d/50-safegate-libvirt.rules"
SUDOERS_FILE="/etc/sudoers.d/safegate"
INSTALL_DIR="/opt/safegate"
MOUNT_ROOT="/media/safe_usb"

# 1. Remove udev rule and reload
if [[ -f "$RULE_FILE" ]]; then
    rm -f "$RULE_FILE"
    echo "Removed $RULE_FILE"
fi
udevadm control --reload-rules
udevadm trigger

# 2. Remove user from libvirt group (if present)
if id "$USER" &>/dev/null; then
    gpasswd -d "$USER" libvirt 2>/dev/null || true

    # 3. Kill any processes owned by the user before deletion
    pkill -u "$USER" 2>/dev/null || true
    sleep 1

    # 4. Delete user and home directory (contains SSH keys + authorized_keys)
    userdel -r "$USER" 2>/dev/null
    echo "Deleted user $USER and home directory"
else
    echo "User $USER not present, skipping"
fi

# 5. Remove polkit rule
if [[ -f "$POLKIT_FILE" ]]; then
    rm -f "$POLKIT_FILE"
    echo "Removed $POLKIT_FILE"
fi

# 6. Remove sudoers entry
if [[ -f "$SUDOERS_FILE" ]]; then
    rm -f "$SUDOERS_FILE"
    echo "Removed $SUDOERS_FILE"
fi

# 7. Unmount + remove mount root
if mountpoint -q "$MOUNT_ROOT" 2>/dev/null; then
    umount "$MOUNT_ROOT" || true
fi
for sub in "$MOUNT_ROOT"/*; do
    [[ -d "$sub" ]] && mountpoint -q "$sub" && umount "$sub" || true
done
if [[ -d "$MOUNT_ROOT" ]]; then
    rm -rf "$MOUNT_ROOT"
    echo "Removed $MOUNT_ROOT"
fi

# 8. Remove deployed host_gate.py / install dir
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo "Removed $INSTALL_DIR"
fi

# 9. Clean up stray temp XML configs created by host_gate.py
rm -f /tmp/usb_*.xml

echo "--------------------------------------------------"
echo "Host Teardown Complete."
echo "Note: dnf-installed packages (python3-pyudev, python3-libvirt,"
echo "libvirt-client, udev) are NOT removed - they may be used elsewhere."
echo "Remove manually with: dnf remove python3-pyudev python3-libvirt"
echo "--------------------------------------------------"
