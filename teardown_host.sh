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
SERVICE_FILE="/etc/systemd/system/safegate-host.service"
AUTOSTART_FILE="/etc/xdg/autostart/safegate-dashboard.desktop"
RUNTIME_DIR="/run/safegate"

# 1. Stop and disable the systemd service
if systemctl list-unit-files | grep -q '^safegate-host\.service'; then
    systemctl disable --now safegate-host.service 2>/dev/null
fi
if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo "Removed $SERVICE_FILE"
fi

# 2. Remove dashboard XDG autostart
if [[ -f "$AUTOSTART_FILE" ]]; then
    rm -f "$AUTOSTART_FILE"
    echo "Removed $AUTOSTART_FILE"
fi

# 3. Remove udev rule and reload
if [[ -f "$RULE_FILE" ]]; then
    rm -f "$RULE_FILE"
    echo "Removed $RULE_FILE"
fi
udevadm control --reload-rules
udevadm trigger

# 4. Remove user, kill any processes first
if id "$USER" &>/dev/null; then
    gpasswd -d "$USER" libvirt  2>/dev/null
    gpasswd -d "$USER" safegate 2>/dev/null
    pkill -u "$USER" 2>/dev/null
    sleep 1
    userdel -r "$USER" 2>/dev/null
    echo "Deleted user $USER and home directory"
else
    echo "User $USER not present, skipping"
fi

# 5. Remove the 'safegate' group (only if no members remain)
if getent group safegate >/dev/null; then
    if [[ -z "$(getent group safegate | awk -F: '{print $4}')" ]]; then
        groupdel safegate 2>/dev/null && echo "Removed group safegate"
    else
        echo "Group safegate still has members; not removing."
    fi
fi

# 6. Remove legacy polkit + sudoers rules from older versions, if present
[[ -f "$POLKIT_FILE"  ]] && rm -f "$POLKIT_FILE"  && echo "Removed $POLKIT_FILE"
[[ -f "$SUDOERS_FILE" ]] && rm -f "$SUDOERS_FILE" && echo "Removed $SUDOERS_FILE"

# 7. Unmount + remove mount root
if mountpoint -q "$MOUNT_ROOT" 2>/dev/null; then
    umount "$MOUNT_ROOT"
fi
for sub in "$MOUNT_ROOT"/*; do
    [[ -d "$sub" ]] && mountpoint -q "$sub" && umount "$sub"
done
if [[ -d "$MOUNT_ROOT" ]]; then
    rm -rf "$MOUNT_ROOT"
    echo "Removed $MOUNT_ROOT"
fi

# 8. Remove deployed code
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo "Removed $INSTALL_DIR"
fi

# 9. Remove runtime socket directory
if [[ -d "$RUNTIME_DIR" ]]; then
    rm -rf "$RUNTIME_DIR"
    echo "Removed $RUNTIME_DIR"
fi

# 10. Clean up stray temp XML configs created by host_gate.py
rm -f /tmp/usb_*.xml

echo "--------------------------------------------------"
echo "Host Teardown Complete."
echo "Note: dnf-installed packages (python3-pyudev, python3-libvirt,"
echo "      libvirt-client, udev, python3-tkinter) are NOT removed - they"
echo "      may be used elsewhere. Remove manually with:"
echo "        dnf remove python3-pyudev python3-libvirt python3-tkinter"
echo "--------------------------------------------------"
