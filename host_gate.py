import asyncio
import os
import pyudev
import subprocess
import sys
import argparse
from pathlib import Path

# Configuration - adjust to your VM name
VM_NAME = "scanner-vm"
MOUNT_ROOT = Path("/media/safe_usb")

class HostGatekeeper:
    def __init__(self, vm_name: str):
        self.vm_name = vm_name
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by('block')
        self.active_devices = {} # serial -> device_node

    def get_usb_info(self, device):
        p = device.properties
        if p.get('ID_BUS') != 'usb' or p.get('DEVTYPE') != 'disk':
            return None
        return {
            'vendor': p.get('ID_VENDOR_ID'),
            'product': p.get('ID_MODEL_ID'),
            'serial': p.get('ID_SERIAL_SHORT'),
            'node': device.device_node
        }

    def attach_to_vm(self, info):
        print(f"Attaching {info['serial']} to VM {self.vm_name}...")
        # Create temporary XML for libvirt
        xml = f"""
        <hostdev mode='subsystem' type='usb' managed='yes'>
          <source>
            <vendor id='0x{info['vendor']}'/>
            <product id='0x{info['product']}'/>
          </source>
        </hostdev>
        """
        xml_path = Path(f"/tmp/usb_{info['serial']}.xml")
        xml_path.write_text(xml)
        
        try:
            subprocess.run(["virsh", "-c", "qemu:///system", "attach-device", self.vm_name, str(xml_path)], check=True)
            self.active_devices[info['serial']] = info['node']
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to attach: {e}")
            return False

    def detach_from_vm(self, serial):
        print(f"Detaching {serial} from VM...")
        xml_path = Path(f"/tmp/usb_{serial}.xml")
        if not xml_path.exists():
            print("XML config not found, cannot detach cleanly.")
            return False
            
        try:
            subprocess.run(["virsh", "-c", "qemu:///system", "detach-device", self.vm_name, str(xml_path)], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to detach: {e}")
            return False

    def mount_on_host(self, serial):
        node = self.active_devices.get(serial)
        if not node:
            print(f"Node for {serial} not found in tracking.")
            return
            
        mount_path = MOUNT_ROOT / serial
        mount_path.mkdir(parents=True, exist_ok=True)
        
        print(f"Mounting {node} to {mount_path}...")
        try:
            subprocess.run(["sudo", "mount", node, str(mount_path)], check=True)
            print(f"Device {serial} is now available at {mount_path}")
        except subprocess.CalledProcessError as e:
            print(f"Mount failed: {e}")

    async def run(self):
        print("Host Gatekeeper active. Monitoring for USB insertions...")
        loop = asyncio.get_event_loop()
        
        while True:
            device = await loop.run_in_executor(None, self.monitor.poll, 1)
            if device is not None and device.properties.get('ACTION') == 'add':
                info = self.get_usb_info(device)
                if info:
                    print(f"Detected USB: {info['vendor']}:{info['product']} ({info['serial']})")
                    self.attach_to_vm(info)

def notify_desktop(summary: str, body: str, urgency: str = "normal"):
    """Send desktop notification to every logged-in graphical user."""
    try:
        # Find active graphical sessions
        sessions = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True, text=True, check=False
        ).stdout.splitlines()
        notified = False
        for line in sessions:
            parts = line.split()
            if len(parts) < 3:
                continue
            session_id, uid, user = parts[0], parts[1], parts[2]
            session_type = subprocess.run(
                ["loginctl", "show-session", session_id, "-p", "Type", "--value"],
                capture_output=True, text=True, check=False
            ).stdout.strip()
            if session_type not in ("x11", "wayland"):
                continue
            env = {
                "DISPLAY": ":0",
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
                "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            }
            env_args = [f"{k}={v}" for k, v in env.items()]
            subprocess.run(
                ["sudo", "-u", user, "env", *env_args,
                 "notify-send", "-u", urgency, "-t", "20000", summary, body],
                check=False
            )
            notified = True
        if not notified:
            # Fallback: broadcast via wall
            subprocess.run(["wall", f"{summary}: {body}"], check=False)
    except Exception as e:
        print(f"notify_desktop error: {e}")


# CLI for the VM to call back via SSH
def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", help="Release device serial")
    parser.add_argument("--block", help="Block device serial")
    args = parser.parse_args()

    gate = HostGatekeeper(VM_NAME) # Minimal instance for CLI

    if args.release:
        print(f"Received RELEASE signal for {args.release}")
        if gate.detach_from_vm(args.release):
            gate.mount_on_host(args.release)
            notify_desktop(
                "SafeGate: USB cleared",
                f"Device {args.release} scanned SAFE. Mounted at {MOUNT_ROOT}/{args.release}",
                urgency="normal",
            )
    elif args.block:
        print(f"Received BLOCK signal for {args.block}. Detaching and quarantining.")
        gate.detach_from_vm(args.block)
        notify_desktop(
            "SafeGate: UNSAFE USB BLOCKED",
            f"Device {args.block} flagged malicious. Detached from VM, NOT mounted on host.",
            urgency="critical",
        )

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        gate = HostGatekeeper(VM_NAME)
        asyncio.run(gate.run())
