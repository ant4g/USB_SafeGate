import asyncio
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
        if device.get('ID_BUS') != 'usb':
            return None
        return {
            'vendor': device.get('ID_VENDOR_ID'),
            'product': device.get('ID_MODEL_ID'),
            'serial': device.get('ID_SERIAL_SHORT'),
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
            subprocess.run(["virsh", "attach-device", self.vm_name, str(xml_path)], check=True)
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
            subprocess.run(["virsh", "detach-device", self.vm_name, str(xml_path)], check=True)
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
            subprocess.run(["mount", node, str(mount_path)], check=True)
            print(f"Device {serial} is now available at {mount_path}")
        except subprocess.CalledProcessError as e:
            print(f"Mount failed: {e}")

    async def run(self):
        print("Host Gatekeeper active. Monitoring for USB insertions...")
        loop = asyncio.get_event_loop()
        
        while True:
            device = await loop.run_in_executor(None, self.monitor.poll, 1)
            if device and device.action == 'add':
                info = self.get_usb_info(device)
                if info:
                    print(f"Detected USB: {info['vendor']}:{info['product']} ({info['serial']})")
                    self.attach_to_vm(info)

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
    elif args.block:
        print(f"Received BLOCK signal for {args.block}. Keeping isolated.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        gate = HostGatekeeper(VM_NAME)
        asyncio.run(gate.run())
