import argparse
import asyncio
import grp
import json
import os
import pyudev
import subprocess
import sys
import time
from pathlib import Path

# Configuration - adjust to your VM name
VM_NAME = "scanner-vm"
MOUNT_ROOT = Path("/media/safe_usb")
SOCKET_PATH = Path("/run/safegate/dashboard.sock")
SOCKET_GROUP = "safegate"
VM_START_TIMEOUT = 120          # seconds to wait for guest-ping after virsh start
UNKNOWN_DECISION_TIMEOUT = 300  # seconds before an UNKNOWN auto-blocks


class HostGatekeeper:
    def __init__(self, vm_name: str):
        self.vm_name = vm_name
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by('block')
        self.active_devices = {}     # serial -> device_node
        self.pending_unknown = {}    # serial -> {"info":..., "task": asyncio.Task}
        self.clients = set()         # set[asyncio.StreamWriter]

    # ---------- USB / libvirt ----------

    def get_usb_info(self, device):
        p = device.properties
        if p.get('ID_BUS') != 'usb' or p.get('DEVTYPE') != 'disk':
            return None
        return {
            'vendor': p.get('ID_VENDOR_ID'),
            'product': p.get('ID_MODEL_ID'),
            'serial': p.get('ID_SERIAL_SHORT'),
            'node': device.device_node,
        }

    def attach_to_vm(self, info):
        print(f"Attaching {info['serial']} to VM {self.vm_name}...")
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
            subprocess.run(
                ["virsh", "-c", "qemu:///system", "attach-device",
                 self.vm_name, str(xml_path)],
                check=True,
            )
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
            subprocess.run(
                ["virsh", "-c", "qemu:///system", "detach-device",
                 self.vm_name, str(xml_path)],
                check=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to detach: {e}")
            return False

    def mount_on_host(self, serial):
        node = self.active_devices.get(serial)
        if not node:
            print(f"Node for {serial} not found in tracking.")
            return False
        mount_path = MOUNT_ROOT / serial
        mount_path.mkdir(parents=True, exist_ok=True)
        print(f"Mounting {node} to {mount_path}...")
        try:
            subprocess.run(["mount", node, str(mount_path)], check=True)
            print(f"Device {serial} is now available at {mount_path}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Mount failed: {e}")
            return False

    def virsh_state(self):
        try:
            r = subprocess.run(
                ["virsh", "-c", "qemu:///system", "domstate", self.vm_name],
                capture_output=True, text=True, check=False,
            )
            return r.stdout.strip()
        except Exception as e:
            print(f"virsh domstate failed: {e}")
            return "unknown"

    async def ensure_vm_running(self):
        state = self.virsh_state()
        if state != "running":
            print(f"VM {self.vm_name} state='{state}', starting...")
            try:
                subprocess.run(
                    ["virsh", "-c", "qemu:///system", "start", self.vm_name],
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                print(f"VM start failed: {e}")
                return False

        deadline = time.time() + VM_START_TIMEOUT
        while time.time() < deadline:
            r = subprocess.run(
                ["virsh", "-c", "qemu:///system", "qemu-agent-command",
                 self.vm_name, '{"execute":"guest-ping"}'],
                capture_output=True,
            )
            if r.returncode == 0:
                print("VM guest agent responded.")
                return True
            await asyncio.sleep(2)

        print("VM agent did not respond; continuing after short grace period.")
        await asyncio.sleep(5)
        return True

    # ---------- IPC ----------

    async def broadcast(self, event: dict):
        line = (json.dumps(event) + "\n").encode()
        dead = []
        for w in list(self.clients):
            try:
                w.write(line)
                await w.drain()
            except Exception:
                dead.append(w)
        for w in dead:
            self.clients.discard(w)
            try:
                w.close()
            except Exception:
                pass
        print(f"event → {event}")

        # Fallback: when no dashboard is connected, ping the desktop directly
        if not self.clients:
            self._fallback_notify(event)

    def _fallback_notify(self, event: dict):
        ev = event.get("event")
        if ev == "result":
            verdict = event.get("verdict", "?")
            urgency = "critical" if verdict in ("UNSAFE", "UNKNOWN") else "normal"
            notify_desktop(
                f"SafeGate: {verdict}",
                f"Device {event.get('serial','?')} scanned {verdict}.",
                urgency=urgency,
            )
        elif ev == "mounted":
            notify_desktop(
                "SafeGate: USB mounted",
                f"Device {event.get('serial','?')} mounted at {event.get('path','?')}",
            )
        elif ev == "error":
            notify_desktop(
                "SafeGate: error",
                f"{event.get('serial','?')}: {event.get('msg','?')}",
                urgency="critical",
            )

    async def handle_client(self, reader, writer):
        self.clients.add(writer)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode().strip())
                except Exception as e:
                    print(f"bad JSON from client: {e}")
                    continue
                await self.handle_action(msg)
        finally:
            self.clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass

    # ---------- Action handlers ----------

    async def handle_action(self, msg: dict):
        action = msg.get("action")
        serial = msg.get("serial")
        if not action or not serial:
            return

        if action == "release":
            await self.broadcast({"event": "result", "serial": serial, "verdict": "SAFE"})
            if self.detach_from_vm(serial) and self.mount_on_host(serial):
                await self.broadcast({"event": "mounted", "serial": serial,
                                      "path": str(MOUNT_ROOT / serial)})
            else:
                await self.broadcast({"event": "error", "serial": serial,
                                      "msg": "release path failed"})

        elif action == "block":
            await self.broadcast({"event": "result", "serial": serial, "verdict": "UNSAFE"})
            self.detach_from_vm(serial)
            await self.broadcast({"event": "detached", "serial": serial})
            self.pending_unknown.pop(serial, None)

        elif action == "unknown":
            await self.broadcast({"event": "result", "serial": serial, "verdict": "UNKNOWN"})
            info = {"node": self.active_devices.get(serial)}
            timeout_task = asyncio.create_task(self._unknown_timeout(serial))
            self.pending_unknown[serial] = {"info": info, "task": timeout_task}

        elif action == "mount_anyway":
            pending = self.pending_unknown.pop(serial, None)
            if pending:
                pending["task"].cancel()
            if self.detach_from_vm(serial) and self.mount_on_host(serial):
                await self.broadcast({"event": "mounted", "serial": serial,
                                      "path": str(MOUNT_ROOT / serial)})
            else:
                await self.broadcast({"event": "error", "serial": serial,
                                      "msg": "mount_anyway failed"})

        else:
            print(f"unknown action: {action}")

    async def _unknown_timeout(self, serial):
        try:
            await asyncio.sleep(UNKNOWN_DECISION_TIMEOUT)
            print(f"UNKNOWN for {serial} timed out → auto-block")
            self.pending_unknown.pop(serial, None)
            self.detach_from_vm(serial)
            await self.broadcast({"event": "detached", "serial": serial,
                                  "msg": "auto-block (timeout)"})
        except asyncio.CancelledError:
            pass

    # ---------- udev loop ----------

    async def udev_loop(self):
        print("Host Gatekeeper active. Monitoring for USB insertions...")
        loop = asyncio.get_event_loop()
        while True:
            device = await loop.run_in_executor(None, self.monitor.poll, 1)
            if device is None:
                continue
            if device.properties.get('ACTION') != 'add':
                continue
            info = self.get_usb_info(device)
            if not info:
                continue
            print(f"Detected USB: {info['vendor']}:{info['product']} ({info['serial']})")
            await self.broadcast({"event": "detected", **info})
            await self.broadcast({"event": "vm_starting", "serial": info['serial']})
            if not await self.ensure_vm_running():
                await self.broadcast({"event": "error", "serial": info['serial'],
                                      "msg": "VM start failed"})
                continue
            if self.attach_to_vm(info):
                await self.broadcast({"event": "scanning", "serial": info['serial']})
            else:
                await self.broadcast({"event": "error", "serial": info['serial'],
                                      "msg": "attach-device failed"})

    # ---------- main ----------

    async def run(self):
        SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Ensure the runtime dir is traversable by the 'safegate' group
        # (systemd's RuntimeDirectory= creates it owned by the service's
        # primary group, which is root here — group members couldn't enter).
        try:
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
            os.chown(SOCKET_PATH.parent, 0, gid)
            os.chmod(SOCKET_PATH.parent, 0o2770)
        except KeyError:
            print(f"group {SOCKET_GROUP} not found; parent dir left as-is")
            gid = None

        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        server = await asyncio.start_unix_server(self.handle_client, path=str(SOCKET_PATH))
        if gid is not None:
            os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
        print(f"IPC socket listening at {SOCKET_PATH}")

        async with server:
            await self.udev_loop()


# ---------- Desktop fallback notifier ----------

def notify_desktop(summary: str, body: str, urgency: str = "normal"):
    """Send a desktop notification to every logged-in graphical user.
    Used as a fallback when no dashboard client is connected.
    Daemon runs as root, so it can switch users via `runuser`.
    """
    try:
        sessions = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True, text=True, check=False,
        ).stdout.splitlines()
        notified = False
        for line in sessions:
            parts = line.split()
            if len(parts) < 3:
                continue
            session_id, uid, user = parts[0], parts[1], parts[2]
            session_type = subprocess.run(
                ["loginctl", "show-session", session_id, "-p", "Type", "--value"],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            if session_type not in ("x11", "wayland"):
                continue
            env_args = [
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                "DISPLAY=:0",
            ]
            subprocess.run(
                ["runuser", "-u", user, "--", "env", *env_args,
                 "notify-send", "-u", urgency, "-t", "20000", summary, body],
                check=False,
            )
            notified = True
        if not notified:
            subprocess.run(["wall", f"{summary}: {body}"], check=False)
    except Exception as e:
        print(f"notify_desktop error: {e}")


# ---------- Thin CLI client (used by VM SSH forced-command) ----------

def send_to_daemon(payload: dict):
    """Open the AF_UNIX socket, send one JSON line. Used by SSH callback."""
    import socket
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(SOCKET_PATH))
        s.sendall((json.dumps(payload) + "\n").encode())
        s.close()
        return True
    except Exception as e:
        print(f"Failed to reach daemon socket: {e}")
        return False


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", help="Device serial scanned SAFE — detach + mount.")
    parser.add_argument("--block",   help="Device serial scanned UNSAFE — detach only.")
    parser.add_argument("--unknown", help="Device serial scanned UNKNOWN — await dashboard.")
    args = parser.parse_args()

    if args.release:
        send_to_daemon({"action": "release", "serial": args.release})
    elif args.block:
        send_to_daemon({"action": "block", "serial": args.block})
    elif args.unknown:
        send_to_daemon({"action": "unknown", "serial": args.unknown})
    else:
        parser.error("one of --release/--block/--unknown is required")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        gate = HostGatekeeper(VM_NAME)
        asyncio.run(gate.run())
