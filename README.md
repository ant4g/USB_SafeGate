# SafeGate USB 🛡️
Isolated USB Sanitization Station (Airlock) with live desktop dashboard.

SafeGate USB is a security solution that creates a "secure airlock" for unknown USB drives. It automatically detects connected devices, isolates them from the host operating system, and passes them to a dedicated, isolated virtual machine for deep security analysis. A dormant on-host dashboard pops to the top of the screen as soon as a device is detected and walks the user through detection → scan → verdict.

## 🏗️ Architecture

Three components on the host plus the scanner VM:

1. **Host gatekeeper daemon** (`host_gate.py`, runs as a systemd service under `safegate-host.service`)
   * Watches `udev` for USB block-device insertions.
   * Auto-starts `scanner-vm` if it isn't already running.
   * Passes the device into the VM via `virsh attach-device`.
   * Centralises every action (detach, mount, block) and broadcasts events over a Unix-domain socket.
2. **Dashboard** (`dashboard.py`, Tkinter, autostarted from `/etc/xdg/autostart/safegate-dashboard.desktop`)
   * Dormant in the user's desktop session — invisible until an event arrives.
   * Forces itself on top of the screen for *detected → vm_starting → scanning → result*.
   * Shows green for SAFE, red for UNSAFE, amber for UNKNOWN.
3. **Scanner VM** (`safegate.py` under `safegate.service`)
   * Mounts the passthrough device read-only inside the VM.
   * SHA-256 hashes every file and queries VirusTotal v3 (`/search?query=<hash>`).
   * Produces an HTML report and signals the verdict back over SSH.

### Verdict logic (mixed precedence)

| Condition                                              | Verdict |
|--------------------------------------------------------|---------|
| Any file's VT lookup failed                            | UNSAFE (fail-closed) |
| Any file has `malicious_count > threshold` in VT       | UNSAFE |
| At least one file's hash is **not in VirusTotal's DB** | UNKNOWN |
| Otherwise                                              | SAFE   |

On **UNKNOWN**, the dashboard prompts the user with `Mount anyway (at own risk)` / `Block`. If nobody decides within 5 minutes, the daemon auto-blocks (detaches the device from the VM, never mounts).

### Wire protocol

The daemon listens on `/run/safegate/dashboard.sock` (mode `0660`, group `safegate`). One newline-delimited JSON object per message.

Daemon → dashboard:
```json
{"event":"detected",    "serial":"...","vendor":"...","product":"..."}
{"event":"vm_starting", "serial":"..."}
{"event":"scanning",    "serial":"..."}
{"event":"result",      "serial":"...","verdict":"SAFE|UNSAFE|UNKNOWN"}
{"event":"mounted",     "serial":"...","path":"/media/safe_usb/<serial>"}
{"event":"detached",    "serial":"..."}
{"event":"error",       "serial":"...","msg":"..."}
```

Dashboard → daemon (only meaningful for an in-flight UNKNOWN):
```json
{"action":"mount_anyway","serial":"..."}
{"action":"block",       "serial":"..."}
```

The VM's SSH callback uses the same socket via the `host_gate.py --release|--block|--unknown <serial>` thin client.

## 🛠️ Tech Stack

* **Language**: Python 3.x (object-oriented, asyncio)
* **GUI**: Tkinter (stdlib — runs on X11 and Wayland via XWayland; no DE-specific deps)
* **IPC**: AF_UNIX socket, newline-delimited JSON
* **Virtualisation**: KVM/QEMU through `libvirt`
* **Libraries**: `httpx`, `pyudev`, `aiofiles`
* **API**: VirusTotal API v3

## 🚀 Setup Instructions

### 1. Host configuration (Fedora-family — script uses `dnf`)

1. Clone the repository onto the host.
2. Run the host setup script (also installs Tkinter and registers the systemd service + XDG autostart):
   ```bash
   sudo chmod +x setup_host.sh teardown_host.sh
   sudo ./setup_host.sh
   ```
3. **Note the private key** the script prints — copy it to the VM at `/root/.ssh/id_rsa_safegate`.
4. Log out and back into your desktop session so the dashboard autostart picks up the new `safegate` group membership.
5. Ensure your scanner VM is named `scanner-vm` in libvirt.

#### Other distributions

The setup script is currently Fedora-only (uses `dnf`). On other distros install the same components manually before running the rest of the script body:

| Distro          | Tkinter package |
|-----------------|-----------------|
| Debian / Ubuntu | `python3-tk`     |
| Arch / Manjaro  | `tk`             |
| openSUSE        | `python3-tk`     |
| Fedora / RHEL   | `python3-tkinter`|

The systemd unit, XDG autostart file, `safegate` group, and `/opt/safegate` deployment are distribution-agnostic.

### 2. VM configuration (Ubuntu guest)

1. Copy `safegate.py`, `requirements.txt`, and `setup_vm.sh` to the VM.
2. Run the VM setup script:
   ```bash
   sudo chmod +x setup_vm.sh
   sudo ./setup_vm.sh
   ```
3. Copy the host's `id_rsa_safegate` private key to `/root/.ssh/id_rsa_safegate` inside the VM.
4. Set your VirusTotal API key when prompted.

### 3. Verification

1. `systemctl status safegate-host.service` should show **active (running)**.
2. `pgrep -af dashboard.py` should list the dashboard in your desktop session.
3. `virsh -c qemu:///system destroy scanner-vm` to exercise the auto-start path.
4. Plug in three test USB sticks:
   * **SAFE**: empty / freshly-formatted (vacuously clean) or one with files that are already in VT.
   * **UNSAFE**: contains the EICAR test file — VT flags it → red verdict, no host mount.
   * **UNKNOWN**: contains random bytes (`dd if=/dev/urandom of=blob bs=1M count=1`) — hash not in VT DB → amber prompt with two buttons.
5. Live JSON tap: `socat - UNIX-CONNECT:/run/safegate/dashboard.sock` (must be a member of group `safegate`).
6. Logs: `journalctl -u safegate-host -f`.

### Tearing down

```bash
sudo ./teardown_host.sh
```

Disables the service, removes the autostart file, deletes `/opt/safegate`, restores normal USB handling on the host.

## 📋 Security Features

* **Airlock isolation** — devices are never mounted by the host until they are verified.
* **Read-only analysis** — files are scanned in a read-only mount inside the VM.
* **Restricted handover** — the VM communicates with the host via a forced-command SSH account that can only invoke `host_gate.py` and only proxies one of three actions.
* **Centralised privilege** — only the root-owned daemon touches `mount`, `umount`, and `virsh`. The SSH callback runs as an unprivileged user that only writes JSON to a group-restricted socket.
* **Fail-closed on transport errors** — any VirusTotal request that fails is treated as UNSAFE.
* **UNKNOWN ≠ SAFE** — files VirusTotal has never seen require explicit user opt-in, with a 5-minute auto-block timeout if no one is at the keyboard.

---

### 👥 Project Team
* Antoni Gąsiorowski
* Szymon Stolarski
* Kamil Wierzbicki
* Mateusz Majcher
