# SafeGate USB 🛡️
Isolated USB Sanitization Station (Airlock)

SafeGate USB is a security solution that creates a "secure airlock" for unknown USB drives. It automatically detects connected devices, isolates them from the host operating system, and passes them to a dedicated, isolated virtual machine for deep security analysis.

## 🏗️ Architecture

The system consists of two primary zones:

1.  **The Host (Gatekeeper)**: Monitors USB insertions, prevents auto-mounting, and passes the device to the VM using `libvirt`.
2.  **The VM (Scanner)**: Mounts the device read-only, hashes files, scans them against the VirusTotal API, generates an HTML report, and notifies the Host if the device is clean.

## 🛠️ Tech Stack

*   **Language**: Python 3.x (Object-Oriented, AsyncIO)
*   **Networking**: Secure SSH tunnel for verdict callbacks
*   **Virtualization**: KVM/QEMU (libvirt)
*   **Libraries**: `httpx`, `pyudev`, `aiofiles`, `pathlib`
*   **API**: VirusTotal API v3

## 🚀 Setup Instructions

### 1. Host Configuration (Ubuntu VM Host)

1.  Clone the repository to your host.
2.  Run the host setup script:
    ```bash
    sudo chmod +x setup_host.sh
    sudo ./setup_host.sh
    ```
3.  **Note your private key**: The script will output an SSH private key. Save this for the VM setup.
4.  Ensure your scanner VM is named `scanner-vm` in libvirt.

### 2. VM Configuration (Ubuntu Guest)

1.  Copy `safegate.py`, `requirements.txt`, and `setup_vm.sh` to the VM.
2.  Run the VM setup script:
    ```bash
    sudo chmod +x setup_vm.sh
    sudo ./setup_vm.sh
    ```
3.  **Configure SSH**: Copy the private key from the Host to `/root/.ssh/id_rsa_safegate` inside the VM.
4.  **Set API Key**: The setup script will prompt for your VirusTotal API key.

### 3. Verification

1.  Start the service on the Host: `sudo python3 host_gate.py`
2.  The VM service `safegate.service` starts automatically on boot.
3.  Plug in a USB drive. It should disappear from the host and appear in the VM.
4.  Check reports in `/var/www/safegate/reports` on the VM.

## 📋 Security Features

*   **Airlock Isolation**: Devices are never mounted by the host until they are verified.
*   **Read-Only Analysis**: Files are scanned in a read-only state inside the VM.
*   **Restricted Handover**: The VM communicates with the host via a restricted SSH account that can only execute the release command.
*   **Pathlib Standard**: All file interactions use modern Python standards.

---
### 👥 Project Team
* Antoni Gąsiorowski
* Szymon Stolarski
* Kamil Wierzbicki
* Mateusz Majcher
