import asyncio
import hashlib
import os
import subprocess
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

import httpx
import pyudev
import aiofiles

class ReportGenerator:
    def __init__(self, report_dir: Path = Path("/var/www/safegate/reports")):
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)

    async def generate_html(self, device_info: Dict, scan_results: List[Dict], verdict: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"report_{device_info['serial']}_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SafeGate Scan Report - {device_info['serial']}</title>
            <style>
                body {{ font-family: sans-serif; margin: 40px; background: #f4f4f9; }}
                .container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; }}
                .verdict {{ font-size: 24px; font-weight: bold; padding: 10px; border-radius: 4px; margin: 20px 0; }}
                .safe {{ background: #d4edda; color: #155724; }}
                .unsafe {{ background: #f8d7da; color: #721c24; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #eee; }}
                .malicious {{ color: #dc3545; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>USB Scan Report</h1>
                <p><strong>Device:</strong> {device_info['vendor']} ({device_info['size_gb']} GB)</p>
                <p><strong>Serial:</strong> {device_info['serial']}</p>
                <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                
                <div class="verdict {verdict.lower()}">Verdict: {verdict}</div>
                
                <table>
                    <thead>
                        <tr>
                            <th>File Path</th>
                            <th>SHA256 Hash</th>
                            <th>VT Malicious Hits</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for result in scan_results:
            malicious_class = "malicious" if result['malicious_count'] > 0 else ""
            html_content += f"""
                        <tr>
                            <td>{result['file_path']}</td>
                            <td><code>{result['hash']}</code></td>
                            <td class="{malicious_class}">{result['malicious_count']}</td>
                        </tr>
            """
            
        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        async with aiofiles.open(report_path, mode='w') as f:
            await f.write(html_content)
        
        return report_path

class HostNotifier:
    def __init__(self, host_ip: str = "192.168.122.1"):
        self.host_ip = host_ip
        self.ssh_key = "/root/.ssh/id_rsa_safegate"

    async def notify_host(self, serial: str, action: str):
        # Action can be 'release' or 'block'
        cmd = [
            "ssh", "-i", self.ssh_key,
            "-o", "StrictHostKeyChecking=no",
            f"safegate-gatekeeper@{self.host_ip}",
            f"gate-cli --{action} {serial}"
        ]
        try:
            subprocess.run(cmd, check=True)
            print(f"Notified host: {action} {serial}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to notify host: {e}")

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "X-Apikey": self.api_key
        }

    async def check_hash(self, file_hash: str) -> Optional[int]:
        url = f"{self.base_url}/search?query={file_hash}"
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    result = response.json()
                    if result.get('data'):
                        return result['data'][0]['attributes']['last_analysis_stats']['malicious']
                    return 0 # Not found is assumed clean for hash search
                else:
                    print(f"API Error: {response.status_code}")
            except Exception as e:
                print(f"Request error: {e}")
        return None

async def calculate_sha256(file_path: Path) -> Optional[str]:
    try:
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, mode='rb') as f:
            while True:
                chunk = await f.read(4096)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Hashing error for {file_path}: {e}")
        return None

class USBMonitor:
    def __init__(self, mount_point: str = "/mnt/Pendrive"):
        self.mount_point = Path(mount_point)
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by('block')
        self.monitor.start()
        self.mount_point.mkdir(parents=True, exist_ok=True)

    async def mount_device(self, device_node: str) -> bool:
        try:
            print(f"Attempting to mount {device_node} as read-only...")
            subprocess.run(
                ["sudo", "mount", "-o", "ro", device_node, str(self.mount_point)],
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Mount error: {e}")
            return False

    async def unmount_device(self) -> bool:
        try:
            subprocess.run(["sudo", "umount", str(self.mount_point)], check=True)
            return True
        except subprocess.CalledProcessError as e:
            # Often fails if already unmounted
            return False

    def get_device_info(self, dev):
        try:
            sectors = int(dev.attributes.get('size', 0))
            size_gb = (sectors * 512) / (1024**3)
            return {
                "vendor": dev.get('ID_VENDOR_FROM_DATABASE') or "Unknown",
                "size_gb": round(size_gb, 2),
                "serial": dev.get('ID_SERIAL_SHORT') or "NoSerial",
                "node": dev.device_node
            }
        except (TypeError, ValueError):
            return {"vendor": "Unknown", "size_gb": 0.0, "serial": "Unknown", "node": dev.device_node}

class SafeGateApp:
    def __init__(self, api_key: str, threshold: int = 0):
        self.vt_client = VirusTotalClient(api_key)
        self.usb_monitor = USBMonitor()
        self.reporter = ReportGenerator()
        self.notifier = HostNotifier()
        self.threshold = threshold

    async def scan_directory(self, path: Path) -> List[Dict]:
        results = []
        tasks = []
        
        # Collect all files first
        files_to_scan = [p for p in path.rglob('*') if p.is_file()]
        
        async def process_task(file_path):
            res = await self.process_file(file_path)
            if res:
                results.append(res)

        await asyncio.gather(*(process_task(f) for f in files_to_scan))
        return results

    async def process_file(self, file_path: Path) -> Optional[Dict]:
        file_hash = await calculate_sha256(file_path)
        if not file_hash:
            return None

        malicious_count = await self.vt_client.check_hash(file_hash)
        if malicious_count is None:
            malicious_count = 0
            
        return {
            "file_path": str(file_path),
            "hash": file_hash,
            "malicious_count": malicious_count
        }

    async def run(self):
        print("SafeGate Scanner is active. Waiting for USB passthrough...")
        loop = asyncio.get_event_loop()
        
        while True:
            dev = await loop.run_in_executor(None, self.usb_monitor.monitor.poll, 1)
            if dev and dev.get('ID_BUS') == 'usb' and dev.action == 'add':
                info = self.usb_monitor.get_device_info(dev)
                print(f"\nScanning Device: {info['vendor']} ({info['serial']})")
                
                if await self.usb_monitor.mount_device(info['node']):
                    scan_results = await self.scan_directory(self.usb_monitor.mount_point)
                    
                    max_malicious = max((r['malicious_count'] for r in scan_results), default=0)
                    verdict = "SAFE" if max_malicious <= self.threshold else "UNSAFE"
                    
                    report_path = await self.reporter.generate_html(info, scan_results, verdict)
                    print(f"Report generated: {report_path}")
                    
                    action = "release" if verdict == "SAFE" else "block"
                    await self.notifier.notify_host(info['serial'], action)
                    
                    await self.usb_monitor.unmount_device()
                    print(f"Finished processing {info['serial']}. Verdict: {verdict}\n")

async def main():
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("Error: VIRUSTOTAL_API_KEY not set.")
        sys.exit(1)
        
    threshold = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    app = SafeGateApp(api_key, threshold)
    await app.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping SafeGate...")
