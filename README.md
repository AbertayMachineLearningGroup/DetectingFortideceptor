# FortiDeceptor Decoy Detection Script

This Python script automates the detection of FortiDeceptor decoys and other deceptive systems within a network. It utilizes various techniques such as network scanning, ARP scanning, banner grabbing, system uptime checks, and virtualization detection to identify potential decoys.

## Features
- **Network Scanning**: Scans all open ports on a target IP using Nmap.
- **ARP Scanning**: Identifies unusual MAC addresses within the local network.
- **Banner Grabbing**: Collects service banners to detect anomalies.
- **System Uptime Check**: Checks the uptime of remote systems to identify freshly deployed decoys.
- **Virtualization Detection**: Detects virtualization artifacts to reveal decoy systems.

## Prerequisites
Ensure the following tools are installed on your system:

- Python 3.x
- Nmap
- arp-scan
- netcat (nc)
- dmidecode
- smbclient (optional for uptime checks)

Install required dependencies on Debian/Ubuntu:
```bash
sudo apt-get install nmap arp-scan netcat dmidecode smbclient
```

## Usage
Run the script with root privileges for ARP scanning:

```bash
sudo python3 fortideceptor_detector.py <target-ip>
```

Replace `<target-ip>` with the IP address of the system you want to scan.

## Code Overview

```python
def run_nmap_scan(target_ip):
    """Runs Nmap scan on the target IP."""
    subprocess.run(["nmap", "-sS", "-p-", "-T4", target_ip], capture_output=True, text=True)

def run_arp_scan():
    """Performs ARP scan on the local network."""
    subprocess.run(["sudo", "arp-scan", "--localnet"], capture_output=True, text=True)

def banner_grab(target_ip, port):
    """Grabs service banner from the specified port."""
    subprocess.run(["nc", "-v", "-n", target_ip, str(port)], capture_output=True, text=True, timeout=5)

def check_uptime(target_ip):
    """Checks system uptime using SMB."""
    subprocess.run(["smbclient", "-L", target_ip, "-N"], capture_output=True, text=True)

def detect_virtualization():
    """Detects virtualization artifacts."""
    subprocess.run(["dmidecode", "-s", "system-manufacturer"], capture_output=True, text=True)
```

## Example

```bash
sudo python3 fortideceptor_detector.py 192.168.1.100
```

## Disclaimer
This script is intended for educational and security testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License
This project is licensed under the MIT License.
