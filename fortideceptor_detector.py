import subprocess
import re
import sys
import socket

def run_nmap_scan(target_ip):
    print(f"[+] Running Nmap scan on {target_ip}")
    result = subprocess.run(["nmap", "-sS", "-p-", "-T4", target_ip], capture_output=True, text=True)
    print(result.stdout)

    # Detect common decoy patterns
    if "FortiDeceptor" in result.stdout or "Honeyd" in result.stdout:
        print("[!] Decoy detected based on Nmap scan!")

def run_arp_scan():
    print("[+] Running ARP scan on local network")
    result = subprocess.run(["sudo", "arp-scan", "--localnet"], capture_output=True, text=True)
    print(result.stdout)

    # Look for virtual MAC addresses often used by decoys
    if re.search(r"(00:0C:29|00:50:56|08:00:27)", result.stdout):
        print("[!] Potential virtual machine detected in ARP scan!")

def banner_grab(target_ip, port):
    print(f"[+] Grabbing banner from {target_ip}:{port}")
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((target_ip, port))
        sock.sendall(b'\n')
        banner = sock.recv(1024).decode().strip()
        print(f"[+] Banner: {banner}")
        sock.close()

        # Detect decoy banners
        if "FortiDeceptor" in banner or "Honeyd" in banner:
            print("[!] Decoy detected based on service banner!")
    except Exception as e:
        print(f"[-] Error grabbing banner: {e}")

def check_uptime(target_ip):
    print(f"[+] Checking system uptime for {target_ip}")
    try:
        result = subprocess.run(["smbclient", "-L", target_ip, "-N"], capture_output=True, text=True)
        print(result.stdout)

        # If uptime is unusually low, it might be a decoy
        if "Uptime" in result.stdout and "0 days" in result.stdout:
            print("[!] System has very low uptime — potential decoy.")
    except Exception as e:
        print(f"[-] Failed to check uptime: {e}")

def detect_virtualization():
    print("[+] Checking for virtualization artifacts")
    try:
        result = subprocess.run(["dmidecode", "-s", "system-manufacturer"], capture_output=True, text=True)
        if re.search(r"VMware|VirtualBox|KVM|Microsoft", result.stdout, re.IGNORECASE):
            print("[!] Virtualization detected: Potential decoy.")
        else:
            print("[-] No obvious virtualization detected.")
    except Exception as e:
        print(f"[-] Error detecting virtualization: {e}")

def check_processes(target_ip):
    print(f"[+] Checking running processes on {target_ip}")
    try:
        result = subprocess.run(["ssh", target_ip, "ps aux"], capture_output=True, text=True)
        print(result.stdout)
        if re.search(r"honeyd|snort|suricata", result.stdout, re.IGNORECASE):
            print("[!] Suspicious process detected — possible decoy.")
    except Exception as e:
        print(f"[-] Failed to check processes: {e}")

def check_filesystem(target_ip):
    print(f"[+] Checking filesystem for decoy indicators on {target_ip}")
    try:
        result = subprocess.run(["ssh", target_ip, "find / -name '*honey*' -o -name '*decoy*'"], capture_output=True, text=True)
        print(result.stdout)
        if result.stdout:
            print("[!] Decoy files detected on filesystem.")
    except Exception as e:
        print(f"[-] Failed to check filesystem: {e}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target-ip> <scan-type>")
        print("Scan types: network | internal")
        sys.exit(1)

    target_ip = sys.argv[1]
    scan_type = sys.argv[2].lower()

    if scan_type == "network":
        run_nmap_scan(target_ip)
        run_arp_scan()
        banner_grab(target_ip, 22)  # Example: SSH
        banner_grab(target_ip, 445) # Example: SMB
    elif scan_type == "internal":
        check_uptime(target_ip)
        detect_virtualization()
        check_processes(target_ip)
        check_filesystem(target_ip)
    else:
        print("[!] Invalid scan type. Use 'network' or 'internal'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
