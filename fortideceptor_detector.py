import subprocess
import re
import sys

def run_nmap_scan(target_ip):
    print(f"[+] Running Nmap scan on {target_ip}")
    result = subprocess.run(["nmap", "-sS", "-p-", "-T4", target_ip], capture_output=True, text=True)
    print(result.stdout)


def run_arp_scan():
    print("[+] Running ARP scan on local network")
    result = subprocess.run(["sudo", "arp-scan", "--localnet"], capture_output=True, text=True)
    print(result.stdout)


def banner_grab(target_ip, port):
    print(f"[+] Grabbing banner from {target_ip}:{port}")
    try:
        result = subprocess.run(["nc", "-v", "-n", target_ip, str(port)], capture_output=True, text=True, timeout=5)
        print(result.stdout)
    except subprocess.TimeoutExpired:
        print("[-] Banner grab timed out.")


def check_uptime(target_ip):
    print(f"[+] Checking system uptime for {target_ip}")
    # Example using SMB to fetch uptime
    try:
        result = subprocess.run(["smbclient", "-L", target_ip, "-N"], capture_output=True, text=True)
        print(result.stdout)
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


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target-ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    run_nmap_scan(target_ip)
    run_arp_scan()
    banner_grab(target_ip, 22)  # Example: SSH
    banner_grab(target_ip, 445) # Example: SMB
    check_uptime(target_ip)
    detect_virtualization()


if __name__ == "__main__":
    main()
