import socket
import psutil
import requests
import time
import threading

# Settings
BLACKLIST_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"  # Public known bad IPs
CHECK_INTERVAL = 60  # seconds
CONNECTION_THRESHOLD = 100  # suspicious if more than this many connections per check

# Global blacklist
blacklisted_ips = set()

def download_blacklist():
    global blacklisted_ips
    try:
        print("[+] Downloading IP blacklist...")
        response = requests.get(BLACKLIST_URL)
        blacklisted_ips = set(response.text.strip().split('\n'))
        print(f"[+] {len(blacklisted_ips)} blacklisted IPs loaded.")
    except Exception as e:
        print(f"[-] Failed to download blacklist: {e}")

def check_connections():
    while True:
        suspicious_connections = []
        connections = psutil.net_connections(kind='inet')

        outbound_count = 0
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                outbound_count += 1
                remote_ip = conn.raddr.ip

                if remote_ip in blacklisted_ips:
                    suspicious_connections.append(remote_ip)

        print(f"[i] Outbound connections: {outbound_count}")

        if outbound_count > CONNECTION_THRESHOLD:
            print("[!] WARNING: High number of outbound connections detected!")

        if suspicious_connections:
            print("[!] WARNING: Connection to blacklisted IP(s) detected!")
            for ip in suspicious_connections:
                print(f"    -> {ip}")

        time.sleep(CHECK_INTERVAL)

def main():
    download_blacklist()
    thread = threading.Thread(target=check_connections)
    thread.start()

if __name__ == "__main__":
    main()
