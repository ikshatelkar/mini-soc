import socket
import time
import threading
from core.db import log_alert  # type: ignore

# List of commonly abused ports (e.g., for bind shells, malware, backdoors)
SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    1337: "Common bind shell port",
    31337: "Back Orifice",
    6667: "IRC (potentially botnet C2)",
}

# Track currently open suspicious ports to avoid spamming the log
alerted_ports = set()

def scan_ports_statefully():
    """Scan local network interfaces for suspicious open ports using socket."""
    global alerted_ports
    current_open = set()
    
    for port, description in SUSPICIOUS_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        # Check localhost
        result = sock.connect_ex(('127.0.0.1', port))
        if result == 0:
            current_open.add(port)
            if port not in alerted_ports:
                msg = f"Suspicious port {port} is OPEN: {description}"
                log_alert('NETWORK', 'Suspicious Port Open', 'HIGH', msg)
                alerted_ports.add(port)
        sock.close()
        
    # Detect if a previously open port has been closed
    closed_ports = alerted_ports - current_open
    for p in closed_ports:
        log_alert('NETWORK', 'Suspicious Port Closed', 'INFO', f"Suspicious port {p} is now closed.")
        
    alerted_ports = current_open

def start_network_monitor(interval=15):
    """Run the port scan periodically."""
    print("[*] Starting Network Port Monitor")
    while True:
        scan_ports_statefully()
        time.sleep(interval)

def run_network_monitor_background():
    """Starts the network monitor in a background thread."""
    t = threading.Thread(target=start_network_monitor, daemon=True)
    t.start()
