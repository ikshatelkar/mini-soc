import os
import time
import random
from datetime import datetime
import threading

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'dummy_auth.log')

USERS = ['root', 'admin', 'user1', 'guest', 'ubuntu', 'pi', 'test']

# Realistic public IPs from common attack-origin countries for mapping
IPS = [
    '185.220.101.34',   # Russia (Tor exit node range)
    '103.75.190.12',    # China
    '177.54.144.79',    # Brazil
    '91.108.56.200',    # Germany
    '185.117.75.218',   # Iran
    '175.45.176.11',    # North Korea range
    '45.33.32.156',     # USA (Linode)
    '104.244.72.115',   # USA (Twitter range - simulates compromised infra)
]

def generate_log_entry():
    """Generates synthetic auth.log entries with occasional attacks."""
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    user = random.choice(USERS)
    ip = random.choice(IPS)
    
    # Determine the event type
    # 70% normal success, 20% random failures, 5% brute force, 5% unusual hours login
    event_type = random.choices(
        ['success', 'failed', 'brute_force', 'unusual_hours'], 
        weights=[0.7, 0.2, 0.05, 0.05]
    )[0]
    
    lines = []
    if event_type == 'success':
        lines.append(f"{timestamp} server sshd[1234]: Accepted password for {user} from {ip} port 50000 ssh2")
    elif event_type == 'failed':
        lines.append(f"{timestamp} server sshd[1234]: Failed password for {user} from {ip} port 50000 ssh2")
    elif event_type == 'brute_force':
        attacker_ip = '198.51.100.99' # specific attacker IP
        # Generate 6 rapid failures
        for _ in range(6):
            lines.append(f"{timestamp} server sshd[1234]: Failed password for admin from {attacker_ip} port 50000 ssh2")
    elif event_type == 'unusual_hours':
        # Force a 3 AM login timestamp
        ts_unusual = datetime.now().replace(hour=3, minute=random.randint(0, 59)).strftime('%b %d %H:%M:%S')
        attacker_ip = '203.0.113.42'
        lines.append(f"{ts_unusual} server sshd[1234]: Accepted password for root from {attacker_ip} port 50000 ssh2")
            
    with open(LOG_FILE, 'a') as f:
        for line in lines:
            f.write(line + '\n')

def run_generator(interval=5):
    """Run log generation continuously."""
    print(f"[*] Starting Dummy Log Generator -> {LOG_FILE}")
    while True:
        generate_log_entry()
        time.sleep(random.randint(1, interval))

def start_background_generator():
    """Starts the generator in a background daemon thread."""
    t = threading.Thread(target=run_generator, daemon=True)
    t.start()

if __name__ == '__main__':
    try:
        run_generator()
    except KeyboardInterrupt:
        print("\n[*] Stopped generator.")
