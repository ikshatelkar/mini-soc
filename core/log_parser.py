import os
import time
import re
import threading
from datetime import datetime, timedelta
from core.db import log_alert  # type: ignore

from config import LOG_FILE_PATH  # type: ignore
LOG_FILE = LOG_FILE_PATH

# Dictionary to track failed attempts: { 'ip': [timestamp1, timestamp2, ...] }
failed_attempts = {}

def parse_log_line(line):
    """Parse a single auth.log line for brute force or unusual access."""
    # Regex for capturing Timestamp, Status, User, IP
    # Matches formats like: "Mar 18 15:17:00 server sshd[1234]: Failed password for admin from 198.51.100.99 port 50000 ssh2"
    match = re.search(r'([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*(Failed|Accepted)\s+password\s+for\s+(\S+)\s+from\s+([0-9\.]+)', line)
    
    if not match:
        return
        
    log_time_str = match.group(1)
    status = match.group(2)
    user = match.group(3)
    ip = match.group(4)
    
    # Assuming the log is for the current year
    current_year = datetime.now().year
    try:
        log_time = datetime.strptime(f"{current_year} {log_time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return
        
    now = datetime.now()
    
    if status == 'Failed':
        if ip not in failed_attempts:
            failed_attempts[ip] = []
        failed_attempts[ip].append(now)
        
        # Keep only attempts within the last 5 minutes
        failed_attempts[ip] = [dt for dt in failed_attempts[ip] if now - dt <= timedelta(minutes=5)]
        
        # Detect Brute Force (>5 attempts in 5 minutes)
        if len(failed_attempts[ip]) >= 5:
            description = f"Brute force detected from {ip} targeting {user} ({len(failed_attempts[ip])} fails)"
            log_alert('LOG_MONITOR', 'Brute Force Attack', 'CRITICAL', description)
            # Clear IP to prevent duplicate alerts for the same burst
            failed_attempts[ip] = []
            
    elif status == 'Accepted':
        # Detect Unusual Access Hours (Outside 6 AM to 10 PM)
        hour = log_time.hour
        if hour < 6 or hour >= 22:
            description = f"Unusual access time ({hour:02d}:00) by {user} from {ip}"
            log_alert('LOG_MONITOR', 'Unusual Access', 'MEDIUM', description)

def start_log_monitor():
    """Tails the log file continuously and parses new entries."""
    if not os.path.exists(LOG_FILE):
        # Create an empty template file if it's missing to avoid crashing
        open(LOG_FILE, 'a').close()
        
    print(f"[*] Starting Log Monitor -> {LOG_FILE}")
    with open(LOG_FILE, 'r') as f:
        # Move pointer to the end of the file when starting
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            parse_log_line(line.strip())

def run_log_monitor_background():
    """Starts the log tailer in a background daemon thread."""
    t = threading.Thread(target=start_log_monitor, daemon=True)
    t.start()
