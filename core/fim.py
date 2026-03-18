import os
import time
import hashlib
from core.db import get_connection, log_alert  # type: ignore

from config import FIM_DIRECTORY  # type: ignore
TEST_DIR = FIM_DIRECTORY

def get_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        # File might be deleted mid-scan, or permission denied
        return None

def scan_directory():
    """Scan the TEST_DIR and compare against baselines stored in SQLite."""
    os.makedirs(TEST_DIR, exist_ok=True)
    
    conn = get_connection()
    c = conn.cursor()
    
    # Get current baselines
    c.execute("SELECT file_path, file_hash FROM fim_baselines")
    baselines = {row['file_path']: row['file_hash'] for row in c.fetchall()}
    
    # Get current files on disk
    current_files = {}
    for root, _, files in os.walk(TEST_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            filehash = get_file_hash(filepath)
            if filehash:
                current_files[filepath] = filehash
            
    # Check for modifications & additions
    for filepath, filehash in current_files.items():
        if filepath not in baselines:
            # New File
            log_alert('FIM', 'File Created', 'LOW', f"New file added: {os.path.basename(filepath)}")
            c.execute("INSERT INTO fim_baselines (file_path, file_hash) VALUES (?, ?)", (filepath, filehash))
        elif baselines[filepath] != filehash:
            # Modified File
            log_alert('FIM', 'File Modified', 'HIGH', f"File modified: {os.path.basename(filepath)}")
            c.execute("UPDATE fim_baselines SET file_hash = ?, last_updated = CURRENT_TIMESTAMP WHERE file_path = ?", (filehash, filepath))
            
    # Check for deletions
    for filepath in baselines.keys():
        if filepath not in current_files:
            log_alert('FIM', 'File Deleted', 'MEDIUM', f"File deleted: {os.path.basename(filepath)}")
            c.execute("DELETE FROM fim_baselines WHERE file_path = ?", (filepath,))
            
    conn.commit()
    conn.close()

def start_fim_monitor(interval=10):
    """Run the directory scan periodically."""
    print(f"[*] Starting File Integrity Monitor -> {TEST_DIR}")
    while True:
        scan_directory()
        time.sleep(interval)

import threading
def run_fim_monitor_background():
    """Starts FIM monitor in a background thread."""
    t = threading.Thread(target=start_fim_monitor, daemon=True)
    t.start()
