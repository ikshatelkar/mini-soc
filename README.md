# 🛡️ Mini SOC (Security Operations Center)

A lightweight, locally-hosted Security Information and Event Management (SIEM) engine built entirely in Python. This project dynamically builds its own local environment, monitors the host machine for active cyber threats, logs attacks to a centralized database, and surfaces them to a beautiful real-time web dashboard.

---

## 🚀 Core Detection Modules

### 1. File Integrity Monitor (FIM)
The FIM module actively protects designated directories against ransomware and unauthorized tampering. 
* **How it works:** It calculates and caches the secure **SHA-256 cryptographic hash** of every file in the directory. 
* **What it catches:** If a file is silently modified, created, or deleted, the hash breaks, and the module immediately alerts the system of potential tampering.

### 2. Network Anomaly Detection
Malware and hackers frequently open hidden "bind shells" or backdoor ports to maintain remote access to a compromised machine.
* **How it works:** Every 10 seconds, this module aggressively sweeps the local network interfaces.
* **What it catches:** It flags unauthorized "Suspicious Ports" known to be used by attackers (such as Port `4444`, `1337`, `31337`, or `6667`).

### 3. Real-Time Log Parsing
The log parser acts exactly like an enterprise SIEM (like Splunk), designed to read server text logs (e.g., OpenSSH auth logs or IIS web logs) line-by-line as they are written.
* **How it works:** It uses Regular Expressions to parse the live text stream and tracks access patterns in memory.
* **What it catches:**
  * **Brute Force Attacks (CRITICAL):** Flags when the same IP fails to login 5 times within a 5-minute window.
  * **Unusual Access Times (MEDIUM):** Flags when a successful login occurs drastically outside normal business hours (e.g., between 10 PM and 6 AM).

---

## 🚨 Live Notification Engine
This SOC does not just passively log data—it actively grabs the user's attention.
All detection modules feed into a centralized `log_alert` database function. This central hub is wired directly into the native Windows OS. 
If an event triggers across **any** module, the system immediately bypasses the web dashboard to trigger a loud, audible **Windows Error Alarm** combined with a visual **Desktop Push Notification** containing the exact attack details.

---

## 📊 The Central Command Dashboard
The project leverages a **Flask** web server to host a real-time command center interface.
* **Database:** All localized alerts and baseline file hashes are stored in a lightweight `mini_soc.db` SQLite database.
* **Frontend:** The frontend UI is built using HTML, CSS, and Vanilla JavaScript. It uses `Chart.js` to render live threat analytics.
* **Polling:** The web browser automatically polls the Flask API router every 3 seconds to ensure the human operator is always viewing a real-time, up-to-the-second layout of the battlefield.

---

## 💻 Deployment & Productization
The entire raw Python source code can be cleanly aggregated and compiled into a single, zero-dependency `MiniSOC.exe` payload using **PyInstaller**. 
When this 36 MB executable is double-clicked on any new Windows machine, it dynamically unpacks its own HTML templates, generates a fresh tracking database, and begins actively monitoring the local host instantly—requiring absolutely zero software installation or terminal configuration from the end user.
