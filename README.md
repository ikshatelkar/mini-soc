# 🛡️ Mini SOC (Security Operations Center)

A lightweight Security Information and Event Management (SIEM) engine built entirely in Python. It monitors a host machine for active cyber threats, logs attacks to a centralized database, and surfaces them to a real-time, authenticated web dashboard. It can run **standalone** on a single machine, or split into a central **server** plus lightweight **agents** that forward raw events from other hosts for centralized detection and triage.

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

### 3. Real-Time Log Parsing & Windows Event Collection
The log parser acts exactly like an enterprise SIEM (like Splunk), designed to read server text logs (e.g., OpenSSH auth logs) line-by-line as they are written. Alongside it, a native Windows Event Log collector tails the Security and System channels directly, with durable checkpoints so a restart never re-processes or skips events.
* **How it works:** Collected events are matched against a declarative rule engine (`core/ruleengine.py`) loaded from YAML rule files in `rules/`, covering authentication logs, the filesystem, the network, and Windows Event Logs, each mapped to a MITRE ATT&CK technique. Rules are isolated from each other, so one bad rule can't take detection down.
* **What it catches:** Brute-force logins, suspicious account/privilege activity, unusual access times, and other patterns defined per-rule — editable and reloadable from the dashboard without restarting the service.

### 4. IP Geolocation Tracer
Every detected threat is automatically enriched with physical location data in real-time.
* **How it works:** When a remote IP is flagged (e.g., by a brute-force attempt), the SOC performs a background traceback using the `ip-api` service.
* **What it provides:**
  * **Visual Mapping:** Pins the attacker's location on an interactive global dashboard map.
  * **Metadata Enrichment:** Captures the attacker's country, city, and ISP (Internet Service Provider).

---

## 🚨 Live Notification Engine
This SOC does not just passively log data—it actively grabs the user's attention, while guarding against alert fatigue.
All detection modules feed into a centralized alert pipeline with deduplication, a severity floor, and a hard per-minute rate cap, so repeated or low-value noise never floods the operator. Anything suppressed is still counted and visible on `/api/health`.
* **Desktop alerts:** When running as a Windows service, a separate `notifier.py` companion process (services can't draw UI themselves) polls the dashboard and surfaces a combined desktop popup for anything crossing the notify threshold.
* **Email alerts:** Critical events can additionally trigger immediate emails, with lower-severity activity batched into digests, via `core/email_alerts.py`.

---

## 📊 The Central Command Dashboard
The project leverages a **Flask** web server to host a real-time command center interface, protected by a single-admin login (CSRF-protected forms, hardened session cookies, one active session per account).
* **Database:** All localized alerts, baseline file hashes, enrolled agents, and geolocation data are stored in a lightweight `mini_soc.db` SQLite database.
* **Frontend:** A collapsible sidebar (grouped into Overview/Triage/Operations/Utilities with live badge counts) replaces a flat top-nav, with dedicated pages for Home, an Activity Log (worst-severity-first, last 24h), full Alerts history with filters, a standalone Threat Map, and Employees (per-computer alert attribution). Built with HTML, CSS, and Vanilla JavaScript, using `Chart.js` for analytics and `Plotly` for the attacker world map.
* **Polling:** The web browser automatically polls the Flask API router every 3 seconds to ensure the human operator is always viewing a real-time, up-to-the-second layout of the battlefield.

---

## 💻 Deployment & Productization
Mini SOC runs in one of three roles, set via `DEPLOYMENT_ROLE` in `config.py`:
* **`standalone`** (default): collectors, rule engine, storage, and dashboard all in one process — today's single-host behavior.
* **`server`**: runs the dashboard, rule engine, and storage, and additionally accepts events forwarded by enrolled agents over a bearer-token-authenticated `/api/ingest` endpoint. Agents are enrolled and revoked directly from the dashboard.
* **`agent`**: runs only the collectors (file integrity, log parsing, network, Windows Event Logs) via `agent.py` and forwards raw events to the server — it never loads rules, runs detection, or stores alerts locally, so a compromised worker can't learn what it's being watched for. Events are buffered to a hash-chained local file first, so a network outage loses nothing.

For long-running deployments, `service.py` (with `service_install.bat` / `service_uninstall.bat`) installs Mini SOC as a native Windows service; since services can't draw UI, desktop popups are handled by the separate `notifier.py` companion running in the user's own session.
