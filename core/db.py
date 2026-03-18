import sqlite3
import os
import csv
from datetime import datetime
from core.ip_tracer import geolocate_ip  # type: ignore

# Initialize database in the root of the project
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'mini_soc.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Alerts Table: Stores threats detected by different modules
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            module TEXT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            source_ip TEXT,
            geo_country TEXT,
            geo_city TEXT,
            geo_isp TEXT,
            geo_lat REAL,
            geo_lon REAL
        )
    ''')

    # Migration: add geo columns to existing databases that pre-date this feature
    geo_columns = [
        ('source_ip',   'TEXT'),
        ('geo_country', 'TEXT'),
        ('geo_city',    'TEXT'),
        ('geo_isp',     'TEXT'),
        ('geo_lat',     'REAL'),
        ('geo_lon',     'REAL'),
    ]
    existing = {row[1] for row in c.execute("PRAGMA table_info(alerts)").fetchall()}
    for col_name, col_type in geo_columns:
        if col_name not in existing:
            c.execute(f'ALTER TABLE alerts ADD COLUMN {col_name} {col_type}')
    
    # FIM Baselines Table: Stores the core hash of monitored files
    c.execute('''
        CREATE TABLE IF NOT EXISTS fim_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            file_hash TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def log_alert(module, alert_type, severity, description, source_ip=None):
    """Log an alert into the database, enrich with geo data, and push a Windows notification."""
    # Geolocate the source IP if provided
    geo = geolocate_ip(source_ip) if source_ip else None

    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (module, alert_type, severity, description,
                            source_ip, geo_country, geo_city, geo_isp, geo_lat, geo_lon)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        module, alert_type, severity, description,
        source_ip,
        geo['country'] if geo else None,
        geo['city']    if geo else None,
        geo['isp']     if geo else None,
        geo['lat']     if geo else None,
        geo['lon']     if geo else None,
    ))
    conn.commit()
    conn.close()

    # Trigger Live Alarm system for all threats
    if severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        try:
            import winsound
            from plyer import notification  # type: ignore
            
            # Play loud standard Windows error sound
            winsound.MessageBeep(winsound.MB_ICONHAND)  # type: ignore
            
            # Slide-in visual Windows notification
            notification.notify(
                title=f"SOC ALERT: {severity}",
                message=f"[{module}] {alert_type}\n{description}",
                app_name="Mini SOC Security Engine",
                timeout=10
            )
        except Exception as e:
            print(f"[!] Alert notification failed: {e}")

def get_recent_alerts(limit=50):
    """Fetch recent alerts for the dashboard."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

import pandas as pd  # type: ignore

def get_alert_stats():
    """Fetch summary stats for visualizations."""
    conn = get_connection()
    try:
        df = pd.read_sql_query("SELECT module, severity FROM alerts", conn)
    except Exception:
        conn.close()
        return {'modules': {}, 'severities': {}}
        
    conn.close()
    
    if df.empty:
        return {'modules': {}, 'severities': {}}
        
    module_stats = df['module'].value_counts().to_dict()
    severity_stats = df['severity'].value_counts().to_dict()
    
    return {
        'modules': module_stats,
        'severities': severity_stats
    }

def export_alerts_to_csv():
    """Export the alerts database to a CSV file."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = c.fetchall()
    
    export_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'alerts_export.csv')
    with open(export_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Timestamp', 'Module', 'Alert Type', 'Severity', 'Description'])
        for row in rows:
            writer.writerow(row)
            
    conn.close()
    return export_path

if __name__ == '__main__':
    init_db()
    print(f"Database initialized at {DB_PATH}")
