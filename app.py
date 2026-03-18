import os
import threading
from flask import Flask, render_template, jsonify, send_file  # type: ignore
from core.db import init_db, get_recent_alerts, get_alert_stats, export_alerts_to_csv  # type: ignore
from core.dummy_log_generator import run_generator  # type: ignore
from core.fim import start_fim_monitor  # type: ignore
from core.log_parser import start_log_monitor  # type: ignore
from core.network_monitor import start_network_monitor  # type: ignore

app = Flask(__name__)

def start_background_services():
    """Initializes the DB and starts all monitoring modules in background threads."""
    print("[*] Initializing Mini SOC Services...")
    init_db()
    
    from config import USE_DUMMY_DATA  # type: ignore
    if USE_DUMMY_DATA:
        # Start Dummy Log Generator (simulates active auth traffic)
        threading.Thread(target=run_generator, args=(3,), daemon=True).start()
    else:
        print("[*] Running in Production Mode (No fake logs generated)")
    
    # Start File Integrity Monitor (scans every 5 seconds)
    threading.Thread(target=start_fim_monitor, args=(5,), daemon=True).start()
    
    # Start Log Parser
    threading.Thread(target=start_log_monitor, daemon=True).start()
    
    # Start Network Monitor (scans ports every 10 seconds)
    threading.Thread(target=start_network_monitor, args=(10,), daemon=True).start()

# Prevent threads from starting twice in Flask debug mode
if not os.environ.get('WERKZEUG_RUN_MAIN'):
    start_background_services()

@app.route('/')
def index():
    """Render the main SOC dashboard."""
    return render_template('index.html')

@app.route('/api/alerts')
def api_alerts():
    """JSON endpoint for recent alerts."""
    return jsonify(get_recent_alerts())

@app.route('/api/stats')
def api_stats():
    """JSON endpoint for dashboard visualization stats."""
    return jsonify(get_alert_stats())

@app.route('/api/export')
def api_export():
    """Endpoint to export DB to CSV and download it."""
    csv_path = export_alerts_to_csv()
    return send_file(csv_path, as_attachment=True)

if __name__ == '__main__':
    # Start the Flask web server
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
