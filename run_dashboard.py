"""
run_dashboard.py
Launches the Phase 2 Flask dashboard.

Usage:
  python run_dashboard.py

Open http://localhost:5000 in your browser.
Make sure you have run main.py at least once to generate alerts.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

# Point Flask to the dashboard package
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from dashboard.app import app

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════╗
║   ThreatIntel AI  —  Dashboard           ║
║   http://localhost:{FLASK_PORT}                ║
║   Press Ctrl+C to stop                   ║
╚══════════════════════════════════════════╝
""")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
