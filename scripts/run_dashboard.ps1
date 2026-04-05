param(
    [string]$PythonExe = "C:\Users\Ananya\AppData\Local\Programs\Python\Python313\python.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$pythonCode = @"
import os, sys
ROOT = r'c:\Users\Ananya\OneDrive\threat-intel\threat_intel_system'
sys.path.insert(0, ROOT)
os.chdir(ROOT)
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
from dashboard.app import app
print(f'''╔══════════════════════════════════════════╗
║   ThreatIntel AI  —  Dashboard           ║
║   http://localhost:{FLASK_PORT}                ║
║   Press Ctrl+C to stop                   ║
╚══════════════════════════════════════════╝''')
app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, use_reloader=False)
"@

& $PythonExe -c $pythonCode