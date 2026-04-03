from __future__ import annotations

from config import NETWORK_LOG_PATH, SYSTEM_LOG_PATH
from core.generate_logs import generate_synthetic_logs


if __name__ == "__main__":
    generate_synthetic_logs(str(SYSTEM_LOG_PATH), str(NETWORK_LOG_PATH), total_minutes=720, seed=42)
    print(f"Demo system logs written to: {SYSTEM_LOG_PATH}")
    print(f"Demo network logs written to: {NETWORK_LOG_PATH}")
