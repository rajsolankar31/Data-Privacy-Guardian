import os
import json
import datetime
from typing import List, Dict, Any

HISTORY_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
HISTORY_FILE = os.path.join(HISTORY_DIR, "scan_history.json")


def log_scan_event(
    source_name: str,
    source_type: str,
    total_findings: int,
    risk_score: float,
    status: str = "Completed"
) -> Dict[str, Any]:
    """
    Persists an auditable scan entry to the local scan history log.
    Enables tracking of recurring scans, privacy regression, and historical audits.
    """
    os.makedirs(HISTORY_DIR, exist_ok=True)
    
    event = {
        "scan_id": f"SCAN_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_name": source_name,
        "source_type": source_type,
        "total_findings": total_findings,
        "risk_score": round(risk_score, 1),
        "status": status
    }

    history = get_scan_history()
    history.insert(0, event) # Most recent first

    # Keep last 100 scans
    history = history[:100]

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    return event


def get_scan_history() -> List[Dict[str, Any]]:
    """Retrieves list of past scans from local audit log."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []
