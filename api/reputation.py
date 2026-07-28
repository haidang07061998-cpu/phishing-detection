import json
import threading
from pathlib import Path
from datetime import datetime

REPUTATION_PATH = Path(__file__).resolve().parents[1] / "data" / "cache" / "reputation.json"
_reputation_lock = threading.Lock()


def load_reputation() -> dict:
    with _reputation_lock:
        if REPUTATION_PATH.exists():
            try:
                return json.loads(REPUTATION_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}


def save_reputation(repo: dict) -> None:
    with _reputation_lock:
        REPUTATION_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPUTATION_PATH.write_text(
            json.dumps(repo, indent=2, default=str), encoding="utf-8"
        )


def get_domain_reputation(domain: str) -> dict:
    repo = load_reputation()
    return repo.get(domain, {})


def update_domain_reputation(domain: str, score: float, verdict: str) -> None:
    if not domain:
        return
    repo = load_reputation()
    entry = repo.get(domain, {
        "first_seen": "", "last_seen": "", "scans": 0,
        "scores": [], "verdicts": [],
    })
    now = datetime.utcnow().isoformat()
    if not entry["first_seen"]:
        entry["first_seen"] = now
    entry["last_seen"] = now
    entry["scans"] += 1
    entry["scores"].append(round(score, 1))
    entry["verdicts"].append(verdict)
    entry["avg_score"] = round(sum(entry["scores"]) / len(entry["scores"]), 1)
    entry["phishing_rate"] = round(
        sum(1 for v in entry["verdicts"] if v == "phishing") / len(entry["verdicts"]), 3
    )
    repo[domain] = entry
    save_reputation(repo)
