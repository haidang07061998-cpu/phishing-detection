import json
import threading
import os
from datetime import datetime
from pathlib import Path

FEEDBACK_DIR = Path(__file__).resolve().parents[1] / "data" / "feedback"
_feedback_lock = threading.Lock()


def _ensure_dir():
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)


def _today_path() -> Path:
    return FEEDBACK_DIR / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"


def submit_feedback(url: str, feedback_type: str, actual_verdict: str, predicted_verdict: str,
                    score: float, comment: str = "", metadata: dict | None = None) -> dict:
    if feedback_type not in ("false_positive", "false_negative", "correct"):
        return {"error": "feedback_type must be false_positive, false_negative, or correct"}
    _ensure_dir()
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "url": url,
        "feedback_type": feedback_type,
        "actual_verdict": actual_verdict,
        "predicted_verdict": predicted_verdict,
        "score": score,
        "comment": comment,
        "metadata": metadata or {},
    }
    with _feedback_lock:
        with open(_today_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return {"status": "ok", "entry": entry}


def get_feedback_stats() -> dict:
    _ensure_dir()
    files = sorted(FEEDBACK_DIR.glob("*.jsonl"))
    total = {"false_positive": 0, "false_negative": 0, "correct": 0}
    for fp in files:
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        ft = entry.get("feedback_type", "")
                        if ft in total:
                            total[ft] += 1
                    except json.JSONDecodeError:
                        pass
    return total
