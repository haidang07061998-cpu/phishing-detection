import json
import threading
import os
from datetime import datetime
from pathlib import Path

FEEDBACK_DIR = Path(__file__).resolve().parents[1] / "data" / "feedback"
_feedback_lock = threading.Lock()

VALID_TYPES = ("false_positive", "false_negative", "correct")
MAX_URL_LEN = 2048
MAX_VERDICT_LEN = 32
MAX_COMMENT_LEN = 2000
MAX_METADATA_JSON = 8192


def _ensure_dir():
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)


def _today_path() -> Path:
    return FEEDBACK_DIR / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"


def _validate(feedback_type, url, actual_verdict, predicted_verdict, score, comment, metadata) -> str | None:
    if feedback_type not in VALID_TYPES:
        return "feedback_type must be false_positive, false_negative, or correct"
    if not isinstance(url, str) or not url.strip():
        return "url must be a non-empty string"
    if len(url) > MAX_URL_LEN:
        return f"url too long (max {MAX_URL_LEN} characters)"
    if actual_verdict is not None and not isinstance(actual_verdict, str):
        return "actual_verdict must be a string"
    if predicted_verdict is not None and not isinstance(predicted_verdict, str):
        return "predicted_verdict must be a string"
    if actual_verdict and len(actual_verdict) > MAX_VERDICT_LEN:
        return f"actual_verdict too long (max {MAX_VERDICT_LEN} characters)"
    if predicted_verdict and len(predicted_verdict) > MAX_VERDICT_LEN:
        return f"predicted_verdict too long (max {MAX_VERDICT_LEN} characters)"
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return "score must be a number"
    if not (-1.0 <= float(score) <= 100.0):
        return "score must be between 0 and 100 (or -1 for unknown)"
    if not isinstance(comment, str):
        return "comment must be a string"
    if len(comment) > MAX_COMMENT_LEN:
        return f"comment too long (max {MAX_COMMENT_LEN} characters)"
    if metadata is not None:
        if not isinstance(metadata, dict):
            return "metadata must be an object"
        if len(json.dumps(metadata)) > MAX_METADATA_JSON:
            return "metadata too large"
    return None


def submit_feedback(url: str, feedback_type: str, actual_verdict: str, predicted_verdict: str,
                    score: float, comment: str = "", metadata: dict | None = None) -> dict:
    err = _validate(feedback_type, url, actual_verdict, predicted_verdict, score, comment, metadata)
    if err:
        return {"error": err}
    _ensure_dir()
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "url": url,
        "feedback_type": feedback_type,
        "actual_verdict": actual_verdict,
        "predicted_verdict": predicted_verdict,
        "score": float(score),
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
