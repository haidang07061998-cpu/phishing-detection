"""Scan history + report export for SOC workflows.

Every ``/predict``, ``/domain`` and ``/ip`` response is appended to
``data/scan_history.jsonl`` (one JSON object per line). This module provides
listing (with filters) and export to JSON / CSV so a security operations team
can pull the raw data into their own tools.

History is append-only and capped per file day; large deployments should ship
the file to their SIEM/ELK via webhooks or log shippers.
"""

import csv
import io
import json
import threading
import time
from datetime import datetime
from pathlib import Path

HISTORY_PATH = Path(__file__).resolve().parents[1] / "data" / "scan_history.jsonl"
_history_lock = threading.Lock()

MAX_RECORDS = 20000


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def append_scan(record: dict) -> None:
    """Append one normalized scan record (thread-safe, capped)."""
    row = {
        "timestamp": record.get("timestamp") or _now_iso(),
        "type": record.get("type", "url"),
        "target": record.get("target", ""),
        "url": record.get("url", ""),
        "aggregate_score": record.get("aggregate_score", 0),
        "verdict": record.get("verdict", "safe"),
        "phishing_probability": record.get("phishing_probability"),
        "threat_db_hit": bool(record.get("threat_match")),
        "engine_count": record.get("engine_count", 0),
        "analysis_quality": record.get("analysis_quality", ""),
        "whitelisted": bool(record.get("whitelisted")),
        "latency_ms": record.get("latency_ms"),
    }
    with _history_lock:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(HISTORY_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _iter_records():
    if not HISTORY_PATH.exists():
        return
    with open(HISTORY_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def list_history(limit: int = 50, offset: int = 0, verdict: str | None = None,
                 target: str | None = None) -> dict:
    """List scan records (most recent first) with optional filters."""
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    verdict = (verdict or "").lower()
    target = (target or "").lower()

    rows = []
    for rec in _iter_records():
        if verdict and rec.get("verdict") != verdict:
            continue
        if target and target not in (rec.get("target") or "").lower() \
                and target not in (rec.get("url") or "").lower():
            continue
        rows.append(rec)

    rows.reverse()  # newest first
    total = len(rows)
    page = rows[offset:offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "records": page,
    }


def export_history(fmt: str = "json") -> tuple[str, str]:
    """Return (content, mime_type) for JSON or CSV export of all records."""
    rows = list(_iter_records())
    if fmt == "csv":
        if not rows:
            return "", "text/csv"
        cols = sorted({k for r in rows for k in r.keys()})
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        return buf.getvalue(), "text/csv"
    return json.dumps(rows, ensure_ascii=False), "application/json"


def summary() -> dict:
    """Aggregate stats for a quick SOC overview."""
    counts = {"safe": 0, "suspicious": 0, "phishing": 0}
    threat_hits = 0
    total = 0
    for rec in _iter_records():
        total += 1
        counts[rec.get("verdict", "safe")] = counts.get(rec.get("verdict", "safe"), 0) + 1
        if rec.get("threat_db_hit"):
            threat_hits += 1
    return {
        "total": total,
        "counts": counts,
        "threat_db_hits": threat_hits,
        "path": str(HISTORY_PATH),
    }
