import json
import threading
import urllib.request
import urllib.error
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "data" / "webhook_config.json"
_config_lock = threading.Lock()


def load_config() -> dict:
    with _config_lock:
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}


def save_config(cfg: dict) -> None:
    with _config_lock:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def set_webhook(url: str, events: list[str] | None = None) -> dict:
    if events is None:
        events = ["scan.completed"]
    cfg = load_config()
    cfg["url"] = url
    cfg["events"] = events
    cfg["enabled"] = True
    save_config(cfg)
    return {"status": "ok", "config": cfg}


def delete_webhook() -> dict:
    cfg = load_config()
    if cfg:
        cfg["enabled"] = False
        save_config(cfg)
    return {"status": "ok"}


def get_webhook() -> dict:
    cfg = load_config()
    return cfg if cfg else {"enabled": False}


def dispatch(event: str, payload: dict) -> None:
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("url"):
        return
    if event not in cfg.get("events", []):
        return
    try:
        data = json.dumps({"event": event, "payload": payload}).encode("utf-8")
        req = urllib.request.Request(
            cfg["url"], data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass
