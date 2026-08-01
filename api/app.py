import json
import logging
import re
import ipaddress
import traceback
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

from api import config
from api.security import rate_limit, require_api_key, reject_oversized_html, _registry as _key_registry

# Fail fast in production: never boot an unauthenticated API when the operator
# forgot to configure keys (env keys or a pre-seeded runtime registry). Runs
# BEFORE the predictor loads, so a misconfigured deploy fails in seconds
# instead of after model weights are loaded into RAM.
config.ensure_production_auth(registry_count=len(_key_registry()))

from api.predictor import predictor
from api.feedback import submit_feedback, get_feedback_stats
from api.webhooks import set_webhook, delete_webhook, get_webhook, dispatch
from api.whitelist import get_all as _get_whitelist, add_dynamic as _add_whitelist, remove_dynamic as _remove_whitelist
from api.llm_explainer import explain as llm_explain
from src.security.url_safety import validate_url as _validate_url_safety

app = Flask(__name__)
CORS(app, origins=config.ALLOWED_ORIGINS or ["http://localhost:3000"])
app.config["MAX_CONTENT_LENGTH"] = config.MAX_JSON_BYTES

# Trust X-Forwarded-For only when explicitly running behind a reverse proxy.
# werkzeug's ProxyFix rewrites request.remote_addr from the header AFTER
# verifying the immediate peer is the trusted proxy (based on TRUST_PROXY hop
# count). Without this, _client_ip() uses the raw TCP peer address, so clients
# cannot spoof their identity to bypass rate limiting or the IP allowlist.
if config.TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.TRUST_PROXY, x_proto=config.TRUST_PROXY)

MAX_BATCH_SIZE = 50

_logger = logging.getLogger(__name__)


@app.errorhandler(413)
def _payload_too_large(_e):
    return jsonify({"error": f"Request body too large (max {config.MAX_JSON_BYTES} bytes)."}), 413


@app.errorhandler(400)
def _bad_request(e):
    return jsonify({"error": e.description or "Bad request."}), 400


@app.errorhandler(401)
def _unauthorized(_e):
    return jsonify({"error": "Authentication required."}), 401


@app.errorhandler(429)
def _too_many_requests(e):
    return jsonify({"error": e.description or "Rate limit exceeded."}), 429


@app.errorhandler(Exception)
def _unhandled(e):
    # Never leak internal exception text to clients — log it server-side instead.
    _logger.error("Unhandled error:\n%s", traceback.format_exc())
    return jsonify({"error": "Internal server error."}), 500


def validate_url(url: str) -> str | None:
    if not url or not url.strip():
        return "URL cannot be empty"
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parsed.netloc:
        return "Invalid URL: missing domain"
    safety = _validate_url_safety(url.strip())
    if not safety["valid"]:
        return f"URL rejected by safety policy: {safety['reason']}"
    return None


def validate_domain(domain: str) -> str | None:
    if not domain or not domain.strip():
        return "Domain cannot be empty"
    domain = domain.strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", domain):
        return "Invalid domain format (e.g. example.com)"
    return None


def validate_ip(ip: str) -> str | None:
    if not ip or not ip.strip():
        return "IP address cannot be empty"
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return "Invalid IP address format (e.g. 8.8.8.8)"
    return None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/metrics", methods=["GET"])
def metrics():
    """Evaluation metrics for the footer cards.

    Reads data/models/evaluation_results.json (written by
    src/evaluation/evaluate.py). Falls back to empty metrics so the frontend
    can render its built-in defaults when no evaluation has been run yet.
    """
    from pathlib import Path
    results_path = Path(__file__).resolve().parents[1] / "data" / "models" / "evaluation_results.json"
    try:
        if not results_path.exists():
            return jsonify({"models": []})
        return jsonify({"models": json.loads(results_path.read_text(encoding="utf-8"))})
    except Exception as e:
        _logger.error("metrics read failed: %s", traceback.format_exc())
        return jsonify({"models": []})

@app.route("/health/llm", methods=["GET"])
def health_llm():
    from api.llm_explainer import is_ollama_available
    return jsonify({
        "available": is_ollama_available(),
        "provider": "ollama",
        "model": "llama3.2:3b",
    })


@app.route("/predict", methods=["POST"])
@reject_oversized_html
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="scan")
def predict():
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data["url"].strip()
    err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    html_content = data.get("html", None)

    # explain=false skips the per-request backward pass (feature importance).
    # Defaults to the PHISHGUARD_COMPUTE_IMPORTANCE config.
    explain = data.get("explain", None)

    try:
        result = predictor.predict(url, html_content, explain=explain)
        dispatch("scan.completed", {
            "url": url,
            "aggregate_score": result.get("aggregate_score"),
            "verdict": "phishing" if result.get("aggregate_score", 0) >= 60 else "suspicious" if result.get("aggregate_score", 0) >= 30 else "safe",
        })
        from api.history import append_scan
        append_scan({
            "timestamp": result.get("timestamp"),
            "type": "url",
            "target": url,
            "url": url,
            "aggregate_score": result.get("aggregate_score"),
            "verdict": "phishing" if result.get("aggregate_score", 0) >= 60 else "suspicious" if result.get("aggregate_score", 0) >= 30 else "safe",
            "phishing_probability": result.get("phishing_probability"),
            "threat_match": result.get("threat_match"),
            "engine_count": result.get("engine_count"),
            "analysis_quality": result.get("analysis_quality"),
            "whitelisted": result.get("whitelisted"),
            "latency_ms": result.get("latency_ms"),
        })
        return jsonify(result)
    except Exception as e:
        _logger.error("predict failed for %r: %s", url, traceback.format_exc())
        return jsonify({"error": "Prediction failed."}), 500


@app.route("/predict/batch", methods=["POST"])
@rate_limit(minute=config.RATE_MIN // 2 or 1, hour=config.RATE_HOUR // 2 or 1)
@require_api_key(scope="scan")
def predict_batch():
    data = request.get_json(force=True)
    if not data or "urls" not in data:
        return jsonify({"error": "Missing 'urls' in request body"}), 400

    urls = data["urls"]
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "'urls' must be a non-empty list"}), 400
    if len(urls) > MAX_BATCH_SIZE:
        return jsonify({"error": f"Batch size cannot exceed {MAX_BATCH_SIZE}"}), 400

    results = []
    urls = [u.strip() for u in urls]
    if config.BATCH_WORKERS > 1 and len(urls) > 1:
        # Parallel extraction (DNS/SSL I/O releases the GIL); model inference is
        # serialized inside predictor via _inference_lock, so CPU-bound forward
        # passes never overlap across threads.
        from concurrent.futures import ThreadPoolExecutor

        def _run(u):
            try:
                return predictor.predict(u)
            except Exception:
                # Never leak exception text to clients — log it server-side.
                _logger.error("batch predict failed for %r: %s", u, traceback.format_exc())
                return {"url": u, "error": "Prediction failed."}

        with ThreadPoolExecutor(max_workers=config.BATCH_WORKERS) as pool:
            results = list(pool.map(_run, urls))
    else:
        for url in urls:
            try:
                results.append(predictor.predict(url))
            except Exception:
                _logger.error("batch predict failed for %r: %s", url, traceback.format_exc())
                results.append({"url": url, "error": "Prediction failed."})

    for r in results:
        if "error" not in r:
            dispatch("scan.completed", {
                "url": r.get("url", ""),
                "aggregate_score": r.get("aggregate_score"),
                "verdict": "phishing" if r.get("aggregate_score", 0) >= 60 else "suspicious" if r.get("aggregate_score", 0) >= 30 else "safe",
            })

    return jsonify({"results": results, "count": len(results)})


@app.route("/domain", methods=["POST"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="scan")
def domain_lookup():
    data = request.get_json(force=True)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request body"}), 400

    domain = data["domain"].strip().lower()
    err = validate_domain(domain)
    if err:
        return jsonify({"error": err}), 400

    try:
        result = predictor.lookup_domain(domain)
        from api.history import append_scan
        append_scan({
            "timestamp": result.get("timestamp"),
            "type": "domain",
            "target": domain,
            "aggregate_score": result.get("aggregate_score"),
            "verdict": "phishing" if result.get("aggregate_score", 0) >= 60 else "suspicious" if result.get("aggregate_score", 0) >= 30 else "safe",
            "engine_count": result.get("engine_count"),
            "latency_ms": result.get("latency_ms"),
        })
        return jsonify(result)
    except Exception as e:
        _logger.error("domain lookup failed for %r: %s", domain, traceback.format_exc())
        return jsonify({"error": "Domain lookup failed."}), 500


@app.route("/ip", methods=["POST"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="scan")
def ip_lookup():
    data = request.get_json(force=True)
    if not data or "ip" not in data:
        return jsonify({"error": "Missing 'ip' in request body"}), 400

    ip = data["ip"].strip()
    err = validate_ip(ip)
    if err:
        return jsonify({"error": err}), 400

    try:
        result = predictor.lookup_ip(ip)
        from api.history import append_scan
        append_scan({
            "timestamp": result.get("timestamp"),
            "type": "ip",
            "target": ip,
            "aggregate_score": result.get("aggregate_score"),
            "verdict": "phishing" if result.get("aggregate_score", 0) >= 60 else "suspicious" if result.get("aggregate_score", 0) >= 30 else "safe",
            "engine_count": result.get("engine_count"),
            "latency_ms": result.get("latency_ms"),
        })
        return jsonify(result)
    except Exception as e:
        _logger.error("ip lookup failed for %r: %s", ip, traceback.format_exc())
        return jsonify({"error": "IP lookup failed."}), 500


@app.route("/feedback", methods=["POST"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="feedback")
def feedback():
    data = request.get_json(force=True)
    if not data or "url" not in data or "feedback_type" not in data:
        return jsonify({"error": "Missing 'url' and 'feedback_type' in request body"}), 400
    result = submit_feedback(
        url=data["url"],
        feedback_type=data["feedback_type"],
        actual_verdict=data.get("actual_verdict", ""),
        predicted_verdict=data.get("predicted_verdict", ""),
        score=data.get("score", 0),
        comment=data.get("comment", ""),
        metadata=data.get("metadata"),
    )
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route("/feedback/stats", methods=["GET"])
@require_api_key(scope="reports")
def feedback_stats():
    return jsonify(get_feedback_stats())


@app.route("/webhook", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key
def webhook_get():
    return jsonify(get_webhook())


@app.route("/webhook", methods=["POST", "DELETE"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="admin")
def webhook_manage():
    if request.method == "DELETE":
        return jsonify(delete_webhook())
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    result = set_webhook(data["url"], data.get("events"))
    if result.get("status") == "error":
        return jsonify(result), 400
    return jsonify(result)


@app.route("/whitelist", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
def whitelist_get():
    return jsonify(_get_whitelist())


@app.route("/whitelist", methods=["POST"])
@require_api_key(scope="admin")
def whitelist_add():
    data = request.get_json(force=True)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    domain = data["domain"].strip().lower()
    err = validate_domain(domain)
    if err:
        return jsonify({"error": err}), 400
    result = _add_whitelist(
        domain,
        added_by=data.get("added_by", "admin"),
        ttl_days=data.get("ttl_days", 30),
        reason=data.get("reason", ""),
    )
    return jsonify(result)


@app.route("/keys", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="admin")
def keys_list():
    from api.security import list_api_keys
    return jsonify(list_api_keys())


@app.route("/keys", methods=["POST"])
@require_api_key(scope="admin")
def keys_create():
    from api.security import create_api_key, SCOPES
    data = request.get_json(force=True) or {}
    scopes = data.get("scopes") or None
    if scopes is not None:
        if not isinstance(scopes, list) or not all(s in SCOPES for s in scopes):
            return jsonify({"error": f"scopes must be a subset of {list(SCOPES)}"}), 400
    expires = data.get("expires_at")
    try:
        expires = float(expires) if expires is not None else None
    except (TypeError, ValueError):
        return jsonify({"error": "expires_at must be a Unix timestamp"}), 400
    result = create_api_key(
        name=data.get("name", "unnamed"),
        scopes=scopes,
        expires_at=expires,
        ip_allowlist=data.get("ip_allowlist"),
        created_by=(getattr(request, "api_key", {}) or {}).get("name", "admin"),
    )
    return jsonify(result)


@app.route("/keys", methods=["DELETE"])
@require_api_key(scope="admin")
def keys_revoke():
    from api.security import revoke_api_key
    data = request.get_json(force=True) or {}
    if not data or "key_id" not in data:
        return jsonify({"error": "Missing 'key_id' in request body"}), 400
    return jsonify(revoke_api_key(data["key_id"], revoked_by=(getattr(request, "api_key", {}) or {}).get("name", "admin")))


@app.route("/threat", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
def threat_get():
    from api.threat_db import get_all, refresh_feed
    force = request.args.get("refresh", "0") == "1"
    if force:
        refresh_feed(force=True)
    return jsonify(get_all())


@app.route("/threat", methods=["POST"])
@require_api_key(scope="admin")
def threat_add():
    from api.threat_db import add_entry
    data = request.get_json(force=True)
    if not data or "value" not in data:
        return jsonify({"error": "Missing 'value' in request body"}), 400
    result = add_entry(
        value=data["value"],
        added_by=data.get("added_by", "admin"),
        source=data.get("source", "manual"),
        notes=data.get("notes", ""),
    )
    if result.get("status") == "error":
        return jsonify(result), 400
    return jsonify(result)


@app.route("/threat", methods=["DELETE"])
@require_api_key(scope="admin")
def threat_remove():
    from api.threat_db import remove_entry
    data = request.get_json(force=True)
    if not data or "value" not in data:
        return jsonify({"error": "Missing 'value' in request body"}), 400
    return jsonify(remove_entry(value=data["value"], removed_by=data.get("removed_by", "admin")))


@app.route("/whitelist", methods=["DELETE"])
@require_api_key(scope="admin")
def whitelist_remove():
    data = request.get_json(force=True)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    domain = data["domain"].strip().lower()
    err = validate_domain(domain)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(_remove_whitelist(domain, removed_by=data.get("removed_by", "admin")))


@app.route("/history", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="reports")
def history():
    from api.history import list_history, summary
    limit = request.args.get("limit", 50)
    offset = request.args.get("offset", 0)
    verdict = request.args.get("verdict")
    target = request.args.get("target")
    data = list_history(limit=limit, offset=offset, verdict=verdict, target=target)
    data["summary"] = summary()
    return jsonify(data)


@app.route("/history/export", methods=["GET"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="reports")
def history_export():
    from api.history import export_history
    fmt = request.args.get("format", "json").lower()
    if fmt not in ("json", "csv"):
        return jsonify({"error": "format must be 'json' or 'csv'"}), 400
    content, mime = export_history(fmt)
    from flask import Response
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename=scan_history.{fmt}"},
    )


@app.route("/explain", methods=["POST"])
@rate_limit(minute=config.RATE_MIN, hour=config.RATE_HOUR)
@require_api_key(scope="scan")
def explain():
    data = request.get_json(force=True)
    if not data or "question" not in data or "result" not in data:
        return jsonify({"error": "Missing 'question' and 'result' in request body"}), 400

    llm_answer = llm_explain(data["result"], data["question"])
    if llm_answer:
        return jsonify({"answer": llm_answer, "source": "llm"})
    return jsonify({"answer": None, "source": "template"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
