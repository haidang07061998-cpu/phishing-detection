import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS

from api.predictor import predictor
from api.feedback import submit_feedback, get_feedback_stats
from api.webhooks import set_webhook, delete_webhook, get_webhook, dispatch
from api.whitelist import get_all as _get_whitelist, add_dynamic as _add_whitelist, remove_dynamic as _remove_whitelist

app = Flask(__name__)
CORS(app)

predictor_lock = threading.Lock()
MAX_BATCH_SIZE = 50


def validate_url(url: str) -> str | None:
    if not url or not url.strip():
        return "URL cannot be empty"
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parsed.netloc:
        return "Invalid URL: missing domain"
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


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data["url"].strip()
    err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    html_content = data.get("html", None)

    try:
        with predictor_lock:
            result = predictor.predict(url, html_content)
        dispatch("scan.completed", {
            "url": url,
            "aggregate_score": result.get("aggregate_score"),
            "verdict": "phishing" if result.get("aggregate_score", 0) >= 60 else "suspicious" if result.get("aggregate_score", 0) >= 30 else "safe",
        })
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    data = request.get_json(force=True)
    if not data or "urls" not in data:
        return jsonify({"error": "Missing 'urls' in request body"}), 400

    urls = data["urls"]
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "'urls' must be a non-empty list"}), 400
    if len(urls) > MAX_BATCH_SIZE:
        return jsonify({"error": f"Batch size cannot exceed {MAX_BATCH_SIZE}"}), 400

    def _predict_single(url: str) -> dict:
        try:
            with predictor_lock:
                return predictor.predict(url.strip())
        except Exception as e:
            return {"url": url, "error": str(e)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_predict_single, urls))

    for r in results:
        if "error" not in r:
            dispatch("scan.completed", {
                "url": r.get("url", ""),
                "aggregate_score": r.get("aggregate_score"),
                "verdict": "phishing" if r.get("aggregate_score", 0) >= 60 else "suspicious" if r.get("aggregate_score", 0) >= 30 else "safe",
            })

    return jsonify({"results": results, "count": len(results)})


@app.route("/domain", methods=["POST"])
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
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ip", methods=["POST"])
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
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/feedback", methods=["POST"])
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
def feedback_stats():
    return jsonify(get_feedback_stats())


@app.route("/webhook", methods=["GET", "POST", "DELETE"])
def webhook():
    if request.method == "GET":
        return jsonify(get_webhook())
    if request.method == "DELETE":
        return jsonify(delete_webhook())
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    return jsonify(set_webhook(data["url"], data.get("events")))


@app.route("/whitelist", methods=["GET"])
def whitelist_get():
    return jsonify(_get_whitelist())


@app.route("/whitelist", methods=["POST"])
def whitelist_add():
    data = request.get_json(force=True)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    return jsonify(_add_whitelist(data["domain"].strip().lower()))


@app.route("/whitelist", methods=["DELETE"])
def whitelist_remove():
    data = request.get_json(force=True)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    return jsonify(_remove_whitelist(data["domain"].strip().lower()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
