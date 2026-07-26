import re
import ipaddress
from urllib.parse import urlparse
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS

from api.predictor import predictor

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

    results = []
    for url in urls:
        try:
            with predictor_lock:
                results.append(predictor.predict(url.strip()))
        except Exception as e:
            results.append({"url": url, "error": str(e)})

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
