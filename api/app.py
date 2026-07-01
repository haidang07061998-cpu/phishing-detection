from flask import Flask, request, jsonify
from flask_cors import CORS

from api.predictor import predictor

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data["url"].strip()
    html_content = data.get("html", None)

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    try:
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

    results = []
    for url in urls:
        try:
            results.append(predictor.predict(url.strip()))
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"results": results, "count": len(results)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
