"""
Latency / throughput / memory benchmark for the API predictor.

Measures end-to-end prediction latency (p50/p95/p99), throughput, per-request
memory delta, and the batch timeout rate. Uses the already-loaded global
predictor so startup time is excluded.

Usage:
    $env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.benchmark [n_samples]

Notes:
    - CPU-bound model inference is serialized by the predictor's internal lock.
    - DNS/SSL network I/O dominates wall time; results depend on network state.
    - Pass n_samples to override the default 20 predictions.
"""

import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api.predictor import predictor, PhishingPredictor

SAMPLE_URLS = [
    ("https://www.google.com", None),
    ("https://github.com/login", None),
    ("https://facebook.com", None),
    ("https://www.microsoft.com/en-us/", None),
    ("https://apple.com", None),
    ("https://secure-paypa1.com/login", "<html><body><h1>Verify your PayPal account</h1><form><input type=password></form></body></html>"),
    ("https://login.faceb00k-security.com/verify", "<html><body><h1>Account suspended</h1><form><input type=password></form></body></html>"),
    ("https://www.wikipedia.org", None),
    ("https://stackoverflow.com/questions", None),
    ("https://www.amazon.com", None),
    ("https://example.com", "<html><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>"),
    ("https://bank-account-update-verify.com/confirm", "<html><body><h1>Update your bank details</h1><form><input type=text name=card></form></body></html>"),
    ("https://www.reddit.com", None),
    ("https://www.netflix.com", None),
    ("https://outlook.live.com/mail/", None),
    ("https://docs.python.org/3/library/", None),
    ("https://pypi.org/project/requests/", None),
    ("https://m.facebook.com", None),
    ("https://www.linkedin.com/in/", None),
    ("https://support.apple.com", None),
]


def _rss_mb() -> float:
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except (ImportError, AttributeError, ValueError):
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)


def run_benchmark(n: int = 20, do_cold: bool = False) -> dict:
    global _do_cold
    _do_cold = do_cold
    urls = SAMPLE_URLS[:n]
    if len(urls) < n:
        urls = (SAMPLE_URLS * (n // len(SAMPLE_URLS) + 1))[:n]

    print(f"Benchmarking {len(urls)} predictions on {predictor.device}")
    print(f"Models loaded: {len(predictor.models)} | temperature={predictor.temperature} | "
          f"feature_importance={'on' if predictor.compute_feature_importance else 'off'}")

    latencies, errors, rss_deltas, agg_scores = [], [], [], []
    base_rss = _rss_mb()

    for url, html in urls:
        t0 = time.perf_counter()
        try:
            res = predictor.predict(url, html)
            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)
            agg_scores.append(res.get("aggregate_score", -1))
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
        rss_deltas.append(_rss_mb() - base_rss)

    lat = np.array(latencies)

    # Cold start (opt-in): first prediction on a fresh predictor with a cold
    # extraction cache. Loads a second model into RAM (~600MB), so it is
    # skipped by default on low-RAM machines. Enable with --cold.
    cold_ms = None
    if _do_cold:
        try:
            fresh = PhishingPredictor(
                compute_feature_importance=predictor.compute_feature_importance,
                extract_cache_ttl=0,  # no warm cache — forces real network I/O
            )
            t0 = time.perf_counter()
            fresh.predict(SAMPLE_URLS[0][0], SAMPLE_URLS[0][1])
            cold_ms = (time.perf_counter() - t0) * 1000.0
            del fresh
        except Exception as e:
            print(f"  cold-start measurement skipped: {e}")

    report = {
        "n": len(urls),
        "n_errors": len(errors),
        "errors": errors,
        "p50_ms": round(float(np.percentile(lat, 50)), 1),
        "p95_ms": round(float(np.percentile(lat, 95)), 1),
        "p99_ms": round(float(np.percentile(lat, 99)), 1),
        "mean_ms": round(float(lat.mean()), 1),
        "min_ms": round(float(lat.min()), 1),
        "max_ms": round(float(lat.max()), 1),
        "warm_start_p50_ms": round(float(np.percentile(lat, 50)), 1),
        "warm_start_p95_ms": round(float(np.percentile(lat, 95)), 1),
        "cold_start_first_ms": round(float(cold_ms), 1) if cold_ms else None,
        "throughput_per_min": round(60.0 / float(lat.mean()) * 1000.0, 1),
        "rss_base_mb": round(base_rss, 1),
        "rss_max_delta_mb": round(float(max(rss_deltas)), 1),
        "timeout_rate": round(len(errors) / max(len(urls), 1), 4),
        "aggregate_scores": [round(s, 1) for s in agg_scores],
        "device": str(predictor.device),
        "temperature": predictor.temperature,
        "ensemble_folds": len(predictor.models),
        "feature_importance": bool(predictor.compute_feature_importance),
        "extract_cache": "redis" if getattr(predictor, "extract_cache", None) and getattr(predictor.extract_cache, "_ok", False) else "memory",
    }

    print(f"  warm  p50={report['warm_start_p50_ms']}ms  p95={report['warm_start_p95_ms']}ms  "
          f"p99={report['p99_ms']}ms")
    if report["cold_start_first_ms"]:
        print(f"  cold  first={report['cold_start_first_ms']}ms")
    print(f"  mean={report['mean_ms']}ms  throughput≈{report['throughput_per_min']}/min  "
          f"errors={report['n_errors']}  rss+{report['rss_max_delta_mb']}MB")
    print(f"  aggregate_scores={report['aggregate_scores']}")

    out_path = Path(__file__).resolve().parents[2] / "results" / "benchmark.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved -> {out_path}")
    return report


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    _do_cold = "--cold" in sys.argv
    n = int(args[0]) if args else 20
    run_benchmark(n)
