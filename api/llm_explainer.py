import json
import traceback
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:3b"


def _build_context(result: dict) -> str:
    lines = []
    lines.append(f"URL: {result.get('url', '')}")
    score = result.get("aggregate_score", 0)
    lines.append(f"Risk Score: {score}/100")
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    lines.append(f"Verdict: {verdict}")

    exp = result.get("explanation") or {}
    if exp.get("key_findings"):
        lines.append(f"Key Findings: {'; '.join(exp['key_findings'])}")
    if exp.get("risk_factors"):
        lines.append(f"Risk Factors: {'; '.join(exp['risk_factors'])}")

    brand = result.get("brand_analysis") or {}
    if brand.get("has_brand_impersonation"):
        lines.append(f"Brand Impersonation: {', '.join(brand.get('brands_detected', []))}")

    sub = result.get("subdomain_info")
    if sub:
        lines.append(f"Subdomain: '{sub['subdomain']}' on '{sub['registered_domain']}'")

    dns = result.get("dns_whois") or {}
    lines.append(f"DNS: A={dns.get('a_record_count', '?')}, MX={dns.get('mx_record_count', '?')}, Age={dns.get('domain_age_days', '?')}d, ASN={dns.get('asn_description', '?')}")

    ssl = result.get("ssl_redirect") or {}
    lines.append(f"SSL: valid={ssl.get('ssl_valid', '?')}, redirect_count={ssl.get('redirect_count', '?')}")

    feats = result.get("features") or {}
    lines.append(f"URL: len={feats.get('url_length', '?')}, entropy={feats.get('entropy', '?')}, keywords={feats.get('suspicious_keywords', '?')}, subdomains={feats.get('subdomain_count', '?')}")

    lines.append(f"Whitelisted: {result.get('whitelisted', False)}")

    engines = result.get("engine_results", {}).get("engines", {})
    for name, data in engines.items():
        lines.append(f"Engine '{name}': {data.get('verdict', '?')} (score={data.get('score', '?')})")

    return "\n".join(lines)


def _ollama_available() -> bool:
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags", method="GET")
        urllib.request.urlopen(req, timeout=2)
        return True
    except Exception:
        return False


def _explain_ollama(context: str, question: str) -> str | None:
    try:
        prompt = (
            "You are a phishing detection AI assistant. Based on the scan results below, "
            "answer the user's question concisely in 2-3 sentences. Be specific and use data from the results.\n\n"
            f"SCAN RESULTS:\n{context}\n\n"
            f"USER QUESTION: {question}\n\n"
            "ANSWER:"
        )
        body = json.dumps({
            "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
            "options": {"num_predict": 250, "temperature": 0.3},
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read().decode())
        return data.get("response", "").strip() or None
    except Exception:
        traceback.print_exc()
        return None


def explain(result: dict, question: str) -> str | None:
    if not _ollama_available():
        return None
    return _explain_ollama(_build_context(result), question)
