import os
import json
from pathlib import Path


def _load_env():
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")


def _build_context(result: dict) -> str:
    lines = []
    lines.append(f"URL: {result.get('url', '')}")
    lines.append(f"Risk Score: {result.get('aggregate_score', 0)}/100")
    score = result.get("aggregate_score", 0)
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
    lines.append(
        f"DNS: A={dns.get('a_record_count', '?')}, "
        f"MX={dns.get('mx_record_count', '?')}, "
        f"Age={dns.get('domain_age_days', '?')}d, "
        f"ASN={dns.get('asn_description', '?')}"
    )

    ssl = result.get("ssl_redirect") or {}
    lines.append(f"SSL: valid={ssl.get('ssl_valid', '?')}, redirect_count={ssl.get('redirect_count', '?')}")

    feats = result.get("features") or {}
    lines.append(
        f"URL: len={feats.get('url_length', '?')}, "
        f"entropy={feats.get('entropy', '?')}, "
        f"keywords={feats.get('suspicious_keywords', '?')}, "
        f"subdomains={feats.get('subdomain_count', '?')}"
    )

    lines.append(f"Whitelisted: {result.get('whitelisted', False)}")

    engines = result.get("engine_results", {}).get("engines", {})
    for name, data in engines.items():
        lines.append(f"Engine '{name}': {data.get('verdict', '?')} (score={data.get('score', '?')})")

    return "\n".join(lines)


def explain(result: dict, question: str) -> str | None:
    if not GEMINI_API_KEY:
        return None

    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash")

        context = _build_context(result)
        prompt = (
            "You are a phishing detection AI assistant. Based on the scan results below, "
            "answer the user's question concisely in 2-3 sentences. Be specific and use data from the results.\n\n"
            f"SCAN RESULTS:\n{context}\n\n"
            f"USER QUESTION: {question}\n\n"
            "ANSWER:"
        )

        response = model.generate_content(
            prompt, generation_config={"max_output_tokens": 250, "temperature": 0.3}
        )
        return response.text.strip()
    except Exception:
        return None
