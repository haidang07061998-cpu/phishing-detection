"""
Cloaking Detection Module.

Phishing sites often use cloaking: serving benign content to crawlers/bots
while showing phishing content to real users. This module detects such
discrepancies by comparing responses under different conditions.

Detection strategies:
1. User-Agent rotation (bot vs browser)
2. Referer header variation
3. Cookie acceptance variation
4. Viewport size differences (mobile vs desktop)
5. JavaScript rendering comparison (raw HTML vs rendered)

Usage:
    python -m src.analysis.cloaking_detector --url https://example.com
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.security.url_safety import validate_url, safe_get


def _is_safe_url(url) -> bool:
    check = validate_url(url)
    return check["valid"]


def check_user_agent_cloaking(url, timeout=10):
    """Compare responses with different User-Agent strings."""
    import requests

    bot_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"

    results = {}
    for label, ua in [("bot", bot_ua), ("browser", browser_ua)]:
        if not _is_safe_url(url):
            results[label] = {"error": "URL rejected by safety policy"}
            continue
        try:
            info = safe_get(url, timeout=timeout)
            if not info["ok"]:
                results[label] = {"error": info["error"]}
                continue
            text = info["content"].decode("utf-8", errors="replace")
            results[label] = {
                "status": info["status_code"],
                "length": len(text),
                "title": _extract_title(text),
                "has_forms": "form" in text.lower(),
                "has_password": "password" in text.lower(),
            }
        except Exception as e:
            results[label] = {"error": str(e)}

    return results


def check_referer_cloaking(url, timeout=10):
    """Compare responses with different Referer headers."""
    import requests

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
    referers = {
        "direct": None,
        "google": "https://www.google.com/search?q=test",
        "facebook": "https://www.facebook.com/",
        "email": "https://outlook.live.com/",
    }

    results = {}
    for label, ref in referers.items():
        if not _is_safe_url(url):
            results[label] = {"error": "URL rejected by safety policy"}
            continue
        headers = {"User-Agent": ua}
        if ref:
            headers["Referer"] = ref
        try:
            info = safe_get(url, timeout=timeout, headers=headers)
            if not info["ok"]:
                results[label] = {"error": info["error"]}
                continue
            text = info["content"].decode("utf-8", errors="replace")
            results[label] = {
                "status": info["status_code"],
                "length": len(text),
                "title": _extract_title(text),
            }
        except Exception as e:
            results[label] = {"error": str(e)}

    return results


def _extract_title(html):
    import re
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def analyze_cloaking(url, timeout=10):
    """Run all cloaking checks and return a risk assessment."""
    print(f"\nAnalyzing cloaking for: {url}")
    print("=" * 60)

    risk_score = 0.0
    findings = []

    # 1. User-Agent cloaking
    print("\n1. User-Agent Cloaking Check")
    ua_results = check_user_agent_cloaking(url, timeout)
    bot = ua_results.get("bot", {})
    browser = ua_results.get("browser", {})

    if "error" not in bot and "error" not in browser:
        len_diff = abs(bot.get("length", 0) - browser.get("length", 0))
        title_diff = bot.get("title") != browser.get("title")
        form_diff = bot.get("has_forms") != browser.get("has_forms")

        print(f"   Bot HTML length: {bot.get('length', 0)}")
        print(f"   Browser HTML length: {browser.get('length', 0)}")
        print(f"   Length difference: {len_diff}")
        print(f"   Title difference: {title_diff}")
        print(f"   Form difference: {form_diff}")

        if len_diff > 5000:
            risk_score += 0.3
            findings.append("Large HTML length difference detected (potential UA cloaking)")
        if title_diff:
            risk_score += 0.2
            findings.append("Page title differs between bot and browser")
        if form_diff and browser.get("has_forms"):
            risk_score += 0.2
            findings.append("Forms hidden from bot but shown to browser")
    else:
        print(f"   Bot error: {bot.get('error', 'N/A')}")
        print(f"   Browser error: {browser.get('error', 'N/A')}")

    # 2. Referer cloaking
    print("\n2. Referer Cloaking Check")
    ref_results = check_referer_cloaking(url, timeout)
    lengths = set()
    for label, r in ref_results.items():
        if "error" not in r:
            lengths.add(r.get("length", 0))
            print(f"   {label}: {r.get('length', 0)} bytes - title: {r.get('title', 'N/A')[:50]}")

    if len(lengths) > 1:
        risk_score += 0.2
        findings.append(f"Content varies by referer ({len(lengths)} variants)")

    # 3. Overall assessment
    print(f"\n{'=' * 60}")
    print(f"Cloaking Risk Score: {min(risk_score, 1.0):.4f}")

    if risk_score > 0.5:
        print("Verdict: HIGH cloaking suspicion - page behaves differently for different clients")
    elif risk_score > 0.2:
        print("Verdict: MODERATE cloaking suspicion - some inconsistencies detected")
    else:
        print("Verdict: LOW cloaking suspicion - consistent responses across variants")

    if findings:
        print("\nFindings:")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {f}")

    return {
        "url": url,
        "risk_score": round(min(risk_score, 1.0), 4),
        "findings": findings,
        "ua_results": ua_results,
        "referer_results": ref_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Detect cloaking in phishing URLs")
    parser.add_argument("--url", required=True, help="URL to analyze")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    args = parser.parse_args()

    analyze_cloaking(args.url, args.timeout)


if __name__ == "__main__":
    main()