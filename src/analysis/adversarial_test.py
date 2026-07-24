"""
Adversarial Robustness Testing for Phishing Detection.

Tests model robustness against common evasion techniques:
1. Character substitution (l33t speak)
2. Domain randomization
3. Keyword obfuscation
4. Path manipulation
5. HTML content perturbation

Usage:
    python -m src.analysis.adversarial_test
"""

import sys, math, re, json, random
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.features.url_extractor import extract_url_features, SUSPICIOUS_KEYWORDS

random.seed(42)


def l33t_substitute(text):
    """Replace characters with visually similar alternatives."""
    subs = {
        'a': ['4', '@'], 'e': ['3', '&'], 'i': ['1', '!'],
        'o': ['0', '()'], 's': ['5', '$'], 't': ['7', '+'],
        'l': ['1', '|'], 'b': ['8', '6'], 'g': ['9', '6'],
    }
    result = list(text)
    for i, c in enumerate(result):
        if c.lower() in subs and random.random() < 0.5:
            result[i] = random.choice(subs[c.lower()])
    return ''.join(result)


def generate_adversarial_urls(original_url, n_variants=5):
    """Generate adversarial variants of a URL."""
    parsed = urlparse(original_url)
    domain = (parsed.netloc or parsed.hostname or "").lower()
    path = parsed.path or ""
    variants = []

    for _ in range(n_variants):
        strategy = random.choice(['subdomain', 'keyword_obfuscate', 'path_deep', 'mixed'])

        if strategy == 'subdomain':
            fake_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(4, 8)))
            new_domain = f"{fake_sub}.{domain}"
            new_url = f"{parsed.scheme}://{new_domain}{path}"
            variants.append((new_url, 'extra_subdomain'))

        elif strategy == 'keyword_obfuscate':
            obfuscated = l33t_substitute(original_url)
            variants.append((obfuscated, 'l33t_obfuscation'))

        elif strategy == 'path_deep':
            extra = '/'.join(random.choices(['secure', 'login', 'verify', 'account', 'update'], k=random.randint(2, 4)))
            new_url = f"{original_url.rstrip('/')}/{extra}"
            variants.append((new_url, 'deep_path'))

        elif strategy == 'mixed':
            fake_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))
            extra = '/'.join(random.choices(['secure', 'login', 'verify'], k=2))
            new_domain = f"{fake_sub}-{domain}"
            new_url = f"{parsed.scheme}://{new_domain}/{l33t_substitute(path.lstrip('/'))}/{extra}"
            variants.append((new_url, 'mixed'))

    return variants


def test_url_feature_robustness(url):
    """Test if URL feature extraction is robust to adversarial modifications."""
    original_feats = extract_url_features(url)
    original_vec = np.array([original_feats[k] for k in [
        'url_length', 'domain_length', 'path_length', 'entropy',
        'special_char_ratio', 'digit_ratio', 'subdomain_count', 'has_https',
        'has_ip_address', 'suspicious_keywords', 'url_depth', 'tld_in_path',
    ]])

    variants = generate_adversarial_urls(url, n_variants=10)
    print(f"\nTesting adversarial robustness for: {url}")
    print(f"{'Variant':<60} {'Strategy':<20} {'SimScore':<10} {'KeywordDelta':<15}")
    print("-" * 105)

    vulnerable = False
    for adv_url, strategy in variants:
        adv_feats = extract_url_features(adv_url)
        adv_vec = np.array([adv_feats[k] for k in [
            'url_length', 'domain_length', 'path_length', 'entropy',
            'special_char_ratio', 'digit_ratio', 'subdomain_count', 'has_https',
            'has_ip_address', 'suspicious_keywords', 'url_depth', 'tld_in_path',
        ]])

        sim = np.dot(original_vec, adv_vec) / (np.linalg.norm(original_vec) * np.linalg.norm(adv_vec) + 1e-8)
        kw_diff = adv_feats['suspicious_keywords'] - original_feats['suspicious_keywords']

        if kw_diff < 0:
            vulnerable = True
            flag = " *** EVADED ***"
        else:
            flag = ""

        print(f"{adv_url:<60} {strategy:<20} {sim:.4f}{'':>5} {kw_diff:+d}{flag}")

    print(f"\nVulnerable to keyword evasion: {'YES' if vulnerable else 'NO'}")
    return vulnerable


def test_html_perturbation(html_text):
    """Test robustness to HTML perturbations."""
    if not html_text:
        return {}

    from src.features.html_dom_extractor import extract_html_features
    from bs4 import BeautifulSoup

    original_dom, original_text = extract_html_features(html_text, "http://example.com")

    perturbations = {
        "comment_injection": lambda h: h.replace("<html", "<!-- hidden --><html"),
        "extra_scripts": lambda h: h.replace("</head>", "<script>/* benign */</script></head>"),
        "attribute_removal": lambda h: re.sub(r'\s+(class|id|style)="[^"]*"', '', h),
        "whitespace_obfuscation": lambda h: re.sub(r'\s+', '  ', h),
    }

    results = {}
    for name, perturb_fn in perturbations.items():
        try:
            perturbed_html = perturb_fn(html_text)
            dom_vec, clean_text = extract_html_features(perturbed_html, "http://example.com")
            dom_diff = float(np.mean(np.abs(dom_vec - original_dom)))
            text_len_diff = abs(len(clean_text) - len(original_text))
            results[name] = {
                "dom_diff": round(dom_diff, 6),
                "text_len_diff": text_len_diff,
                "stable": dom_diff < 0.1,
            }
        except Exception as e:
            results[name] = {"error": str(e)}

    return results


def main():
    print("=" * 60)
    print("Adversarial Robustness Testing for Phishing Detection")
    print("=" * 60)

    test_urls = [
        "https://paypal.com/webscr",
        "http://secure-login.com/verify/account",
        "https://www.google.com/search",
    ]

    for url in test_urls:
        vulnerable = test_url_feature_robustness(url)
        if vulnerable:
            print("  RECOMMENDATION: Add l33t-speak normalization to keyword detection")

    print("\n--- Recommendations for Adversarial Robustness ---")
    print("1. Add character normalization (l33t -> plain text) to keyword detection")
    print("2. Use ensemble of models with different feature sets")
    print("3. Add adversarial training examples to training data")
    print("4. Monitor feature distribution drift in production")
    print("5. Add randomized input preprocessing to foil evasion attempts")


if __name__ == "__main__":
    main()