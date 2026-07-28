import re
import sys
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.full_model import PhishingDetector, load_checkpoint
from src.features.url_extractor import extract_url_features, check_suspicious_tld, is_url_shortener
from src.features.html_dom_extractor import extract_html_features
from src.features.dns_whois_extractor import extract_dns_whois_features
from src.features.ssl_redirect_extractor import extract_ssl_redirect_features
from src.brand_detection import get_brand_risk_score
from api.reputation import get_domain_reputation, update_domain_reputation
from api.explainer import generate_explanation

PROJECT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

FEATURE_KEYS = [
    "url_length", "domain_length", "path_length", "entropy",
    "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
    "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
]
TABULAR_DIM = len(FEATURE_KEYS)

WHITELIST_DOMAINS = {
    # Google
    "google.com", "googleapis.com", "googleusercontent.com",
    "gmail.com", "youtube.com", "youtu.be", "blogspot.com",
    "google.vn",
    # Microsoft
    "microsoft.com", "office.com", "office365.com",
    "live.com", "outlook.com", "azure.com",
    "github.com", "githubusercontent.com",
    # Meta
    "facebook.com", "fb.com", "fbcdn.net",
    "instagram.com", "whatsapp.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon
    "amazon.com", "aws.amazon.com",
    # Social & Communication
    "twitter.com", "x.com", "linkedin.com",
    "telegram.org", "discord.com", "slack.com",
    # Development
    "gitlab.com", "bitbucket.org", "npmjs.com",
    "docker.com", "stackoverflow.com",
    # Other major
    "wikipedia.org", "wikimedia.org",
    "netflix.com", "spotify.com", "adobe.com",
    "paypal.com", "ebay.com",
    "zoom.us", "dropbox.com",
    "cloudflare.com",
    # Vietnamese major sites
    "vietnamnet.vn", "vnexpress.net", "tuoitre.vn",
    "thanhnien.vn", "dantri.com.vn", "nguoiduatin.vn",
    "vov.vn", "baomoi.com", "cafef.vn", "cafebiz.vn",
    "zalo.me", "chotot.com", "batdongsan.com.vn",
    "tiki.vn", "shopee.vn", "thegioididong.com",
    "vietcombank.com.vn", "techcombank.com.vn",
    "acb.com.vn", "vpbank.com.vn", "mbbank.com.vn",
    "vietinbank.vn", "bidv.com.vn",
}

# Country TLDs with strong regulatory oversight — model may not have seen during training
SAFE_COUNTRY_TLDS = {
    ".vn", ".uk", ".jp", ".de", ".fr", ".it", ".es", ".nl",
    ".se", ".no", ".dk", ".fi", ".au", ".nz", ".sg", ".my",
    ".kr", ".tw", ".hk", ".cn", ".in", ".br", ".mx", ".ar",
    ".ch", ".at", ".be", ".ie", ".pl", ".cz", ".hu", ".pt",
    ".gov", ".edu", ".mil",
}


def _get_registered_domain(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.hostname or "").lower()
        # Remove port
        domain = domain.split(":")[0]
        if not domain:
            return None
        # Handle IP addresses
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return domain
        # Extract last 2-3 parts (e.g., "google.com" or "co.uk" special cases)
        parts = domain.split(".")
        if len(parts) < 2:
            return domain
        # Handle common 2-part TLDs like co.uk, com.au
        two_part_tlds = {"co.uk", "com.au", "co.nz", "co.jp", "co.kr",
                         "or.jp", "ac.uk", "gov.uk", "org.uk", "net.au",
                         "com.vn", "co.vn", "com.sg", "com.hk", "com.tw",
                         "co.id", "or.id", "ac.id", "go.id"}
        if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    except Exception:
        return None


def _get_subdomain_info(url: str) -> dict | None:
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or parsed.hostname or "").lower().split(":")[0]
        if not hostname:
            return None
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            return None
        reg_domain = _get_registered_domain(url)
        if not reg_domain or hostname == reg_domain:
            return None
        subdomain = hostname[:-(len(reg_domain) + 1)]
        if subdomain:
            sub_parts = subdomain.split(".")
            if sub_parts and sub_parts[-1] in ("www", "mail", "smtp", "api", "cdn", "ftp", "webmail", "m", "app", "dev", "test", "beta"):
                return None
            return {
                "full_hostname": hostname,
                "registered_domain": reg_domain,
                "subdomain": subdomain,
                "parts": sub_parts,
            }
    except Exception:
        return None
    return None


TEMPERATURE = 2.8


class PhishingPredictor:
    def __init__(self, checkpoint_path: str | Path | None = None, temperature: float = TEMPERATURE):
        if checkpoint_path is None:
            fold_ckpts = sorted(MODEL_DIR.glob("proposed_fold*_best.pt"))
            if fold_ckpts:
                checkpoint_path = str(fold_ckpts[0])
            else:
                raise FileNotFoundError(
                    "No proposed_fold*_best.pt checkpoint found in "
                    f"{MODEL_DIR}. Train the model first or specify checkpoint_path."
                )
        self.checkpoint_path = Path(checkpoint_path)
        self.device = DEVICE
        self.temperature = temperature

        if not self.checkpoint_path.exists():
            raise FileNotFoundError(
                f"Checkpoint not found at {self.checkpoint_path}. "
                "Train the model first or download a pre-trained checkpoint."
            )

        self.model = PhishingDetector().to(DEVICE)
        ckpt = torch.load(self.checkpoint_path, map_location=DEVICE, weights_only=False)
        if isinstance(ckpt, dict) and "model_state_dict" in ckpt:
            self.model.load_state_dict(ckpt["model_state_dict"])
        else:
            self.model.load_state_dict(ckpt)
        self.model.eval()
        self.tokenizer = self.model.bert.tokenizer

    def predict(self, url: str, html_content: str | None = None) -> dict:
        brand_info = {"has_brand_impersonation": False, "brands_detected": [],
                      "max_confidence": 0.0, "risk_score": 0.0}

        dns_whois = self._extract_dns_whois(url)
        ssl_redirect = self._extract_ssl_redirect(url)
        susp_tld = check_suspicious_tld(url)
        is_short = is_url_shortener(url)
        expanded_url = ssl_redirect.get("final_url", "") if ssl_redirect else ""

        reg_domain = _get_registered_domain(url)
        effective_url = url

        redirect_whitelisted = False
        subdomain_info = _get_subdomain_info(url)
        if expanded_url:
            final_domain = _get_registered_domain(expanded_url)
            if final_domain and final_domain in WHITELIST_DOMAINS:
                redirect_whitelisted = True
                tab_features = self._get_feature_summary(self._extract_tabular(url))
                reg_domain = _get_registered_domain(expanded_url) or ""
                rd = {
                    "url": url,
                    "phishing_probability": 0.001,
                    "is_phishing": False,
                    "html_provided": html_content is not None,
                    "brand_analysis": get_brand_risk_score(expanded_url, ""),
                    "features": tab_features,
                    "whitelisted": True,
                    "redirect_whitelisted": True,
                    "dns_whois": dns_whois,
                    "ssl_redirect": ssl_redirect,
                    "suspicious_tld": susp_tld,
                    "is_shortener": is_short,
                    "expanded_url": expanded_url,
                    "effective_url": expanded_url,
                    "engine_results": {"final_score": 0.0, "final_verdict": "safe", "engines": {}},
                    "aggregate_score": 0.0,
                    "engine_count": 0,
                    "reputation": get_domain_reputation(reg_domain),
                    "subdomain_info": subdomain_info,
                }
                rd["explanation"] = generate_explanation(rd)
                return rd
            effective_url = expanded_url

        is_whitelisted = bool(
            _get_registered_domain(effective_url)
            and _get_registered_domain(effective_url) in WHITELIST_DOMAINS
        )

        if is_whitelisted:
            brand_info = get_brand_risk_score(url, "")
            tab_features = self._get_feature_summary(self._extract_tabular(url))
            reg_domain = _get_registered_domain(effective_url) or ""
            rd = {
                "url": url,
                "phishing_probability": 0.001,
                "is_phishing": False,
                "html_provided": html_content is not None,
                "brand_analysis": brand_info,
                "features": tab_features,
                "whitelisted": True,
                "redirect_whitelisted": False,
                "dns_whois": dns_whois,
                "ssl_redirect": ssl_redirect,
                "suspicious_tld": susp_tld,
                "is_shortener": is_short,
                "expanded_url": expanded_url if expanded_url else None,
                "engine_results": {"final_score": 0.0, "final_verdict": "safe", "engines": {}},
                "aggregate_score": 0.0,
                "engine_count": 0,
                "reputation": get_domain_reputation(reg_domain),
                "subdomain_info": subdomain_info,
            }
            rd["explanation"] = generate_explanation(rd)
            return rd

        self.model.eval()
        tab_vec = self._extract_tabular(effective_url)
        dom_vec, clean_text = self._extract_html(html_content, effective_url) if html_content else (
            np.zeros(64, dtype=np.float32), "[content not provided]"
        )

        tab_tensor = torch.from_numpy(tab_vec).unsqueeze(0).to(DEVICE)
        dom_tensor = torch.from_numpy(dom_vec).unsqueeze(0).to(DEVICE)
        tokens = self.tokenizer(
            [clean_text], padding=True, truncation=True,
            max_length=512, return_tensors="pt",
        )

        tab_tensor.requires_grad_(True)
        logits = self.model(
            tab_tensor,
            tokens["input_ids"].to(DEVICE),
            tokens["attention_mask"].to(DEVICE),
            dom_tensor,
        )
        # Temperature scaling before sigmoid
        logits = logits / self.temperature
        prob = torch.sigmoid(logits)
        prob_val = prob.item()

        # Infrastructure sanity check: strong DNS+SSL contradicts phishing
        if prob_val > 0.5 and dns_whois and ssl_redirect and not susp_tld and not is_short:
            a_count = dns_whois.get("a_record_count", -1)
            mx_count = dns_whois.get("mx_record_count", -1)
            ssl_ok = ssl_redirect.get("ssl_valid", -1) == 1
            strong_infra = a_count >= 2 and mx_count >= 1 and ssl_ok
            cdn_scale = a_count >= 3 and ssl_ok
            if strong_infra or cdn_scale:
                prob_val = min(prob_val, 0.15)
            else:
                domain = _get_registered_domain(effective_url)
                if domain and a_count >= 1 and ssl_ok and \
                   any(domain.endswith(t) for t in SAFE_COUNTRY_TLDS):
                    prob_val = min(prob_val, 0.15)

        self.model.zero_grad()
        prob.backward()
        grads = tab_tensor.grad[0].cpu().numpy() if tab_tensor.grad is not None else np.zeros(TABULAR_DIM)
        feature_importance = {
            FEATURE_KEYS[i]: round(float(grads[i] * tab_vec[i]), 4)
            for i in range(TABULAR_DIM)
        }
        tab_tensor.requires_grad_(False)

        brand_info = get_brand_risk_score(effective_url, clean_text)
        dom_signals = self._extract_dom_signals(dom_vec)

        # Multi-engine analysis
        from api.engines import ai_engine, dns_infra_engine, url_pattern_engine, brand_engine, combine_engines

        tab_features = self._get_feature_summary(tab_vec)
        ai_result = ai_engine(prob_val, tab_features, feature_importance, dns_whois, ssl_redirect)
        dns_result = dns_infra_engine(dns_whois, ssl_redirect)
        url_result = url_pattern_engine(effective_url, tab_features)
        br_result = brand_engine(effective_url, clean_text, brand_info)
        combined = combine_engines({
            "ai_model": ai_result,
            "dns_infrastructure": dns_result,
            "url_pattern": url_result,
            "brand": br_result,
        })
        final_prob = combined["final_score"] / 100.0

        reg_domain = _get_registered_domain(effective_url) or ""
        if reg_domain:
            update_domain_reputation(reg_domain, final_prob * 100,
                                     combined["final_verdict"])
        reputation = get_domain_reputation(reg_domain) if reg_domain else {}

        result_dict = {
            "url": url,
            "effective_url": effective_url if effective_url != url else None,
            "phishing_probability": round(prob_val, 4),
            "is_phishing": final_prob >= 0.5,
            "html_provided": html_content is not None,
            "brand_analysis": brand_info,
            "features": tab_features,
            "feature_importance": feature_importance,
            "whitelisted": False,
            "redirect_whitelisted": False,
            "dns_whois": dns_whois,
            "ssl_redirect": ssl_redirect,
            "dom_signals": dom_signals,
            "suspicious_tld": susp_tld,
            "is_shortener": is_short,
            "expanded_url": expanded_url if expanded_url else None,
            "engine_results": combined,
            "aggregate_score": combined["final_score"],
            "engine_count": len(combined["engines"]),
            "reputation": reputation if reputation else {},
            "subdomain_info": subdomain_info,
        }
        result_dict["explanation"] = generate_explanation(result_dict)
        return result_dict

    def _get_feature_summary(self, tab_vec: np.ndarray) -> dict:
        keys = FEATURE_KEYS
        values = tab_vec.tolist()
        return {k: round(v, 4) for k, v in zip(keys, values)}

    def _extract_tabular(self, url: str) -> np.ndarray:
        feats = extract_url_features(url)
        return np.array([feats[k] for k in FEATURE_KEYS], dtype=np.float32)

    def _extract_html(self, html: str | None, base_url: str):
        if html is None or html.strip() == "":
            return np.zeros(64, dtype=np.float32), ""
        try:
            return extract_html_features(html, base_url)
        except Exception:
            return np.zeros(64, dtype=np.float32), ""

    def _extract_dns_whois(self, url: str) -> dict:
        try:
            return extract_dns_whois_features(url)
        except Exception:
            return {"a_record_count": -1, "mx_record_count": -1,
                    "ns_record_count": -1, "ttl": -1,
                    "domain_age_days": -1, "registrar": "",
                    "is_privacy_protected": -1, "country": "",
                    "resolved_ips": [], "ptr_record": "",
                    "asn": "", "asn_description": "",
                    "asn_country": ""}

    def _extract_ssl_redirect(self, url: str) -> dict:
        try:
            return extract_ssl_redirect_features(url)
        except Exception:
            return {"ssl_valid": -1, "ssl_age_days": -1,
                    "ssl_issuer_trusted": -1,
                    "redirect_count": -1, "cross_domain_redirect": -1}

    def _extract_dom_signals(self, dom_vec: np.ndarray) -> dict:
        return {
            "script_count": int(dom_vec[0]),
            "iframe_count": int(dom_vec[1]),
            "form_count": int(dom_vec[2]),
            "input_count": int(dom_vec[3]),
            "password_input": int(dom_vec[4]),
            "button_count": int(dom_vec[5]),
            "total_links": int(dom_vec[6]),
            "external_scripts": int(dom_vec[7]),
            "external_link_ratio": round(float(dom_vec[8]), 4),
            "hidden_elements": int(dom_vec[13]),
            "meta_refresh": int(dom_vec[14]),
            "eval_count": int(dom_vec[15]),
            "document_write": int(dom_vec[16]),
            "suspicious_js": int(dom_vec[17]),
            "empty_links": int(dom_vec[18]),
        }

    def lookup_domain(self, domain: str) -> dict:
        url = f"https://{domain}"
        dns_whois = self._extract_dns_whois(url)
        from api.engines import dns_infra_engine, url_pattern_engine, brand_engine, combine_engines
        dns_result = dns_infra_engine(dns_whois, {})
        url_result = url_pattern_engine(url, {})
        br_result = brand_engine(url, "", None)
        combined = combine_engines({
            "ai_model": {"score": 0, "verdict": "safe", "details": "No model inference"},
            "dns_infrastructure": dns_result,
            "url_pattern": url_result,
            "brand": br_result,
        })
        rep = get_domain_reputation(domain)
        return {
            "domain": domain,
            "dns_whois": dns_whois,
            "suspicious_tld": check_suspicious_tld(url),
            "type": "domain",
            "engine_results": combined,
            "aggregate_score": combined["final_score"],
            "engine_count": len(combined["engines"]),
            "reputation": rep,
        }

    def lookup_ip(self, ip: str) -> dict:
        url = f"http://{ip}"
        dns_whois = self._extract_dns_whois(url)
        ssl_redirect = self._extract_ssl_redirect(f"https://{ip}")
        from api.engines import dns_infra_engine, url_pattern_engine, brand_engine, combine_engines
        dns_result = dns_infra_engine(dns_whois, ssl_redirect)
        url_result = url_pattern_engine(url, {"has_ip_address": 1, "url_length": len(url)})
        br_result = brand_engine(url, "", None)
        combined = combine_engines({
            "ai_model": {"score": 50, "verdict": "suspicious", "details": "IP-based — skipped model"},
            "dns_infrastructure": dns_result,
            "url_pattern": url_result,
            "brand": br_result,
        })
        return {
            "ip": ip,
            "dns_whois": dns_whois,
            "ssl_redirect": ssl_redirect,
            "suspicious_tld": 0,
            "type": "ip",
            "engine_results": combined,
            "aggregate_score": combined["final_score"],
            "engine_count": len(combined["engines"]),
        }


predictor = PhishingPredictor()
