import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
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
from api.whitelist import get_domain_status as _get_domain_status
from api.utils import get_registered_domain as _get_registered_domain, get_subdomain_info as _get_subdomain_info

PROJECT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

FEATURE_KEYS = [
    "url_length", "domain_length", "path_length", "entropy",
    "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
    "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
]
TABULAR_DIM = len(FEATURE_KEYS)

# Country TLDs with strong regulatory oversight — model may not have seen during training
SAFE_COUNTRY_TLDS = {
    ".vn", ".uk", ".jp", ".de", ".fr", ".it", ".es", ".nl",
    ".se", ".no", ".dk", ".fi", ".au", ".nz", ".sg", ".my",
    ".kr", ".tw", ".hk", ".cn", ".in", ".br", ".mx", ".ar",
    ".ch", ".at", ".be", ".ie", ".pl", ".cz", ".hu", ".pt",
    ".gov", ".edu", ".mil",
}


TEMPERATURE = 2.8

# Known-reputable reputation discount: even a trusted domain never yields a
# hard 0% verdict. We still run the full analysis and only lower the final
# score to this ceiling when the registered domain is reputable AND the full
# hostname is covered by that reputation (no arbitrary user-content subdomain).
REPUTABLE_SCORE_CEILING = 15.0


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
        self._inference_lock = threading.Lock()
        self._maybe_quantize()

    def _maybe_quantize(self) -> None:
        quant_path = self.checkpoint_path.with_suffix(".quantized.pt")
        try:
            if quant_path.exists():
                state = torch.load(quant_path, map_location=self.device, weights_only=False)
                self.model.load_state_dict(state, strict=False)
                self.model.eval()
                return
            import torch.ao.quantization as quant
            self.model.bert.apply(quant.QuantStub())
            self.model.bert = torch.quantization.quantize_dynamic(
                self.model.bert, {torch.nn.Linear}, dtype=torch.qint8, inplace=True
            )
            torch.save(self.model.state_dict(), quant_path)
        except Exception:
            pass

    def predict(self, url: str, html_content: str | None = None) -> dict:
        brand_info = {"has_brand_impersonation": False, "brands_detected": [],
                      "max_confidence": 0.0, "risk_score": 0.0}

        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = pool.submit(self._extract_dns_whois, url)
            ssl_future = pool.submit(self._extract_ssl_redirect, url)
            dns_whois = dns_future.result()
            ssl_redirect = ssl_future.result()
        susp_tld = check_suspicious_tld(url)
        is_short = is_url_shortener(url)
        expanded_url = ssl_redirect.get("final_url", "") if ssl_redirect else ""

        # The effective URL is the redirect destination when a cross-domain
        # redirect exists; otherwise the original URL. Full analysis ALWAYS runs
        # — whitelist/reputation is only a soft signal, never a hard verdict.
        effective_url = expanded_url if expanded_url else url
        reg_domain = _get_registered_domain(effective_url) or ""
        subdomain_info = _get_subdomain_info(effective_url)

        tab_vec = self._extract_tabular(effective_url)
        dom_vec, clean_text = self._extract_html(html_content, effective_url) if html_content else (
            np.zeros(64, dtype=np.float32), "[content not provided]"
        )

        with self._inference_lock:
            self.model.eval()
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
            logits = logits / self.temperature
            prob = torch.sigmoid(logits)
            prob_val = prob.item()

            self.model.zero_grad()
            prob.backward()
            grads = tab_tensor.grad[0].cpu().numpy() if tab_tensor.grad is not None else np.zeros(TABULAR_DIM)
            feature_importance = {
                FEATURE_KEYS[i]: round(float(grads[i] * tab_vec[i]), 4)
                for i in range(TABULAR_DIM)
            }
            tab_tensor.requires_grad_(False)

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
                if reg_domain and a_count >= 1 and ssl_ok and \
                   any(reg_domain.endswith(t) for t in SAFE_COUNTRY_TLDS):
                    prob_val = min(prob_val, 0.15)

        brand_info = get_brand_risk_score(effective_url, clean_text)
        dom_signals = self._extract_dom_signals(dom_vec)

        # Multi-engine analysis (reputation/whitelist is a soft 5th engine)
        from api.engines import (ai_engine, dns_infra_engine, url_pattern_engine,
                                 brand_engine, reputation_engine, combine_engines)

        tab_features = self._get_feature_summary(tab_vec)
        ai_result = ai_engine(prob_val, tab_features, feature_importance, dns_whois, ssl_redirect)
        dns_result = dns_infra_engine(dns_whois, ssl_redirect)
        url_result = url_pattern_engine(effective_url, tab_features)
        br_result = brand_engine(effective_url, clean_text, brand_info)
        domain_status = _get_domain_status(effective_url, reg_domain) if reg_domain else {}
        rep_result = reputation_engine(domain_status)
        combined = combine_engines({
            "ai_model": ai_result,
            "dns_infrastructure": dns_result,
            "url_pattern": url_result,
            "brand": br_result,
            "reputation": rep_result,
        })
        final_prob = combined["final_score"] / 100.0

        if reg_domain:
            update_domain_reputation(reg_domain, final_prob * 100,
                                     combined["final_verdict"])
            reputation = get_domain_reputation(reg_domain)
        else:
            reputation = {}

        result_dict = {
            "url": url,
            "effective_url": effective_url if effective_url != url else None,
            "phishing_probability": round(prob_val, 4),
            "is_phishing": final_prob >= 0.5,
            "html_provided": html_content is not None,
            "brand_analysis": brand_info,
            "features": tab_features,
            "feature_importance": feature_importance,
            "whitelisted": bool(domain_status.get("known_reputable_domain") and domain_status.get("subdomain_trusted")),
            "redirect_whitelisted": False,
            "whitelist_status": domain_status,
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
