import json
import re
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.full_model import PhishingDetector
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


@contextmanager
def _noop_context():
    """Identity context manager (grad tracking on)."""
    yield

FEATURE_KEYS = [
    "url_length", "domain_length", "path_length", "entropy",
    "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
    "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
]
TABULAR_DIM = len(FEATURE_KEYS)
DOM_DIM = 64

# Token length used during training (train_proposed.py max_length=128). Inference
# MUST match this exactly — feeding 512 tokens to a model fine-tuned on 128-token
# sequences produces out-of-distribution inputs.
MAX_SEQ_LEN = 128

# Country TLDs with strong regulatory oversight — model may not have seen during training
SAFE_COUNTRY_TLDS = {
    ".vn", ".uk", ".jp", ".de", ".fr", ".it", ".es", ".nl",
    ".se", ".no", ".dk", ".fi", ".au", ".nz", ".sg", ".my",
    ".kr", ".tw", ".hk", ".cn", ".in", ".br", ".mx", ".ar",
    ".ch", ".at", ".be", ".ie", ".pl", ".cz", ".hu", ".pt",
    ".gov", ".edu", ".mil",
}

# Default temperature scaling factor applied to logits before sigmoid.
# Overridable via data/models/temperature.json (produced by calibrate.py) or
# the PHISHGUARD_TEMPERATURE env var.
DEFAULT_TEMPERATURE = 2.8
TEMPERATURE_PATH = MODEL_DIR / "temperature.json"

# Known-reputable reputation discount: even a trusted domain never yields a
# hard 0% verdict. We still run the full analysis and only lower the final
# score to this ceiling when the registered domain is reputable AND the full
# hostname is covered by that reputation (no arbitrary user-content subdomain).
REPUTABLE_SCORE_CEILING = 15.0

# Width (in raw-logit units, before temperature scaling) used to build a
# plausible probability band around the point estimate. ~1.0 logit unit is a
# heuristic "one standard deviation" for typical binary classifiers.
UNCERTAINTY_LOGIT_MARGIN = 1.0


def _load_temperature() -> float:
    """Load calibrated temperature from disk, else default.

    Order of precedence:
      1. PHISHGUARD_TEMPERATURE env var
      2. data/models/temperature.json (written by src/evaluation/calibrate.py)
      3. DEFAULT_TEMPERATURE
    """
    import os
    env = os.environ.get("PHISHGUARD_TEMPERATURE")
    if env:
        try:
            t = float(env)
            if t > 0:
                return t
        except ValueError:
            pass
    if TEMPERATURE_PATH.exists():
        try:
            data = json.loads(TEMPERATURE_PATH.read_text(encoding="utf-8"))
            t = float(data.get("temperature", DEFAULT_TEMPERATURE))
            if t > 0:
                return t
        except (ValueError, OSError, json.JSONDecodeError):
            pass
    return DEFAULT_TEMPERATURE


def _utc_timestamp() -> str:
    """RFC-3339 UTC timestamp for API responses."""
    return datetime.now(timezone.utc).isoformat()


def _probability_band(raw_logit: float, temperature: float) -> dict:
    """Plausible probability band around a point estimate.

    The model outputs a single logit; without a full Bayesian treatment we
    approximate an uncertainty band by pushing the logit ± one heuristic
    logit-standard-deviation (UNCERTAINTY_LOGIT_MARGIN) through the same
    temperature-scaled sigmoid. Used for the UI confidence display only.
    """
    import math

    def _sig(x: float) -> float:
        return 1.0 / (1.0 + math.exp(-x))

    p = _sig(raw_logit / temperature)
    lo = _sig((raw_logit - UNCERTAINTY_LOGIT_MARGIN) / temperature)
    hi = _sig((raw_logit + UNCERTAINTY_LOGIT_MARGIN) / temperature)
    return {
        "low": round(min(p, lo), 4),
        "high": round(max(p, hi), 4),
    }


def _load_fold_meta() -> dict:
    """Load per-fold normalization params from proposed_folds.json.
    Training normalizes URL/DOM features per fold via (x - mean) / std
    (see train_proposed.py CachedDataset). Inference MUST apply the same
    normalization or the model receives out-of-distribution inputs.
    """
    folds_path = MODEL_DIR / "proposed_folds.json"
    if not folds_path.exists():
        return {"n_folds": 0, "folds": {}}
    data = json.loads(folds_path.read_text(encoding="utf-8"))
    folds = {}
    for meta in data.get("folds", []):
        folds[int(meta["fold"])] = {
            "url_mean": np.asarray(meta["url_mean"], dtype=np.float32),
            "url_std": np.asarray(meta["url_std"], dtype=np.float32),
            "dom_mean": np.asarray(meta["dom_mean"], dtype=np.float32),
            "dom_std": np.asarray(meta["dom_std"], dtype=np.float32),
        }
    return {"n_folds": data.get("n_folds", len(folds)), "folds": folds}


class _TTLCache:
    """Simple thread-safe time-to-live cache keyed by URL."""

    def __init__(self, ttl_seconds: float = 300.0):
        self.ttl = ttl_seconds
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        if self.ttl <= 0:
            return None
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if time.monotonic() - entry[0] > self.ttl:
                del self._data[key]
                return None
            return entry[1]

    def set(self, key: str, value) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            if len(self._data) > 4096:
                now = time.monotonic()
                self._data = {k: v for k, v in self._data.items() if now - v[0] <= self.ttl}
            self._data[key] = (time.monotonic(), value)


class PhishingPredictor:
    def __init__(self, checkpoint_path: str | Path | None = None,
                 temperature: float | None = None,
                 ensemble_folds: int = 1,
                 compute_feature_importance: bool = True,
                 extract_cache_ttl: float = 300.0):
        self.device = DEVICE
        self.temperature = temperature if temperature and temperature > 0 else _load_temperature()

        self.ensemble_folds = max(int(ensemble_folds), 1)
        self.compute_feature_importance = compute_feature_importance
        self.extract_cache = _TTLCache(ttl_seconds=extract_cache_ttl)

        self.fold_meta = _load_fold_meta()
        self.models = []          # list[(model, fold_scaler_or_None)]
        self._inference_lock = threading.Lock()

        if checkpoint_path is None:
            fold_ckpts = sorted(MODEL_DIR.glob("proposed_fold*_best.pt"))
            if not fold_ckpts:
                raise FileNotFoundError(
                    "No proposed_fold*_best.pt checkpoint found in "
                    f"{MODEL_DIR}. Train the model first or specify checkpoint_path."
                )
            checkpoint_path = str(fold_ckpts[0])
        self.checkpoint_path = Path(checkpoint_path)

        if not self.checkpoint_path.exists():
            raise FileNotFoundError(
                f"Checkpoint not found at {self.checkpoint_path}. "
                "Train the model first or download a pre-trained checkpoint."
            )

        self._load_models()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------
    def _resolve_fold_number(self, path: Path) -> int | None:
        m = re.search(r"fold(\d+)", path.name)
        return int(m.group(1)) if m else None

    def _load_models(self) -> None:
        """Load 1..N fold checkpoints. Each model uses its OWN fold scaler.

        Single-fold mode (default): the checkpoint's own fold scaler is used,
        mirroring training/evaluation. Ensemble mode averages logits across
        folds before temperature scaling.
        """
        start = time.monotonic()
        selected = [self.checkpoint_path]
        if self.ensemble_folds > 1:
            fold_no = self._resolve_fold_number(self.checkpoint_path)
            ckpts = sorted(MODEL_DIR.glob("proposed_fold*_best.pt"))
            picked = []
            if fold_no is not None:
                for ck in ckpts:
                    if self._resolve_fold_number(ck) == fold_no:
                        picked.append(ck)
            for ck in ckpts:
                if len(picked) >= self.ensemble_folds:
                    break
                if ck not in picked:
                    picked.append(ck)
            selected = picked or selected

        for path in selected:
            model = self._build_model(path)
            self.models.append((model, self._scaler_for(path)))

        # First model's tokenizer is shared for all folds
        if self.models:
            self.tokenizer = self.models[0][0].bert.tokenizer
        self._model_names = [p.name for p in selected]
        elapsed = time.monotonic() - start
        print(f"[predictor] Loaded {len(self.models)} fold model(s) in {elapsed:.1f}s")

    def _scaler_for(self, path: Path) -> dict | None:
        """Return per-fold normalization params for a checkpoint path."""
        fold_no = self._resolve_fold_number(path)
        if fold_no is None:
            return None
        return self.fold_meta["folds"].get(fold_no)

    def _build_model(self, path: Path):
        model = PhishingDetector().to(DEVICE)
        ckpt = torch.load(path, map_location=DEVICE, weights_only=False)
        if isinstance(ckpt, dict) and "model_state_dict" in ckpt:
            model.load_state_dict(ckpt["model_state_dict"])
        else:
            model.load_state_dict(ckpt)
        model.eval()
        self._maybe_quantize(model, path)
        return model

    def _maybe_quantize(self, model: PhishingDetector, path: Path) -> None:
        quant_path = path.with_suffix(".quantized.pt")
        try:
            if quant_path.exists():
                state = torch.load(quant_path, map_location=self.device, weights_only=False)
                model.load_state_dict(state, strict=False)
                model.eval()
                return
            import torch.ao.quantization as quant
            model.bert.apply(quant.QuantStub())
            model.bert = torch.quantization.quantize_dynamic(
                model.bert, {torch.nn.Linear}, dtype=torch.qint8, inplace=True
            )
            torch.save(model.state_dict(), quant_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Feature extraction helpers
    # ------------------------------------------------------------------
    def _extract_tabular(self, url: str) -> np.ndarray:
        feats = extract_url_features(url)
        return np.array([feats[k] for k in FEATURE_KEYS], dtype=np.float32)

    def _extract_html(self, html: str | None, base_url: str):
        if html is None or html.strip() == "":
            return np.zeros(DOM_DIM, dtype=np.float32), ""
        try:
            return extract_html_features(html, base_url)
        except Exception:
            return np.zeros(DOM_DIM, dtype=np.float32), ""

    def _cached_dns_whois(self, url: str) -> dict:
        cached = self.extract_cache.get("dns:" + url)
        if cached is not None:
            return cached
        val = self._extract_dns_whois(url)
        self.extract_cache.set("dns:" + url, val)
        return val

    def _cached_ssl_redirect(self, url: str) -> dict:
        cached = self.extract_cache.get("ssl:" + url)
        if cached is not None:
            return cached
        val = self._extract_ssl_redirect(url)
        self.extract_cache.set("ssl:" + url, val)
        return val

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

    def _normalize(self, tab_vec: np.ndarray, dom_vec: np.ndarray,
                   scaler: dict | None):
        """Apply the same normalization used during training (fold scaler)."""
        if scaler is None:
            return tab_vec, dom_vec
        tab = (tab_vec - scaler["url_mean"]) / np.maximum(scaler["url_std"], 1e-8)
        dom = (dom_vec - scaler["dom_mean"]) / np.maximum(scaler["dom_std"], 1e-8)
        return tab.astype(np.float32), dom.astype(np.float32)

    def _run_models(self, tab_tensor, input_ids, attn_mask, dom_tensor):
        """Run all loaded fold models, return raw logits tensor (mean over folds).

        Uses no_grad() UNLESS tab_tensor requires grad (feature-importance mode),
        so a single backward pass can still propagate to the tabular input.
        """
        logits = None
        grad_mode = tab_tensor.requires_grad
        with torch.no_grad() if not grad_mode else _noop_context():
            for model, _ in self.models:
                lo = model(tab_tensor, input_ids, attn_mask, dom_tensor)
                logits = lo if logits is None else logits + lo
        return logits / len(self.models)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def predict(self, url: str, html_content: str | None = None,
                explain: bool | None = None) -> dict:
        brand_info = {"has_brand_impersonation": False, "brands_detected": [],
                      "max_confidence": 0.0, "risk_score": 0.0}

        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = pool.submit(self._cached_dns_whois, url)
            ssl_future = pool.submit(self._cached_ssl_redirect, url)
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
        html_provided = html_content is not None
        if html_provided:
            dom_vec, clean_text = self._extract_html(html_content, effective_url)
        else:
            dom_vec, clean_text = np.zeros(DOM_DIM, dtype=np.float32), "[content not provided]"

        # analysis_quality: 'full' when real HTML was parsed, else 'limited'.
        html_parsed_ok = html_provided and clean_text.strip() != ""
        analysis_quality = "full" if html_parsed_ok else "limited"
        if html_provided and not html_parsed_ok:
            analysis_reason = "html parse failed or produced no text"
        elif not html_provided:
            analysis_reason = "no html content provided"
        else:
            analysis_reason = ""

        with self._inference_lock:
            self.model_eval()
            feature_importance = {}
            scaler = self.models[0][1] if self.models else None

            tab_norm, dom_norm = self._normalize(tab_vec, dom_vec, scaler)

            tab_tensor = torch.from_numpy(tab_norm).unsqueeze(0).to(DEVICE)
            dom_tensor = torch.from_numpy(dom_norm).unsqueeze(0).to(DEVICE)
            tokens = self.tokenizer(
                [clean_text], padding="max_length", truncation=True,
                max_length=MAX_SEQ_LEN, return_tensors="pt",
            )

            do_explain = self.compute_feature_importance if explain is None else explain
            compute_grad = do_explain and len(self.models) == 1
            if compute_grad:
                tab_tensor.requires_grad_(True)

            logits = self._run_models(
                tab_tensor,
                tokens["input_ids"].to(DEVICE),
                tokens["attention_mask"].to(DEVICE),
                dom_tensor,
            )
            raw_logit = float(logits.detach().cpu().item())
            logits = logits / self.temperature
            prob = torch.sigmoid(logits)
            prob_val = prob.item()

            if compute_grad:
                self.model_zero_grad()
                prob.backward()
                grads = tab_tensor.grad[0].cpu().numpy() if tab_tensor.grad is not None else np.zeros(TABULAR_DIM)
                feature_importance = {
                    FEATURE_KEYS[i]: round(float(grads[i] * tab_norm[i]), 4)
                    for i in range(TABULAR_DIM)
                }
                tab_tensor.requires_grad_(False)
            elif do_explain:
                # Ensemble mode: per-feature gradient would need separate runs;
                # report a neutral vector instead so the UI stays consistent.
                feature_importance = {k: 0.0 for k in FEATURE_KEYS}

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

        # Known-threat database (local blocklist + optional community feed)
        from api.threat_db import match_threat
        threat_match = match_threat(effective_url)

        # Multi-engine analysis (reputation/whitelist is a soft 5th engine)
        from api.engines import (ai_engine, dns_infra_engine, url_pattern_engine,
                                 brand_engine, reputation_engine, threat_db_engine,
                                 combine_engines)

        tab_features = self._get_feature_summary(tab_vec)
        ai_result = ai_engine(prob_val, tab_features, feature_importance, dns_whois, ssl_redirect)
        dns_result = dns_infra_engine(dns_whois, ssl_redirect)
        url_result = url_pattern_engine(effective_url, tab_features)
        br_result = brand_engine(effective_url, clean_text, brand_info)
        domain_status = _get_domain_status(effective_url, reg_domain) if reg_domain else {}
        rep_result = reputation_engine(domain_status)
        threat_result = threat_db_engine(threat_match)
        combined = combine_engines({
            "ai_model": ai_result,
            "dns_infrastructure": dns_result,
            "url_pattern": url_result,
            "brand": br_result,
            "reputation": rep_result,
            "threat_db": threat_result,
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
            "timestamp": _utc_timestamp(),
            "effective_url": effective_url if effective_url != url else None,
            "phishing_probability": round(prob_val, 4),
            "probability_band": _probability_band(raw_logit, self.temperature),
            "is_phishing": final_prob >= 0.5,
            "html_provided": html_provided,
            "analysis_quality": analysis_quality,
            "analysis_reason": analysis_reason,
            "model_name": ",".join(self._model_names),
            "ensemble_folds": len(self.models),
            "temperature": self.temperature,
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
            "threat_match": threat_match,
            "reputation": reputation if reputation else {},
            "subdomain_info": subdomain_info,
        }
        result_dict["explanation"] = generate_explanation(result_dict)
        return result_dict

    # Hooks so the inference lock can switch all loaded models into eval/zero-grad
    def model_eval(self) -> None:
        for model, _ in self.models:
            model.eval()

    def model_zero_grad(self) -> None:
        for model, _ in self.models:
            model.zero_grad()

    def _get_feature_summary(self, tab_vec: np.ndarray) -> dict:
        keys = FEATURE_KEYS
        values = tab_vec.tolist()
        return {k: round(v, 4) for k, v in zip(keys, values)}

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
            "timestamp": _utc_timestamp(),
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
            "timestamp": _utc_timestamp(),
            "dns_whois": dns_whois,
            "ssl_redirect": ssl_redirect,
            "suspicious_tld": 0,
            "type": "ip",
            "engine_results": combined,
            "aggregate_score": combined["final_score"],
            "engine_count": len(combined["engines"]),
        }


def _make_predictor() -> PhishingPredictor:
    """Build the global predictor from environment config (lazy on first use)."""
    import os
    def _env_int(name, default):
        try:
            return int(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    def _env_float(name, default):
        try:
            return float(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    def _env_bool(name, default):
        v = os.environ.get(name)
        if v is None:
            return default
        return v.strip().lower() in ("1", "true", "yes", "on")

    return PhishingPredictor(
        temperature=_env_float("PHISHGUARD_TEMPERATURE", 0) or None,
        ensemble_folds=_env_int("PHISHGUARD_ENSEMBLE_FOLDS", 1),
        compute_feature_importance=_env_bool("PHISHGUARD_COMPUTE_IMPORTANCE", True),
        extract_cache_ttl=_env_float("PHISHGUARD_EXTRACT_CACHE_TTL", 300.0),
    )


predictor = _make_predictor()
