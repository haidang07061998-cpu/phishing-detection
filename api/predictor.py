import sys
from pathlib import Path
import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.full_model import PhishingDetector, load_checkpoint
from src.features.url_extractor import extract_url_features
from src.features.html_dom_extractor import extract_html_features
from src.brand_detection import get_brand_risk_score

PROJECT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

FEATURE_KEYS = [
    "url_length", "domain_length", "path_length", "entropy",
    "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
    "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
]
TABULAR_DIM = len(FEATURE_KEYS)


class PhishingPredictor:
    def __init__(self, checkpoint_path: str | Path | None = None):
        if checkpoint_path is None:
            # Use first available fold checkpoint
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
        self.model.eval()
        with torch.no_grad():
            tab_vec = self._extract_tabular(url)
            dom_vec, clean_text = self._extract_html(html_content, url) if html_content else (
                np.zeros(64, dtype=np.float32), "[content not provided]"
            )

            tab_tensor = torch.from_numpy(tab_vec).unsqueeze(0).to(DEVICE)
            dom_tensor = torch.from_numpy(dom_vec).unsqueeze(0).to(DEVICE)
            tokens = self.tokenizer(
                [clean_text], padding=True, truncation=True,
                max_length=512, return_tensors="pt",
            )

            logits = self.model(
                tab_tensor,
                tokens["input_ids"].to(DEVICE),
                tokens["attention_mask"].to(DEVICE),
                dom_tensor,
            )
            prob = torch.sigmoid(logits).item()

        brand_info = get_brand_risk_score(url, clean_text)

        return {
            "url": url,
            "phishing_probability": round(prob, 4),
            "is_phishing": prob >= 0.5,
            "html_provided": html_content is not None,
            "brand_analysis": brand_info,
            "features": self._get_feature_summary(tab_vec),
        }

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


predictor = PhishingPredictor()
