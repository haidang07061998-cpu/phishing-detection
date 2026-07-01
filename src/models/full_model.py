"""
Full PhishingDetector model combining TabTransformer, ModernBERT,
DOM features, and Gated Fusion.

Architecture:
    tabular (29) --> TabTransformer --> 128
    HTML text   --> ModernBERT     --> 768
    DOM (64)    --> Linear+ReLU    -->  64
                      |---concat---|> 832
    [128, 832] --> GatedFusion --> 960 --> FC head --> 1 (sigmoid)
"""

import re
import json
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import torch
import torch.nn as nn

from src.models.tab_transformer import TabTransformer
from src.models.modernbert_branch import ModernBERTBranch
from src.models.gated_fusion import GatedFusion
from src.features.url_extractor import extract_url_features
from src.features.html_dom_extractor import extract_html_features


def _get_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


class PhishingDetector(nn.Module):
    """
    End-to-end phishing detection model.

    Args:
        tabular_dim: Number of tabular input features (default 29).
        tab_embedding_dim: Feature embedding dimension for TabTransformer (default 32).
        tab_heads: Number of attention heads (default 4).
        tab_output_dim: TabTransformer output dimension (default 128).
        modernbert_model: HuggingFace model name (default answerdotai/ModernBERT-base).
        modernbert_max_length: Max token length (default 512).
        modernbert_projection: Projection dimension (default 768).
        dom_dim: DOM feature dimension (default 64).
        fusion_hidden: Gated Fusion hidden dimension (default 960).
    """

    def __init__(
        self,
        tabular_dim: int = 12,
        tab_embedding_dim: int = 32,
        tab_heads: int = 4,
        tab_output_dim: int = 128,
        modernbert_model: str = "answerdotai/ModernBERT-base",
        modernbert_max_length: int = 512,
        modernbert_projection: int = 768,
        dom_dim: int = 64,
        fusion_hidden: int = 960,
    ):
        super().__init__()
        self.tabular_dim = tabular_dim
        self.dom_dim = dom_dim
        self.fusion_hidden = fusion_hidden

        # Branches
        # Note: attribute names match Kaggle proposed notebook exactly
        # for direct state_dict loading from checkpoints
        self.tab = TabTransformer(
            nf=tabular_dim,
            ed=tab_embedding_dim,
            nh=tab_heads,
            ff_hidden=128,
            od=tab_output_dim,
            classifier=False,
            proj_norm=True,
        )

        self.bert = ModernBERTBranch(
            model_name=modernbert_model,
            max_length=modernbert_max_length,
            projection_dim=modernbert_projection,
        )

        # DOM feature projector
        self.dom = nn.Sequential(
            nn.Linear(dom_dim, dom_dim),
            nn.ReLU(),
            nn.LayerNorm(dom_dim),
        )

        # Gated Fusion
        html_dim = modernbert_projection + dom_dim
        self.fusion = GatedFusion(
            url_dim=tab_output_dim,
            html_dim=html_dim,
            hidden_dim=fusion_hidden,
        )

        # Classification head
        self.cls = nn.Sequential(
            nn.Linear(fusion_hidden, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
        )

    def forward(
        self,
        tabular_features: torch.Tensor,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        dom_features: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            tabular_features: (batch, tabular_dim) — URL+DNS+SSL+WHOIS.
            input_ids: (batch, seq_len) — tokenized HTML text.
            attention_mask: (batch, seq_len).
            dom_features: (batch, dom_dim) — DOM vector.

        Returns:
            Tensor (batch, 1) with raw logits (no sigmoid).
            Use torch.sigmoid() for probabilities, or BCEWithLogitsLoss for training.
        """
        v_url = self.tab(tabular_features)
        v_cls = self.bert(input_ids, attention_mask)
        v_dom = self.dom(dom_features)
        v_html = torch.cat([v_cls, v_dom], dim=-1)

        v_fused = self.fusion(v_url, v_html)
        logits = self.cls(v_fused)
        return logits

    def predict_proba(self, url: str) -> float:
        """
        Real-time inference for a single URL.

        Extracts all features on-the-fly and runs the model.

        Args:
            url: Full URL string.

        Returns:
            Phishing probability in [0, 1].
        """
        device = next(self.parameters()).device
        self.eval()

        # URL features (12-dim, no padding needed for Mendeley model)
        url_feats = extract_url_features(url)
        tab_vector = np.array([
            url_feats[k] for k in [
                "url_length", "domain_length", "path_length", "entropy",
                "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
                "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
            ]
        ], dtype=np.float32)
        tab_tensor = torch.from_numpy(tab_vector).unsqueeze(0).to(device)

        # DOM and text — use placeholders if page not fetched yet
        dom_vec = np.zeros(64, dtype=np.float32)
        dom_tensor = torch.from_numpy(dom_vec).unsqueeze(0).to(device)

        text = "[placeholder - page not crawled in predict_proba]"
        tokens = self.bert.tokenize([text])
        input_ids = tokens["input_ids"].to(device)
        attn_mask = tokens["attention_mask"].to(device)

        with torch.no_grad():
            logits = self.forward(tab_tensor, input_ids, attn_mask, dom_tensor)
        return float(torch.sigmoid(logits).item())


def load_checkpoint(path: str | Path, device: str = "cpu") -> PhishingDetector:
    """
    Load a trained PhishingDetector from a checkpoint file.

    Supports both Kaggle format (raw state_dict) and local format
    (dict with 'model_state_dict' key).

    Args:
        path: Path to .pt checkpoint.
        device: Device to load the model onto.

    Returns:
        PhishingDetector in eval mode.
    """
    model = PhishingDetector()
    state = torch.load(path, map_location=device, weights_only=False)
    if isinstance(state, dict) and "model_state_dict" in state:
        model.load_state_dict(state["model_state_dict"])
    else:
        model.load_state_dict(state)
    model.to(device)
    model.eval()
    return model


if __name__ == "__main__":
    model = PhishingDetector()
    batch = 2
    tab = torch.randn(batch, 29)
    ids = torch.randint(0, 1000, (batch, 128))
    mask = torch.ones(batch, 128)
    dom = torch.randn(batch, 64)
    out = model(tab, ids, mask, dom)
    print(f"Output shape: {out.shape}")
    print(f"Output values: {out.squeeze().tolist()}")
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total params: {total:,}")
    print(f"Trainable params: {trainable:,}")
