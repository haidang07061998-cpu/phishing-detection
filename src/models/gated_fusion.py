"""
Gated Fusion module for combining URL features and HTML features.

The URL branch produces a 128-dim vector; the HTML branch (ModernBERT + DOM)
produces an 832-dim vector (768 CLS + 64 DOM).

This module applies a learned gate to fuse the two representations.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class GatedFusion(nn.Module):
    """
    Gated fusion of URL and HTML feature vectors.

    Args:
        url_dim: Dimension of URL features (default 128).
        html_dim: Dimension of HTML features (default 832).
        hidden_dim: Hidden dimension for the gate (default 960).
    """

    def __init__(
        self,
        url_dim: int = 128,
        html_dim: int = 832,
        hidden_dim: int = 960,
    ):
        super().__init__()
        self.url_dim = url_dim
        self.html_dim = html_dim
        self.hidden_dim = hidden_dim

        # Project URL to hidden_dim
        self.url_proj = nn.Linear(url_dim, hidden_dim)

        # Gate
        self.gate = nn.Sequential(
            nn.Linear(hidden_dim + html_dim, hidden_dim),
            nn.Sigmoid(),
        )

        # Output projection
        self.out = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
        )

    def forward(
        self, v_url: torch.Tensor, v_html: torch.Tensor
    ) -> torch.Tensor:
        """
        Args:
            v_url: Tensor of shape (batch, url_dim).
            v_html: Tensor of shape (batch, html_dim).

        Returns:
            Fused tensor of shape (batch, hidden_dim).
        """
        # Project URL to hidden_dim
        v_url_proj = self.url_proj(v_url)

        # Concatenate for gate computation
        gate_input = torch.cat([v_url_proj, v_html], dim=-1)
        gate = self.gate(gate_input)

        # Fuse: gate * v_url_proj + (1 - gate) * pad(v_html)
        v_html_proj = F.pad(v_html, (0, self.hidden_dim - v_html.size(-1)))
        v_fused = gate * v_url_proj + (1 - gate) * v_html_proj

        out = self.out(v_fused)
        return out


if __name__ == "__main__":
    model = GatedFusion()
    v_url = torch.randn(4, 128)
    v_html = torch.randn(4, 832)
    out = model(v_url, v_html)
    print(f"v_url shape:  {v_url.shape}")
    print(f"v_html shape: {v_html.shape}")
    print(f"Output shape: {out.shape}")
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Params: {total_params:,}")
