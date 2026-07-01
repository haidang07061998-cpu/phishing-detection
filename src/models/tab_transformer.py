"""
TabTransformer — matching Kaggle notebook implementation exactly.
Supports both standalone classification and embedding mode (for GatedFusion).

Kaggle checkpoint keys (compatible):
    embs.*.e.weight, embs.*.e.bias
    attn.in_proj_weight, attn.in_proj_bias, attn.out_proj.weight, attn.out_proj.bias
    n1.weight, n1.bias, n2.weight, n2.bias
    ff.0.weight, ff.0.bias, ff.2.weight, ff.2.bias, ff.4.weight, ff.4.bias
    proj.weight, proj.bias
    cls.0.weight, cls.0.bias, cls.3.weight, cls.3.bias  (if classifier=True)
"""

import torch
import torch.nn as nn


class FeatureEmbedding(nn.Module):
    def __init__(self, d=32):
        super().__init__()
        self.e = nn.Linear(1, d)

    def forward(self, x):
        return self.e(x.unsqueeze(-1))


class TabTransformer(nn.Module):
    def __init__(self, nf=29, ed=32, nh=4, ff_hidden=256, od=128, dp=0.1,
                 classifier=True, proj_norm=False):
        super().__init__()
        self.classifier = classifier
        self.embs = nn.ModuleList([FeatureEmbedding(ed) for _ in range(nf)])
        self.attn = nn.MultiheadAttention(ed, nh, batch_first=True, dropout=dp)
        self.n1 = nn.LayerNorm(ed)
        self.n2 = nn.LayerNorm(ed)
        self.ff = nn.Sequential(
            nn.Linear(ed, ff_hidden), nn.GELU(), nn.Dropout(dp),
            nn.Linear(ff_hidden, ed), nn.Dropout(dp),
        )
        if proj_norm:
            self.proj = nn.Sequential(
                nn.Linear(ed * nf, od),
                nn.LayerNorm(od),
            )
        else:
            self.proj = nn.Linear(ed * nf, od)
        if classifier:
            self.cls = nn.Sequential(
                nn.Linear(od, 64), nn.ReLU(), nn.Dropout(dp), nn.Linear(64, 1),
            )

    def forward(self, x):
        h = torch.stack([e(x[:, i]) for i, e in enumerate(self.embs)], dim=1)
        a, _ = self.attn(h, h, h)
        h = self.n1(h + a)
        h = self.n2(h + self.ff(h))
        out = self.proj(h.reshape(h.size(0), -1))
        if self.classifier:
            return self.cls(out)
        return out
