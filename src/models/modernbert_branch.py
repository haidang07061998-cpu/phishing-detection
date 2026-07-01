"""
ModernBERT branch for HTML text encoding.

Loads answerdotai/ModernBERT-base from HuggingFace, extracts the [CLS]
embedding (768-dim), and passes it through a projection head.

Freezes the first 8 encoder layers; only fine-tunes the last 4 layers
and the projection head.
"""

import torch
import torch.nn as nn

# Patch torch.compile for Windows compatibility
# ModernBERT uses @torch.compile(dynamic=True) decorator which breaks on Windows
_orig_compile = getattr(torch, 'compile', None)
if _orig_compile is not None:
    try:
        torch.compile = lambda **kwargs: lambda obj: obj
    except Exception:
        pass

from transformers import AutoModel, AutoTokenizer


class ModernBERTBranch(nn.Module):
    """
    ModernBERT wrapper for phishing text classification.

    Args:
        model_name: HuggingFace model name (default answerdotai/ModernBERT-base).
        max_length: Maximum token length (default 512 for VRAM efficiency).
        freeze_layers: Number of initial encoder layers to freeze (default 8).
        projection_dim: Output dimension of the projection head (default 768).
        dropout: Dropout rate (default 0.1).
    """

    def __init__(
        self,
        model_name: str = "answerdotai/ModernBERT-base",
        max_length: int = 512,
        freeze_layers: int = 8,
        projection_dim: int = 768,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.bert = AutoModel.from_pretrained(model_name)
        self.hidden_dim = self.bert.config.hidden_size  # typically 768

        # Freeze specified initial layers
        enc = (getattr(self.bert, 'encoder', None) or
               getattr(self.bert, 'model', None) or self.bert)
        layers = getattr(enc, 'layer', None) or getattr(enc, 'layers', None) or []
        for i, layer in enumerate(layers):
            if i < freeze_layers:
                for param in layer.parameters():
                    param.requires_grad = False

        # Projection head — matches Kaggle proposed notebook naming & structure
        self.proj = nn.Sequential(
            nn.Linear(self.hidden_dim, projection_dim),
            nn.ReLU(),
            nn.LayerNorm(projection_dim),
        )

    def forward(
        self, input_ids: torch.Tensor, attention_mask: torch.Tensor
    ) -> torch.Tensor:
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls_embedding = outputs.last_hidden_state[:, 0, :]
        out = self.proj(cls_embedding)
        return out

    def tokenize(self, texts: list[str]) -> dict:
        return self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )


if __name__ == "__main__":
    model = ModernBERTBranch()
    print(f"BERT hidden dim: {model.hidden_dim}")
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total params: {total:,}")
    print(f"Trainable params: {trainable:,}")
    print(f"Frozen: {total - trainable:,}")

    texts = ["This is a test phishing page with login form."]
    tokens = model.tokenize(texts)
    out = model(tokens["input_ids"], tokens["attention_mask"])
    print(f"Output shape: {out.shape}")
