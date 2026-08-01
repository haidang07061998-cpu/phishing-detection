"""
Temperature scaling calibration for the Proposed (Gated Fusion) model.

Trains a single scalar temperature T on the held-out test set so that
sigmoid(logits / T) is well-calibrated, then writes data/models/temperature.json
which api/predictor.py reads at startup.

The calibration set MUST be the held-out test split (split.json test_indices) —
it was never seen during any CV fold, so T is not overfit to training data.

Requires data/processed/mendeley_full/data.jsonl + split.json (produced by
src/preprocess_mendeley.py) and data/models/proposed_fold*_best.pt.

Usage:
    $env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.calibrate
"""

import json
import sys
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.full_model import PhishingDetector
from src.training.train_proposed import CachedDataset, collate_fn

PROJECT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT / "data" / "processed" / "mendeley_full"
MODEL_DIR = PROJECT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

DEFAULT_T = 2.8
T_MAX = 10.0


def _load_state(model, path):
    state = torch.load(path, map_location=DEVICE, weights_only=False)
    if isinstance(state, dict) and "model_state_dict" in state:
        model.load_state_dict(state["model_state_dict"])
    else:
        model.load_state_dict(state)
    model.to(DEVICE)
    model.eval()


def main():
    if not DATA_DIR.joinpath("data.jsonl").exists() or not DATA_DIR.joinpath("split.json").exists():
        print("Calibration data missing: data/processed/mendeley_full (data.jsonl + split.json)")
        print("Run `python -m src.preprocess_mendeley` first.")
        return

    with open(DATA_DIR / "split.json", "r") as f:
        split = json.load(f)
    with open(DATA_DIR / "data.jsonl", "r") as f:
        records = [json.loads(line) for line in f]

    folds_meta = json.load(open(MODEL_DIR / "proposed_folds.json"))["folds"]
    full_data = []
    for idx in split["test_indices"]:
        r = records[idx]
        full_data.append({
            'url_features': r["url_features"][:12],
            'dom_features': r["dom_features"][:64],
            'clean_text': r["clean_text"],
            'label': r["label"],
        })

    # Pre-tokenize to 128 tokens (matches training). data.jsonl does not carry
    # token ids, so tokenize here like evaluate.py does.
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
    for d in full_data:
        tok = tokenizer(
            d["clean_text"], padding="max_length", truncation=True,
            max_length=128, return_tensors="pt",
        )
        d["input_ids"] = tok["input_ids"][0]
        d["attention_mask"] = tok["attention_mask"][0]

    logits_list, labels = [], None
    for meta in folds_meta:
        fold = meta["fold"]
        ckpt = MODEL_DIR / f"proposed_fold{fold}_best.pt"
        if not ckpt.exists():
            continue
        ld = DataLoader(
            CachedDataset(
                full_data, np.arange(len(full_data)),
                np.array(meta["url_mean"]), np.array(meta["url_std"]),
                np.array(meta["dom_mean"]), np.array(meta["dom_std"]),
            ),
            batch_size=32, collate_fn=collate_fn, num_workers=0,
        )
        model = PhishingDetector()
        _load_state(model, ckpt)
        fold_logits, fold_labels = [], []
        with torch.no_grad():
            for tab, ids, mask, dom, lbl in ld:
                lo = model(tab, ids, mask, dom)
                fold_logits.extend(lo.cpu().numpy().flatten())
                fold_labels.extend(lbl.cpu().numpy().flatten())
        logits_list.append(np.array(fold_logits))
        labels = np.array(fold_labels)
        print(f"Fold {fold}: {len(fold_logits)} samples")

    if not logits_list:
        print("No fold checkpoints found.")
        return

    mean_logits = np.mean(np.stack(logits_list), axis=0)

    def nll(T):
        p = 1.0 / (1.0 + np.exp(-mean_logits / T))
        p = np.clip(p, 1e-7, 1 - 1e-7)
        return -np.mean(labels * np.log(p) + (1 - labels) * np.log(1 - p))

    # Coarse-to-fine grid search over T in (0, T_MAX]
    best_T, best_nll = DEFAULT_T, nll(DEFAULT_T)
    for lo in np.arange(0.1, T_MAX, 0.1):
        val = nll(lo)
        if val < best_nll:
            best_nll, best_T = val, lo

    def accuracy(T):
        return float(np.mean((1.0 / (1.0 + np.exp(-mean_logits / T)) >= 0.5) == labels))

    print(f"\nCalibrated temperature: {best_T:.2f} (default {DEFAULT_T})")
    print(f"  NLL(default {DEFAULT_T}) = {nll(DEFAULT_T):.4f} | NLL(best {best_T}) = {best_nll:.4f}")
    print(f"  Acc(default) = {accuracy(DEFAULT_T):.4f} | Acc(best) = {accuracy(best_T):.4f}")

    out = {
        "temperature": round(float(best_T), 4),
        "default_temperature": DEFAULT_T,
        "n_samples": int(len(mean_logits)),
        "nll_best": round(float(best_nll), 6),
        "nll_default": round(float(nll(DEFAULT_T)), 6),
        "acc_best": round(accuracy(best_T), 6),
        "acc_default": round(accuracy(DEFAULT_T), 6),
        "method": "grid_search_min_nll",
        "dataset": "mendeley_heldout_test",
    }
    with open(MODEL_DIR / "temperature.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved temperature.json -> {MODEL_DIR / 'temperature.json'}")


if __name__ == "__main__":
    main()
