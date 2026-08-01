"""
Temperature scaling calibration for the Proposed (Gated Fusion) model.

Splits the held-out test set into two disjoint halves:

- **calibration set** — used to fit the single scalar temperature T
  (grid search over T minimizing negative log-likelihood).
- **final untouched test set** — NEVER used for any hyper-parameter fitting
  (model or temperature). Used only to report the final calibrated metrics.

This follows the ML standard "train / validation / test" separation: the model
was trained on the train split (5-fold CV), T is fit on the calibration split,
and the final numbers are reported on the untouched test split. Optimizing T on
the same set you later report quality on would overfit the temperature.

Writes data/models/temperature.json which api/predictor.py reads at startup.

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

# Fixed fraction of the held-out test used for CALIBRATION; the remainder is the
# untouched final test set. Kept as a plain split (not a separate seed shuffle)
# so results are deterministic and reproducible.
CALIBRATION_FRACTION = 0.5


def _load_state(model, path):
    state = torch.load(path, map_location=DEVICE, weights_only=False)
    if isinstance(state, dict) and "model_state_dict" in state:
        model.load_state_dict(state["model_state_dict"])
    else:
        model.load_state_dict(state)
    model.to(DEVICE)
    model.eval()


def _load_records(split: dict) -> tuple[list, np.ndarray]:
    """Load calibration + final-test records and their labels from split.json.

    The held-out test indices are deterministically divided in two:
    calibration (first CALIBRATION_FRACTION) and final test (the rest).
    """
    with open(DATA_DIR / "data.jsonl", "r") as f:
        records = [json.loads(line) for line in f]

    test_idx = np.asarray(split["test_indices"], dtype=int)
    n_cal = max(1, int(len(test_idx) * CALIBRATION_FRACTION))
    cal_idx = test_idx[:n_cal]
    test_idx_final = test_idx[n_cal:]

    def _build(indices: np.ndarray) -> list[dict]:
        out = []
        for idx in indices:
            r = records[int(idx)]
            out.append({
                'url_features': r["url_features"][:12],
                'dom_features': r["dom_features"][:64],
                'clean_text': r["clean_text"],
                'label': r["label"],
            })
        return out

    return _build(cal_idx), _build(test_idx_final)


def _tokenize(dataset: list[dict], tokenizer) -> None:
    """Pre-tokenize to 128 tokens (matches training)."""
    for d in dataset:
        tok = tokenizer(
            d["clean_text"], padding="max_length", truncation=True,
            max_length=128, return_tensors="pt",
        )
        d["input_ids"] = tok["input_ids"][0]
        d["attention_mask"] = tok["attention_mask"][0]


def _mean_logits(dataset: list[dict], folds_meta: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    """Forward all fold models, return mean logits + labels over the dataset."""
    logits_list = []
    for meta in folds_meta:
        fold = meta["fold"]
        ckpt = MODEL_DIR / f"proposed_fold{fold}_best.pt"
        if not ckpt.exists():
            continue
        ld = DataLoader(
            CachedDataset(
                dataset, np.arange(len(dataset)),
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
        print(f"  Fold {fold}: {len(fold_logits)} samples")
    if not logits_list:
        raise RuntimeError("No fold checkpoints found.")
    return np.mean(np.stack(logits_list), axis=0), labels


def _nll(logits: np.ndarray, labels: np.ndarray, T: float) -> float:
    p = 1.0 / (1.0 + np.exp(-logits / T))
    p = np.clip(p, 1e-7, 1 - 1e-7)
    return float(-np.mean(labels * np.log(p) + (1 - labels) * np.log(1 - p)))


def _accuracy(logits: np.ndarray, labels: np.ndarray, T: float) -> float:
    return float(np.mean((1.0 / (1.0 + np.exp(-logits / T)) >= 0.5) == labels))


def main():
    if not DATA_DIR.joinpath("data.jsonl").exists() or not DATA_DIR.joinpath("split.json").exists():
        print("Calibration data missing: data/processed/mendeley_full (data.jsonl + split.json)")
        print("Run `python -m src.preprocess_mendeley` first.")
        return

    with open(DATA_DIR / "split.json", "r") as f:
        split = json.load(f)
    folds_meta = json.load(open(MODEL_DIR / "proposed_folds.json"))["folds"]

    print(f"Splitting held-out test ({len(split['test_indices'])} rows) into "
          f"calibration ({int(len(split['test_indices']) * CALIBRATION_FRACTION)}) + "
          f"untouched final test.")
    cal_data, test_data = _load_records(split)

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
    _tokenize(cal_data, tokenizer)
    _tokenize(test_data, tokenizer)

    print("Forwarding calibration set...")
    cal_logits, cal_labels = _mean_logits(cal_data, folds_meta)
    print("Forwarding final test set...")
    test_logits, test_labels = _mean_logits(test_data, folds_meta)

    # Fit T ONLY on the calibration set.
    def nll_cal(T):
        return _nll(cal_logits, cal_labels, T)

    best_T, best_nll = DEFAULT_T, nll_cal(DEFAULT_T)
    for lo in np.arange(0.1, T_MAX, 0.1):
        val = nll_cal(lo)
        if val < best_nll:
            best_nll, best_T = val, lo

    print(f"\nCalibrated temperature: {best_T:.2f} (default {DEFAULT_T})")
    print(f"  [calibration]  NLL(default)={nll_cal(DEFAULT_T):.4f} | NLL(best)={best_nll:.4f}")
    print(f"  [calibration]  Acc(default)={_accuracy(cal_logits, cal_labels, DEFAULT_T):.4f} | "
          f"Acc(best)={_accuracy(cal_logits, cal_labels, best_T):.4f}")
    print(f"  [final test]   Acc(default)={_accuracy(test_logits, test_labels, DEFAULT_T):.4f} | "
          f"Acc(best)={_accuracy(test_logits, test_labels, best_T):.4f}  "
          f"(untouched by calibration)")

    out = {
        "temperature": round(float(best_T), 4),
        "default_temperature": DEFAULT_T,
        "n_calibration": int(len(cal_labels)),
        "n_final_test": int(len(test_labels)),
        "calibration_fraction": CALIBRATION_FRACTION,
        "nll_best": round(float(best_nll), 6),
        "nll_default": round(float(nll_cal(DEFAULT_T)), 6),
        "calibration_acc_best": round(_accuracy(cal_logits, cal_labels, best_T), 6),
        "calibration_acc_default": round(_accuracy(cal_logits, cal_labels, DEFAULT_T), 6),
        "final_test_acc_best": round(_accuracy(test_logits, test_labels, best_T), 6),
        "final_test_acc_default": round(_accuracy(test_logits, test_labels, DEFAULT_T), 6),
        "method": "grid_search_min_nll_on_calibration_set",
        "dataset": "mendeley_heldout_test (calibration split)",
    }
    with open(MODEL_DIR / "temperature.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved temperature.json -> {MODEL_DIR / 'temperature.json'}")


if __name__ == "__main__":
    main()
