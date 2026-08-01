"""
Evaluate all 3 trained models and produce comparison JSON files.
Matches kaggle_compare.ipynb logic for local evaluation.
"""

import json, sys
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.full_model import PhishingDetector
from src.models.tab_transformer import TabTransformer

PROJECT = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_model_weights(model, path):
    state = torch.load(path, map_location=DEVICE, weights_only=False)
    if isinstance(state, dict) and "model_state_dict" in state:
        model.load_state_dict(state["model_state_dict"])
    else:
        model.load_state_dict(state)
    model.to(DEVICE)
    model.eval()


def compute_metrics(labels, preds):
    pb = (preds >= 0.5).astype(int)
    fpr_val = 0.0
    if len(np.unique(labels)) > 1:
        cm = confusion_matrix(labels, pb)
        tn, fp = cm[0, 0], cm[0, 1]
        fpr_val = round(fp / max(tn + fp, 1), 4)
    return {
        "accuracy":  accuracy_score(labels, pb),
        "precision": precision_score(labels, pb, zero_division=0),
        "recall":    recall_score(labels, pb, zero_division=0),
        "f1":        f1_score(labels, pb, zero_division=0),
        "auc":       roc_auc_score(labels, preds) if len(np.unique(labels)) > 1 else 0.0,
        "fpr":       fpr_val,
    }


def _restore_scaler(meta, n_features):
    """Rebuild a StandardScaler from per-fold params saved during training."""
    from sklearn.preprocessing import StandardScaler
    sc = StandardScaler()
    sc.mean_ = np.asarray(meta["scaler_mean"], dtype=np.float64)
    sc.scale_ = np.asarray(meta["scaler_scale"], dtype=np.float64)
    sc.n_features_in_ = n_features
    return sc


def evaluate_baseline1():
    import pandas as pd
    from src.training.train_baseline1 import ISCX_FEATURES_NUM, ISCX_FEATURES_CAT, TABULAR_DIM

    df = pd.read_csv(PROJECT / "data" / "raw" / "ISCXURL2016.csv", encoding="utf-8", low_memory=False)
    avail_num = [c for c in ISCX_FEATURES_NUM if c in df.columns]
    avail_cat = [c for c in ISCX_FEATURES_CAT if c in df.columns]

    # Same raw feature pipeline as train_baseline1.py (scaler applied per-fold)
    X_num = df[avail_num].copy().replace([np.inf, -np.inf], np.nan)
    for c in X_num.columns:
        X_num[c] = pd.to_numeric(X_num[c], errors="coerce")
    X_num = X_num.fillna(0).astype(np.float32).values

    if avail_cat:
        X_cat = df[avail_cat].fillna(0).astype(int).clip(lower=0).values.astype(np.float32)
    else:
        X_cat = None

    y = (df['URL_Type_obf_Type'].astype(str).str.strip().str.lower() == 'phishing').astype(int).values.astype(np.float32)

    def build_features(num, cat):
        if cat is not None:
            feat = np.concatenate([num, cat], axis=1)
        else:
            feat = num
        if feat.shape[1] < TABULAR_DIM:
            pad = np.zeros((feat.shape[0], TABULAR_DIM - feat.shape[1]), dtype=np.float32)
            feat = np.concatenate([feat, pad], axis=1)
        return feat.astype(np.float32)

    folds_path = MODEL_DIR / "baseline1_folds.json"
    if not folds_path.exists():
        print("baseline1_folds.json not found - run train_baseline1.py first")
        return {"model": "Baseline 1 - TabTransformer (ISCX)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    folds_meta = json.load(open(folds_path))["folds"]

    # Each fold model is evaluated ONLY on its own hold-out fold (no leakage)
    fold_preds, fold_labels = [], []
    for meta in folds_meta:
        fold = meta["fold"]
        ckpt = MODEL_DIR / f"baseline1_fold{fold}.pt"
        if not ckpt.exists():
            continue
        sc = _restore_scaler(meta, X_num.shape[1])
        te_idx = np.asarray(meta["test_indices"], dtype=np.int64)
        X_te = build_features(sc.transform(X_num[te_idx]).astype(np.float32), None if X_cat is None else X_cat[te_idx])
        y_te = y[te_idx]
        ds = torch.utils.data.TensorDataset(torch.from_numpy(X_te), torch.from_numpy(y_te).unsqueeze(1))
        loader = DataLoader(ds, batch_size=256)

        model = TabTransformer(nf=X_te.shape[1], classifier=True)
        load_model_weights(model, ckpt)
        preds, labs = [], []
        with torch.no_grad():
            for Xb, yb in loader:
                logits = model(Xb.to(DEVICE))
                preds.extend(torch.sigmoid(logits).cpu().numpy())
                labs.extend(yb.numpy())
        fold_preds.append(np.array(preds))
        fold_labels.append(np.array(labs))

    if not fold_preds:
        return {"model": "Baseline 1 - TabTransformer (ISCX)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    metrics_list = [compute_metrics(fl, fp) for fl, fp in zip(fold_labels, fold_preds)]
    avg = {k: np.mean([m[k] for m in metrics_list]) for k in metrics_list[0]}
    std = {k: np.std([m[k] for m in metrics_list]) for k in metrics_list[0]}
    results = {"model": "Baseline 1 - TabTransformer (ISCX)", **avg, **{k + "_std": float(std[k]) for k in std}}
    with open(MODEL_DIR / "evaluation_baseline1.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Baseline 1: Acc={avg['accuracy']:.4f}, AUC={avg['auc']:.4f}, F1={avg['f1']:.4f}")
    return results


def evaluate_baseline2():
    import pandas as pd
    from src.training.train_baseline2 import extract_url_features, URL_FEATURE_KEYS, TABULAR_DIM

    SEED = 42

    # Reconstruct the SAME 50k sampled df as train_baseline2.py / kaggle_baseline2.ipynb
    df = pd.read_csv(PROJECT / "data" / "raw" / "mendeley" / "index.csv", encoding="utf-8")
    SAMPLE_SIZE = 50000
    n_each = SAMPLE_SIZE // 2
    df_p = df[df['result']==1].sample(n=min(n_each, (df['result']==1).sum()), random_state=SEED)
    df_g = df[df['result']==0].sample(n=min(n_each, (df['result']==0).sum()), random_state=SEED)
    df = pd.concat([df_p, df_g]).sample(frac=1, random_state=SEED).reset_index(drop=True)

    url_vectors = []
    for _, row in df.iterrows():
        feats = extract_url_features(str(row['url']).strip())
        vec = [feats[k] for k in URL_FEATURE_KEYS]
        vec += [-1.0] * (TABULAR_DIM - len(vec))
        url_vectors.append(vec)

    X = np.array(url_vectors, dtype=np.float32)
    y = df['result'].values.astype(np.float32)

    folds_path = MODEL_DIR / "baseline2_folds.json"
    splits_path = MODEL_DIR / "baseline2_splits.json"
    if not folds_path.exists():
        print("baseline2_folds.json not found - run train_baseline2.py first")
        return {"model": "Baseline 2 - TabTransformer (Mendeley URL)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    folds_meta = json.load(open(folds_path))["folds"]
    test_idx = np.asarray(json.load(open(splits_path))["test_indices"], dtype=np.int64) if splits_path.exists() else None

    # Each fold model is evaluated on its own CV hold-out fold AND on the held-out test set
    cv_preds, cv_labels, test_preds, test_labels = [], [], [], []
    for meta in folds_meta:
        fold = meta["fold"]
        ckpt = MODEL_DIR / f"baseline2_fold{fold}.pt"
        if not ckpt.exists():
            continue
        sc = _restore_scaler(meta, X.shape[1])

        def run(idx):
            X_te = sc.transform(X[idx]).astype(np.float32)
            ds = torch.utils.data.TensorDataset(torch.from_numpy(X_te), torch.from_numpy(y[idx]).unsqueeze(1))
            loader = DataLoader(ds, batch_size=256)
            model = TabTransformer(nf=X_te.shape[1], classifier=True)
            load_model_weights(model, ckpt)
            preds, labs = [], []
            with torch.no_grad():
                for Xb, yb in loader:
                    logits = model(Xb.to(DEVICE))
                    preds.extend(torch.sigmoid(logits).cpu().numpy())
                    labs.extend(yb.numpy())
            return np.array(preds), np.array(labs)

        p, l = run(np.asarray(meta["test_indices"], dtype=np.int64))
        cv_preds.append(p); cv_labels.append(l)
        if test_idx is not None:
            p, l = run(test_idx)
            test_preds.append(p); test_labels.append(l)

    if not cv_preds:
        return {"model": "Baseline 2 - TabTransformer (Mendeley URL)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    cv_metrics = [compute_metrics(fl, fp) for fl, fp in zip(cv_labels, cv_preds)]
    avg = {k: np.mean([m[k] for m in cv_metrics]) for k in cv_metrics[0]}
    std = {k: np.std([m[k] for m in cv_metrics]) for k in cv_metrics[0]}

    if test_preds:
        test_metrics = [compute_metrics(fl, fp) for fl, fp in zip(test_labels, test_preds)]
        test_avg = {k: np.mean([m[k] for m in test_metrics]) for k in test_metrics[0]}
        test_std = {k: np.std([m[k] for m in test_metrics]) for k in test_metrics[0]}
        results = {
            "model": "Baseline 2 - TabTransformer (Mendeley URL)",
            **test_avg, **{k + "_std": float(test_std[k]) for k in test_std},
            **{"cv_" + k: float(avg[k]) for k in avg},
            **{"cv_" + k + "_std": float(std[k]) for k in std},
        }
        print(f"Baseline 2 held-out test: Acc={test_avg['accuracy']:.4f}, AUC={test_avg['auc']:.4f}, F1={test_avg['f1']:.4f}")
    else:
        results = {"model": "Baseline 2 - TabTransformer (Mendeley URL)", **avg, **{k + "_std": float(std[k]) for k in std}}
        print(f"Baseline 2 CV: Acc={avg['accuracy']:.4f}, AUC={avg['auc']:.4f}, F1={avg['f1']:.4f}")
    with open(MODEL_DIR / "evaluation_baseline2.json", "w") as f:
        json.dump(results, f, indent=2)
    return results


def evaluate_proposed():
    from src.training.train_proposed import CachedDataset, collate_fn

    with open(PROJECT / "data" / "processed" / "mendeley_full" / "split.json", "r") as f:
        split = json.load(f)
    with open(PROJECT / "data" / "processed" / "mendeley_full" / "data.jsonl", "r") as f:
        records = [json.loads(line) for line in f]

    folds_path = MODEL_DIR / "proposed_folds.json"
    if not folds_path.exists():
        print("proposed_folds.json not found - run train_proposed.py first")
        return {"model": "Proposed (Gated Fusion)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}
    folds_meta = json.load(open(folds_path))["folds"]

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")

    full_data = []
    for idx in split["test_indices"]:
        r = records[idx]
        tok = tokenizer(r["clean_text"], padding="max_length", truncation=True, max_length=128, return_tensors="pt")
        full_data.append({
            'url_features': r["url_features"][:12],
            'dom_features': r["dom_features"][:64],
            'input_ids': tok['input_ids'][0],
            'attention_mask': tok['attention_mask'][0],
            'label': r["label"],
        })

    # Evaluate each fold model on the held-out test set using its own train-fold scaler
    fold_preds, fold_labels = [], []
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
        load_model_weights(model, ckpt)
        preds, labs = [], []
        with torch.no_grad():
            for tab, ids, mask, dom, lbl in ld:
                logits = model(tab, ids, mask, dom)
                preds.extend(torch.sigmoid(logits).cpu().numpy())
                labs.extend(lbl.cpu().numpy())
        fold_preds.append(np.array(preds).flatten())
        fold_labels.append(np.array(labs).flatten())

    if not fold_preds:
        return {"model": "Proposed (Gated Fusion)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    metrics_list = [compute_metrics(fl, fp) for fl, fp in zip(fold_labels, fold_preds)]
    avg = {k: np.mean([m[k] for m in metrics_list]) for k in metrics_list[0]}
    std = {k: np.std([m[k] for m in metrics_list]) for k in metrics_list[0]}
    results = {"model": "TabTransformer + ModernBERT + GatedFusion", **avg, **{k + "_std": float(std[k]) for k in std}}
    with open(MODEL_DIR / "evaluation_proposed.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Proposed: Acc={avg['accuracy']:.4f}, AUC={avg['auc']:.4f}, F1={avg['f1']:.4f}")
    return results


def main():
    print(f"Device: {DEVICE}\n")

    evals = [
        ("baseline1", evaluate_baseline1),
        ("baseline2", evaluate_baseline2),
        ("proposed",  evaluate_proposed),
    ]

    all_results = {}
    for name, fn in evals:
        ckpt_exists = any(MODEL_DIR.glob(f"{name}_fold*"))
        if not ckpt_exists:
            print(f"Skipping {name}: no fold checkpoints found")
            continue
        all_results[name] = fn()
        print()

    # Aggregate
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    header = f"{'Model':<40} {'Acc':<8} {'Prec':<8} {'Recall':<8} {'F1':<8} {'AUC':<8} {'FPR':<8}"
    print(header)
    print("-" * 80)
    for name, res in all_results.items():
        print(f"{res.get('model','')[:38]:<40} {res['accuracy']:<8.4f} {res['precision']:<8.4f} {res['recall']:<8.4f} {res['f1']:<8.4f} {res['auc']:<8.4f} {res['fpr']:<8.4f}")

    output_path = MODEL_DIR / "evaluation_results.json"
    with open(output_path, "w") as f:
        json.dump(list(all_results.values()), f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
