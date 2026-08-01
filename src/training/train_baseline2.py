"""
Baseline 2 - TabTransformer on Mendeley URL features (12-dim + padding to 29).
Matches kaggle_baseline2.ipynb logic for local training.

Padding rationale: TabTransformer expects TABULAR_DIM=29 (same architecture as
Baseline 1 on ISCX). Since Mendeley only has 12 URL features (no DNS/WHOIS/SSL
at inference time), we pad the remaining 17 dimensions with -1.0 so the same
TabTransformer class can be reused without modification. The Transformer
attention can learn to ignore constant padded dimensions.

NOTE: All models (Baseline 1, Baseline 2, Proposed) use 5-fold CV with the
same split/seed, so fold counts and variance estimates are directly comparable.

Leakage fixes (July 2026):
- StandardScaler is now fitted per-fold on the train fold ONLY and then
  applied to the test fold (no preprocessing leakage).
- Per-fold test indices + scaler params are saved to baseline2_folds.json
  so evaluate.py evaluates each fold model on its own hold-out fold only.
"""

import os, sys, json, re, math
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score,
)
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.tab_transformer import TabTransformer

PROJECT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT / "data" / "raw" / "mendeley"
DATA_OUT = PROJECT / "data"
MODEL_DIR = DATA_OUT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42; N_FOLDS = 5
torch.manual_seed(SEED); np.random.seed(SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BS = 128; EP = 50; LR = 1e-3

SUSPICIOUS_KEYWORDS = ['login','secure','verify','account','update','banking',
    'confirm','signin','password','reset','authenticate','paypal','webscr','free','bonus']
COMMON_TLDS = {'com','org','net','gov','edu','mil','io','co','uk',
               'au','de','jp','fr','ca','ru','cn','in','br','pl',
               'html','php','asp','jsp'}
URL_FEATURE_KEYS = ['url_length','domain_length','path_length','entropy',
    'special_char_ratio','digit_ratio','subdomain_count','has_https',
    'has_ip_address','suspicious_keywords','url_depth','tld_in_path']
TABULAR_DIM = 29


def shannon_entropy(text):
    if not text: return 0.0
    e, l = 0.0, len(text)
    for c in set(text):
        p = text.count(c) / l
        if p > 0: e -= p * math.log2(p)
    return round(e, 4)


def extract_url_features(url):
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.hostname or '').split(':')[0]
    path = parsed.path or ''
    fu = url.strip(); parts = domain.split('.')
    sc = sum(1 for c in fu if c in '@-_?.&=%+#~!'); dc = sum(1 for c in fu if c.isdigit())
    tc = max(len(fu), 1)
    ip_r = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    return {
        'url_length': len(fu), 'domain_length': len(domain),
        'path_length': len(path), 'entropy': shannon_entropy(fu),
        'special_char_ratio': round(sc/tc, 4), 'digit_ratio': round(dc/tc, 4),
        'subdomain_count': max(0, len(parts)-2) if len(parts) >= 2 else 0,
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'has_ip_address': 1 if ip_r.match(domain) else 0,
        'suspicious_keywords': sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in fu.lower()),
        'url_depth': len([s for s in path.split('/') if s]),
        'tld_in_path': 1 if any(f'.{t}' in path.lower() for t in COMMON_TLDS) else 0,
    }


class SimpleDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.from_numpy(X) if isinstance(X, np.ndarray) else X
        self.y = torch.from_numpy(y.reshape(-1,1).astype(np.float32)) if isinstance(y, np.ndarray) else y
    def __len__(self): return len(self.y)
    def __getitem__(self, i): return self.X[i], self.y[i]


def compute_metrics(labels, preds):
    pb = (preds >= 0.5).astype(int)
    return {
        'accuracy':  accuracy_score(labels, pb),
        'precision': precision_score(labels, pb, zero_division=0),
        'recall':    recall_score(labels, pb, zero_division=0),
        'f1':        f1_score(labels, pb, zero_division=0),
        'auc':       roc_auc_score(labels, preds) if len(np.unique(labels)) > 1 else 0.0,
    }


def train_epoch(model, loader, opt, crit):
    model.train(); total = 0
    for Xb, yb in loader:
        Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
        opt.zero_grad(); loss = crit(model(Xb), yb)
        loss.backward(); opt.step(); total += loss.item() * Xb.size(0)
    return total / len(loader.dataset)


def evaluate(model, loader, crit):
    model.eval(); total = 0; preds, labs = [], []
    with torch.no_grad():
        for Xb, yb in loader:
            Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
            logits = model(Xb)
            total += crit(logits, yb).item() * Xb.size(0)
            preds.extend(torch.sigmoid(logits).cpu().numpy())
            labs.extend(yb.cpu().numpy())
    preds, labs = np.array(preds), np.array(labs)
    m = compute_metrics(labs, preds); m['loss'] = total / len(loader.dataset)
    return m, preds, labs


def main():
    print(f"Device: {DEVICE}")
    print(f"Loading Mendeley index.csv...")

    idx_path = DATA_DIR / "index.csv"
    df = pd.read_csv(idx_path, encoding='utf-8')
    print(f"Full dataset : {len(df):,} | Phishing: {(df['result']==1).sum():,} | Genuine: {(df['result']==0).sum():,}")

    n_full = len(df); n_full_ph = int((df['result']==1).sum()); n_full_be = int((df['result']==0).sum())

    # Deterministic balanced sample — IDENTICAL to kaggle_baseline2.ipynb
    SAMPLE_SIZE = 50000
    n_each = SAMPLE_SIZE // 2
    df_p = df[df['result']==1].sample(n=min(n_each, (df['result']==1).sum()), random_state=SEED)
    df_g = df[df['result']==0].sample(n=min(n_each, (df['result']==0).sum()), random_state=SEED)
    df = pd.concat([df_p, df_g]).sample(frac=1, random_state=SEED).reset_index(drop=True)
    print(f"Sampled      : {len(df):,} | Phishing: {(df['result']==1).sum():,} | Genuine: {(df['result']==0).sum():,}")

    url_vectors = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc='Extracting URL features'):
        feats = extract_url_features(str(row['url']).strip())
        vec = [feats[k] for k in URL_FEATURE_KEYS]
        vec += [-1.0] * (TABULAR_DIM - len(vec))
        url_vectors.append(vec)

    X = np.array(url_vectors, dtype=np.float32)
    y = df['result'].values.astype(np.float32)
    print(f"Shape: {X.shape}, Phishing: {y.sum()}, Benign: {(y==0).sum()}")

    # Dataset statistics (match kaggle_baseline2.ipynb artifact)
    dataset_stats = {
        'dataset': 'Mendeley 2021',
        'n_full': n_full,
        'n_full_phishing': n_full_ph,
        'n_full_benign': n_full_be,
        'n_samples': int(len(df)),
        'n_phishing': int(y.sum()),
        'n_benign': int((y==0).sum()),
        'phishing_ratio': round(float(y.mean()), 6),
        'n_features': len(URL_FEATURE_KEYS),
        'feature_keys': URL_FEATURE_KEYS,
    }
    with open(DATA_OUT / 'dataset_stats_mendeley.json', 'w') as f:
        json.dump(dataset_stats, f, indent=2)
    print("Dataset stats saved to data/dataset_stats_mendeley.json")

    # Stratified 80/20 train/test split — test NEVER used in CV (same logic as notebook)
    train_idx, test_idx = train_test_split(
        np.arange(len(df)), test_size=0.2, random_state=SEED, stratify=df['result'].values
    )
    train_idx = np.array(train_idx, dtype=np.int64)
    test_idx  = np.array(test_idx,  dtype=np.int64)
    print(f"Train: {len(train_idx):,} | Test (held-out): {len(test_idx):,}")
    with open(MODEL_DIR / 'baseline2_splits.json', 'w') as f:
        json.dump({'train_indices': train_idx.tolist(), 'test_indices': test_idx.tolist()}, f, indent=2)
    print(f"Saved: {MODEL_DIR / 'baseline2_splits.json'}")

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    all_metrics, test_metrics = [], []
    test_preds = []
    folds_meta, history = [], []
    train_labels = y[train_idx]
    pos_count = int(train_labels.sum()); neg_count = len(train_labels) - pos_count
    pos_weight = torch.tensor([neg_count / max(pos_count, 1)], device=DEVICE)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    print(f"pos_weight={pos_weight.item():.2f} (neg={neg_count}, pos={pos_count})")

    for fold, (tr_rel, te_rel) in enumerate(skf.split(train_idx, train_labels)):
        tr_idx = train_idx[tr_rel]
        te_idx = train_idx[te_rel]
        print(f"\n--- Fold {fold+1}/{N_FOLDS} ---")

        # Per-fold StandardScaler: fit on train fold ONLY, then transform test fold
        scaler = StandardScaler().fit(X[tr_idx])
        X_tr = scaler.transform(X[tr_idx]).astype(np.float32)
        X_te = scaler.transform(X[te_idx]).astype(np.float32)
        y_tr, y_te = y[tr_idx], y[te_idx]
        tr_ld = DataLoader(SimpleDataset(X_tr, y_tr), batch_size=BS, shuffle=True)
        te_ld = DataLoader(SimpleDataset(X_te, y_te), batch_size=BS)

        model = TabTransformer(nf=X_tr.shape[1], classifier=True).to(DEVICE)
        opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-5)
        sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EP)

        hist = []
        for ep in range(1, EP + 1):
            tl = train_epoch(model, tr_ld, opt, crit)
            m, _, _ = evaluate(model, te_ld, crit)
            sched.step()
            hist.append({'epoch': ep, 'train_loss': round(float(tl), 5),
                         'val_auc': round(float(m['auc']), 5), 'val_f1': round(float(m['f1']), 5)})
            if ep % 10 == 0:
                print(f"  Epoch {ep:2d}/{EP} | Loss: {tl:.4f} | AUC: {m['auc']:.4f} | F1: {m['f1']:.4f}")

        fm, _, _ = evaluate(model, te_ld, crit)
        fm['fold'] = fold + 1
        all_metrics.append(fm)
        history.append({'fold': fold + 1, 'epochs': hist})
        torch.save(model.state_dict(), MODEL_DIR / f'baseline2_fold{fold+1}.pt')
        folds_meta.append({
            "fold": int(fold + 1),
            "test_indices": te_idx.tolist(),
            "scaler_mean": scaler.mean_.tolist(),
            "scaler_scale": scaler.scale_.tolist(),
            "n_features": int(X_tr.shape[1]),
        })
        print(f"  Done (CV): Acc={fm['accuracy']:.4f}, AUC={fm['auc']:.4f}, F1={fm['f1']:.4f}")

        # Held-out test evaluation using this fold's train scaler (test never in CV)
        X_ts = scaler.transform(X[test_idx]).astype(np.float32)
        test_ld = DataLoader(SimpleDataset(X_ts, y[test_idx]), batch_size=BS)
        tm, tp, _ = evaluate(model, test_ld, crit)
        tm['fold'] = fold + 1
        test_metrics.append(tm)
        test_preds.append(tp)
        print(f"  Test    : Acc={tm['accuracy']:.4f}, AUC={tm['auc']:.4f}, F1={tm['f1']:.4f}")

    with open(MODEL_DIR / 'baseline2_folds.json', 'w') as f:
        json.dump({"n_folds": N_FOLDS, "folds": folds_meta}, f, indent=2)
    print(f"Fold metadata saved to baseline2_folds.json")

    with open(DATA_OUT / 'training_logs_baseline2.json', 'w') as f:
        json.dump(history, f, indent=2)
    test_labels_arr = y[test_idx].astype(np.float32)
    test_preds_mean = np.mean(np.stack(test_preds), axis=0)
    tp_obj = np.empty(N_FOLDS, dtype=object)
    for f in range(N_FOLDS):
        tp_obj[f] = test_preds[f]
    np.savez(DATA_OUT / 'predictions_baseline2.npz',
             test_preds_mean=test_preds_mean, test_labels=test_labels_arr, test_preds=tp_obj)
    print("Training logs + predictions saved to data/")

    avg = {k: np.mean([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    std = {k: np.std([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    test_avg = {k: np.mean([m[k] for m in test_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    test_std = {k: np.std([m[k] for m in test_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    print(f"\n>>> {N_FOLDS}-Fold CV (train portion): Acc={avg['accuracy']:.4f}+-{std['accuracy']:.4f}, AUC={avg['auc']:.4f}+-{std['auc']:.4f}, F1={avg['f1']:.4f}+-{std['f1']:.4f}")
    print(f">>> Held-out test (never in CV): Acc={test_avg['accuracy']:.4f}+-{test_std['accuracy']:.4f}, AUC={test_avg['auc']:.4f}+-{test_std['auc']:.4f}, F1={test_avg['f1']:.4f}+-{test_std['f1']:.4f}")

    results = {
        'model': 'Baseline 2 - TabTransformer (Mendeley URL)',
        'n_folds': N_FOLDS,
        'sample_size': len(df),
        **{k: round(float(test_avg[k]), 6) for k in test_avg},
        **{k + '_std': round(float(test_std[k]), 6) for k in test_std},
        **{'cv_' + k: round(float(avg[k]), 6) for k in avg},
        **{'cv_' + k + '_std': round(float(std[k]), 6) for k in std},
    }
    with open(MODEL_DIR / 'evaluation_baseline2.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved.")


if __name__ == "__main__":
    main()
