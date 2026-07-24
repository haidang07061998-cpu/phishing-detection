"""
Baseline 1 - TabTransformer on ISCX-URL2016 (29 features) with 5-fold CV.
Matches kaggle_baseline1.ipynb logic for local training.
"""

import os, sys, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.tab_transformer import TabTransformer

PROJECT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT / "data" / "processed" / "iscx_features.csv"
MODEL_DIR = PROJECT / "data" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42; N_FOLDS = 5
torch.manual_seed(SEED); np.random.seed(SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BS = 64; EP = 50; LR = 1e-3


ISCX_FEATURES_NUM = [
    'urlLen','domainlength','pathLength','subDirLen','fileNameLen',
    'this.fileExtLen','ArgLen','Entropy_URL','Entropy_Domain',
    'Entropy_DirectoryName','Entropy_Filename','Entropy_Afterpath',
    'spcharUrl','URL_DigitCount','host_DigitCount','NumberRate_URL',
    'NumberRate_Domain','NumberRate_DirectoryName','NumberRate_FileName',
    'SymbolCount_URL','SymbolCount_Domain','URL_Letter_Count',
    'host_letter_count','NumberofDotsinURL','LongestPathTokenLength',
    'CharacterContinuityRate','Domain_LongestWordLength',
]
ISCX_FEATURES_CAT = ['URL_sensitiveWord', 'ISIpAddressInDomainName']
TABULAR_DIM = 29


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

    if DATA_PATH.exists():
        print(f"Loading preprocessed features from {DATA_PATH}")
        df = pd.read_csv(DATA_PATH)
        feat_cols = [c for c in df.columns if c not in ("label", "split")]
        X = df[feat_cols].values.astype(np.float32)
        y = df["label"].values.astype(np.float32)
        print(f"Loaded: {X.shape}")
    else:
        print(f"Loading raw ISCX CSV...")
        raw_path = PROJECT / "data" / "raw" / "ISCXURL2016.csv"
        df = pd.read_csv(raw_path, encoding='utf-8', low_memory=False)
        avail_num = [c for c in ISCX_FEATURES_NUM if c in df.columns]
        avail_cat = [c for c in ISCX_FEATURES_CAT if c in df.columns]

        X_num = df[avail_num].copy().replace([np.inf, -np.inf], np.nan)
        for c in X_num.columns: X_num[c] = pd.to_numeric(X_num[c], errors='coerce')
        X_num = X_num.fillna(0).astype(np.float32)
        X_num_scaled = StandardScaler().fit_transform(X_num).astype(np.float32)

        if avail_cat:
            X_cat = df[avail_cat].fillna(0).astype(int).clip(lower=0)
            X = np.concatenate([X_num_scaled, X_cat.values.astype(np.float32)], axis=1)
        else:
            X = X_num_scaled
        y = (df['URL_Type_obf_Type'].astype(str).str.strip().str.lower() == 'phishing').astype(int).values
        print(f"Loaded raw: {X.shape}, Phishing: {y.sum()}, Benign: {(y==0).sum()}")

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    all_metrics = []
    pos_count = y.sum(); neg_count = len(y) - pos_count
    pos_weight = torch.tensor([neg_count / pos_count], device=DEVICE)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    print(f"pos_weight={pos_weight.item():.2f} (neg={neg_count}, pos={int(pos_count)})")

    for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y)):
        print(f"\n--- Fold {fold+1}/{N_FOLDS} ---")
        X_tr, X_te = X[tr_idx], X[te_idx]
        y_tr, y_te = y[tr_idx], y[te_idx]
        tr_ld = DataLoader(SimpleDataset(X_tr, y_tr), batch_size=BS, shuffle=True)
        te_ld = DataLoader(SimpleDataset(X_te, y_te), batch_size=BS)

        model = TabTransformer(nf=X.shape[1], classifier=True).to(DEVICE)
        opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-5)
        sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EP)

        for ep in range(1, EP + 1):
            tl = train_epoch(model, tr_ld, opt, crit)
            m, _, _ = evaluate(model, te_ld, crit)
            sched.step()
            if ep % 10 == 0:
                print(f"  Epoch {ep:2d}/{EP} | Loss: {tl:.4f} | AUC: {m['auc']:.4f} | F1: {m['f1']:.4f}")

        fm, _, _ = evaluate(model, te_ld, crit)
        fm['fold'] = fold + 1
        all_metrics.append(fm)
        torch.save(model.state_dict(), MODEL_DIR / f'baseline1_fold{fold+1}.pt')
        print(f"  Done: Acc={fm['accuracy']:.4f}, AUC={fm['auc']:.4f}, F1={fm['f1']:.4f}")

    avg = {k: np.mean([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    std = {k: np.std([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    print(f"\n>>> {N_FOLDS}-Fold CV: Acc={avg['accuracy']:.4f}+-{std['accuracy']:.4f}, AUC={avg['auc']:.4f}+-{std['auc']:.4f}, F1={avg['f1']:.4f}+-{std['f1']:.4f}")

    results = {'model': 'Baseline 1 - TabTransformer (ISCX)', **avg, **{k + '_std': float(std[k]) for k in std}}
    with open(MODEL_DIR / 'evaluation_baseline1.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved.")


if __name__ == "__main__":
    main()
