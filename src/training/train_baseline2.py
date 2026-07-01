"""
Baseline 2 - TabTransformer on Mendeley URL features (12-dim + padding to 29).
Matches kaggle_baseline2.ipynb logic for local training.
"""

import os, sys, json, re, math
from pathlib import Path
from urllib.parse import urlparse

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
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.tab_transformer import TabTransformer

PROJECT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT / "data" / "raw" / "mendeley"
MODEL_DIR = PROJECT / "data" / "models"
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
    print(f"Records: {len(df)}")

    url_vectors = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc='Extracting URL features'):
        feats = extract_url_features(str(row['url']).strip())
        vec = [feats[k] for k in URL_FEATURE_KEYS]
        vec += [-1.0] * (TABULAR_DIM - len(vec))
        url_vectors.append(vec)

    X = np.array(url_vectors, dtype=np.float32)
    scaler = StandardScaler()
    X = scaler.fit_transform(X).astype(np.float32)
    y = df['result'].values.astype(np.float32)
    print(f"Shape: {X.shape}, Phishing: {y.sum()}, Benign: {(y==0).sum()}")

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    all_metrics = []
    crit = nn.BCEWithLogitsLoss()

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
        torch.save(model.state_dict(), MODEL_DIR / f'baseline2_fold{fold+1}.pt')
        print(f"  Done: Acc={fm['accuracy']:.4f}, AUC={fm['auc']:.4f}, F1={fm['f1']:.4f}")

    avg = {k: np.mean([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    std = {k: np.std([m[k] for m in all_metrics]) for k in ['accuracy','precision','recall','f1','auc']}
    print(f"\n>>> {N_FOLDS}-Fold CV: Acc={avg['accuracy']:.4f}+-{std['accuracy']:.4f}, AUC={avg['auc']:.4f}+-{std['auc']:.4f}, F1={avg['f1']:.4f}+-{std['f1']:.4f}")

    results = {'model': 'Baseline 2 - TabTransformer (Mendeley URL)', **avg, **{k + '_std': float(std[k]) for k in std}}
    with open(MODEL_DIR / 'evaluation_baseline2.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved.")


if __name__ == "__main__":
    main()
