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


def evaluate_baseline1():
    import pandas as pd
    from sklearn.preprocessing import StandardScaler

    try:
        df = pd.read_csv(MODEL_DIR.parent / "processed" / "iscx_features.csv")
        feat_cols = [c for c in df.columns if c not in ("label", "split")]
        X = df[feat_cols].values.astype(np.float32)
        y = df["label"].values.astype(np.float32)
    except FileNotFoundError:
        df = pd.read_csv(PROJECT / "data" / "raw" / "ISCXURL2016.csv", encoding="utf-8", low_memory=False)
        ISCX_NUM = ['urlLen','domainlength','pathLength','subDirLen','fileNameLen',
            'this.fileExtLen','ArgLen','Entropy_URL','Entropy_Domain','Entropy_DirectoryName',
            'Entropy_Filename','Entropy_Afterpath','spcharUrl','URL_DigitCount','host_DigitCount',
            'NumberRate_URL','NumberRate_Domain','NumberRate_DirectoryName','NumberRate_FileName',
            'SymbolCount_URL','SymbolCount_Domain','URL_Letter_Count','host_letter_count',
            'NumberofDotsinURL','LongestPathTokenLength','CharacterContinuityRate','Domain_LongestWordLength']
        ISCX_CAT = ['URL_sensitiveWord','ISIpAddressInDomainName']
        X_num = df[ISCX_NUM].copy().replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        X_num = StandardScaler().fit_transform(X_num).astype(np.float32)
        X_cat = df[ISCX_CAT].fillna(0).astype(int).clip(lower=0).values.astype(np.float32)
        X = np.concatenate([X_num, X_cat], axis=1)
        y = (df['URL_Type_obf_Type'].astype(str).str.strip().str.lower() == 'phishing').astype(int).values

    ds = torch.utils.data.TensorDataset(torch.from_numpy(X), torch.from_numpy(y).unsqueeze(1))
    loader = DataLoader(ds, batch_size=256)

    # Average over all fold checkpoints
    fold_preds, fold_labels = [], []
    for fold in range(1, 6):
        ckpt = MODEL_DIR / f"baseline1_fold{fold}.pt"
        if not ckpt.exists():
            continue
        model = TabTransformer(nf=X.shape[1], classifier=True)
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
    from sklearn.preprocessing import StandardScaler

    # Reconstruct URL features from raw data (same as train_baseline2)
    df = pd.read_csv(PROJECT / "data" / "raw" / "mendeley" / "index.csv", encoding="utf-8")
    TABULAR_DIM = 29
    URL_KEYS = ['url_length','domain_length','path_length','entropy','special_char_ratio',
                'digit_ratio','subdomain_count','has_https','has_ip_address',
                'suspicious_keywords','url_depth','tld_in_path']

    import re, math
    from urllib.parse import urlparse

    def extract_url_features(url):
        parsed = urlparse(str(url).strip())
        domain = (parsed.netloc or parsed.hostname or '').split(':')[0]
        path = parsed.path or ''
        fu = str(url).strip(); parts = domain.split('.')
        sc = sum(1 for c in fu if c in '@-_?.&=%+#~!'); dc = sum(1 for c in fu if c.isdigit())
        tc = max(len(fu), 1)
        ip_r = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        return {k: 0.0 for k in URL_KEYS} | {
            'url_length': len(fu), 'domain_length': len(domain), 'path_length': len(path),
            'entropy': round(-sum((text.count(c)/len(text))*math.log2(text.count(c)/len(text)) for c in set(text) if text.count(c)>0), 4) if (text := fu) else 0.0,
            'special_char_ratio': round(sc/tc, 4), 'digit_ratio': round(dc/tc, 4),
            'subdomain_count': max(0, len(parts)-2) if len(parts) >= 2 else 0,
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_ip_address': 1 if ip_r.match(domain) else 0,
            'suspicious_keywords': sum(1 for kw in ['login','secure','verify','account','update','banking',
                'confirm','signin','password','reset','authenticate','paypal','webscr','free','bonus'] if kw in fu.lower()),
            'url_depth': len([s for s in path.split('/') if s]),
            'tld_in_path': 1 if any(f'.{t}' in path.lower() for t in
                {'com','org','net','gov','edu','mil','io','co','uk','au','de','jp','fr','ca','ru','cn','in','br','pl','html','php','asp','jsp'}) else 0,
        }

    url_vectors = []
    for _, row in df.iterrows():
        vec = [extract_url_features(str(row['url']).strip())[k] for k in URL_KEYS]
        vec += [-1.0] * (TABULAR_DIM - len(vec))
        url_vectors.append(vec)

    X = np.array(url_vectors, dtype=np.float32)
    X = StandardScaler().fit_transform(X).astype(np.float32)
    y = df['result'].values.astype(np.float32)

    ds = torch.utils.data.TensorDataset(torch.from_numpy(X), torch.from_numpy(y).unsqueeze(1))
    loader = DataLoader(ds, batch_size=256)

    fold_preds, fold_labels = [], []
    for fold in range(1, 6):
        ckpt = MODEL_DIR / f"baseline2_fold{fold}.pt"
        if not ckpt.exists():
            continue
        model = TabTransformer(nf=X.shape[1], classifier=True)
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
        return {"model": "Baseline 2 - TabTransformer (Mendeley URL)", "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": 0, "fpr": 0}

    metrics_list = [compute_metrics(fl, fp) for fl, fp in zip(fold_labels, fold_preds)]
    avg = {k: np.mean([m[k] for m in metrics_list]) for k in metrics_list[0]}
    std = {k: np.std([m[k] for m in metrics_list]) for k in metrics_list[0]}
    results = {"model": "Baseline 2 - TabTransformer (Mendeley URL)", **avg, **{k + "_std": float(std[k]) for k in std}}
    with open(MODEL_DIR / "evaluation_baseline2.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Baseline 2: Acc={avg['accuracy']:.4f}, AUC={avg['auc']:.4f}, F1={avg['f1']:.4f}")
    return results


def evaluate_proposed():
    from src.training.train_proposed import CachedDataset, collate_fn

    with open(PROJECT / "data" / "processed" / "mendeley_full" / "split.json", "r") as f:
        split = json.load(f)
    with open(PROJECT / "data" / "processed" / "mendeley_full" / "data.jsonl", "r") as f:
        records = [json.loads(line) for line in f]

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

    ld = DataLoader(CachedDataset(full_data, np.arange(len(full_data))),
                    batch_size=32, collate_fn=collate_fn, num_workers=0)

    fold_preds, fold_labels = [], []
    for fold in range(1, 4):
        ckpt = MODEL_DIR / f"proposed_fold{fold}_best.pt"
        if not ckpt.exists():
            continue
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
