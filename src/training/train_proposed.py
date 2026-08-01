"""
Proposed - TabTransformer + ModernBERT + GatedFusion with 5-fold CV.
Matches kaggle_proposed.ipynb logic for local training.

Leakage fixes (July 2026):
- The fixed 80/20 split in split.json is now RESPECTED: 5-fold CV runs ONLY
  on split["train_indices"]; the test set is completely held out during training.
- URL/DOM feature normalization is fitted per-fold on the train fold ONLY
  (matching kaggle_proposed.ipynb).
- After CV, each fold's best checkpoint is evaluated on the held-out test set
  (never seen in any fold), and those test metrics are reported in
  evaluation_proposed.json. Per-fold train scalers are saved to
  proposed_folds.json so evaluate.py reproduces the same numbers.
"""

import os, sys, json, gc
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score,
)
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.models.full_model import PhishingDetector

PROJECT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT / "data" / "processed" / "mendeley_full"
DATA_OUT = PROJECT / "data"
MODEL_DIR = DATA_OUT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42; N_FOLDS = 5
torch.manual_seed(SEED); np.random.seed(SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BS = 16; EP = 8
LR_TAB = 5e-5; LR_BERT = 1e-5
PATIENCE = 3
MAX_GRAD_NORM = 0.5
ACC_STEPS = 2


class CachedDataset(Dataset):
    def __init__(self, records, indices, url_mean=None, url_std=None,
                 dom_mean=None, dom_std=None):
        self.data = [records[i] for i in indices]
        self.url_mean = url_mean
        self.url_std = url_std
        self.dom_mean = dom_mean
        self.dom_std = dom_std
    def __len__(self): return len(self.data)
    def __getitem__(self, i):
        r = self.data[i]
        if self.url_mean is not None:
            url = (np.array(r['url_features'], dtype=np.float32) - self.url_mean) / self.url_std
            dom = (np.array(r['dom_features'], dtype=np.float32) - self.dom_mean) / self.dom_std
        else:
            url = np.array(r['url_features'], dtype=np.float32)
            dom = np.array(r['dom_features'], dtype=np.float32)
        return (
            torch.tensor(url, dtype=torch.float32),
            r['input_ids'],
            r['attention_mask'],
            torch.tensor(dom, dtype=torch.float32),
            torch.tensor(r['label'], dtype=torch.float32),
        )


def collate_fn(batch):
    tab, ids, mask, dom, lbl = zip(*batch)
    return (
        torch.stack(tab).to(DEVICE),
        torch.stack(ids).to(DEVICE),
        torch.stack(mask).to(DEVICE),
        torch.stack(dom).to(DEVICE),
        torch.stack(lbl).unsqueeze(1).to(DEVICE),
    )


def compute_metrics(labs, preds):
    preds = np.clip(np.nan_to_num(preds, nan=0.5), 0.0, 1.0)
    pb = (preds >= 0.5).astype(int)
    return {
        'accuracy':  accuracy_score(labs, pb),
        'precision': precision_score(labs, pb, zero_division=0),
        'recall':    recall_score(labs, pb, zero_division=0),
        'f1':        f1_score(labs, pb, zero_division=0),
        'auc':       roc_auc_score(labs, preds) if len(np.unique(labs)) > 1 else 0.0,
    }


def train_epoch(model, loader, opt, crit, scaler):
    model.train()
    total_loss = 0.0
    pending_update = False
    opt.zero_grad()
    n = len(loader)

    for step, (tab, ids, mask, dom, lbl) in enumerate(loader):
        with torch.amp.autocast(device_type='cuda', enabled=DEVICE.type == 'cuda'):
            logits = model(tab, ids, mask, dom)
            loss = crit(logits, lbl)

        if torch.isnan(loss) or torch.isinf(loss):
            opt.zero_grad()
            pending_update = False
            continue

        scaler.scale(loss).backward()
        pending_update = True
        total_loss += loss.item() * tab.size(0)

        if (step + 1) % ACC_STEPS == 0:
            scaler.unscale_(opt)
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=MAX_GRAD_NORM)
            scaler.step(opt)
            scaler.update()
            opt.zero_grad()
            pending_update = False

    if pending_update:
        scaler.unscale_(opt)
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=MAX_GRAD_NORM)
        scaler.step(opt)
        scaler.update()
        opt.zero_grad()

    return total_loss / max(len(loader.dataset), 1)


def evaluate(model, loader, crit):
    model.eval()
    total_loss = 0.0
    preds, labs = [], []
    with torch.no_grad():
        for tab, ids, mask, dom, lbl in loader:
            with torch.amp.autocast(device_type='cuda', enabled=DEVICE.type == 'cuda'):
                logits = model(tab, ids, mask, dom)
                loss = crit(logits, lbl)
            total_loss += loss.item() * tab.size(0)
            p = torch.sigmoid(logits).cpu().numpy().flatten()
            preds.extend(p)
            labs.extend(lbl.cpu().numpy().flatten())

    preds = np.nan_to_num(np.array(preds), nan=0.5)
    labs = np.array(labs)
    m = compute_metrics(labs, preds)
    m['loss'] = total_loss / len(loader.dataset)
    return m, preds, labs


def main():
    print(f"Device: {DEVICE}")

    # Load pre-tokenized data
    with open(DATA_DIR / "data.jsonl", "r") as f:
        records = [json.loads(line) for line in f]
    with open(DATA_DIR / "split.json", "r") as f:
        split = json.load(f)

    # Build full_data with pre-tokenized tensors
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")

    full_data = []
    for idx in tqdm(range(len(records)), desc="Loading records"):
        r = records[idx]
        tok = tokenizer(
            r["clean_text"], padding="max_length", truncation=True,
            max_length=128, return_tensors="pt",
        )
        full_data.append({
            'url_features': r["url_features"][:12],
            'dom_features': r["dom_features"][:64],
            'input_ids': tok['input_ids'][0],
            'attention_mask': tok['attention_mask'][0],
            'label': r["label"],
        })

    labels = [d['label'] for d in full_data]
    train_indices = np.array(split["train_indices"], dtype=np.int64)
    test_indices = np.array(split["test_indices"], dtype=np.int64)
    print(f"Train indices: {len(train_indices):,} | Test indices (held-out): {len(test_indices):,}")

    # Dataset statistics (local uses full 80k pre-tokenized data; Kaggle uses 50k sample)
    lab_arr = np.array(labels, dtype=np.float32)
    dataset_stats = {
        'dataset': 'Mendeley 2021 (HTML)',
        'n_full': len(labels),
        'n_full_phishing': int((lab_arr == 1).sum()),
        'n_full_benign': int((lab_arr == 0).sum()),
        'n_samples': len(labels),
        'n_phishing': int((lab_arr == 1).sum()),
        'n_benign': int((lab_arr == 0).sum()),
        'phishing_ratio': round(float(lab_arr.mean()), 6),
        'n_features': 12,
        'feature_keys': ['url_length','domain_length','path_length','entropy',
                         'special_char_ratio','digit_ratio','subdomain_count','has_https',
                         'has_ip_address','suspicious_keywords','url_depth','tld_in_path'],
    }
    with open(DATA_OUT / 'dataset_stats_proposed.json', 'w') as f:
        json.dump(dataset_stats, f, indent=2)
    print("Dataset stats saved to data/dataset_stats_proposed.json")

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    train_labels = [labels[i] for i in train_indices]
    pos_count = sum(train_labels); neg_count = len(train_labels) - pos_count
    pos_weight = torch.tensor([neg_count / pos_count], device=DEVICE)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    print(f"pos_weight={pos_weight.item():.2f} (neg={neg_count}, pos={int(pos_count)})")

    all_metrics = []
    test_metrics = []
    test_preds = []
    folds_meta = []
    history = []

    for fold, (tr_rel, te_rel) in enumerate(skf.split(train_indices, train_labels)):
        tr_idx = train_indices[tr_rel]
        te_idx = train_indices[te_rel]
        print(f"\n{'='*58}")
        print(f"  FOLD {fold+1}/{N_FOLDS}  |  train={len(tr_idx)}  val={len(te_idx)}")
        print(f"{'='*58}")

        # Per-fold normalization fitted on the train fold ONLY (no leakage)
        tr_url_arr = np.array([full_data[i]['url_features'] for i in tr_idx], dtype=np.float32)
        url_mean, url_std = tr_url_arr.mean(axis=0), tr_url_arr.std(axis=0) + 1e-8
        tr_dom_arr = np.array([full_data[i]['dom_features'] for i in tr_idx], dtype=np.float32)
        dom_mean, dom_std = tr_dom_arr.mean(axis=0), tr_dom_arr.std(axis=0) + 1e-8

        model = PhishingDetector().to(DEVICE)
        total_p = sum(p.numel() for p in model.parameters())
        train_p = sum(p.numel() for p in model.parameters() if p.requires_grad)
        print(f"Params: total={total_p:,} | trainable={train_p:,}")

        tr_ld = DataLoader(
            CachedDataset(full_data, tr_idx, url_mean, url_std, dom_mean, dom_std),
            batch_size=BS, shuffle=True, collate_fn=collate_fn, num_workers=0
        )
        te_ld = DataLoader(
            CachedDataset(full_data, te_idx, url_mean, url_std, dom_mean, dom_std),
            batch_size=BS*2, shuffle=False, collate_fn=collate_fn, num_workers=0
        )

        opt = torch.optim.AdamW([
            {'params': model.tab.parameters(),  'lr': LR_TAB},
            {'params': model.bert.parameters(), 'lr': LR_BERT},
            {'params': model.dom.parameters(),  'lr': LR_TAB},
            {'params': model.fusion.parameters(), 'lr': LR_TAB},
            {'params': model.cls.parameters(),  'lr': LR_TAB},
        ], weight_decay=1e-5, eps=1e-8)

        def lr_lambda(e):
            return 0.3 if e == 1 else 1.0
        warmup = torch.optim.lr_scheduler.LambdaLR(opt, lr_lambda)
        cosine = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EP-1, eta_min=1e-6)
        scheduler = torch.optim.lr_scheduler.ChainedScheduler([warmup, cosine])

        scaler = torch.amp.GradScaler(enabled=DEVICE.type == 'cuda')
        best_f1, patience_count = 0.0, 0
        best_ckpt = MODEL_DIR / f'proposed_fold{fold+1}_best.pt'
        hist = []

        for ep in range(1, EP + 1):
            tl = train_epoch(model, tr_ld, opt, crit, scaler)
            m, _, _ = evaluate(model, te_ld, crit)
            scheduler.step()

            hist.append({'epoch': ep, 'train_loss': round(float(tl), 5),
                         'val_auc': round(float(m['auc']), 5), 'val_f1': round(float(m['f1']), 5)})

            flag = ''
            if m['f1'] > best_f1:
                best_f1 = m['f1']
                patience_count = 0
                torch.save(model.state_dict(), best_ckpt)
                flag = '   <- best'
            else:
                patience_count += 1

            print(f"  Ep {ep:2d}/{EP} | Loss {tl:.4f} | Val {m['loss']:.4f} | AUC {m['auc']:.4f} | F1 {m['f1']:.4f} | Acc {m['accuracy']:.4f} {flag}")

            if patience_count >= PATIENCE:
                print(f"  Early stopping at epoch {ep}")
                break

        model.load_state_dict(torch.load(best_ckpt, map_location=DEVICE))
        fm, _, _ = evaluate(model, te_ld, crit)
        fm['fold'] = fold + 1
        all_metrics.append(fm)
        history.append({'fold': fold + 1, 'epochs': hist})
        print(f"  Fold {fold+1} -> CV   Acc={fm['accuracy']:.4f} | AUC={fm['auc']:.4f} | F1={fm['f1']:.4f}")

        # Held-out test evaluation using this fold's train scaler (test never seen in CV)
        test_ld = DataLoader(
            CachedDataset(full_data, test_indices, url_mean, url_std, dom_mean, dom_std),
            batch_size=BS*2, shuffle=False, collate_fn=collate_fn, num_workers=0
        )
        tm, tp, _ = evaluate(model, test_ld, crit)
        tm['fold'] = fold + 1
        test_metrics.append(tm)
        test_preds.append(tp)
        print(f"  Fold {fold+1} -> Test Acc={tm['accuracy']:.4f} | AUC={tm['auc']:.4f} | F1={tm['f1']:.4f}")

        folds_meta.append({
            "fold": int(fold + 1),
            "url_mean": url_mean.tolist(),
            "url_std": url_std.tolist(),
            "dom_mean": dom_mean.tolist(),
            "dom_std": dom_std.tolist(),
        })

        del model, opt, scheduler, scaler, tr_ld, te_ld, test_ld
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    with open(MODEL_DIR / 'proposed_folds.json', 'w') as f:
        json.dump({"n_folds": N_FOLDS, "folds": folds_meta}, f, indent=2)
    print("Fold metadata saved to proposed_folds.json")

    with open(DATA_OUT / 'training_logs_proposed.json', 'w') as f:
        json.dump(history, f, indent=2)
    test_labels_arr = np.array([full_data[i]['label'] for i in test_indices], dtype=np.float32)
    test_preds_mean = np.mean(np.stack(test_preds), axis=0)
    tp_obj = np.empty(N_FOLDS, dtype=object)
    for f in range(N_FOLDS):
        tp_obj[f] = test_preds[f]
    np.savez(DATA_OUT / 'predictions_proposed.npz',
             test_preds_mean=test_preds_mean, test_labels=test_labels_arr, test_preds=tp_obj)
    print("Training logs + predictions saved to data/")

    metric_keys = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    avg = {k: np.mean([m[k] for m in all_metrics]) for k in metric_keys}
    std = {k: np.std([m[k] for m in all_metrics]) for k in metric_keys}
    test_avg = {k: np.mean([m[k] for m in test_metrics]) for k in metric_keys}
    test_std = {k: np.std([m[k] for m in test_metrics]) for k in metric_keys}

    print(f"\n>>> {N_FOLDS}-Fold CV (train portion):")
    for k in metric_keys:
        print(f"  {k.upper():10s}: {avg[k]:.4f} +/- {std[k]:.4f}")
    print(f"\n>>> Held-out test (never in CV):")
    for k in metric_keys:
        print(f"  {k.upper():10s}: {test_avg[k]:.4f} +/- {test_std[k]:.4f}")

    results = {'model': 'TabTransformer + ModernBERT + GatedFusion', 'n_folds': N_FOLDS}
    for k in metric_keys:
        results[k] = round(float(test_avg[k]), 6)
        results[k + '_std'] = round(float(test_std[k]), 6)
        results['cv_' + k] = round(float(avg[k]), 6)
        results['cv_' + k + '_std'] = round(float(std[k]), 6)

    with open(MODEL_DIR / 'evaluation_proposed.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("Results saved.")


if __name__ == "__main__":
    main()
