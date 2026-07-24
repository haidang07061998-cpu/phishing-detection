"""
Proposed - TabTransformer + ModernBERT + GatedFusion with 3-fold CV.
Matches kaggle_proposed.ipynb logic for local training.

3-fold CV rationale: The Proposed model is 10-15x larger than baselines
(TabTransformer + ModernBERT + GatedFusion), and training on Kaggle free GPUs
has a 30-hour weekly quota. 3 folds keep each run under ~8 hours, allowing
iterative development within quota limits.

IMPORTANT comparison disclaimer: Proposed uses 3-fold CV while baselines use
5-fold CV. Direct comparison of variance/std across models is not meaningful —
the Proposed model's std is computed from 3 folds vs 5 for baselines.
Reported mean metrics are still comparable, but the Proposed model's variance
estimates are less reliable.
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
MODEL_DIR = PROJECT / "data" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42; N_FOLDS = 3
torch.manual_seed(SEED); np.random.seed(SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BS = 16; EP = 8
LR_TAB = 5e-5; LR_BERT = 1e-5
PATIENCE = 3
MAX_GRAD_NORM = 0.5
ACC_STEPS = 2


class CachedDataset(Dataset):
    def __init__(self, records, indices):
        self.data = [records[i] for i in indices]
    def __len__(self): return len(self.data)
    def __getitem__(self, i):
        r = self.data[i]
        return (
            torch.tensor(r['url_features'], dtype=torch.float32),
            r['input_ids'],
            r['attention_mask'],
            torch.tensor(r['dom_features'], dtype=torch.float32),
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
    indices = np.arange(len(full_data))
    all_metrics = []
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    pos_count = sum(labels); neg_count = len(labels) - pos_count
    pos_weight = torch.tensor([neg_count / pos_count], device=DEVICE)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    print(f"pos_weight={pos_weight.item():.2f} (neg={neg_count}, pos={int(pos_count)})")

    for fold, (tr_idx, te_idx) in enumerate(skf.split(indices, labels)):
        print(f"\n{'='*58}")
        print(f"  FOLD {fold+1}/{N_FOLDS}  |  train={len(tr_idx)}  val={len(te_idx)}")
        print(f"{'='*58}")

        model = PhishingDetector().to(DEVICE)
        total_p = sum(p.numel() for p in model.parameters())
        train_p = sum(p.numel() for p in model.parameters() if p.requires_grad)
        print(f"Params: total={total_p:,} | trainable={train_p:,}")

        tr_ld = DataLoader(
            CachedDataset(full_data, tr_idx),
            batch_size=BS, shuffle=True, collate_fn=collate_fn, num_workers=0
        )
        te_ld = DataLoader(
            CachedDataset(full_data, te_idx),
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

        for ep in range(1, EP + 1):
            tl = train_epoch(model, tr_ld, opt, crit, scaler)
            m, _, _ = evaluate(model, te_ld, crit)
            scheduler.step()

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
        print(f"  Fold {fold+1} -> Acc={fm['accuracy']:.4f} | AUC={fm['auc']:.4f} | F1={fm['f1']:.4f}")

        del model, opt, scheduler, scaler, tr_ld, te_ld
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    metric_keys = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    avg = {k: np.mean([m[k] for m in all_metrics]) for k in metric_keys}
    std = {k: np.std([m[k] for m in all_metrics]) for k in metric_keys}

    print(f"\n>>> {N_FOLDS}-Fold CV:")
    for k in metric_keys:
        print(f"  {k.upper():10s}: {avg[k]:.4f} +/- {std[k]:.4f}")

    results = {'model': 'TabTransformer + ModernBERT + GatedFusion', 'n_folds': N_FOLDS}
    for k in metric_keys:
        results[k] = round(float(avg[k]), 6)
        results[k + '_std'] = round(float(std[k]), 6)

    with open(MODEL_DIR / 'evaluation_proposed.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("Results saved.")


if __name__ == "__main__":
    main()
