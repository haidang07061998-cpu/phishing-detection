"""
Generate evaluation figures for phishing detection models.
Saves all figures to results/figures/.

IMPORTANT — figures are only ever drawn from REAL predictions:
- Confusion matrices and ROC curves are computed from the held-out test
  predictions saved by the training scripts (`data/predictions_*.npz`).
- If a model's prediction file is missing, its confusion matrix / ROC curve is
  SKIPPED (with a warning) instead of being fabricated from aggregate metrics —
  synthetic curves are misleading and must not be used in reports/thesis.
- Bar comparisons (metrics, FPR) use the real metrics from evaluation_results.json.
"""

import json, sys, warnings
from pathlib import Path
import numpy as np

warnings.filterwarnings('ignore')

PROJECT = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT / 'data' / 'models'
DATA_DIR = PROJECT / 'data'
FIGURE_DIR = PROJECT / 'results' / 'figures'
FIGURE_DIR.mkdir(parents=True, exist_ok=True)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib not installed. Install with: pip install matplotlib seaborn")
    sys.exit(1)

try:
    import seaborn as sns
except ImportError:
    sns = None

sns_available = sns is not None

# Model name keyword -> prediction artifact (written by train_*.py).
PREDICTION_FILES = [
    ("baseline 1", "predictions_baseline1.npz"),
    ("baseline 2", "predictions_baseline2.npz"),
    ("gatedfusion", "predictions_proposed.npz"),
]


def _prediction_path(model_name: str) -> Path | None:
    """Return the predictions npz path for a model, or None if unmatched."""
    key = (model_name or "").lower()
    for keyword, fname in PREDICTION_FILES:
        if keyword in key:
            return DATA_DIR / fname
    return None


def _load_predictions(model_name: str) -> tuple[np.ndarray, np.ndarray] | None:
    """Load (labels, probability_scores) for a model from its npz file.

    Accepts both the `preds`/`labels` (baseline1, concatenated folds) and
    `test_preds_mean`/`test_labels` (baseline2/proposed, held-out test) layouts.
    Returns None when the file is absent.
    """
    path = _prediction_path(model_name)
    if path is None or not path.exists():
        return None
    try:
        z = np.load(path)
        labels = z['labels'] if 'labels' in z else z['test_labels']
        probs = z['preds'] if 'preds' in z else z['test_preds_mean']
        return np.asarray(labels).astype(int), np.asarray(probs).astype(float)
    except (KeyError, ValueError, OSError) as exc:
        print(f"  Warning: could not read predictions for '{model_name}' ({path}): {exc}")
        return None


def load_evals():
    evals_path = MODEL_DIR / 'evaluation_results.json'
    if not evals_path.exists():
        print("Warning: evaluation_results.json not found")
        return {}
    with open(evals_path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return {e.get('model', f'model_{i}'): e for i, e in enumerate(data)}
    return data


def plot_model_comparison(evals):
    print("Generating model_comparison.png...")
    if not evals:
        return

    models = []
    metrics_data = {'accuracy': [], 'precision': [], 'recall': [], 'f1': [], 'auc': []}

    for name, e in evals.items():
        label = name[:25]
        models.append(label)
        for m in metrics_data:
            metrics_data[m].append(e.get(m, 0))

    n_models = len(models)
    n_metrics = len(metrics_data)
    x = np.arange(n_metrics)
    width = 0.8 / max(n_models, 1)

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ['#38bdf8', '#818cf8', '#f472b6', '#34d399', '#fbbf24']
    for i, model in enumerate(models):
        vals = [metrics_data[m][i] for m in metrics_data]
        offset = (i - n_models / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, label=model, color=colors[i % len(colors)])
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f'{v:.4f}', ha='center', va='bottom', fontsize=7, rotation=45)

    ax.set_xticks(x)
    ax.set_xticklabels([m.upper() for m in metrics_data])
    ax.set_ylabel('Score')
    ax.set_ylim(0, 1.05)
    ax.set_title('Model Performance Comparison', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right')
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(str(FIGURE_DIR / 'model_comparison.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("  Saved: model_comparison.png")


def plot_confusion_matrices(evals):
    """Confusion matrices from REAL held-out predictions (skips missing data)."""
    from sklearn.metrics import confusion_matrix as cm_fn

    print("Generating confusion_matrices.png...")
    if not evals:
        return

    loaded = []
    for name, e in evals.items():
        pred = _load_predictions(name)
        if pred is None:
            print(f"  Warning: no predictions file for '{name[:40]}' — skipping its "
                  f"confusion matrix (run training to generate predictions_*.npz).")
            continue
        labels, probs = pred
        preds = (probs >= 0.5).astype(int)
        if len(labels) == 0:
            continue
        cm = cm_fn(labels, preds, labels=[0, 1])
        loaded.append((name, e, cm))

    if not loaded:
        print("  No real predictions available — confusion_matrices.png NOT generated "
              "(avoids fabricating data).")
        return

    n = len(loaded)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]

    for ax, (name, e, cm) in zip(axes, loaded):
        if sns_available:
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False,
                        xticklabels=['Pred Benign', 'Pred Phish'],
                        yticklabels=['True Benign', 'True Phish'])
        else:
            im = ax.imshow(cm, cmap='Blues')
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, str(cm[i, j]), ha='center', va='center', fontsize=14)
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Pred Benign', 'Pred Phish'])
            ax.set_yticklabels(['True Benign', 'True Phish'])

        tn, fp, fn, tp = cm.ravel()
        acc = (tn + tp) / max(tn + fp + fn + tp, 1)
        short_name = name[:25]
        ax.set_title(f'{short_name}\nAcc={acc:.4f}', fontsize=10)

    plt.tight_layout()
    plt.savefig(str(FIGURE_DIR / 'confusion_matrices.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("  Saved: confusion_matrices.png")


def plot_roc_curves(evals):
    """ROC curves from REAL held-out predictions (skips missing data)."""
    from sklearn.metrics import roc_curve, roc_auc_score

    print("Generating roc_curves.png...")
    if not evals:
        return

    loaded = []
    for name, e in evals.items():
        pred = _load_predictions(name)
        if pred is None:
            print(f"  Warning: no predictions file for '{name[:40]}' — skipping its "
                  f"ROC curve (run training to generate predictions_*.npz).")
            continue
        labels, probs = pred
        if len(labels) == 0 or len(np.unique(labels)) < 2:
            continue
        fpr, tpr, _ = roc_curve(labels, probs)
        auc = roc_auc_score(labels, probs)
        loaded.append((name, fpr, tpr, auc))

    if not loaded:
        print("  No real predictions available — roc_curves.png NOT generated "
              "(avoids fabricating data).")
        return

    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#38bdf8', '#818cf8', '#f472b6']

    for i, (name, fpr, tpr, auc) in enumerate(loaded):
        label = f'{name[:30]} (AUC={auc:.4f})'
        ax.plot(fpr, tpr, color=colors[i % len(colors)], label=label, linewidth=2)

    ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curves Comparison', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    plt.tight_layout()
    plt.savefig(str(FIGURE_DIR / 'roc_curves.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("  Saved: roc_curves.png")


def plot_fpr_comparison(evals):
    print("Generating fpr_comparison.png...")
    if not evals:
        return

    models = [name[:20] for name in evals]
    fprs = [e.get('fpr', 0) for e in evals.values()]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ['#22c55e' if f < 0.05 else '#fbbf24' if f < 0.1 else '#ef4444' for f in fprs]
    bars = ax.bar(models, fprs, color=colors)
    ax.set_ylabel('False Positive Rate')
    ax.set_title('False Positive Rate Comparison', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)

    for bar, fpr in zip(bars, fprs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                f'{fpr:.4f}', ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.savefig(str(FIGURE_DIR / 'fpr_comparison.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("  Saved: fpr_comparison.png")


def main():
    print("Generating evaluation figures...")
    evals = load_evals()
    if not evals:
        print("No evaluation data found. Run evaluation first.")
        return

    print(f"Found {len(evals)} model evaluations")
    for name, e in evals.items():
        print(f"  {name[:40]}: Acc={e.get('accuracy', 0):.4f}, AUC={e.get('auc', 0):.4f}, F1={e.get('f1', 0):.4f}")

    plot_model_comparison(evals)
    plot_confusion_matrices(evals)
    plot_roc_curves(evals)
    plot_fpr_comparison(evals)
    print(f"\nAll figures saved to {FIGURE_DIR}")


if __name__ == '__main__':
    main()
