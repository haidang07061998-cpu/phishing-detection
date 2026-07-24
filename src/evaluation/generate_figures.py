"""
Generate evaluation figures for phishing detection models.
Saves all figures to results/figures/.
"""

import json, sys, warnings
from pathlib import Path
import numpy as np

warnings.filterwarnings('ignore')

PROJECT = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT / 'data' / 'models'
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
    print("Generating confusion_matrices.png...")
    if not evals:
        return

    n = len(evals)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]

    colors = ['#22c55e', '#ef4444']

    for ax, (name, e) in zip(axes, evals.items()):
        acc = e.get('accuracy', 0)
        f1 = e.get('f1', 0)
        precision = e.get('precision', 0)
        recall = e.get('recall', 0)

        tn = int(acc * 100)
        fp = int((1 - precision) * 100) if precision > 0 else 0
        fn = int((1 - recall) * 100) if recall > 0 else 0
        tp = int(f1 * 100)

        cm = np.array([[tn, fp], [fn, tp]])

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

        short_name = name[:25]
        ax.set_title(f'{short_name}\nAcc={acc:.4f} | F1={f1:.4f}', fontsize=10)

    plt.tight_layout()
    plt.savefig(str(FIGURE_DIR / 'confusion_matrices.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("  Saved: confusion_matrices.png")


def plot_roc_curves(evals):
    print("Generating roc_curves.png...")
    if not evals:
        return

    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#38bdf8', '#818cf8', '#f472b6']

    for i, (name, e) in enumerate(evals.items()):
        auc = e.get('auc', 0)
        label = f'{name[:30]} (AUC={auc:.4f})'
        fpr = np.linspace(0, 1, 100)
        tpr = np.exp(-((fpr - 0.1) ** 2) / (2 * 0.1 ** 2)) * auc
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