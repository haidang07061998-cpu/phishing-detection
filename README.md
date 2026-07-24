# Phishing Detection - Multimodal Gated Fusion

A deep learning system for phishing URL detection combining structural URL features, HTML DOM analysis, and ModernBERT-based text understanding via a learnable gated fusion mechanism.

## Project Structure

`
phishing-detection/
├── api/                    # Flask REST API for inference
│   ├── app.py              # Routes: /health, /predict, /predict/batch
│   ├── predictor.py        # PhishingPredictor: loads checkpoint + runs inference
│   └── requirements.txt    # API dependencies
├── data/
│   ├── raw/                # Immutable source data (ISCX-URL2016 + Mendeley)
│   ├── processed/          # Preprocessed features (CSV, JSONL)
│   ├── cache/              # DNS/WHOIS query cache
│   └── models/             # Trained checkpoints + evaluation results
├── frontend/               # React + Vite SPA
├── src/                    # Python source code
│   ├── features/           # Feature extractors (URL, DNS, SSL, DOM, Brand)
│   ├── models/             # PyTorch model definitions
│   ├── training/           # Training scripts (5-fold CV)
│   ├── evaluation/         # Evaluation scripts
│   ├── explainability/     # SHAP analysis module
│   └── brand_detection/    # Brand impersonation detection
├── kaggle_baseline1.ipynb  # TabTransformer on ISCX-URL2016
├── kaggle_baseline2.ipynb  # TabTransformer on Mendeley URL
├── kaggle_proposed.ipynb   # Gated Fusion (URL + ModernBERT + DOM)
├── kaggle_compare.ipynb    # Comparison of all 3 models
├── results/                # Figures and evaluation charts
├── docker/                 # Docker configuration
├── AGENTS.md               # AI assistant context
└── README.md               # This file
`

## Models (Ablation Study)

Three models form a controlled ablation study:

| Model | Features | Params | Acc | AUC | F1 |
|-------|----------|--------|-----|-----|-----|
| Baseline 1 | TabTransformer (29 ISCX feats) | 71K | 0.9858 | 0.9980 | 0.9655 |
| Baseline 2 | TabTransformer (12 URL feats only) | 71K | 0.8966 | 0.9593 | 0.8578 |
| Proposed | Gated Fusion (URL 12 + ModernBERT 768 + DOM 64) | 32.9M | 0.9770 | 0.9928 | 0.9770 |

### Baseline 1 - TabTransformer on ISCX-URL2016
- 29 tabular features (27 numerical + 2 categorical) from ISCX-URL2016
- 5-fold stratified CV, 50 epochs, AdamW lr=1e-3
- Strongest tabular baseline with all engineered features

### Baseline 2 - TabTransformer on Mendeley URL only
- 12 URL structural features only (padded to 29 dims as controlled ablation)
- Same architecture as Baseline 1 for fair comparison
- Demonstrates performance ceiling of URL-only approaches

### Proposed - Gated Fusion (URL + ModernBERT + DOM)
- TabTransformer encodes 12 URL features into 128-dim embedding
- ModernBERT encodes HTML text into 768-dim CLS vector
- DOM projector encodes 64 structural DOM features
- Gated Fusion learns adaptive weighting of URL vs HTML modalities
- 3-fold CV (Kaggle GPU quota limitation - see Notes)
- Early stopping, gradient clipping, per-parameter-group LR

## Dataset

### ISCX-URL2016
- 36,707 rows (7,586 phishing / 29,121 benign)
- 80+ pre-computed URL features
- Source: University of New Brunswick

### Mendeley 2021
- 80,000 records (30,000 phishing / 50,000 genuine)
- 83,275 raw HTML files with genuine/ and phishing/ split
- Contains full page HTML for DOM + text analysis
- Source: Mendeley Data

## Setup

### Prerequisites
- Python 3.10+
- Node.js 18+
- PyTorch 2.3+
- Kaggle account (for GPU training)

### Installation
`ash
# Python environment
pip install -r requirements.txt

# Frontend
cd frontend && npm install && cd ..

# Download trained models from Kaggle to data/models/
`

### Quick Start
`ash
# Run API server
='utf-8'
python -m api.app

# Run frontend (separate terminal)
cd frontend && npm run dev
`

### Training (local verification only - use Kaggle for full training)
`ash
python -m src.training.train_baseline1
python -m src.training.train_baseline2
python -m src.training.train_proposed
`

### Evaluation
`ash
python -m src.evaluation.evaluate
python -m src.explainability.shap_analysis
`

## Key Results

- Proposed model achieves F1=0.9770, outperforming URL-only baseline by 12% in F1
- Gated fusion successfully learns to weight URL vs HTML modalities per input
- SHAP analysis (see results/figures/) shows top-5 URL features driving predictions

## Important Notes

### 3-fold vs 5-fold CV
Baseline 1 and 2 use 5-fold CV. The Proposed model uses 3-fold CV due to ModernBERT's memory requirements under Kaggle's GPU quota (16GB VRAM on T4). This does not invalidate comparison - 3-fold still yields robust estimates with low variance.

### Baseline 2 padding (12 -> 29)
Baseline 2 pads 12 URL features to 29 dimensions with -1.0 to reuse the same TabTransformer architecture as Baseline 1. This is a controlled ablation choice - the padded dimensions receive zero attention weight after training, making the effective capacity comparable.

### Class Imbalance
ISCX: 20.7% phishing. Mendeley: 37.5% phishing. Training uses BCEWithLogitsLoss with pos_weight to handle imbalance.

### Unicode on Windows
Set $env:PYTHONIOENCODING='utf-8' before running Python scripts.

### Windows Defender
Phishing HTML files may trigger Windows Defender. DOM extractor falls back to zero vector.

## Results

All figures and evaluation results are in results/ and data/models/:
- results/figures/confusion_matrices.png
- results/figures/roc_curves.png
- results/figures/loss_curves.png
- results/figures/model_comparison.png
- results/figures/shap_summary.png
- data/models/evaluation_results.json

## License

Academic project - graduation thesis.
