# Phishing Detection Project — Context for AI Assistants

## Project Structure
```
phishing-detection/
├── api/                    # Flask API
│   ├── app.py              # Flask routes (health, predict, predict/batch, domain, ip, feedback, webhook, whitelist)
│   ├── predictor.py        # PhishingPredictor: loads checkpoint + runs inference + temperature scaling + reputation + BERT quantization
│   ├── engines.py          # Multi-engine analysis: AI Model, DNS Infra, URL Pattern, Brand
│   ├── explainer.py        # Natural language explanation generator (template-based, no LLM API needed)
│   ├── reputation.py       # Thread-safe reputation storage (JSON cache with threading.Lock)
│   ├── feedback.py         # Feedback loop: FP/FN reporting to data/feedback/*.jsonl
│   ├── webhooks.py         # Webhook config + dispatch to external SIEM/SOAR
│   ├── whitelist.py        # Adaptive whitelist (static + dynamic auto-learned from reputation)
│   └── requirements.txt    # Python dependencies
├── data/
│   ├── raw/                # Immutable source data
│   │   ├── ISCXURL2016.csv
│   │   └── mendeley/       # Mendeley 2021 dataset
│   │       ├── index.csv
│   │       └── html/       # 83k HTML files in genuine/ and phishing/
│   ├── processed/          # Preprocessed features (created by preprocess scripts / Kaggle)
│   │   ├── iscx_features.csv
│   │   ├── mendeley_url_dns.csv
│   │   └── mendeley_full/  # data.jsonl + split.json
│   ├── cache/              # DNS/WHOIS cache (created during extraction)
│   └── models/             # Trained checkpoints (created by Kaggle / training scripts)
│       ├── baseline1_fold*.pt
│       ├── baseline2_fold*.pt
│       ├── proposed_fold*_best.pt
│       ├── evaluation_baseline1.json
│       ├── evaluation_baseline2.json
│       ├── evaluation_proposed.json
│       └── evaluation_results.json
├── frontend/               # ReactJS + Vite
│   ├── index.html          # CSS vars cho dark/light theme
│   ├── package.json
│   ├── vite.config.js      # host: 0.0.0.0 cho mobile
│   └── src/
│       ├── main.jsx
│       ├── App.jsx         # Theme toggle, skeleton loading, tabs
│       ├── ThemeContext.jsx # Dark/light mode context + localStorage
│       └── components/
│           ├── UrlInput.jsx
│           └── ResultCard.jsx
├── src/
│   ├── features/           # Feature extractors
│   │   ├── url_extractor.py         # 12 URL features
│   │   ├── dns_whois_extractor.py   # 8 DNS/WHOIS features
│   │   ├── ssl_redirect_extractor.py # 5 SSL/Redirect features
│   │   └── html_dom_extractor.py    # 64-dim DOM + clean text
│   ├── models/             # PyTorch model definitions
│   │   ├── tab_transformer.py       # 29→128 (Baseline 1 & 2)
│   │   ├── modernbert_branch.py     # ModernBERT 768-dim
│   │   ├── gated_fusion.py          # 128×832→960 + LayerNorm
│   │   └── full_model.py            # PhishingDetector end-to-end
│   ├── training/           # Standalone training scripts (5-fold CV)
│   │   ├── train_baseline1.py
│   │   ├── train_baseline2.py
│   │   └── train_proposed.py
│   ├── evaluation/
│   │   ├── evaluate.py           # Evaluate all 3 models, save JSONs
│   │   ├── generate_figures.py   # Generate evaluation figures
│   │   └── deep_analysis.py      # Deep analysis Proposed vs Baselines
│   ├── explainability/
│   │   └── shap_analysis.py    # SHAP feature importance
│   ├── brand_detection/
│   │   └── __init__.py         # Brand impersonation detection
│   ├── preprocess_iscx.py      # ISCX → 29 features
│   └── preprocess_mendeley.py  # Mendeley → URL features + DOM + text
├── docs/
│   └── architecture_diagrams.md  # SE diagrams (UC, Sequence, ERD)
├── docker/
│   ├── Dockerfile.api
│   └── Dockerfile.frontend
├── docker-compose.yml        # Docker compose
├── results/
│   └── figures/              # Generated charts and figures
├── README.md                 # Project documentation
├── kaggle_baseline1.ipynb   # Kaggle: TabTransformer on ISCX (29 feats)
├── kaggle_baseline2.ipynb   # Kaggle: TabTransformer on Mendeley URL (12→29 pad)
├── kaggle_proposed.ipynb    # Kaggle: Gated Fusion (URL + ModernBERT + DOM)
├── kaggle_compare.ipynb     # Kaggle: compare all 3 models
└── AGENTS.md
```

## Dataset Details
- **ISCX-URL2016**: 36,707 rows (7,586 phishing / 29,121 benign), 80+ columns → 29 selected
- **Mendeley 2021**: 80,000 records (30,000 phishing / 50,000 genuine), 83,275 HTML files

## Architecture
- **Baseline 1**: TabTransformer (29 ISCX features → 128-dim → raw logits)
- **Baseline 2**: TabTransformer (12 URL features + 17 DNS/WHOIS/SSL padding → 128-dim → raw logits)
- **Proposed**: Gated Fusion of TabTransformer(12→128) + ModernBERT(768) + DOM(64) → 960 hidden
- All models output **raw logits**, combined with `BCEWithLogitsLoss`; sigmoid applied only in evaluation/prediction

## Key Commands
```bash
# Train locally (5-fold CV)
$env:PYTHONIOENCODING='utf-8'; python -m src.training.train_baseline1
$env:PYTHONIOENCODING='utf-8'; python -m src.training.train_baseline2
$env:PYTHONIOENCODING='utf-8'; python -m src.training.train_proposed
# Evaluate all 3 models
$env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.evaluate
# Run API
$env:PYTHONIOENCODING='utf-8'; python -m api.app
```

## Critical Notes
- Path "F:\Đồ án" causes UnicodeEncodeError in print() — set `$env:PYTHONIOENCODING='utf-8'`
- Phishing HTML files may trigger Windows Defender — DOM extractor falls back to zero vector
- Training happens on **Kaggle (GPU)** preferred; local training scripts for verification
- Download trained .pt files from Kaggle outputs into `data/models/`
- Frontend uses Vite (npm run dev on port 3000, proxies /api to Flask on 5000)

## Checkpoint Format Compatibility
Checkpoints saved by Kaggle notebooks use **raw `state_dict()`** (not wrapped in dict).
Local training scripts also save raw `state_dict()`. The old format (`dict` with `model_state_dict` key) is still supported for loading via `load_checkpoint()` and `predictor.py`.

### TABULAR_DIM = 12 for Proposed (not 29)
Mendeley has only 12 URL features (no DNS/WHOIS/SSL at inference time). **Do NOT pad to 29**:
- `kaggle_proposed.ipynb`: `TABULAR_DIM = len(URL_FEATURE_KEYS)` (=12)
- `full_model.py`: default `tabular_dim=12`
- `api/predictor.py`: `TABULAR_DIM = len(FEATURE_KEYS)` (=12), no padding
- ISCX (Baseline 1) still uses 29 real features — correct.
- Baseline 2 pads 12→29 to reuse the same TabTransformer.

### Raw logits + BCEWithLogitsLoss (no sigmoid in forward)
All models return raw logits from `forward()`. `torch.sigmoid()` is applied only during evaluation and `predict_proba`.

### Kaggle Proposed Training Config
1. `N_FOLDS = 3` (baseline1/2 use 5; proposed uses 3 for quota)
2. `EP = 8` with early stopping patience=3
3. Stratified sample `n=50000` (was 20k for faster runs)
4. Only save `*_best.pt` per fold
5. Per-parameter-group LR: `LR_TAB=5e-5, LR_BERT=1e-5`
6. ChainedScheduler (warmup + cosine)
7. Gradient clipping at 0.5 + GradScaler
8. Per-fold feature normalization to prevent data leakage

## New Commands
```bash
# Generate SHAP analysis
$env:PYTHONIOENCODING='utf-8'; python -m src.explainability.shap_analysis
# Generate evaluation figures
$env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.generate_figures
# Run deep analysis
$env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.deep_analysis
# Test brand detection
$env:PYTHONIOENCODING='utf-8'; python -m src.brand_detection
# Docker compose
docker-compose up --build
```

## New Modules
- **explainability/** - SHAP DeepExplainer for TabTransformer models
- **brand_detection/** - Brand impersonation detection via URL + text matching
- **evaluation/generate_figures.py** - matplotlib/seaborn charts
- **evaluation/deep_analysis.py** - Per-class metrics + error analysis

## Multi-Engine Architecture
`api/engines.py` implements 4 virtual engines with weighted voting:
- **AI Model** (weight 4): Gated Fusion output + temperature scaling
- **DNS Infrastructure** (weight 2): DNS records, SSL, domain age
- **URL Pattern** (weight 2): URL features, TLD, keywords, entropy
- **Brand Impersonation** (weight 1): Brand name detection

`combine_engines()` returns `final_score` (0-100), `final_verdict`, and per-engine details.

## Temperature Scaling
`TEMPERATURE = 2.8` in `predictor.py`. Applied to logits before sigmoid: `logits /= self.temperature`.

## Historical Reputation
`data/cache/reputation.json` stores per-domain scan history (first_seen, last_seen, scans, avg_score, phishing_rate). Updated on every prediction.

## Natural Language Explainer (`api/explainer.py`)
Template-based explanation generator (no LLM API required). Analyzes all signals:
- Engine verdicts (AI, DNS, URL Pattern, Brand)
- Brand impersonation detection
- DNS/WHOIS/SSL signals (domain age, ASN, certificate)
- URL features (entropy, keywords, TLD, redirects)
- Subdomain structure vs registered domain
- Historical reputation

Returns `verdict_summary`, `key_findings[]`, `risk_factors[]`, `recommendations[]`.

## API Response Changes
New fields in `/predict` response:
- `engine_results`: { final_score, final_verdict, engines: { name: { score, verdict, details } } }
- `aggregate_score`: (0-100) combined multi-engine score
- `engine_count`: number of active engines (0-4)
- `reputation`: historical scan data for the domain
- `subdomain_info`: { full_hostname, registered_domain, subdomain, parts } — null if no subdomain
- `explanation`: { verdict_summary, key_findings[], risk_factors[], recommendations[] }

## Frontend Changes
- Gauge uses calibrated `aggregate_score` instead of raw sigmoid
- `EngineResultRow` component shows each engine's score + verdict
- `ReputationSection` shows historical scan data
- OverviewTab displays engine breakdown under Advanced Analysis
- OverviewTab has Analysis Summary card (natural language explanation at top)
- DetailsTab shows Subdomain Note warning when subdomain != registered domain
- BehaviorTab shows warning banner when html_provided=false
- "AI Confidence" → "Risk Score" label with temperature scaling tooltip

## Class Imbalance
All training scripts now use `pos_weight` in `BCEWithLogitsLoss`

## CV note
3-fold (Proposed) vs 5-fold (Baselines) explained in code docstrings

## Recent Fixes & Improvements (July 2026)

### Bugs Fixed
1. **ThreadPoolExecutor false parallelism in `/predict/batch`**: Replaced with sequential loop — model inference is CPU-bound, threads just queue on GIL anyway.
2. **`get_all()` double-loaded `load_dynamic()`**: Changed to single load, reuse variable.
3. **Global `predictor_lock` serialized ALL requests**: Moved lock into `predictor.py` as `_inference_lock` wrapping ~50ms of model forward/backward only. DNS/SSL I/O (seconds) now runs in parallel across concurrent requests.
4. **`eval(atob(...))` not in suspicious JS patterns**: Added `r"\batob\s*\("` to `SUSPICIOUS_JS_PATTERNS` in `html_dom_extractor.py`.
5. **`s.string` fragile with multi-node script tags**: Changed to `s.get_text()` for robust inline JS extraction.

### Improvements
1. **`GET /health/llm`**: Returns `{available, provider: "ollama", model: "llama3.2:3b"}`. Frontend CopilotTab shows "AI Enhanced" (green) or "Template" (gray) badge.
2. **`logging.info()` in `maybe_add_dynamic()`**: Logs domain, scan count, avg_score when auto-whitelisted.
3. **Form action in `external_link_ratio`**: Now includes `<form action>` external domains, not just `<a href>`.
4. **Theme toggle (dark/light)**: CSS custom properties + `data-theme` attribute + localStorage. Toggle button (☀/🌙) in header.
5. **Skeleton loading**: `SkeletonResult` component replaces spinner — matches ResultCard layout with shimmer animation.
6. **Responsive layout**: `flexWrap`, `auto-fit` grid, media queries at 768px/640px, overflow scroll for tabs.
7. **Vite host `0.0.0.0`**: Mobile access via http://local-ip:3000 on same Wi-Fi.

### New Files
- `frontend/src/ThemeContext.jsx` — Dark/light theme provider
- `test_phishing.html` — Manual test file with eval(atob), password form, document.write iframe
- `test_genuine.html` — Manual test file with clean blog layout
- `docs/technical_report.md` — Comprehensive 17-section technical document for thesis reference

### Project State
- All 8 fixable bugs/improvements from code review completed.
- 1 known limitation: static DOM parsing vs dynamic JavaScript — would need Playwright/Puppeteer.
- F1=0.977, AUC=0.993, multi-engine weighted voting, Ollama AI Copilot.
- Last commit: `28a4563` (responsive layout). Push history: `9d9c8bc → a44852c → eadd0f3 → 14d0175 → 5a94e60 → 6809aba → 28a4563 → 4dc8774`
