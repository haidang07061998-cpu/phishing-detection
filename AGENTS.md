# Phishing Detection Project — Context for AI Assistants

## Project Structure
```
phishing-detection/
├── api/                    # Flask API
│   ├── app.py              # Flask routes (health, predict, predict/batch, domain, ip, feedback, webhook, whitelist, threat, keys, history)
│   ├── predictor.py        # PhishingPredictor: loads checkpoint + runs inference + temperature scaling + reputation + BERT quantization
│   ├── engines.py          # Multi-engine analysis: AI Model, DNS Infra, URL Pattern, Brand, Known-Threat DB
│   ├── explainer.py        # Natural language explanation generator (template-based, no LLM API needed)
│   ├── reputation.py       # Thread-safe reputation storage (JSON cache with threading.Lock)
│   ├── feedback.py         # Feedback loop: FP/FN reporting to data/feedback/*.jsonl
│   ├── webhooks.py         # Webhook config + dispatch to external SIEM/SOAR
│   ├── whitelist.py        # Reputation whitelist: known-reputable signal (TTL, audit, revoke), NOT a verdict override
│   ├── threat_db.py        # Known-threat database: admin blocklist (data/known_malicious.json) + optional community feed + audit
│   ├── history.py          # Scan history store (data/scan_history.jsonl) + summary + CSV/JSON export
│   ├── security.py         # API-key auth (env + registry), per-IP rate limiting, payload size guard
│   ├── config.py           # env-driven config (API keys, CORS, limits, webhooks, threat feed)
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
1. `N_FOLDS = 5` (same as baselines — all models use 5-fold CV)
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
# Calibrate temperature scaling (needs mendeley_full + checkpoints)
$env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.calibrate
# Benchmark predictor latency/throughput/memory
$env:PYTHONIOENCODING='utf-8'; python -m src.evaluation.benchmark [n]
# Docker compose
docker-compose up --build
```

## New Modules
- **explainability/** - SHAP DeepExplainer for TabTransformer models
- **brand_detection/** - Brand impersonation detection via URL + text matching
- **evaluation/generate_figures.py** - matplotlib/seaborn charts
- **evaluation/deep_analysis.py** - Per-class metrics + error analysis
- **evaluation/calibrate.py** - Temperature scaling on held-out test → data/models/temperature.json
- **evaluation/benchmark.py** - Latency/throughput/memory benchmark → results/benchmark.json

## Multi-Engine Architecture
`api/engines.py` implements 5 virtual engines with weighted voting:
- **AI Model** (weight 4): Gated Fusion output + temperature scaling
- **DNS Infrastructure** (weight 2): DNS records, SSL, domain age
- **URL Pattern** (weight 2): URL features, TLD, keywords, entropy
- **Brand Impersonation** (weight 1): Brand name detection
- **Known-Threat DB** (weight 2, active only when URL/domain matches a blocklist entry): local admin blocklist `data/known_malicious.json` + optional community feed (`PHISHGUARD_THREAT_FEED_URL`), audited in `data/audit/threat.jsonl`. A hit is a strong signal, never a hard verdict.
- **Reputation** (weight 1, active only when domain is known reputable): whitelist signal, only lowers score

`combine_engines()` returns `final_score` (0-100), `final_verdict`, and per-engine details. `reputation_engine()` returns `None` when the domain is not known reputable, so the engine stays out of the weighted vote for unknown domains.

## Scan History & Reports
`api/history.py` appends a row to `data/scan_history.jsonl` on every predict/domain/ip scan (capped at `MAX_RECORDS = 20000`).
- `GET /history` → recent records + summary counts (total, verdicts, threat_db_hits)
- `GET /history/export?format=csv|json` → full export
- `GET /threat` → blocklist entries (local + community), `POST /threat` → add, `DELETE /threat` → remove (admin scope)
- `GET /whitelist` → list, `POST /whitelist` → add, `DELETE /whitelist` → remove (admin scope for write)
- Frontend `Reports` tab (`ReportsPanel.jsx`) shows summary cards, filterable history table, JSON/CSV export (via authenticated fetch + blob download), and blocklist add/remove.

## API Key Management
`api/security.py` supports two key sources:
- **Env keys** (`PHISHGUARD_API_KEYS`) — legacy, always granted full `admin` scope.
- **Registry keys** (`data/api_keys.json`, SHA-256 hashed secrets) — managed via `/keys` endpoints with scopes `admin`/`scan`/`feedback`/`reports`, optional expiry + IP allowlist. Plaintext secret returned once at creation.
- Endpoint scopes: `scan` → `/predict`, `/predict/batch`, `/domain`, `/ip`, `/explain`; `feedback` → `/feedback`; `reports` → `/history`, `/history/export`, `/feedback/stats`; `admin` → `/keys`, `/threat` (POST/DELETE), `/whitelist` (POST/DELETE), `/webhook` (POST/DELETE). Read-only GETs (`/webhook`, `/whitelist`, `/threat`) require any valid key.
- Auth is a no-op only when auth is disabled AND the registry is empty. Scope checks return 403; missing/invalid keys return 401.
- **Fail-fast**: `PHISHGUARD_ENV=production` → `config.ensure_production_auth()` raises RuntimeError at `api/app.py` import (before model load) unless env keys or a pre-seeded registry exist. `docker-compose.yml` defaults `PHISHGUARD_ENV=production`.
- **X-Forwarded-For không tin mù**: `_client_ip()` chỉ dùng `request.remote_addr`. Header `X-Forwarded-For` được tôn trọng duy nhất khi `PHISHGUARD_TRUST_PROXY>=1` — `api/app.py` bọc `werkzeug ProxyFix(x_for=N, x_proto=N)` để xác thực chuỗi proxy tin cậy. Mặc định `0` → client không thể spoof IP để bypass rate limit / IP allowlist.

## Temperature Scaling
`DEFAULT_TEMPERATURE = 2.8` in `predictor.py`. Precedence: `PHISHGUARD_TEMPERATURE` env → `data/models/temperature.json` (tạo bởi `src/evaluation/calibrate.py`) → default 2.8. Applied to logits before sigmoid: `logits /= self.temperature`.

## Inference Alignment & Performance (Aug 2026)
- **Per-fold normalization BẮT BUỘC**: training (`train_proposed.py`) và `evaluate.py` chuẩn hóa URL/DOM features per-fold bằng `(x - mean)/std`. `predictor.py` đọc `data/models/proposed_folds.json` và áp dụng đúng scaler của fold tương ứng trước inference. KHÔNG được đưa feature thô vào model (bug OOD).
- **Token length = 128**: `MAX_SEQ_LEN = 128` trong predictor, khớp `train_proposed.py max_length=128`. Không dùng 512.
- **Fold ensemble (opt-in)**: `PHISHGUARD_ENSEMBLE_FOLDS` (default 1). Mỗi fold model dùng scaler riêng của nó; logits được trung bình (mean) trước temperature scaling. Bật 5 cần ~1.4GB RAM (quantized) — máy 7.7GB RAM nên giữ 1.
- **Feature importance opt-in**: `PHISHGUARD_COMPUTE_IMPORTANCE` (default True) + per-request `{"explain": bool}` override trong body POST `/predict`. Ensemble mode không tính gradient (trả vector 0).
- **DNS/SSL extraction cache**: `_TTLCache` trong predictor (`PHISHGUARD_EXTRACT_CACHE_TTL`, default 300s). Cache kết quả DNS/WHOIS/SSL/redirect theo URL — giảm network I/O lặp.
- **Batch workers**: `PHISHGUARD_BATCH_WORKERS` (default 1 = sequential). >1 dùng `ThreadPoolExecutor` overlap DNS/SSL I/O; model inference vẫn serialize qua `_inference_lock` nên CPU-bound forward không overlap.
- **`analysis_quality`**: `"full"` (HTML parse thành công) hoặc `"limited"` (không HTML / parse fail) + `analysis_reason`. Frontend hiển thị badge "Limited Analysis".
- Response thêm: `model_name`, `ensemble_folds`, `temperature`.
- **Benchmark**: `python -m src.evaluation.benchmark [n]` → `results/benchmark.json` (p50/p95/p99 ms, throughput/min, RSS delta, timeout rate).

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
- `analysis_quality`: "full" | "limited" + `analysis_reason` (machine-readable limited-analysis flag)
- `model_name`, `ensemble_folds`, `temperature`: which checkpoint(s)/config produced the result

## Frontend Changes
- Gauge uses calibrated `aggregate_score` instead of raw sigmoid
- `EngineResultRow` component shows each engine's score + verdict
- `ReputationSection` shows historical scan data
- OverviewTab displays engine breakdown under Advanced Analysis
- OverviewTab has Analysis Summary card (natural language explanation at top)
- DetailsTab shows Subdomain Note warning when subdomain != registered domain
- BehaviorTab shows warning banner when html_provided=false
- OverviewTab shows amber "Limited Analysis" badge when analysis_quality !== 'full'
- "AI Confidence" → "Risk Score" label with temperature scaling tooltip

## Class Imbalance
All training scripts now use `pos_weight` in `BCEWithLogitsLoss`

## CV note
All 3 models use 5-fold CV (same split/seed).

## Training/Evaluation Pipeline (leakage-safe, July 2026)
Data leakage fixes applied to all training scripts + Kaggle notebooks:

- **Held-out 80/20 split** for Baseline 2 & Proposed: `train_test_split(stratify=y, random_state=SEED)`; indices saved to `baseline2_splits.json` / `proposed_splits.json`. The test set is NEVER used during training/CV.
- **StandardScaler fit per-fold** (Baseline 1 & 2): `scaler = StandardScaler().fit(X[tr_idx])`, then transform both train/test folds. No global `fit_transform`.
- **Proposed per-fold normalization**: URL/DOM mean+std computed on train fold only, applied via `CachedDataset(full_data, idx, url_mean, url_std, dom_mean, dom_std)`.
- **`evaluate.py` evaluates each fold model ONLY on its own hold-out fold**: uses `test_indices` from `*_folds.json` and restores scaler params (`_restore_scaler()`) from the saved metadata.
- **Metadata files**: `baseline1_folds.json`, `baseline2_folds.json`, `proposed_folds.json` (test_indices + scaler mean/scale per fold).
- **Result JSON keys**: Baseline 2 & Proposed → top-level metrics = **held-out test**, `cv_*` keys = CV-on-train metrics. Baseline 1 → top-level = 5-fold CV (no external test set).
- Kaggle notebooks must be run in order: baseline1 → baseline2 → proposed → compare. Split logic is duplicated identically across baseline2/proposed notebooks (same SEED + row order) so all models share the same test split.

## Recent Fixes & Improvements (July 2026)

### Bugs Fixed
1. **ThreadPoolExecutor false parallelism in `/predict/batch`**: Replaced with sequential loop — model inference is CPU-bound, threads just queue on GIL anyway.
2. **`get_all()` double-loaded `load_dynamic()`**: Changed to single load, reuse variable.
3. **Global `predictor_lock` serialized ALL requests**: Moved lock into `predictor.py` as `_inference_lock` wrapping ~50ms of model forward/backward only. DNS/SSL I/O (seconds) now runs in parallel across concurrent requests.
4. **`eval(atob(...))` not in suspicious JS patterns**: Added `r"\batob\s*\("` to `SUSPICIOUS_JS_PATTERNS` in `html_dom_extractor.py`.
5. **`s.string` fragile with multi-node script tags**: Changed to `s.get_text()` for robust inline JS extraction.

### Improvements
1. **`GET /health/llm`**: Returns `{available, provider: "ollama", model: "llama3.2:3b"}`. Frontend CopilotTab shows "AI Enhanced" (green) or "Template" (gray) badge.
2. **Form action in `external_link_ratio`**: Now includes `<form action>` external domains, not just `<a href>`.
3. **Theme toggle (dark/light)**: CSS custom properties + `data-theme` attribute + localStorage. Toggle button (☀/🌙) in header.
4. **Skeleton loading**: `SkeletonResult` component replaces spinner — matches ResultCard layout with shimmer animation.
5. **Responsive layout**: `flexWrap`, `auto-fit` grid, media queries at 768px/640px, overflow scroll for tabs.
6. **Vite host `0.0.0.0`**: Mobile access via http://local-ip:3000 on same Wi-Fi.

### Whitelist = reputation signal, NOT a verdict override (Aug 2026)
- `get_domain_status()` returns `{known_reputable_domain, source, expires_at, subdomain_trusted, reason}`.
- Subdomains of `USER_CONTENT_DOMAINS` (github.io, blogspot.com, netlify.app, ...) are NOT trusted — a known parent does not cover arbitrary user content subdomains.
- Dynamic entries have TTL (default 30 days, configurable `ttl_days`), auto-expire + audited.
- Every add/remove/expire is appended to `data/audit/whitelist.jsonl`.
- Auto-whitelist after N scans was REMOVED — attacker can craft clean scan history. Whitelist is admin-only via POST /whitelist (requires API key).
- Predictor runs the FULL analysis always. Reputation is a 5th engine (weight 1) that only lowers the score; strong phishing signals always override it.

### New Files
- `frontend/src/ThemeContext.jsx` — Dark/light theme provider
- `test_phishing.html` — Manual test file with eval(atob), password form, document.write iframe
- `test_genuine.html` — Manual test file with clean blog layout
- `docs/technical_report.md` — Comprehensive 17-section technical document for thesis reference
- `src/security/url_safety.py` — SSRF/URL-safety layer: blocks private/reserved IP (IPv4+IPv6), internal hostnames (localhost, *.local, *.internal...), resolves DNS and validates real IPs, `safe_get()` checks every redirect hop + caps redirects & response size (2 MiB). Applied to `ssl_redirect_extractor.py`, `dns_whois_extractor.py`, `cloaking_detector.py`, `app.py validate_url`, `webhooks.py set_webhook`.
- `api/config.py` — env-driven config (API keys, CORS origins, payload limits, rate limits, webhook allowlist/secret). `.env.example` là mẫu.
- `api/security.py` — `require_api_key` + `rate_limit` decorators, `reject_oversized_html`. Auth tắt khi `PHISHGUARD_API_KEYS` rỗng.
- `frontend/src/api.js` — API client helper: tự gắn `X-API-Key` từ `VITE_API_KEY`, xử lý lỗi JSON.

### Project State
- All 8 fixable bugs/improvements from code review completed.
- 1 known limitation: static DOM parsing vs dynamic JavaScript — would need Playwright/Puppeteer.
- **Kết quả chính thức (sau fix leakage, train lại trên Kaggle, July 2026):** Baseline 1 (ISCX, 5-fold CV) `Acc=0.9665+-0.0006, Prec=0.8922+-0.0030, Recall=0.9532+-0.0023, F1=0.9217+-0.0013, AUC=0.9925+-0.0007`; Baseline 2 (Mendeley, held-out test) `Acc=0.8719+-0.0015, Prec=0.8864+-0.0028, Recall=0.8531+-0.0020, F1=0.8694+-0.0014, AUC=0.9490+-0.0006`; Proposed (Mendeley, held-out test) `Acc=0.9725+-0.0016, Prec=0.9684+-0.0050, Recall=0.9769+-0.0022, F1=0.9726+-0.0015, AUC=0.9917+-0.0011, FPR=0.0320+-0.0053`. So sánh có nghĩa: **Proposed vs Baseline 2** (cùng dataset + split) → +0.1006 Acc, +0.0819 Prec, +0.1238 Recall, +0.1032 F1, +0.0427 AUC. Các số cũ F1=0.977/AUC=0.993 và bản intermediate (Acc=0.9725/AUC=0.9927/F1=0.9326) **KHÔNG còn dùng**. Artifact mới đã nằm trong `data/models/` (15 checkpoint + evaluation/folds JSON) + `results/figures/` (8 PNG). `evaluation_results.json` đã tạo (gộp 3 eval JSON). File quantized cũ đã xóa — predictor tự regenerate từ checkpoint mới khi khởi động API.
- Retrain workflow: `kaggle_baseline1.ipynb` → `kaggle_baseline2.ipynb` → `kaggle_proposed.ipynb` → `kaggle_compare.ipynb`. Mỗi notebook train tự sinh biểu đồ (`figures/*_summary.png`) + artifact (`predictions_*.npz`, `training_logs_*.json`, `*_folds.json`, `*_splits.json`, `dataset_stats_*.json`, `evaluation_*.json`).
- **CẢNH BÁO notebook:** không dùng helper script `.split("\n")` để sửa source cell (mất newline → notebook hỏng). Sửa bằng cách thay source list với từng dòng có `\n` cuối, rồi chạy `nbformat.validate` + `compile()` từng cell.
- Last commit: `44f8437`
