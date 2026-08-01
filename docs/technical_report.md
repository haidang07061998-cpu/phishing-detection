# Phishing Detection System — Tài liệu kỹ thuật cho Đồ án Tốt nghiệp

## 1. Tổng quan kiến trúc

```
┌─────────────────────────────────────────────────────────┐
│                      Frontend (React + Vite)            │
│  Port 3000                                              │
│  UrlInput → ResultCard (Overview | Details | Behavior   │
│             | AI Copilot) → FeedbackButton              │
└──────────────────────┬──────────────────────────────────┘
                       │ /api/* proxy
                       ▼
┌─────────────────────────────────────────────────────────┐
│                      API (Flask Python)                  │
│  Port 5000                                              │
│                                                         │
│  /predict      → predictor.predict(url, html)           │
│  /predict/batch→ predictor.predict() loop               │
│  /domain       → DNS/WHOIS lookup only                  │
│  /ip           → Reverse DNS + WHOIS                    │
│  /explain      → llm_explainer (Ollama LLM)             │
│  /feedback     → Feedback loop (FP/FN tracking)         │
│  /webhook      → Webhook config (Slack/Teams/SIEM)      │
│  /whitelist    → CRUD adaptive whitelist                │
│  /reputation   → Historical scan stats                  │
│  /health       → Health check                           │
│  /health/llm   → Ollama availability                    │
└──────┬──────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│                   Predictor Core                         │
│                                                         │
│  1. DNS/SSL extraction (ThreadPoolExecutor max_workers=2)│
│  2. Whitelist check (static + dynamic auto-learned)     │
│  3. URL redirect expansion + subdomain detection         │
│  4. Gated Fusion inference (lock-protected, ~50ms)       │
│  5. Gradient-based feature importance                    │
│  6. Multi-engine weighted voting                         │
│  7. Reputation update + auto-whitelist                   │
│  8. Natural language explanation (template)              │
└─────────────────────────────────────────────────────────┘
```

## 2. Multi-Engine System

4 virtual engines hoạt động độc lập, kết hợp bằng weighted voting:

| Engine | Weight | Input | Mô tả |
|--------|--------|-------|-------|
| AI Model | 4 | Gated Fusion output + temperature scaling | Deep learning model (TabTransformer + ModernBERT + DOM) |
| DNS Infrastructure | 2 | DNS records, SSL, domain age, ASN | Phân tích hạ tầng mạng |
| URL Pattern | 2 | URL features, entropy, keywords, TLD | Phân tích cấu trúc URL |
| Brand Impersonation | 1 | Brand detection + text matching | Phát hiện giả mạo thương hiệu |

Công thức weighted voting:
```
final_score = Σ(engine_score_i × weight_i) / Σ(weight_i)
final_score >= 60 → phishing
final_score >= 30 → suspicious
else → safe
```

## 3. Gated Fusion Model

### Kiến trúc
```
URL (12 features) ──→ TabTransformer (12→128) ──┐
HTML clean text   ──→ ModernBERT (768)     ──┤──→ Gated Fusion (960) → Logits → Sigmoid
DOM (64 features) ──→ Projector (64→64)    ──┘
```

### 3 nhánh
1. **TabTransformer**: 12 URL features → embedding → Transformer → 128-dim
2. **ModernBERT**: clean text → BERT tokenizer → 768-dim (quantized dynamic)
3. **DOM Projector**: 64 DOM features → linear projection → 64-dim

### Gated Fusion
```
gates = sigmoid(W_g × concat(tab, bert, dom) + b_g)
fused = gates × concat(tab, bert, dom)
output = W_o × LayerNorm(fused) + b_o
```

### Training
- Dataset: Mendeley 2021 (80k records) + ISCX-URL2016 (36k records)
- 5-fold cross validation (tất cả 3 model, cùng split/seed)
- BCEWithLogitsLoss + pos_weight cho class imbalance
- ChainedScheduler: warmup + cosine annealing
- Gradient clipping 0.5 + AMP (GradScaler)
- Per-fold feature normalization

### Performance

Kết quả chính thức (chạy lại trên Kaggle sau fix data leakage, 5-fold CV, cùng split/seed — chi tiết trong `data/models/evaluation_*.json`):

- **Baseline 1** (ISCX, 5-fold CV): Acc=0.9665 ±0.0006, Prec=0.8922 ±0.0030, Recall=0.9532 ±0.0023, F1=0.9217 ±0.0013, AUC=0.9925 ±0.0007
- **Baseline 2** (Mendeley, held-out test): Acc=0.8719 ±0.0015, Prec=0.8864 ±0.0028, Recall=0.8531 ±0.0020, F1=0.8694 ±0.0014, AUC=0.9490 ±0.0006
- **Proposed** (Mendeley, held-out test): Acc=0.9725 ±0.0016, Prec=0.9684 ±0.0050, Recall=0.9769 ±0.0022, **F1=0.9726 ±0.0015**, **AUC=0.9917 ±0.0011**
- So sánh cùng held-out test (Mendeley): **Proposed vs Baseline 2** — +0.1006 Acc, +0.0819 Prec, +0.1238 Recall, +0.1032 F1, +0.0427 AUC
- Temperature Scaling: T = 2.8

### Ablation reporting (hiện tại)
- **Baseline 1** (ISCX): báo cáo 5-fold CV (không có test set ngoài).
- **Baseline 2** & **Proposed** (Mendeley): split 80/20 giống nhau (cùng SEED/row order) → báo cáo **held-out test** (top-level trong `evaluation_*.json`), CV ghi dưới key `cv_*`.

### Feature Importance
Gradient-based: ∂(loss)/∂(feature) × feature_value → xếp hạng đóng góp

## 4. AI Copilot (LLM Integration)

- **Provider**: Ollama local (llama3.2:3b)
- **Endpoint**: POST /explain { question, result } → LLM answer
- **Anti-hallucination prompt**: "ONLY use data in SCAN RESULTS, NEVER make up data"
- **Temperature**: 0.2 (deterministic)
- **Max tokens**: 300
- **Fallback**: Nếu Ollama unavailable → template-based explanation (explainer.py)
- **Context builder**: Flags HTML/DNS/SSL: AVAILABLE / NOT AVAILABLE
- **Frontend**: TypewriterText animation, skeleton loading, badge "AI Enhanced" / "Template"

## 5. Adaptive Whitelist

2 tầng:
- **Static**: 80+ domains (Google, Microsoft, Facebook, Apple, Amazon, VN domains...)
- **Dynamic auto-learned**: Domain tự động thêm sau 5 scans với avg_score ≤ 15
- **Persistent storage**: data/dynamic_whitelist.json (JSONL)
- Thread-safe với threading.Lock

## 6. Historical Reputation

- File: data/cache/reputation.json
- Mỗi domain: first_seen, last_seen, scans, avg_score, phishing_rate
- Update trên mỗi prediction
- Thread-safe append

## 7. Feedback Loop

- Ghi nhận: correct / false_positive / false_negative
- File: data/feedback/YYYY-MM-DD.jsonl (append-only, phân loại theo ngày)
- Dùng cho retraining dataset

## 8. Webhook System

- Config CRUD qua API
- Dispatch async (threading.Thread daemon)
- Payload: { url, aggregate_score, verdict, timestamp }
- Tích hợp SIEM/SOAR

## 9. DOM Extractor (64 features)

### Feature groups
| Index | Group | Features |
|-------|-------|----------|
| 0-6 | Basic tag counts | script, iframe, form, input, password, button, a |
| 7-12 | External references | external script, external link ratio (gồm form action), external image, favicon, total images, total links |
| 13-18 | Security indicators | hidden elements, meta refresh, eval count, document.write, suspicious JS (gồm atob()), empty links |
| 19-24 | Structural | meta, div, p, table, span, ul |
| 25-30 | Special | li, h*, br, comment, noscript, style |
| 31-38 | JS syntactic | http, https, ., =, +, [, {, ( |
| 39-54 | JS keywords | function, var, let, const, return, if, for, while, try, catch, new, this, null, undefined, true, false |
| 55-62 | JS modern | Promise, async, await, import, export, class, =>, //, /* |
| 63 | HTML attrs | Total attribute count |

### Hạn chế đã biết
- Static HTML parsing (BeautifulSoup) → không detect được dynamic content (eval trong document.write, iframe tạo bằng JS)
- Cần headless browser (Playwright/Puppeteer) để xử lý JavaScript thật

## 10. API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /predict | Scan URL + optional HTML |
| POST | /predict/batch | Batch scan max 50 URLs |
| POST | /domain | DNS/WHOIS lookup |
| POST | /ip | Reverse DNS + WHOIS |
| POST | /explain | LLM explanation (Ollama) |
| POST | /feedback | Submit FP/FN feedback |
| POST | /webhook | Register webhook |
| DELETE | /webhook | Delete webhook |
| GET | /webhook | Get webhook config |
| GET | /whitelist | Get whitelist (static + dynamic) |
| POST | /whitelist/add | Add domain to dynamic whitelist |
| POST | /whitelist/remove | Remove domain from dynamic whitelist |
| GET | /reputation/<domain> | Get reputation stats |
| GET | /health | Health check |
| GET | /health/llm | LLM availability check |

## 11. Frontend Components

| Component | File | Chức năng |
|-----------|------|-----------|
| App.jsx | root | Tabs (URL/Domain/IP), theme toggle, skeleton loading, history |
| UrlInput | components/ | Input + examples + HTML file upload |
| ResultCard | components/ | 4 tabs: Overview, Details, Behavior, AI Copilot |
| Gauge | inside ResultCard | SVG gauge 0-100% |
| FeatureImportanceChart | inside ResultCard | Bar chart, top-3 features highlighted |
| EngineResultRow | inside ResultCard | Per-engine score + verdict + details |
| CopilotTab | inside ResultCard | FAQ accordion + LLM answers + TypewriterText |
| FeedbackButton | inside ResultCard | Correct / FP / FN |
| ThemeContext | ThemeContext.jsx | Dark/light mode with localStorage |

### Theme system
- CSS custom properties: --bg-page, --bg-card, --bg-header, --bg-tab, --border, --text-primary, --text-secondary, --text-muted, --text-bright
- Toggle via data-theme="dark" | "light" trên <html>
- Persist trong localStorage

## 12. Temperature Scaling

```
logits /= T (T = 2.8)
prob = sigmoid(logits)
```

T=2.8 làm phẳng probability distribution → giảm overconfidence, tạo khoảng cách giữa các lớp tốt hơn cho multi-engine voting.

## 13. Infrastructure Sanity Check

Nếu DNS mạnh (≥2 A records + ≥1 MX) và SSL valid → cap probability xuống 0.15
Heuristic giảm false positive với domain hợp lệ có hạ tầng tốt.

## 14. Concurrency Model

- **DNS/SSL lookups**: ThreadPoolExecutor trong predict() (max_workers=2)
- **Model inference**: _inference_lock (threading.Lock) — chỉ lock ~50ms
- **Batch predict**: Sequential loop (không ThreadPoolExecutor vì model inference là bottleneck)
- **Webhook dispatch**: threading.Thread daemon
- **Reputation update**: Thread-safe với lock riêng
- **Feedback write**: Thread-safe append

Không còn global predictor_lock → DNS/SSL I/O chạy song song giữa các request.

## 15. Project Structure

```
phishing-detection/
├── api/                    # Flask API (app.py, predictor.py, engines.py, ...)
├── src/                    # Source code
│   ├── features/           # Feature extractors (url, dom, dns, ssl)
│   ├── models/             # PyTorch models (full_model, tab_transformer, modernbert, gated_fusion)
│   ├── training/           # Training scripts (baseline1, baseline2, proposed)
│   ├── evaluation/         # Evaluation + figures
│   ├── explainability/     # SHAP analysis
│   └── brand_detection/    # Brand impersonation
├── frontend/               # React + Vite (port 3000)
├── data/                   # Datasets, cache, models
├── docker/                 # Dockerfile.api, Dockerfile.frontend
├── docker-compose.yml
├── README.md
└── AGENTS.md
```

## 16. Key Files

| File | Vai trò |
|------|---------|
| api/app.py | Flask routes, error handling |
| api/predictor.py | PhishingPredictor class — orchestration |
| api/engines.py | 4 engine definitions + weighted voting |
| api/explainer.py | Template-based NLG explanation |
| api/llm_explainer.py | Ollama LLM client |
| api/whitelist.py | Static + dynamic adaptive whitelist |
| api/reputation.py | Domain reputation storage |
| api/feedback.py | Feedback loop |
| api/webhooks.py | Webhook dispatch |
| api/utils.py | Shared helpers (domain parsing) |
| src/models/full_model.py | PhishingDetector end-to-end |
| src/models/gated_fusion.py | Gated fusion layer |
| src/models/modernbert_branch.py | ModernBERT wrapper |
| src/models/tab_transformer.py | TabTransformer |
| src/features/html_dom_extractor.py | 64-dim DOM feature extractor |
| src/features/url_extractor.py | 12 URL features |
| src/brand_detection/__init__.py | Brand impersonation detection |

## 17. Deployment

### Local development
```bash
# Terminal 1 — API
$env:PYTHONIOENCODING='utf-8'; python -m api.app

# Terminal 2 — Frontend
cd frontend && npm run dev

# Hoặc dùng script tự động
./start.ps1
```

### Docker (cần fix path Unicode)
```bash
docker-compose up --build
```

### Mobile access
Same Wi-Fi → http://<local-ip>:3000 (vite host 0.0.0.0)
