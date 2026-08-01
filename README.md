# Phishing Detection System — Multi-Engine MVP

Gated Fusion deep learning model + 4 rule-based engines + adaptive defenses for phishing URL detection.

> ✅ **Kết quả chính thức (sau fix data leakage, July 2026, chạy trên Kaggle):** Baseline 1 (ISCX, 5-fold CV) Acc=0.9665, AUC=0.9925; Baseline 2 (Mendeley, held-out test) Acc=0.8719, AUC=0.9490; **Proposed** (Mendeley, held-out test) **Acc=0.9725, AUC=0.9917, F1=0.9726**. Chi tiết trong bảng bên dưới.

## Architecture

```
User ──→ Frontend (React/Vite :3000)
              │ POST /api/predict
              ▼
          Flask API (:5000)
              │
        ┌─────┼──────┬──────────┐
        ▼     ▼      ▼          ▼
    AI Model  DNS   URL Pattern Brand
    (weight 4)(w=2)  (w=2)     (w=1)
        │     │      │          │
        └─────┴──────┴──────────┘
              ▼
      combine_engines()
      (weighted voting)
              │
        ┌─────┼──────┬──────────┐
        ▼     ▼      ▼          ▼
    Explainer Reputation Feedback Webhook
              │
        ┌─────┘
        ▼
    Reputation Whitelist
    (known-reputable signal)
```

**Gated Fusion** — 3 branches:
- **TabTransformer** (12 URL features → 128-dim)
- **ModernBERT** (HTML text → 768-dim CLS)
- **DOM Projector** (64 structural features)
- Temperature scaling T=2.8

**4 Virtual Engines** (weighted voting):
| Engine | Weight | What it checks |
|--------|--------|----------------|
| AI Model | 4 | Gated Fusion output + gradient-based feature importance |
| DNS Infrastructure | 2 | DNS records, SSL cert, domain age, ASN reputation |
| URL Pattern | 2 | Entropy, suspicious TLD, keywords, redirects, shorteners |
| Brand | 1 | Brand name impersonation in URL/page text |

## Quick Start

```bash
# API
$env:PYTHONIOENCODING='utf-8'
python -m api.app

# Frontend (separate terminal)
cd frontend && npm run dev
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/predict` | Analyze a URL (optional `html`) |
| POST | `/predict/batch` | Batch analyze up to 50 URLs |
| POST | `/domain` | Domain-only lookup (DNS + engines) |
| POST | `/ip` | IP-only lookup |
| POST | `/feedback` | Submit FP/FN correction |
| GET | `/feedback/stats` | Feedback statistics |
| GET/POST/DELETE | `/webhook` | Webhook config for SIEM/SOAR |
| GET/POST/DELETE | `/whitelist` | Manage known-reputable domain list (admin-only, TTL, audited) |
| GET/POST/DELETE | `/threat` | Known-threat database: list / add / remove blocklist entries (admin-only, audited) |
| GET | `/history` | Scan history + summary counts |
| GET | `/history/export?format=csv|json` | Export full scan history |
| GET/POST/DELETE | `/keys` | API key registry management (admin-only) |

### /predict Response

```json
{
  "url": "https://example.com",
  "phishing_probability": 0.023,
  "is_phishing": false,
  "aggregate_score": 8.3,
  "analysis_quality": "full",
  "analysis_reason": "",
  "model_name": "proposed_fold1_best.pt",
  "ensemble_folds": 1,
  "temperature": 2.8,
  "engine_results": {
    "final_score": 8.3,
    "final_verdict": "safe",
    "engines": {
      "ai_model": { "score": 5, "verdict": "safe", "details": "...", "confidence": 0.03 },
      "dns_infrastructure": { "score": 10, "verdict": "safe", "details": "..." },
      "url_pattern": { "score": 5, "verdict": "safe", "details": "..." },
      "brand": { "score": 0, "verdict": "safe", "details": "..." }
    }
  },
  "reputation": { "scans": 12, "avg_score": 9.2, "phishing_rate": 0.0 },
  "whitelist_status": { "known_reputable_domain": false, "source": null, "expires_at": null, "subdomain_trusted": false, "reason": "" },
  "subdomain_info": null,
  "explanation": {
    "verdict_summary": "All 4 analysis engines returned benign — no phishing indicators detected.",
    "key_findings": ["..."],
    "risk_factors": [],
    "recommendations": ["No immediate action required"]
  },
  "features": { "url_length": 42, "entropy": 3.8, ... },
  "brand_analysis": { "has_brand_impersonation": false },
  "dns_whois": { "a_record_count": 3, "mx_record_count": 1, ... },
  "ssl_redirect": { "ssl_valid": 1, ... },
  "suspicious_tld": 0,
  "is_shortener": false
}
```

## System Components

### Reputation Whitelist (`api/whitelist.py`)
- **Không phải "safe verdict"**: whitelist chỉ là *known-reputable signal*. Predictor LUÔN chạy đầy đủ URL/brand/content analysis; reputation là engine thứ 5 (weight 1) chỉ **giảm nhẹ** điểm rủi ro — tín hiệu phishing mạnh luôn thắng.
- Static: ~80 domain admin-verified (không hết hạn).
- Dynamic: admin-only qua `POST /whitelist` (cần API key), có `ttl_days` (mặc định 30), auto-expire.
- **Subdomain không tự tin cậy**: subdomain của `USER_CONTENT_DOMAINS` (github.io, blogspot.com, netlify.app, ...) KHÔNG được phủ bởi reputation của domain cha.
- Mọi add/remove/expire được audit tại `data/audit/whitelist.jsonl`.
- Auto-whitelist theo lịch sử quét đã bị **loại bỏ** (attacker có thể làm sạch lịch sử quét).

### Reputation (`api/reputation.py`)
- Per-domain: scan count, average score, phishing rate
- Thread-safe JSON persistence (`data/cache/reputation.json`)
- Updated on every prediction

### Explainer (`api/explainer.py`)
- Template-based natural language generator (no LLM API)
- Analyzes 15+ signals: brand, DNS, SSL, ASN, entropy, TLD, redirects, subdomains, reputation
- Returns: verdict_summary, key_findings[], risk_factors[], recommendations[]

### Inference Quality & Performance (`api/predictor.py`)
Các fix alignment + hiệu năng (Aug 2026), tất cả config-driven qua env:

- **Per-fold feature normalization**: training/evaluation chuẩn hóa URL/DOM features bằng `(x-mean)/std` theo fold (`train_proposed.py CachedDataset`). Predictor giờ đọc `data/models/proposed_folds.json` và áp dụng đúng scaler của fold tương ứng trước khi inference — sửa bug input OOD nghiêm trọng.
- **Token length khớp training**: inference dùng `max_length=128` (không còn 512) — model được fine-tune trên chuỗi 128 token.
- **Temperature calibration**: `TEMPERATURE=2.8` mặc định; nếu `data/models/temperature.json` tồn tại (tạo bởi `src/evaluation/calibrate.py`) thì dùng giá trị calibrated; env `PHISHGUARD_TEMPERATURE` override. **Hiện tại chưa áp dụng** — `temperature.json` đang missing trên máy này (thiếu `mendeley_full/data.jsonl` + `split.json`; calibrate cần nạp 5 checkpoint ModernBERT ~582MB/fold → OOM trên máy 7.7GB RAM). Muốn áp dụng: chạy `python -m src.preprocess_mendeley --dynamic` → `python -m src.evaluation.calibrate` trên Kaggle/GPU rồi copy về `data/models/`.
- **Fold ensemble (opt-in)**: `PHISHGUARD_ENSEMBLE_FOLDS=N` average logits của N fold checkpoints. Mặc định `1` (đơn fold, RAM thấp). Bật `5` cần ~1.4GB RAM (quantized).
- **Feature importance theo yêu cầu**: `PHISHGUARD_COMPUTE_IMPORTANCE=0` (mặc định) bỏ backward pass mỗi request; client có thể override per-call với `{"explain": true/false}`.
- **DNS/SSL extraction cache**: `PHISHGUARD_EXTRACT_CACHE_TTL=300` cache kết quả DNS/WHOIS/SSL/redirect để giảm network I/O lặp (mặc định 300s, `0` = tắt). `PHISHGUARD_REDIS_URL` (optional) chuyển cache sang Redis chia sẻ giữa workers/restart; fallback memory khi Redis không khả dụng.
- **`analysis_quality`**: `"full"` khi HTML được parse, `"limited"` khi không có HTML/parse fail — kèm `analysis_reason`.
- **Batch workers**: `PHISHGUARD_BATCH_WORKERS>1` chạy `/predict/batch` với thread pool nhỏ (overlap DNS/SSL I/O); model inference luôn serialize qua `_inference_lock`.

Benchmark: `python -m src.evaluation.benchmark [n] [--cold]` → ghi `results/benchmark.json` (warm p50/p95/p99, throughput, RSS delta, timeout rate; `--cold` đo thêm cold-start first-prediction ms nhưng tốn ~600MB RAM).

### Feedback Loop (`api/feedback.py`)
- JSONL format (append-only, crash-safe)
- Labels: `false_positive`, `false_negative`, `correct`
- Stored in `data/feedback/YYYY-MM-DD.jsonl`

### Webhook (`api/webhooks.py`)
- Async dispatch via background thread (non-blocking)
- Event: `scan.completed`
- POST JSON payload to external SIEM/SOAR endpoint
- URL phải pass URL safety policy (không cho webhook vào mạng nội bộ)

## URL Safety / SSRF Protection

Mọi hoạt động mạng do URL người dùng kích hoạt (DNS, WHOIS, SSL handshake, HTTP GET, redirect, webhook dispatch) đều đi qua `src/security/url_safety.py`:

- **Chặn non-global IP**: private (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1), link-local (169.254/16, fe80::/10), CGNAT (100.64/10), multicast, reserved, unspecified — cả IPv4 lẫn IPv6.
- **Chặn hostname nội bộ**: `localhost`, `*.local`, `*.internal`, `*.lan`, `*.intranet`, `*.corp`, `*.home.arpa`, ...
- **Resolve DNS rồi kiểm tra IP thực**: resolve A+AAAA, nếu bất kỳ IP nào không global → chặn. Không resolve được → chặn.
- **Chặn scheme nguy hiểm**: chỉ cho `http`/`https` (`file://`, `ftp://`, ... bị từ chối).
- **`safe_get()` kiểm tra từng redirect hop**: redirect vào IP/hostname nội bộ bị chặn ngay trước khi follow; giới hạn số redirect (mặc định 5) + phát hiện redirect loop.
- **Giới hạn kích thước response**: body được stream và cắt ở 2 MiB.
- **Endpoint chặn ở tầng validate**: `/predict`, `/predict/batch`, `/webhook` trả 400 khi URL không pass safety policy.

> ⚠️ **Cảnh báo deploy:** lớp này là defense-in-depth, không thay thế sandbox mạng. Với môi trường multi-tenant/tin cậy thấp, hãy chạy crawler trong container/VM riêng **không có route vào mạng nội bộ** (xem `docker/Dockerfile.api` + `docker-compose.yml`), đồng thời chặn outbound ở firewall tầng mạng.

### Docker persistence

`docker-compose.yml` mount **toàn bộ** `./data:/app/data` (không chỉ `models` + `processed`), để mọi runtime state tồn tại qua restart container:

- `data/api_keys.json` — key registry (key đã tạo không mất)
- `data/scan_history.jsonl` — lịch sử scan
- `data/audit/` — audit log (threat/webhook/whitelist/keys)
- `data/dynamic_whitelist.json`, `data/known_malicious.json`, `data/webhook_config.json`
- `data/feedback/`, `data/cache/`

`.dockerignore` loại `data/` khỏi build context (83k HTML, checkpoint hàng GB) — model vẫn được cung cấp qua volume mount. Nếu chạy `docker run` độc lập (không qua compose), hãy mount thủ công `-v ./data:/app/data`.

## API Production Security

Bảo mật được bật theo môi trường qua biến env (xem `api/config.py`, mẫu trong `.env.example`):

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `PHISHGUARD_ENV` | development | `production` → **fail-fast**: API KHÔNG khởi động nếu thiếu API keys (env keys hoặc registry). `development` cho phép chạy không auth để dev |
| `PHISHGUARD_API_KEYS` | rỗng (auth tắt) | Danh sách API key cách nhau bằng dấu phẩy. Khi đặt → mọi endpoint nhạy cảm yêu cầu header `X-API-Key` |
| `PHISHGUARD_ALLOWED_ORIGINS` | localhost:3000 | Danh sách CORS origin được phép |
| `PHISHGUARD_MAX_JSON_BYTES` | 2 MiB | Giới hạn kích thước body JSON (413 nếu vượt) |
| `PHISHGUARD_MAX_HTML_BYTES` | 2 MiB | Giới hạn HTML client gửi lên (413 nếu vượt) |
| `PHISHGUARD_RATE_MIN` / `PHISHGUARD_RATE_HOUR` | 60 / 600 | Rate limit theo IP (sliding window, 429 nếu vượt) |
| `PHISHGUARD_TRUST_PROXY` | 0 | Số hop reverse-proxy đáng tin cậy. `0` (mặc định) → **bỏ qua `X-Forwarded-For`**, dùng IP TCP peer (client không spoof được). `>=1` → bật `werkzeug ProxyFix` (x_for, x_proto) để đọc header từ proxy tin cậy |
| `PHISHGUARD_WEBHOOK_ALLOWLIST` | rỗng (webhook tắt) | Allowlist hostname cho webhook; rỗng → webhook bị vô hiệu |
| `PHISHGUARD_WEBHOOK_SECRET` | rỗng | HMAC-SHA256 signing key cho payload gửi webhook |
| `PHISHGUARD_WEBHOOK_TIMEOUT` / `_RETRIES` | 10s / 3 | Timeout và số lần retry (backoff 2^n) |
| `PHISHGUARD_THREAT_FEED_URL` | rỗng (feed tắt) | Community threat feed URL (PhishTank CSV / OpenPhish / line-list) |
| `PHISHGUARD_THREAT_FEED_REFRESH_HOURS` | 24 | Chu kỳ re-fetch feed (giờ) |

Các điểm đã xử lý:
- **Fail-fast trong production**: khi `PHISHGUARD_ENV=production`, API từ chối khởi động (RuntimeError) nếu không có key nào — env keys hoặc registry (`data/api_keys.json`) — thay vì chạy công khai không auth. Kiểm tra trước khi nạp model (fail trong ~1s). `docker-compose.yml` mặc định `production` để người vận hành quên cấu hình key là fail, không im lặng mở auth.
- **CORS hạn chế** origin theo allowlist (không còn `CORS(app)` mặc định cho phép mọi origin).
- **API key auth** trên `/predict`, `/predict/batch`, `/domain`, `/ip`, `/feedback`, `/explain`, `/webhook`, `/whitelist` (POST/DELETE), `/threat` (GET/POST/DELETE). Khi không đặt `API_KEYS`, app chạy chế độ dev không auth.
- **Key registry** (`data/api_keys.json`): SHA-256 hash secret, scopes `admin`/`scan`/`feedback`/`reports`, expiry + IP allowlist, plaintext secret trả 1 lần khi tạo, audit `data/audit/api_keys.jsonl`. Auth là no-op chỉ khi auth tắt VÀ registry rỗng; scope check → 403, key sai → 401.
- **Frontend key tối thiểu**: `VITE_API_KEY` trong `frontend/.env` bị đóng gói vào JS bundle nên **chỉ được dùng registry key có scope `scan` + `feedback`** (tạo qua `POST /keys`). Tuyệt đối KHÔNG đặt `PHISHGUARD_API_KEYS`, admin key hay reports-scoped key vào đây — ai mở trang cũng đọc được từ bundle. Dữ liệu reports (scan history, threat DB) nhạy cảm: tab Reports yêu cầu **nhập runtime** một reports/admin key (giữ trong memory, không lưu/đóng gói) mới xem/export được; thao tác admin (sửa blocklist/webhook/whitelist) cũng dùng chính key đó.
- **Rate limiting** theo IP (in-memory sliding window; ghi chú: reset khi restart, không chia sẻ giữa multi-worker gunicorn — cần Redis nếu scale).
- **Chống bypass rate-limit/IP-allowlist**: `_client_ip()` KHÔNG tin `X-Forwarded-For` từ client — dùng `request.remote_addr`. Chỉ khi `PHISHGUARD_TRUST_PROXY>=1` thì `ProxyFix` (werkzeug) mới đọc header sau khi xác thực proxy tin cậy.
- **Audit actor lấy từ key, không từ body**: các write endpoint (`/whitelist` POST/DELETE, `/threat` POST/DELETE, `/keys` POST/DELETE) ghi `added_by`/`removed_by`/`created_by` bằng helper `_actor()` — identity chỉ lấy từ `request.api_key` đã verify (name + key_id), các field gửi trong body bị **bỏ qua** → không giả mạo được người thao tác trong audit log.
- **`GET /threat` phân quyền theo query**: xem blocklist cần scope `reports`; `GET /threat?refresh=1` (force-refresh community feed) thêm yêu cầu scope `admin` — key chỉ có `reports` bị từ chối 403, không cho ai kích hoạt tải feed ngoài khi chưa được cấp admin.
- **Type-guard POST body**: `/predict`, `/predict/batch` (list ≤50, mỗi phần tử string), `/domain`, `/ip`, `/feedback`, `/explain`, `/whitelist`, `/threat` trả **400** khi kiểu sai (vd `{"url": 123}`) thay vì crash 500.
- **Giới hạn payload**: Flask `MAX_CONTENT_LENGTH` + HTML size cap riêng.
- **Không lộ `str(e)`**: error handler trả `Internal server error.` chung, log traceback đầy đủ server-side.
- **`/feedback` validate chặt**: feedback_type hợp lệ, url/verdict/comment giới hạn độ dài, score phải là số trong [-1,100], metadata là object ≤ 8 KiB.
- **`/whitelist`**: validate định dạng domain + cần API key.
- **`/threat`** (Known-Threat DB): local admin blocklist `data/known_malicious.json` + community feed tùy chọn; add/remove đều audit tại `data/audit/threat.jsonl`; hit là tín hiệu mạnh (weight 2) trong multi-engine vote, không phải hard verdict.
- **Webhook**: URL phải pass safety policy + host trong allowlist, payload ký HMAC-SHA256 (`X-PhishGuard-Signature`), dispatch bất đồng bộ có timeout, retry backoff, audit log tại `data/audit/webhooks.jsonl`.

> ⚠️ **Ghi chú**: rate limiter dùng bộ nhớ trong — phù hợp single-process/single-worker. Khi chạy gunicorn nhiều worker, mỗi worker có bucket riêng; để chính xác tuyệt đối cần nguồn chia sẻ (Redis).

## Models (Ablation Study)

Kết quả chính thức (chạy lại trên Kaggle sau fix data leakage, 5-fold CV, cùng split/seed):

| Model | Features | Params | Metric base | Acc | Prec | Recall | F1 | AUC |
|-------|----------|--------|-------------|-----|------|--------|-----|-----|
| Baseline 1 | TabTransformer (29 ISCX feats) | 150K | 5-fold CV | 0.9665 ±0.0006 | 0.8922 ±0.0030 | 0.9532 ±0.0023 | 0.9217 ±0.0013 | 0.9925 ±0.0007 |
| Baseline 2 | TabTransformer (12 URL feats) | 150K | held-out test | 0.8719 ±0.0015 | 0.8864 ±0.0028 | 0.8531 ±0.0020 | 0.8694 ±0.0014 | 0.9490 ±0.0006 |
| **Proposed** | **Gated Fusion (URL + ModernBERT + DOM)** | **152.7M** | **held-out test** | **0.9725 ±0.0016** | **0.9684 ±0.0050** | **0.9769 ±0.0022** | **0.9726 ±0.0015** | **0.9917 ±0.0011** |

Lưu ý so sánh: Baseline 2 & Proposed đánh giá trên **cùng held-out test** (Mendeley, split 80/20 cùng SEED) nên so sánh trực tiếp **Proposed vs Baseline 2**: +0.1006 Acc, +0.0819 Prec, +0.1238 Recall, +0.1032 F1, +0.0427 AUC. Baseline 1 dùng dataset khác (ISCX) nên không so sánh trực tiếp.

Số liệu nằm trong `data/models/evaluation_baseline1.json` / `evaluation_baseline2.json` / `evaluation_proposed.json`.

## Frontend

React + Vite with 4 tabs:
- **Overview** — Calibrated gauge (0-100), engine breakdown bar chart, analysis summary card, historical reputation
- **Details** — Feature table, feature importance, subdomain note, ASN/PTR with color badges
- **Behavior** — DOM signals table, banner when HTML not provided
- **AI Copilot** — 5 preset Q&A with typing animation, uses live result data

## Datasets

- **ISCX-URL2016**: 36,707 rows (7,586 phishing / 29,121 benign)
- **Mendeley 2021**: 80,000 records (30,000 phishing / 50,000 genuine) + 83,275 HTML files

## Training

```bash
# Local (all 3 models use 5-fold CV)
python -m src.training.train_baseline1
python -m src.training.train_baseline2
python -m src.training.train_proposed

# Evaluation
python -m src.evaluation.evaluate
python -m src.explainability.shap_analysis
```

## Retrain tất cả trên Kaggle (workflow chính thức)

Chạy lần lượt (mỗi notebook tự sinh biểu đồ báo cáo + artifact):

1. **`kaggle_baseline1.ipynb`** — 5-fold CV trên ISCX (không có test set ngoài). Tự sinh: `figures/baseline1_summary.png`, `evaluation_baseline1.json`, `baseline1_folds.json`, `training_logs_baseline1.json`, `predictions_baseline1.npz`, `dataset_stats_iscx.json`.
2. **`kaggle_baseline2.ipynb`** — sample 50k + split 80/20, CV trên train + đánh giá held-out test. Tự sinh: `figures/baseline2_summary.png`, `evaluation_baseline2.json` (top-level = test, `cv_*` = CV), `baseline2_splits.json`, `baseline2_folds.json`, `training_logs_baseline2.json`, `predictions_baseline2.npz`, `dataset_stats_mendeley.json`.
3. **`kaggle_proposed.ipynb`** — giống baseline 2. Tự sinh: `figures/proposed_summary.png`, `evaluation_proposed.json`, `proposed_splits.json`, `proposed_folds.json`, `training_logs_proposed.json`, `predictions_proposed.npz`, `dataset_stats_proposed.json`.

Sau khi có đủ artifact: upload vào dataset của **`kaggle_compare.ipynb`** → chạy → sinh `figures/compare_bar.png`, `compare_roc.png`, `compare_cm.png`, `compare_curves.png`, `compare_dist.png`.

Tải toàn bộ về và đặt vào `data/models/` (JSON/`*.pt`) và `data/` (npz/logs/stats) để `evaluate.py` chạy cục bộ.

## Notes

- Unicode on Windows: set `$env:PYTHONIOENCODING='utf-8'` first
- Docker không chạy được trên máy — chạy thủ công 2 terminal
- HTML phishing files may trigger Windows Defender — DOM extractor falls back to zero vector
