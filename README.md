# Phishing Detection System — Multi-Engine MVP

Gated Fusion deep learning model + 4 rule-based engines + adaptive defenses for phishing URL detection. F1=0.977, AUC=0.993.

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
    Adaptive Whitelist
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
| GET/POST/DELETE | `/whitelist` | Manage trusted domain list |

### /predict Response

```json
{
  "url": "https://example.com",
  "phishing_probability": 0.023,
  "is_phishing": false,
  "aggregate_score": 8.3,
  "engine_results": {
    "final_score": 8.3,
    "final_verdict": "safe",
    "engines": {
      "ai_model": { "score": 5, "verdict": "safe", "details": "...", "confidence": 0.977 },
      "dns_infrastructure": { "score": 10, "verdict": "safe", "details": "..." },
      "url_pattern": { "score": 5, "verdict": "safe", "details": "..." },
      "brand": { "score": 0, "verdict": "safe", "details": "..." }
    }
  },
  "reputation": { "scans": 12, "avg_score": 9.2, "phishing_rate": 0.0 },
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

### Adaptive Whitelist (`api/whitelist.py`)
- 80+ hardcoded trusted domains (Google, Microsoft, GitHub, etc.)
- Dynamic auto-learned: domains with ≥5 scans and avg_score ≤15 auto-added
- REST API for manual add/remove

### Reputation (`api/reputation.py`)
- Per-domain: scan count, average score, phishing rate
- Thread-safe JSON persistence (`data/cache/reputation.json`)
- Updated on every prediction

### Explainer (`api/explainer.py`)
- Template-based natural language generator (no LLM API)
- Analyzes 15+ signals: brand, DNS, SSL, ASN, entropy, TLD, redirects, subdomains, reputation
- Returns: verdict_summary, key_findings[], risk_factors[], recommendations[]

### Feedback Loop (`api/feedback.py`)
- JSONL format (append-only, crash-safe)
- Labels: `false_positive`, `false_negative`, `correct`
- Stored in `data/feedback/YYYY-MM-DD.jsonl`

### Webhook (`api/webhooks.py`)
- Async dispatch via background thread (non-blocking)
- Event: `scan.completed`
- POST JSON payload to external SIEM/SOAR endpoint

## Models (Ablation Study)

| Model | Features | Params | Acc | AUC | F1 |
|-------|----------|--------|-----|-----|-----|
| Baseline 1 | TabTransformer (29 ISCX feats) | 71K | 0.9858 | 0.9980 | 0.9655 |
| Baseline 2 | TabTransformer (12 URL feats) | 71K | 0.8966 | 0.9593 | 0.8578 |
| **Proposed** | **Gated Fusion (URL + ModernBERT + DOM)** | **32.9M** | **0.9770** | **0.9928** | **0.9770** |

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
# Local (3-fold for Proposed, 5-fold for baselines)
python -m src.training.train_baseline1
python -m src.training.train_baseline2
python -m src.training.train_proposed

# Evaluation
python -m src.evaluation.evaluate
python -m src.explainability.shap_analysis
```

Full training on Kaggle (GPU): `kaggle_proposed.ipynb`

## Notes

- Unicode on Windows: set `$env:PYTHONIOENCODING='utf-8'` first
- Docker không chạy được trên máy — chạy thủ công 2 terminal
- HTML phishing files may trigger Windows Defender — DOM extractor falls back to zero vector
