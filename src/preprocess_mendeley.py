"""
Preprocess Mendeley Phishing 2021 for Baseline 2 + Proposed Model.

Pipeline Tĩnh (→ mendeley_url_dns.csv cho Baseline 2):
  index.csv → URL normalization → URL features (12) + DNS/WHOIS (8) + SSL/Redirect (5)
  → StandardScaler (numerical) + Vocab mapping (categorical) → 29-dim tabular

Pipeline Động (→ mendeley_full/ cho Proposed Model):
  A. HTML → DOM features (64-dim) via html_dom_extractor
  B. HTML → Clean text (max 8192 ký tự) → save raw để tokenize lúc train

Usage:
  # Chạy cả 2 pipeline (có network queries)
  python -m src.preprocess_mendeley

  # Static pipeline only, skip network (dùng -1 defaults)
  python -m src.preprocess_mendeley --static --no-network

  # Dynamic pipeline only
  python -m src.preprocess_mendeley --dynamic
"""

import json, re, sys
from pathlib import Path
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from bs4 import BeautifulSoup, Comment

from src.features.url_extractor import extract_url_features
from src.features.html_dom_extractor import extract_dom_features, extract_clean_text

PROJECT = Path(__file__).resolve().parents[1]
INDEX_CSV = PROJECT / "data" / "raw" / "mendeley" / "index.csv"
HTML_DIR = PROJECT / "data" / "raw" / "mendeley" / "html"
OUT_DIR = PROJECT / "data" / "processed"
OUT_CSV = OUT_DIR / "mendeley_url_dns.csv"
OUT_FULL_DIR = OUT_DIR / "mendeley_full"

TABULAR_DIM = 29
FEATURE_KEYS = [
    "url_length", "domain_length", "path_length", "entropy",
    "special_char_ratio", "digit_ratio", "subdomain_count", "has_https",
    "has_ip_address", "suspicious_keywords", "url_depth", "tld_in_path",
]


def normalize_url(url: str) -> str:
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


# ═══════════════════════════════════════════════════════════════════════════
# STATIC PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def build_tabular_vector(url: str, use_network: bool) -> dict:
    """Build a dict of tabular features (aligned with ISCX format)."""
    url_norm = normalize_url(url)
    feats = extract_url_features(url_norm)

    # DNS/WHOIS/SSL — fallback defaults nếu không dùng network hoặc lỗi
    for k in ["a_record_count", "mx_record_count", "ns_record_count", "ttl"]:
        feats[k] = -1
    for k in ["domain_age_days", "registrar", "is_privacy_protected", "country"]:
        feats[k] = -1
    for k in ["ssl_valid", "ssl_age_days", "ssl_issuer_trusted",
              "redirect_count", "cross_domain_redirect"]:
        feats[k] = -1

    if use_network:
        try:
            from src.features.dns_whois_extractor import extract_dns_whois_features
            from src.features.ssl_redirect_extractor import extract_ssl_redirect_features
            dns_whois = extract_dns_whois_features(url_norm, use_cache=True)
            feats.update({k: dns_whois.get(k, -1) for k in
                          ["a_record_count", "mx_record_count", "ns_record_count",
                           "ttl", "domain_age_days", "registrar",
                           "is_privacy_protected", "country"]})
        except Exception:
            pass
        try:
            ssl_redir = extract_ssl_redirect_features(url_norm)
            feats.update({k: ssl_redir.get(k, -1) for k in
                          ["ssl_valid", "ssl_age_days", "ssl_issuer_trusted",
                           "redirect_count", "cross_domain_redirect"]})
        except Exception:
            pass

    return feats


def preprocess_static(use_network: bool = True):
    """
    Static pipeline: index.csv → 29-dim tabular features.
    Lưu mendeley_url_dns.csv (chuẩn hóa giống ISCX).
    """
    print("=" * 60)
    print("STATIC PIPELINE: URL + DNS/WHOIS + SSL/Redirect")
    print("=" * 60)

    df = pd.read_csv(INDEX_CSV, encoding="utf-8")
    print(f"  Records: {len(df)}")
    print(f"  Phishing: {(df['result']==1).sum()}, Genuine: {(df['result']==0).sum()}")

    all_keys = FEATURE_KEYS + [
        "a_record_count", "mx_record_count", "ns_record_count", "ttl",
        "domain_age_days", "registrar", "is_privacy_protected", "country",
        "ssl_valid", "ssl_age_days", "ssl_issuer_trusted",
        "redirect_count", "cross_domain_redirect",
    ]

    rows = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Static"):
        feats = build_tabular_vector(str(row["url"]), use_network)
        vec = [feats.get(k, -1) for k in all_keys]
        rows.append(vec + [int(row["result"])])

    col_names = all_keys + ["label"]
    raw_df = pd.DataFrame(rows, columns=col_names)

    # Clean
    for col in all_keys:
        raw_df[col] = pd.to_numeric(raw_df[col], errors="coerce")
    raw_df = raw_df.replace([np.inf, -np.inf], np.nan).fillna(-1)
    print(f"  Feature frame: {raw_df.shape}, NaN: {raw_df.isna().sum().sum()}")

    # Numerical vs Categorical
    numerical_keys = [k for k in all_keys if k not in ("registrar", "country")]
    categorical_keys = [k for k in all_keys if k in ("registrar", "country")]

    X_num = raw_df[numerical_keys].astype(np.float32)
    scaler = StandardScaler()
    X_num_scaled = scaler.fit_transform(X_num).astype(np.float32)

    X_cat = raw_df[categorical_keys].astype(str)
    vocab_maps = {}
    for col in categorical_keys:
        uniq = sorted(X_cat[col].unique())
        vocab = {v: i for i, v in enumerate(uniq)}
        vocab_maps[col] = {"mapping": vocab, "num_classes": len(vocab)}
        X_cat[col] = X_cat[col].map(vocab).fillna(0).astype(int)

    X_all = np.concatenate([
        X_num_scaled,
        X_cat.values.astype(np.float32),
    ], axis=1) if len(categorical_keys) > 0 else X_num_scaled

    # Pad/truncate to TABULAR_DIM
    if X_all.shape[1] < TABULAR_DIM:
        pad = np.zeros((len(X_all), TABULAR_DIM - X_all.shape[1]), dtype=np.float32)
        X_all = np.concatenate([X_all, pad], axis=1)
    elif X_all.shape[1] > TABULAR_DIM:
        X_all = X_all[:, :TABULAR_DIM]

    out_df = pd.DataFrame(X_all, columns=[f"f{i}" for i in range(TABULAR_DIM)])
    out_df["label"] = raw_df["label"].values

    y = raw_df["label"].values
    train_idx, test_idx = train_test_split(
        range(len(out_df)), test_size=0.2, random_state=42, stratify=y
    )
    out_df["split"] = "train"
    out_df.loc[test_idx, "split"] = "test"

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(OUT_CSV, index=False)
    print(f"\nSaved: {OUT_CSV}")
    print(f"  Train: {len(train_idx)}, Test: {len(test_idx)}")
    print(f"  Shape: {out_df.shape}")

    meta = {
        "tabular_dim": TABULAR_DIM,
        "numerical_keys": numerical_keys,
        "categorical_keys": categorical_keys,
        "vocab_maps": vocab_maps,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
    }
    meta_path = OUT_DIR / "mendeley_metadata.json"
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Metadata: {meta_path}")


# ═══════════════════════════════════════════════════════════════════════════
# DYNAMIC PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def preprocess_dynamic():
    """
    Dynamic pipeline: HTML files → DOM (64-dim) + Clean text.
    Lưu mendeley_full/ (data.jsonl + split.json).
    """
    print("\n" + "=" * 60)
    print("DYNAMIC PIPELINE: DOM (64-dim) + HTML Text")
    print("=" * 60)

    df = pd.read_csv(INDEX_CSV, encoding="utf-8")
    print(f"  Records: {len(df)}")

    OUT_FULL_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = OUT_FULL_DIR / "data.jsonl"
    skipped = 0

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for _, row in tqdm(df.iterrows(), total=len(df), desc="Dynamic"):
            url = str(row["url"]).strip()
            fname = str(row["website"]).strip()
            label = int(row["result"])

            # URL features (cho tabular branch)
            url_feats = extract_url_features(normalize_url(url))
            url_vec = [url_feats[k] for k in FEATURE_KEYS]

            # HTML file
            subdir = "phishing" if label == 1 else "genuine"
            html_path = HTML_DIR / subdir / fname

            dom_vec = np.zeros(64, dtype=np.float32)
            clean_text = ""

            if html_path.exists():
                try:
                    raw_html = html_path.read_text(encoding="utf-8", errors="replace")
                    dom_vec = extract_dom_features(raw_html, base_url=url)
                    soup = BeautifulSoup(raw_html, "html.parser")
                    for tag in soup(["script", "style", "noscript"]):
                        tag.decompose()
                    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
                        comment.extract()
                    clean_text = soup.get_text(separator=" ", strip=True)
                    clean_text = re.sub(r"\s+", " ", clean_text).strip()
                except OSError:
                    skipped += 1
            else:
                skipped += 1

            record = {
                "url": url,
                "filename": fname,
                "label": label,
                "url_features": url_vec,
                "dom_features": dom_vec.tolist(),
                "clean_text": clean_text,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    if skipped:
        print(f"  Warning: {skipped}/{len(df)} files skipped")

    labels = df["result"].values
    train_idx, test_idx = train_test_split(
        range(len(df)), test_size=0.2, random_state=42, stratify=labels
    )
    split = {"train_indices": train_idx.tolist(), "test_indices": test_idx.tolist()}
    (OUT_FULL_DIR / "split.json").write_text(json.dumps(split), encoding="utf-8")
    print(f"\nSaved: {jsonl_path}")
    print(f"  Train: {len(train_idx)}, Test: {len(test_idx)}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Preprocess Mendeley Phishing 2021")
    parser.add_argument("--static", action="store_true", help="Run static pipeline")
    parser.add_argument("--dynamic", action="store_true", help="Run dynamic pipeline")
    parser.add_argument("--no-network", action="store_true",
                        help="Skip DNS/WHOIS/SSL (use -1 defaults)")
    parser.add_argument("--all", action="store_true", help="Run both pipelines")
    args = parser.parse_args()

    run_static = args.static or args.all or not (args.dynamic or args.all)
    run_dynamic = args.dynamic or args.all

    # Default: run both if no flags given
    if not (args.static or args.dynamic or args.all):
        run_static = run_dynamic = True

    if run_static:
        preprocess_static(use_network=not args.no_network)

    if run_dynamic:
        preprocess_dynamic()

    print("\nDone.")


if __name__ == "__main__":
    main()
