"""
Preprocess ISCX-URL2016 for TabTransformer (Baseline 1).

Pipeline Tĩnh:
  ISCXURL2016.csv (80 pre-computed columns, no raw URLs)
  → Feature selection (29 features)
  → NaN/inf handling
  → Categorical / Numerical split
  → StandardScaler (numerical) + Vocabulary mapping (categorical)
  → iscx_features.csv + iscx_metadata.json

Output columns (29 features + label + split):
  Numerical (27): urlLen, domainlength, pathLength, subDirLen, fileNameLen,
    this.fileExtLen, ArgLen, Entropy_URL, Entropy_Domain, Entropy_DirectoryName,
    Entropy_Filename, Entropy_Afterpath, spcharUrl, URL_DigitCount, host_DigitCount,
    NumberRate_URL, NumberRate_Domain, NumberRate_DirectoryName, NumberRate_FileName,
    SymbolCount_URL, SymbolCount_Domain, URL_Letter_Count, host_letter_count,
    NumberofDotsinURL, LongestPathTokenLength, CharacterContinuityRate,
    Domain_LongestWordLength
  Categorical (2): URL_sensitiveWord, ISIpAddressInDomainName
"""

import json, sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

PROJECT = Path(__file__).resolve().parents[1]
RAW_CSV = PROJECT / "data" / "raw" / "ISCXURL2016.csv"
OUT_CSV = PROJECT / "data" / "processed" / "iscx_features.csv"
OUT_META = PROJECT / "data" / "processed" / "iscx_metadata.json"

NUMERICAL_FEATURES = [
    "urlLen", "domainlength", "pathLength", "subDirLen", "fileNameLen",
    "this.fileExtLen", "ArgLen",
    "Entropy_URL", "Entropy_Domain", "Entropy_DirectoryName",
    "Entropy_Filename", "Entropy_Afterpath",
    "spcharUrl", "URL_DigitCount", "host_DigitCount",
    "NumberRate_URL", "NumberRate_Domain", "NumberRate_DirectoryName",
    "NumberRate_FileName",
    "SymbolCount_URL", "SymbolCount_Domain",
    "URL_Letter_Count", "host_letter_count",
    "NumberofDotsinURL", "LongestPathTokenLength",
    "CharacterContinuityRate", "Domain_LongestWordLength",
]

CATEGORICAL_FEATURES = [
    "URL_sensitiveWord",
    "ISIpAddressInDomainName",
]

ALL_FEATURES = NUMERICAL_FEATURES + CATEGORICAL_FEATURES


def label_mapping(label_str: str) -> int:
    label = str(label_str).strip().lower()
    return 1 if label == "phishing" else 0


def main():
    print(f"Reading {RAW_CSV}...")
    df = pd.read_csv(RAW_CSV, encoding="utf-8", low_memory=False)
    print(f"  Rows: {len(df)}, Columns: {len(df.columns)}")

    available_num = [c for c in NUMERICAL_FEATURES if c in df.columns]
    available_cat = [c for c in CATEGORICAL_FEATURES if c in df.columns]
    missing_num = [c for c in NUMERICAL_FEATURES if c not in df.columns]
    missing_cat = [c for c in CATEGORICAL_FEATURES if c not in df.columns]

    if missing_num:
        print(f"  Missing numerical: {missing_num}")
    if missing_cat:
        print(f"  Missing categorical: {missing_cat}")

    print(f"  Numerical: {len(available_num)}, Categorical: {len(available_cat)}")

    # Extract numerical
    X_num = df[available_num].copy()
    X_num = X_num.replace([np.inf, -np.inf], np.nan)
    for col in X_num.columns:
        X_num[col] = pd.to_numeric(X_num[col], errors="coerce")
    X_num = X_num.fillna(0).astype(np.float32)

    # Extract categorical
    X_cat = df[available_cat].copy()
    X_cat = X_cat.fillna(0).astype(int).clip(lower=0)

    # Label
    y = df["URL_Type_obf_Type"].apply(label_mapping)
    label_counts = y.value_counts()
    print(f"  Labels: phishing={label_counts.get(1, 0)}, benign={label_counts.get(0, 0)}")

    # ── Fit StandardScaler on numerical ──
    scaler = StandardScaler()
    X_num_scaled = scaler.fit_transform(X_num).astype(np.float32)

    # ── Build vocabulary maps for categorical features ──
    vocab_maps = {}
    for col in available_cat:
        unique_vals = sorted(X_cat[col].unique())
        vocab = {str(v): i for i, v in enumerate(unique_vals)}
        vocab_maps[col] = {"mapping": vocab, "num_classes": len(vocab)}
        X_cat[col] = X_cat[col].astype(str).map(vocab).fillna(0).astype(int)

    cat_array = X_cat.values.astype(np.int64) if len(available_cat) > 0 else \
        np.zeros((len(df), 0), dtype=np.int64)

    # ── Combine ──
    if cat_array.shape[1] > 0:
        X_combined = np.concatenate([X_num_scaled, cat_array], axis=1)
    else:
        X_combined = X_num_scaled

    feature_order = available_num + available_cat
    print(f"  Final feature dim: {X_combined.shape[1]}")

    # Pad to 29
    final_dim = 29
    if X_combined.shape[1] < final_dim:
        pad = np.zeros((len(df), final_dim - X_combined.shape[1]), dtype=np.float32)
        X_combined = np.concatenate([X_combined, pad], axis=1)
        print(f"  Padded to {final_dim}")
    elif X_combined.shape[1] > final_dim:
        X_combined = X_combined[:, :final_dim]
        print(f"  Truncated to {final_dim}")

    out_df = pd.DataFrame(X_combined, columns=[f"f{i}" for i in range(final_dim)])
    out_df["label"] = y.values

    # Train/test split
    train_idx, test_idx = train_test_split(
        range(len(out_df)), test_size=0.2, random_state=42, stratify=y
    )
    out_df["split"] = "train"
    out_df.loc[test_idx, "split"] = "test"

    out_df.to_csv(OUT_CSV, index=False)
    print(f"\nSaved: {OUT_CSV}")
    print(f"  Train: {len(train_idx)}, Test: {len(test_idx)}")
    print(f"  Shape: {out_df.shape}")

    # ── Save metadata ──
    metadata = {
        "num_features": final_dim,
        "num_numerical": len(available_num),
        "num_categorical": len(available_cat),
        "numerical_columns": available_num,
        "categorical_columns": available_cat,
        "feature_order": feature_order,
        "vocab_maps": vocab_maps,
        "scaler_mean": scaler.mean_.tolist() if hasattr(scaler, "mean_") else [],
        "scaler_scale": scaler.scale_.tolist() if hasattr(scaler, "scale_") else [],
        "n_samples": len(df),
    }
    OUT_META.parent.mkdir(parents=True, exist_ok=True)
    OUT_META.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Metadata: {OUT_META}")


if __name__ == "__main__":
    main()
