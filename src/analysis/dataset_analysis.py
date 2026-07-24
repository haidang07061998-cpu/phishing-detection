"""
Dataset Analysis and Recommendations for Phishing Detection.

Analyzes current datasets and suggests improvements.
"""

import argparse
import sys
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def analyze_iscx():
    """Analyze ISCX-URL2016 dataset."""
    path = Path(__file__).resolve().parents[2] / "data" / "raw" / "ISCXURL2016.csv"
    if not path.exists():
        return {"error": "ISCX-URL2016.csv not found"}

    df = pd.read_csv(path, encoding='utf-8', low_memory=False)
    label_col = 'URL_Type_obf_Type'
    phishing = (df[label_col].astype(str).str.strip().str.lower() == 'phishing').sum()
    benign = len(df) - phishing

    return {
        "name": "ISCX-URL2016",
        "source": "University of New Brunswick",
        "year": 2016,
        "total_samples": len(df),
        "phishing": int(phishing),
        "benign": int(benign),
        "phishing_pct": round(phishing / len(df) * 100, 2),
        "feature_cols": len(df.columns),
        "limitations": [
            "Dataset from 2016 - phishing techniques have evolved significantly",
            "Features are pre-computed (not raw URL/HTML)",
            "Only 36,707 samples - relatively small for deep learning",
            "Binary classification only (no subcategories)",
        ],
        "recommendations": [
            "Supplement with newer data (2023-2025)",
            "Consider OpenPhish or PhishTank for fresh feeds",
            "Use as pre-training only, fine-tune on recent data",
        ],
    }


def analyze_mendeley():
    """Analyze Mendeley 2021 dataset."""
    path = Path(__file__).resolve().parents[2] / "data" / "raw" / "mendeley" / "index.csv"
    html_dir = Path(__file__).resolve().parents[2] / "data" / "raw" / "mendeley" / "html"

    if not path.exists():
        return {"error": "Mendeley index.csv not found"}

    df = pd.read_csv(path, encoding='utf-8')
    phishing = (df['result'] == 1).sum()
    benign = (df['result'] == 0).sum()

    html_files = 0
    if html_dir.exists():
        html_files = sum(1 for _ in html_dir.rglob("*.html"))

    return {
        "name": "Mendeley 2021",
        "source": "Mendeley Data",
        "year": 2021,
        "total_samples": len(df),
        "phishing": int(phishing),
        "benign": int(benign),
        "phishing_pct": round(phishing / len(df) * 100, 2),
        "html_files_available": html_files,
        "limitations": [
            "Dataset from 2021 - still somewhat dated",
            "HTML files may trigger antivirus (Windows Defender)",
            "No timestamp data for temporal analysis",
            "Single source - may not generalize globally",
        ],
        "recommendations": [
            "Augment with PhishStorm (real-time feed)",
            "Add temporal validation split to test time-based generalization",
            "Consider adding URLstatus.io or VirusTotal labels for enrichment",
        ],
    }


def suggest_new_datasets():
    """Suggest newer datasets for improvement."""
    return {
        "recommended_datasets": [
            {
                "name": "PhishStorm",
                "year": 2024,
                "description": "Real-time phishing URL feed from PhishTank and OpenPhish",
                "size": "100,000+ live URLs",
                "access": "API-based, regular updates",
                "use_case": "Real-time detection and continuous learning",
            },
            {
                "name": "URLNet (2023 version)",
                "year": 2023,
                "description": "Large-scale URL dataset with character-level features",
                "size": "2.4M+ URLs",
                "access": "Public research dataset",
                "use_case": "Pre-training character-level models",
            },
            {
                "name": "CatchPhish",
                "year": 2024,
                "description": "Multi-modal phishing dataset with screenshots + HTML + URL",
                "size": "30,000+ samples",
                "access": "Academic request",
                "use_case": "Visual + textual phishing detection",
            },
            {
                "name": "PhishIntention",
                "year": 2023,
                "description": "Brand-targeted phishing pages with visual similarities",
                "size": "20,000+ samples",
                "access": "GitHub public",
                "use_case": "Brand impersonation + visual detection",
            },
        ],
        "improvement_strategies": [
            "1. Self-collection: Crawl top 500 brands and register typosquatted domains",
            "2. Active learning: Deploy model, collect false negatives, retrain",
            "3. Semi-supervised: Use model predictions to label uncurated URL feeds",
            "4. Data augmentation: Generate synthetic phishing variants via GANs",
            "5. Cross-validation: Add temporal split (train on old, test on new)",
        ],
    }


def main():
    print("=" * 60)
    print("Dataset Analysis for Phishing Detection")
    print("=" * 60)

    print("\n--- Current Datasets ---")
    iscx = analyze_iscx()
    if "error" not in iscx:
        print(f"\nISCX-URL2016 ({iscx['year']}):")
        print(f"  Samples: {iscx['total_samples']:,} ({iscx['phishing_pct']:.1f}% phishing)")
        print(f"  Features: {iscx['feature_cols']}")
        print(f"  Limitations: {iscx['limitations'][0]}")
    else:
        print(f"\nISCX-URL2016: {iscx['error']}")

    men = analyze_mendeley()
    if "error" not in men:
        print(f"\nMendeley 2021 ({men['year']}):")
        print(f"  Samples: {men['total_samples']:,} ({men['phishing_pct']:.1f}% phishing)")
        print(f"  HTML files: {men['html_files_available']:,}")
        print(f"  Limitations: {men['limitations'][0]}")
    else:
        print(f"\nMendeley: {men['error']}")

    print("\n--- Recommended New Datasets ---")
    datasets = suggest_new_datasets()
    for ds in datasets["recommended_datasets"]:
        print(f"\n{ds['name']} ({ds['year']}):")
        print(f"  {ds['description']}")
        print(f"  Size: {ds['size']}")
        print(f"  Access: {ds['access']}")

    print("\n--- Improvement Strategies ---")
    for s in datasets["improvement_strategies"]:
        print(f"  {s}")


if __name__ == "__main__":
    main()