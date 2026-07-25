"""Comprehensive test of all modules."""
import sys, json, os
sys.path.insert(0, os.path.dirname(__file__) or '.')
results = []

def log(msg):
    print(msg)
    results.append(msg)

# 1. Brand Detection
log("=== 1. BRAND DETECTION ===")
from src.brand_detection import get_brand_risk_score
tests = [
    ("https://www.paypal.com/webscr", "legit paypal"),
    ("http://secure-paypa1.com/login", "fake paypal"),
    ("https://www.google.com", "legit google"),
    ("http://faceb00k-login.com/reset", "fake fb"),
]
for url, desc in tests:
    r = get_brand_risk_score(url)
    log(f"  {desc:20} -> brands={r['brands_detected']} risk={r['risk_score']:.4f} impersonation={r['has_brand_impersonation']}")

# 2. Proposed Model (with HTML)
log("\n=== 2. PROPOSED MODEL PREDICTION ===")
from api.predictor import predictor
r1 = predictor.predict("https://www.google.com", "<html><body><h1>Google Search</h1><p>Safe page</p></body></html>")
log(f"  google.com (with HTML):  prob={r1['phishing_probability']:.4f} verdict={'PHISHING' if r1['is_phishing'] else 'SAFE'}")
r2 = predictor.predict("http://secure-paypa1.com/login", "<html><body><h1>Verify your PayPal account</h1><form><input type=password></form></body></html>")
log(f"  fake-paypal (with HTML): prob={r2['phishing_probability']:.4f} verdict={'PHISHING' if r2['is_phishing'] else 'SAFE'}")
log(f"    brand analysis: {r2['brand_analysis']['brands_detected']} risk={r2['brand_analysis']['risk_score']:.4f}")

# 3. Evaluation Results
log("\n=== 3. EVALUATION RESULTS ===")
for fname in ['evaluation_baseline1.json', 'evaluation_baseline2.json', 'evaluation_proposed.json']:
    fpath = os.path.join('data/models', fname)
    if os.path.exists(fpath):
        e = json.load(open(fpath))
        log(f"  {e['model'][:40]:40} Acc={e['accuracy']:.4f} F1={e['f1']:.4f} AUC={e['auc']:.4f}")

log("\n=== ALL TESTS COMPLETED ===")