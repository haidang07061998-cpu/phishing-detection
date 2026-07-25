import sys; sys.path.insert(0, 'F:\\Đồ án\\phishing-detection')
from api.predictor import predictor

urls = [
    'https://google.com',
    'https://bit.ly/3abcde',
    'http://192.168.1.1/login.php',
    'https://github.com',
]
for url in urls:
    r = predictor.predict(url)
    p = r['phishing_probability']
    print(f'URL: {url}')
    print(f'  prob: {p:.4f}')
    print(f'  feats: {r["features"]}')
    print()
