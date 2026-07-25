import urllib.request, json
url = 'https://api.github.com/repos/haidang07061998-cpu/phishing-detection/contents'
items = json.loads(urllib.request.urlopen(url).read())
for i in sorted(items, key=lambda x: x['name']):
    print(f"{i['type']:5s} {i['name']}")
