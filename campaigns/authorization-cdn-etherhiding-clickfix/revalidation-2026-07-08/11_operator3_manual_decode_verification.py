import urllib.request, base64, re

req = urllib.request.Request(
    'https://greencoalition.pl/',
    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'}
)
with urllib.request.urlopen(req, timeout=15) as resp:
    body = resp.read().decode('utf-8', 'replace')

ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
blobs = ATOB.findall(body)
print('blobs found:', len(blobs))
for i, blob in enumerate(blobs):
    raw = base64.b64decode(blob + '=' * (-len(blob) % 4))
    dec = bytes(b ^ 114 for b in raw).decode('utf-8', 'replace')
    print(f'--- blob {i} len={len(raw)} ---')
    print(dec[:600])
    print()
