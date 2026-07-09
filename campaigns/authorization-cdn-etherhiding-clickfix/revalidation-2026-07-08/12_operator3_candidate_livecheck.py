import base64, re, urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")
CONTRACT = re.compile(r"0x[0-9a-fA-F]{40}")

def is_kit(dec):
    d = dec.lower()
    hits = sum(x in d for x in ("polygon", "eth_call", "api.php"))
    return (GUARD.search(dec) is not None and hits >= 2) or ("api.php?s=" in d and "polygon" in d)

def fetch(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.read(3_000_000).decode("utf-8", "replace")
        except Exception:
            continue
    return None

def check(host):
    body = fetch(host)
    if body is None:
        return host, "UNREACHABLE", ""
    for blob in ATOB.findall(body):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        for k in range(256):
            dec = bytes(b ^ k for b in raw).decode("utf-8", "replace")
            if is_kit(dec):
                c = CONTRACT.search(dec)
                return host, "CONFIRMED", f"xor={k} contract={c.group(0) if c else '?'}"
    if re.search(r"new Function\(new TextDecoder", body, re.I) and ATOB.search(body):
        return host, "WRAPPER_NO_MATCH", ""
    return host, "CLEAN", ""

for h in ["apimetrology.com", "www.motorbeam.com", "greencoalition.pl"]:
    print(check(h))
