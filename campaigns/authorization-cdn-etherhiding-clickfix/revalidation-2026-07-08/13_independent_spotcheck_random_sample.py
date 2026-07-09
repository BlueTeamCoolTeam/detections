"""Independent spot-check: fresh fetch, fresh decode, print enough of the
decoded content for a human to eyeball. Does NOT reuse the checker script's
reported XOR key -- re-derives it from scratch to cross-check the original
tool's own logic wasn't just repeating a shared bug."""
import base64, re, urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")

def fetch(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(3_000_000).decode("utf-8", "replace")
        except Exception as e:
            last = e
            continue
    return None

def spotcheck(host):
    print(f"\n{'='*70}\n{host}\n{'='*70}")
    body = fetch(host)
    if body is None:
        print("  UNREACHABLE on this independent re-fetch")
        return
    blobs = ATOB.findall(body)
    print(f"  atob() blobs found: {len(blobs)}")
    found = False
    for blob in blobs:
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        for k in range(256):
            dec = bytes(b ^ k for b in raw).decode("utf-8", "replace")
            d = dec.lower()
            hits = sum(x in d for x in ("polygon", "eth_call", "api.php"))
            if (GUARD.search(dec) and hits >= 2) or ("api.php?s=" in d and "polygon" in d):
                print(f"  MATCH at xor={k}")
                print(f"  decoded excerpt (first 400 chars):")
                print(f"  {dec[:400]}")
                found = True
                break
        if found:
            break
    if not found:
        print("  NO MATCH on this independent re-fetch/re-decode")

for h in ["www.valores.ae", "mecfpune.com", "makeupgirl.org", "profesormatematica.cl", "www.redlodgeoutfitters.com"]:
    spotcheck(h)
