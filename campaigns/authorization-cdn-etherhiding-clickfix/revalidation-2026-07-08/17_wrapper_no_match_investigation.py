import base64, re, urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{40,})['\"]\)")

def fetch(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(3_000_000).decode("utf-8", "replace")
        except Exception as e:
            print(f"  fetch error ({scheme}): {e}")
            continue
    return None

for host in ["offertic.net", "www.cartolibreriabisceglia.it"]:
    print(f"\n{'='*70}\n{host}\n{'='*70}")
    body = fetch(host)
    if body is None:
        print("  UNREACHABLE")
        continue
    print(f"  page length: {len(body)}")
    # find the "new Function" wrapper context, print surrounding code verbatim
    idx = body.find("new Function")
    if idx == -1:
        idx = body.lower().find("newfunction")
    if idx != -1:
        print("  --- context around 'new Function' (800 chars before/after) ---")
        print(body[max(0,idx-800):idx+800])
    else:
        print("  'new Function' string not found on this fetch (may have changed since verification run)")

    blobs = ATOB.findall(body)
    print(f"\n  atob() blobs found: {len(blobs)}")
    for i, blob in enumerate(blobs[:3]):
        print(f"  blob {i}: len={len(blob)} first80={blob[:80]}")
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
            print(f"    raw decoded (no XOR) first120 bytes as text: {raw[:120]!r}")
        except Exception as e:
            print("    b64 decode error:", e)
