"""
Step 8 - fresh re-investigation of the WRAPPER_NO_MATCH bucket.

Same two sites landed here across all 3 fresh passes (offertic.net,
www.cartolibreriabisceglia.it), consistent with the prior round. Re-fetches
each site fresh, right now, and saves the FULL page content and FULL decoded
output to file (not excerpted -- the prior round only quoted the first
~400 chars in chat).

Usage: python 08_wrapper_no_match_investigation.py
"""
import base64, re, urllib.request, os

HERE = os.path.dirname(__file__)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{40,})['\"]\)")

SITES = ["offertic.net", "www.cartolibreriabisceglia.it"]


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


for host in SITES:
    print(f"\n{'=' * 76}\n{host}\n{'=' * 76}")
    body = fetch(host)
    if body is None:
        print("  UNREACHABLE")
        continue
    print(f"  page length: {len(body)} bytes")

    page_file = os.path.join(HERE, f"wrapper_investigation_{host.replace('.', '_')}_full_page.html")
    with open(page_file, "w", encoding="utf-8") as f:
        f.write(body)
    print(f"  wrote FULL page content to {page_file}")

    blobs = ATOB.findall(body)
    print(f"  atob() blobs found: {len(blobs)}")

    decode_log = []
    for i, blob in enumerate(blobs):
        decode_log.append(f"--- blob {i} (len={len(blob)}) ---")
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception as e:
            decode_log.append(f"  b64 decode error: {e}")
            continue
        # brute-force printable-ratio scan across all 256 keys, report the best candidates
        best = []
        for k in range(256):
            dec = bytes(b ^ k for b in raw)
            text = dec.decode("utf-8", "replace")
            printable = sum(32 <= c < 127 for c in dec) / max(len(dec), 1)
            best.append((k, printable, text))
        best.sort(key=lambda x: -x[1])
        decode_log.append(f"  top 5 XOR keys by printable-ASCII ratio:")
        for k, ratio, text in best[:5]:
            decode_log.append(f"    key={k:3d}  printable_ratio={ratio:.3f}")
            decode_log.append(f"    FULL decoded text: {text}")

    decode_file = os.path.join(HERE, f"wrapper_investigation_{host.replace('.', '_')}_decode_log.txt")
    with open(decode_file, "w", encoding="utf-8") as f:
        f.write("\n".join(decode_log))
    print(f"  wrote FULL decode log to {decode_file}")
