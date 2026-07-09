"""
Step 9 - independent spot-check of this session's fresh confirmed list.

Separately-written script (does not reuse 03_live_verification_checker.py's
code or its reported XOR key) that fetches each sampled site fresh and
re-derives the decode from scratch, to confirm the bulk confirmed numbers
aren't an artifact of one script's logic. Full decoded output saved,
not excerpted.

Usage: python 09_independent_spotcheck.py
"""
import base64, re, urllib.request, os

HERE = os.path.dirname(__file__)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")

SAMPLE = [
    "killtonyticket.com", "kienthucquocphong.com", "astrohubpro.com",  # operator 1
    "www.tramites-usa.com", "www.abenegihugu.com",                     # operator 2
    "greencoalition.pl", "www.motorbeam.com", "www.realoptionsvaluation.com",  # operator 3
]


def fetch(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(3_000_000).decode("utf-8", "replace")
        except Exception:
            continue
    return None


log = []
results_summary = []
for host in SAMPLE:
    log.append(f"\n{'=' * 76}\n{host}\n{'=' * 76}")
    body = fetch(host)
    if body is None:
        log.append("  UNREACHABLE on this independent re-fetch")
        results_summary.append((host, "UNREACHABLE"))
        continue
    blobs = ATOB.findall(body)
    log.append(f"  atob() blobs found: {len(blobs)}")
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
                log.append(f"  MATCH at xor={k}")
                log.append(f"  FULL decoded content:\n{dec}")
                results_summary.append((host, f"CONFIRMED xor={k}"))
                found = True
                break
        if found:
            break
    if not found:
        log.append("  NO MATCH on this independent re-fetch/re-decode")
        results_summary.append((host, "NO MATCH"))

out_file = os.path.join(HERE, "09_independent_spotcheck_full_log.txt")
with open(out_file, "w", encoding="utf-8") as f:
    f.write("\n".join(log))
print(f"wrote FULL log to {out_file}")

print("\nSUMMARY:")
for host, status in results_summary:
    print(f"  {host}: {status}")
confirmed_count = sum(1 for _, s in results_summary if s.startswith("CONFIRMED"))
print(f"\n{confirmed_count}/{len(SAMPLE)} independently reconfirmed")
