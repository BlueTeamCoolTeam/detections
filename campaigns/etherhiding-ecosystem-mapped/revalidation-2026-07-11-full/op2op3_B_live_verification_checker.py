#!/usr/bin/env python3
"""
PART B - full 3-pass live re-confirmation of the existing Operator 2 (27 hosts)
and Operator 3 (3 hosts) confirmed lists.

Decode/detection logic is reused, unmodified in substance, from the
already-proven checker at:
  detections/campaigns/authorization-cdn-etherhiding-clickfix/
    revalidation-2026-07-08-full/03_live_verification_checker.py

That checker:
  - fetches https then http fallback with a realistic browser UA
  - looks for a cleartext api.php?s=...+polygon/1rpc.io/matic marker, OR
  - brute-forces every atob('...') blob in the page against all 256
    single-byte XOR keys, decoding each candidate and checking for a
    run-once guard variable window['_<hex>'] plus 2+ hits among
    polygon / eth_call / api.php substrings
  - falls back to a WRAPPER_NO_MATCH bucket if a new Function(new TextDecoder
    ...) wrapper + atob is present but nothing decoded to a kit match
  - otherwise CLEAN, or UNREACHABLE if neither https nor http responded

This run-specific wrapper just fetches BOTH operators' confirmed lists in one
pass, tags every row with which operator it belongs to, and writes a
single labeled results file plus a per-operator CONFIRMED list.

Usage:
  python op2op3_B_live_verification_checker.py <out_prefix>

Writes:
  <out_prefix>results.txt      - full labeled results (OP2/OP3 tagged)
  <out_prefix>confirmed_op2.txt
  <out_prefix>confirmed_op3.txt
"""
import base64, re, sys, time
import urllib.request, urllib.error, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

OP2_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\reproduction-log\family_a_operator2_confirmed.txt"
OP3_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\reproduction-log\family_a_operator3_confirmed.txt"

OUT_PREFIX = sys.argv[1] if len(sys.argv) > 1 else "op2op3_B_pass_"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")
CONTRACT = re.compile(r"0x[0-9a-fA-F]{40}")
SELECTOR = re.compile(r"data:\s*['\"]0x([0-9a-f]{8})")


def is_kit(dec):
    d = dec.lower()
    hits = sum(x in d for x in ("polygon", "eth_call", "api.php"))
    return (GUARD.search(dec) is not None and hits >= 2) or ("api.php?s=" in d and "polygon" in d)


def fetch(host):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read(3_000_000).decode("utf-8", "replace")
                if body:
                    return body
        except Exception:
            continue
    return None


def check(host):
    body = fetch(host)
    if body is None:
        return (host, "UNREACHABLE", "")
    low = body.lower()
    if "api.php?s=" in low and ("polygon" in low or "1rpc.io/matic" in low):
        c = CONTRACT.search(body)
        return (host, "CONFIRMED", f"cleartext contract={c.group(0) if c else '?'}")
    for blob in ATOB.findall(body):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        for k in range(256):
            dec = bytes(b ^ k for b in raw).decode("utf-8", "replace")
            if is_kit(dec):
                c = CONTRACT.search(dec)
                s = SELECTOR.search(dec)
                return (host, "CONFIRMED", f"xor={k} contract={c.group(0) if c else '?'} sel={s.group(1) if s else '?'}")
    if re.search(r"new Function\(new TextDecoder", body, re.I) and ATOB.search(body):
        return (host, "WRAPPER_NO_MATCH", "atob+newFunction present; kit not confirmed")
    return (host, "CLEAN", "")


def load_hosts(path, tag):
    hosts = [s.strip() for s in open(path, encoding="utf-8", errors="replace") if s.strip()]
    return [(h, tag) for h in hosts]


targets = load_hosts(OP2_FILE, "OP2") + load_hosts(OP3_FILE, "OP3")
print(f"Checking {len(targets)} sites ({sum(1 for _,t in targets if t=='OP2')} OP2 + "
      f"{sum(1 for _,t in targets if t=='OP3')} OP3), 16 workers, single pass...")

results = []
t0 = time.time()
with ThreadPoolExecutor(max_workers=16) as ex:
    futs = {ex.submit(check, h): (h, tag) for h, tag in targets}
    done = 0
    for fut in as_completed(futs):
        h, tag = futs[fut]
        host, verdict, note = fut.result()
        results.append((tag, host, verdict, note))
        done += 1
        print(f"  [{done}/{len(targets)}] {tag} {host} -> {verdict} {note}")

buckets = {}
for tag, h, v, n in results:
    buckets.setdefault(v, []).append((tag, h, n))

order = ["CONFIRMED", "WRAPPER_NO_MATCH", "CLEAN", "UNREACHABLE"]
print(f"\n{'='*60}\nScanned {len(results)} in {time.time()-t0:.0f}s\n{'='*60}")
for v in order:
    rows = buckets.get(v, [])
    n_op2 = sum(1 for tag, _, _ in rows if tag == "OP2")
    n_op3 = sum(1 for tag, _, _ in rows if tag == "OP3")
    print(f"{v}: {len(rows)}  (OP2={n_op2}, OP3={n_op3})")

with open(f"{OUT_PREFIX}results.txt", "w", encoding="utf-8") as f:
    f.write(f"Pass run timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    f.write(f"Total sites checked: {len(results)} (OP2=27 expected, OP3=3 expected)\n")
    for v in order:
        rows = sorted(buckets.get(v, []), key=lambda r: (r[0], r[1]))
        f.write(f"\n### {v} ({len(rows)})\n")
        for tag, h, n in rows:
            f.write(f"{tag}\t{h}\t{n}\n")

with open(f"{OUT_PREFIX}confirmed_op2.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(h for tag, h, n in buckets.get("CONFIRMED", []) if tag == "OP2")))

with open(f"{OUT_PREFIX}confirmed_op3.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(h for tag, h, n in buckets.get("CONFIRMED", []) if tag == "OP3")))

print(f"\nWrote {OUT_PREFIX}results.txt, {OUT_PREFIX}confirmed_op2.txt, {OUT_PREFIX}confirmed_op3.txt")
