#!/usr/bin/env python3
"""
Part B - live 3-pass re-confirmation checker for Operator 1 ("xdav" /
authorization-cdn EtherHiding operator)'s 123 previously-confirmed
compromised sites.

Adapted from the already-proven checker at:
  detections/campaigns/authorization-cdn-etherhiding-clickfix/
  revalidation-2026-07-08-full/03_live_verification_checker.py

Same decode/detection logic, reused as-is:
  - fetch https then http fallback, realistic browser UA
  - look for cleartext api.php?s=...&polygon/1rpc.io/matic gate
  - otherwise brute-force every atob('...') blob against all 256
    single-byte XOR keys, decode as utf-8, and check for the kit's
    run-once guard variable window['_<hex>'] plus 2+ hits among
    polygon / eth_call / api.php
  - flag atob+new Function(new TextDecoder...) wrapper present but not
    matched as WRAPPER_NO_MATCH (reachable, kit-shaped, but not confirmed)
  - otherwise CLEAN (reachable, no kit markers)
  - fetch failure on both schemes -> UNREACHABLE

This script is invoked once per pass (3 independent passes total, run
back-to-back). Each invocation is a fresh, independent set of network
fetches - no caching/reuse of a prior pass's results.

Usage:
  python op1_B_live_verification_checker.py <sites_file> <out_prefix>

Writes:
  <out_prefix>results.txt    - full per-site verdict, bucketed by status
  <out_prefix>confirmed.txt  - just the CONFIRMED hostnames, sorted
"""
import base64, re, sys, time
import urllib.request, urllib.error, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

SITES_FILE = sys.argv[1]
OUT_PREFIX = sys.argv[2] if len(sys.argv) > 2 else "revalidate_"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")
CONTRACT = re.compile(r"0x[0-9a-fA-F]{40}")
SELECTOR = re.compile(r"data:\s*['\"]0x([0-9a-f]{8})")

WORKERS = 25
TIMEOUT = 18


def is_kit(dec):
    d = dec.lower()
    hits = sum(x in d for x in ("polygon", "eth_call", "api.php"))
    return (GUARD.search(dec) is not None and hits >= 2) or ("api.php?s=" in d and "polygon" in d)


def fetch(host):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
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


def main():
    sites = [s.strip() for s in open(SITES_FILE, encoding="utf-8", errors="replace") if s.strip()]
    print(f"Checking {len(sites)} sites, {WORKERS} workers, single pass...")

    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(check, h): h for h in sites}
        done = 0
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append((futs[fut], "UNREACHABLE", f"exception: {e}"))
            done += 1
            if done % 20 == 0 or done == len(sites):
                print(f"  ...{done}/{len(sites)} checked ({time.time()-t0:.0f}s elapsed)")

    buckets = {}
    for h, v, n in results:
        buckets.setdefault(v, []).append((h, n))

    order = ["CONFIRMED", "WRAPPER_NO_MATCH", "CLEAN", "UNREACHABLE"]
    print(f"\n{'='*60}\nScanned {len(results)} in {time.time()-t0:.0f}s\n{'='*60}")
    for v in order:
        print(f"{v}: {len(buckets.get(v, []))}")

    with open(f"{OUT_PREFIX}results.txt", "w", encoding="utf-8") as f:
        f.write(f"Total sites checked: {len(results)}\n")
        for v in order:
            f.write(f"\n### {v} ({len(buckets.get(v, []))})\n")
            for h, n in sorted(buckets.get(v, [])):
                f.write(f"{h}\t{v}\t{n}\n")

    with open(f"{OUT_PREFIX}confirmed.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(h for h, _ in buckets.get("CONFIRMED", []))))

    import collections
    cons = collections.Counter()
    for h, n in buckets.get("CONFIRMED", []):
        m = re.search(r"contract=(\S+)", n)
        if m:
            cons[m.group(1)] += 1
    print("\nContracts seen among CONFIRMED:", dict(cons))
    print(f"\nWrote {OUT_PREFIX}results.txt and {OUT_PREFIX}confirmed.txt")


if __name__ == "__main__":
    main()
