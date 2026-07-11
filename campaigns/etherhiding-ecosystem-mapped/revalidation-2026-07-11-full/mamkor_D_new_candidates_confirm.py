#!/usr/bin/env python3
"""
PART D - additive live confirm/decode check against NEW candidate hostnames
surfaced by the Part A urlscan.io candidate-pool pivot that are NOT already
in the existing 638-site confirmed list or the Part B 3-pass reconfirmed
union (mamkor_B_final_confirmed_union.txt, a subset of the 638).

Reuses the exact same fetch/decode logic as mamkor_B_confirm_checker.py
(cleartext markers, atob+sub-then-XOR, plain single-byte XOR, 256-byte
S-box, 20MB read cap). Single pass only (not a 3-pass cycle) per the
coordinator's instruction - this is an additive discovery check, not a
re-confirmation of an already-3x-verified list.

Usage:
    python mamkor_D_new_candidates_confirm.py

Writes:
    mamkor_D_new_candidates_confirm_results.txt - one line per host:
        host\tSTATUS\tdetail
"""
import base64
import concurrent.futures
import re
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

NEW_CANDIDATES_PATH = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\revalidation-2026-07-11-full\mamkor_D_new_candidates.txt"
OUT_DIR = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\revalidation-2026-07-11-full"

MAX_WORKERS = 32
TIMEOUT = 18  # seconds per request
READ_CAP = 20_000_000  # 20MB - do NOT shrink; injected script can sit well past ~600KB on some WP pages

INSECURE_CTX = ssl.create_default_context()
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE

CONTRACT = "08207b08"
SELECTOR = "38bcdc1c"
RPC_HOSTS = ["polygon.drpc.org", "polygon-bor-rpc.publicnode.com", "polygon.lava.build",
             "polygon.rpc.subquery.network", "polygon-public.nodies.app", "polygon-pokt.nodies.app"]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def fetch(host):
    last_err = "unreachable"
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                body = r.read(READ_CAP).decode("utf-8", errors="replace")
                return host, body, None
        except Exception as e:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=TIMEOUT, context=INSECURE_CTX) as r:
                    body = r.read(READ_CAP).decode("utf-8", errors="replace")
                    return host, body, None
            except Exception as e2:
                last_err = str(e2)
                continue
    return host, None, last_err


def check_cleartext(html):
    low = html.lower()
    hits = []
    if CONTRACT in low: hits.append("contract")
    if SELECTOR in low: hits.append("selector")
    rpc_hits = sum(1 for h in RPC_HOSTS if h in low)
    if rpc_hits >= 2: hits.append(f"rpc_hosts({rpc_hits})")
    if "a=tds_cfg" in low: hits.append("tds_cfg")
    if "_cf_verified" in low: hits.append("_cf_verified")
    if "clipboard-write" in low: hits.append("clipboard-write")
    return hits


def extract_blobs(html):
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    candidates = []
    for s in scripts:
        if "new Function(" in s.replace(" ", "") or "newFunction(" in s.replace(" ", ""):
            candidates.append(s)
        elif "atob(" in s and len(s) > 200:
            candidates.append(s)
    return candidates


def try_decode_schemes(script_body):
    hits = []
    b64s = re.findall(r"[\"']([A-Za-z0-9+/]{100,}={0,2})[\"']", script_body)
    arrs = re.findall(r"\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){99,})\s*\]", script_body)
    blobs = [("b64", b) for b in b64s[:6]] + [("arr", a) for a in arrs[:2]]

    for kind, blob in blobs:
        if kind == "b64":
            try:
                raw = base64.b64decode(blob + "===")
            except Exception:
                continue
        else:
            try:
                raw = bytes(int(x) & 0xff for x in blob.split(","))
            except Exception:
                continue

        def has_marker(dec):
            return b"08207" in dec or b"38bcdc1c" in dec.lower()

        raw_s = raw[:60_000]

        matched = False
        for key in range(256):
            trans = bytes(i ^ key for i in range(256))
            if has_marker(raw_s.translate(trans)):
                hits.append(("xor", None, key)); matched = True; break
        if matched:
            continue

        for sub in range(256):
            base = [((i - sub + 256) & 255) for i in range(256)]
            found = False
            for xor in range(256):
                trans = bytes(b ^ xor for b in base)
                if has_marker(raw_s.translate(trans)):
                    hits.append(("sub_xor", sub, xor)); found = True; break
            if found:
                matched = True
                break
        if matched:
            continue

        sboxes = re.findall(r"\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){255})\s*\]", script_body)
        for sb in sboxes[:2]:
            try:
                table = [int(x) & 0xff for x in sb.split(",")]
                if len(table) != 256:
                    continue
                dec = bytes(table[c] for c in raw)
                if has_marker(dec):
                    hits.append(("sbox", None, None)); matched = True; break
            except Exception:
                continue
    return hits


def process(host):
    host, html, err = fetch(host)
    if err and html is None:
        return {"host": host, "status": "UNREACHABLE", "detail": err}
    cleartext_hits = check_cleartext(html)
    if cleartext_hits:
        return {"host": host, "status": "CONFIRMED", "detail": f"cleartext:{','.join(cleartext_hits)}"}
    blobs = extract_blobs(html)
    if not blobs:
        return {"host": host, "status": "NOT_CONFIRMED", "detail": "no_injection_shape"}
    for blob in blobs:
        decode_hits = try_decode_schemes(blob)
        if decode_hits:
            detail = ";".join(f"{s}:sub={sub}:xor={xor}" for s, sub, xor in decode_hits)
            return {"host": host, "status": "CONFIRMED", "detail": f"decoded:{detail}"}
    return {"host": host, "status": "NOT_CONFIRMED", "detail": "injection_shape_present_undecoded"}


def main():
    hosts = [l.strip() for l in open(NEW_CANDIDATES_PATH, encoding="utf-8") if l.strip()]
    print(f"=== PART D - additive new-candidate confirm check (single pass) ===")
    print(f"Start (UTC): {datetime.now(timezone.utc).isoformat()}")
    print(f"Checking {len(hosts)} NEW candidate hosts (Part A pool minus existing 638 minus Part B union), "
          f"{MAX_WORKERS} workers, {TIMEOUT}s timeout, {READ_CAP} byte read cap...")

    results = []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(process, h): h for h in hosts}
        done_count = 0
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {"host": futures[fut], "status": "UNREACHABLE", "detail": f"exception:{e}"}
            results.append(res)
            done_count += 1
            if done_count % 100 == 0 or done_count == len(hosts):
                elapsed = time.time() - t0
                print(f"  ...{done_count}/{len(hosts)}  ({elapsed:.0f}s elapsed)")

    order = {h: i for i, h in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r["host"], 10**9))

    out_path = f"{OUT_DIR}\\mamkor_D_new_candidates_confirm_results.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['host']}\t{r['status']}\t{r['detail']}\n")

    from collections import Counter
    c = Counter(r["status"] for r in results)
    elapsed = time.time() - t0
    print(f"\n=== PART D summary ({elapsed:.0f}s total) ===")
    for status in ("CONFIRMED", "NOT_CONFIRMED", "UNREACHABLE"):
        print(f"  {status}: {c.get(status, 0)}")
    print(f"  TOTAL: {len(results)}")

    confirmed_hosts = sorted(r["host"] for r in results if r["status"] == "CONFIRMED")
    with open(f"{OUT_DIR}\\mamkor_D_new_confirmed_hosts.txt", "w", encoding="utf-8") as f:
        for h in confirmed_hosts:
            f.write(h + "\n")

    print(f"\nWrote {out_path}")
    print(f"Wrote {OUT_DIR}\\mamkor_D_new_confirmed_hosts.txt ({len(confirmed_hosts)} newly confirmed hosts)")
    print(f"End (UTC): {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()
