#!/usr/bin/env python3
"""Independent re-validation of the agent-confirmed compromised-site list.
Re-fetches each site fresh and checks for the campaign fingerprint using all
four known decode schemes, rather than trusting the subagents' prior fetch.
"""
import concurrent.futures
import json
import re
import ssl
import urllib.request
import urllib.error

INSECURE_CTX = ssl.create_default_context()
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE

CONTRACT = "08207b08"
SELECTOR = "38bcdc1c"
RPC_HOSTS = ["polygon.drpc.org", "polygon-bor-rpc.publicnode.com", "polygon.lava.build",
             "polygon.rpc.subquery.network", "polygon-public.nodies.app", "polygon-pokt.nodies.app"]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

def fetch(host):
    url = f"https://{host}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(20_000_000).decode("utf-8", errors="replace")
            return host, body, None
    except Exception as e:
        # retry once ignoring TLS verification (self-signed certs on some sites)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30, context=INSECURE_CTX) as r:
                body = r.read(20_000_000).decode("utf-8", errors="replace")
                return host, body, None
        except Exception as e2:
            return host, None, str(e2)

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
    """Find inline <script> bodies that look like injected loaders: contain
    atob(...) or a long base64/hex-ish literal, feeding new Function(...)."""
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    candidates = []
    for s in scripts:
        if "new Function(" in s.replace(" ", "") or "newFunction(" in s.replace(" ", ""):
            candidates.append(s)
        elif "atob(" in s and len(s) > 200:
            candidates.append(s)
    return candidates

def try_decode_schemes(script_body):
    """Try: (a) atob + (c-SUB+256)&255 ^ XOR  for SUB,XOR in 0..255 (limited sweep)
             (b) atob + single-byte XOR key 0..255
             (c) direct byte array + XOR key 0..255
       Return list of (scheme, sub, xor_or_key) that decode to contain our markers.
    """
    import base64
    hits = []
    # broadened: any long base64-charset literal in the script, not just atob(...)-wrapped
    b64s = re.findall(r"[\"']([A-Za-z0-9+/]{100,}={0,2})[\"']", script_body)
    # also catch raw byte-array literals: [12,34,201,...] of substantial length
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

        raw_s = raw[:60_000]  # cap for speed; marker is near-guaranteed within this window

        # scheme: single-byte xor (fast C-level translate)
        matched = False
        for key in range(256):
            trans = bytes(i ^ key for i in range(256))
            if has_marker(raw_s.translate(trans)):
                hits.append(("xor", None, key)); matched = True; break
        if matched:
            continue

        # scheme: (c - SUB + 256)&255 ^ XOR -- full sweep, translate-accelerated
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

        # scheme: 256-byte S-box substitution table declared nearby in the script
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
    if err:
        return {"host": host, "status": "unreachable", "error": err}
    cleartext_hits = check_cleartext(html)
    if cleartext_hits:
        return {"host": host, "status": "reconfirmed_cleartext", "hits": cleartext_hits}
    blobs = extract_blobs(html)
    if not blobs:
        return {"host": host, "status": "clean_no_injection_shape"}
    for blob in blobs:
        decode_hits = try_decode_schemes(blob)
        if decode_hits:
            return {"host": host, "status": "reconfirmed_decoded", "scheme_hits": decode_hits}
    return {"host": host, "status": "injection_shape_present_undecoded"}

def main():
    hosts = [l.strip() for l in open("confirmed_compromised_ALL.txt") if l.strip()]
    print(f"Validating {len(hosts)} confirmed sites...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for i, res in enumerate(ex.map(process, hosts)):
            results.append(res)
            if (i + 1) % 25 == 0:
                print(f"  ...{i+1}/{len(hosts)}")
    json.dump(results, open("validation_results.json", "w"), indent=1)

    from collections import Counter
    c = Counter(r["status"] for r in results)
    print("\n=== Validation summary ===")
    for status, count in c.most_common():
        print(f"  {status}: {count}")

    print("\n=== Sites that did NOT re-confirm (need manual review) ===")
    for r in results:
        if r["status"] not in ("reconfirmed_cleartext", "reconfirmed_decoded"):
            print(f"  {r['host']}: {r['status']}" + (f" ({r.get('error','')})" if r.get('error') else ""))

if __name__ == "__main__":
    main()
