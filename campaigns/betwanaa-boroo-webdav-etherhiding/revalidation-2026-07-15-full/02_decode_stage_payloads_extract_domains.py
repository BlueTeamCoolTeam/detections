#!/usr/bin/env python3
"""
Phase 1, step 3: second-layer decode of every contract's get() payload
(the bytes saved by 01_onchain_get_owner_reverify.py are themselves a
base64-encoded ASCII string, matching the report's `data:text/javascript;
base64,...` observation) and independent extraction of any embedded WebDAV
C2 apex domain / IP / URL-shaped string from the resulting JS source.

Also computes SHA256 of both the outer (get() return) and inner (decoded
JS) bytes for every contract, and diffs same-shaped pairs (a1decfb7 vs
df132e28; 7fd85c09 vs fb448d46; 46790e2a vs 68dce15c vs 0cd58060) to
determine whether they are byte-identical deployments or genuinely
different code, independent of any assumption in report.md.
"""
import base64
import hashlib
import json
import re

CONTRACTS = [
    ("0xA1decFB75C8C0CA28C10517ce56B710baf727d2e", "contract_0xa1decfb75c8c0ca28c10517ce56b710baf727d2e_get_decoded.bin"),
    ("0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff", "contract_0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff_get_decoded.bin"),
    ("0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5", "contract_0x68dce15c1002a2689e19d33a3ae509dd1feb11a5_get_decoded.bin"),
    ("0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437", "contract_0x7fd85c090f2b35071c57a3b9feaf462aaeb0e437_get_decoded.bin"),
    ("0xfb448d465841c63f3bc433be61eb692b813d469d", "contract_0xfb448d465841c63f3bc433be61eb692b813d469d_get_decoded.bin"),
    ("0xdf132e2893824e26ec8ae8014b4f4facd54ed67f", "contract_0xdf132e2893824e26ec8ae8014b4f4facd54ed67f_get_decoded.bin"),
    ("0x0cd58060328e308a43d3c53cfd03a45233ea308a", "contract_0x0cd58060328e308a43d3c53cfd03a45233ea308a_get_decoded.bin"),
]

DOMAIN_RE = re.compile(rb"[A-Za-z0-9][A-Za-z0-9\-\.]{2,60}\.(?:com|bet|net|org|xyz|info|cc|pro|beer|boats|shartbandi|io)\b")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

summary = {}

for addr, fname in CONTRACTS:
    with open(fname, "rb") as f:
        outer_b64 = f.read()
    outer_sha = hashlib.sha256(outer_b64).hexdigest()

    try:
        inner = base64.b64decode(outer_b64 + b"=" * (-len(outer_b64) % 4))
    except Exception as e:
        summary[addr] = {"error": f"base64 decode failed: {e}", "outer_sha256": outer_sha}
        continue

    inner_sha = hashlib.sha256(inner).hexdigest()
    inner_fname = f"contract_{addr.lower()}_stage_js_decoded.js"
    with open(inner_fname, "wb") as f:
        f.write(inner)

    domains = sorted(set(m.group(0).decode("latin1") for m in DOMAIN_RE.finditer(inner)))
    ips = sorted(set(m.group(0).decode("latin1") for m in IP_RE.finditer(inner)))

    summary[addr] = {
        "outer_get_return_len": len(outer_b64),
        "outer_sha256": outer_sha,
        "inner_js_len": len(inner),
        "inner_sha256": inner_sha,
        "inner_saved_to": inner_fname,
        "domains_found": domains,
        "ips_found": ips,
    }
    print(f"{addr}")
    print(f"  outer_len={len(outer_b64)} outer_sha256={outer_sha[:16]}...")
    print(f"  inner_len={len(inner)} inner_sha256={inner_sha[:16]}...")
    print(f"  domains_found: {domains}")
    print(f"  ips_found: {ips}")
    print()

with open("02_decode_stage_payloads_extract_domains_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print("Full results saved to 02_decode_stage_payloads_extract_domains_RESULTS.json")
print()
print("=== Pairwise identity check (same-shaped pairs) ===")
pairs = [
    ("0xA1decFB75C8C0CA28C10517ce56B710baf727d2e", "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f", "stage-1 pair (symmetryclosets vs eu.mk)"),
    ("0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437", "0xfb448d465841c63f3bc433be61eb692b813d469d", "rotated-stage-1 pair (25a7625b vs 09813ef4 wallets)"),
    ("0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff", "0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5", "Windows vs macOS branch (symmetryclosets)"),
    ("0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff", "0x0cd58060328e308a43d3c53cfd03a45233ea308a", "Windows branch (symmetryclosets) vs 0cd58060 (eu.mk)"),
]
for a, b, label in pairs:
    sa = summary.get(a, {}).get("inner_sha256")
    sb = summary.get(b, {}).get("inner_sha256")
    identical = "IDENTICAL" if sa == sb else "DIFFERENT"
    print(f"{label}: {identical}  ({a[:10]}... = {sa[:12] if sa else None}...  vs  {b[:10]}... = {sb[:12] if sb else None}...)")
