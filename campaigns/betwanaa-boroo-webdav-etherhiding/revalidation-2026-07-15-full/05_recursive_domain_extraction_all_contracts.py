#!/usr/bin/env python3
"""
Applies the self-contained recursive atob()-unwrap extraction (developed and
verified in 04_domain_rotation_diff.py) to all 7 confirmed-live contracts
from Step 1/2, replacing the earlier reliance on external `npx webcrack`
tooling with a script that has no dependency beyond the Python standard
library - fully reproducible without network/node access.
"""
import re
import base64
import hashlib
import json

CONTRACTS = [
    "0xA1decFB75C8C0CA28C10517ce56B710baf727d2e",
    "0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff",
    "0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5",
    "0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437",
    "0xfb448d465841c63f3bc433be61eb692b813d469d",
    "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f",
    "0x0cd58060328e308a43d3c53cfd03a45233ea308a",
]

ATOB_RE = re.compile(r'atob\("([A-Za-z0-9+/=]+)"\)')
QUOTED_B64_RE = re.compile(r"'([A-Za-z0-9+/]{16,}={0,2})'")
DOMAIN_FULLMATCH_RE = re.compile(r"[a-z0-9\-]+\.[a-z]{2,}")
BASH_CURL_RE = re.compile(r"curl[^']{0,200}", re.DOTALL)


def b64try(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None


def recursive_unwrap(text, depth=0, max_depth=4, seen=None):
    if seen is None:
        seen = set()
    key = hash(text)
    if key in seen or depth > max_depth:
        return
    seen.add(key)
    yield depth, text
    for m in ATOB_RE.finditer(text):
        dec = b64try(m.group(1))
        if dec is None:
            continue
        try:
            inner_text = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        yield from recursive_unwrap(inner_text, depth + 1, max_depth, seen)


def find_domain_and_command(text):
    domains, commands = set(), set()
    for m in QUOTED_B64_RE.finditer(text):
        dec = b64try(m.group(1))
        if dec is None:
            continue
        try:
            txt = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "pcalua.exe" in txt or "bash -c" in txt or "curl " in txt:
            commands.add(txt)
        elif DOMAIN_FULLMATCH_RE.fullmatch(txt):
            domains.add(txt)
    # also catch bash/curl commands that appear as plain (non-base64) literals
    for m in BASH_CURL_RE.finditer(text):
        commands.add(m.group(0))
    return domains, commands


results = {}
for addr in CONTRACTS:
    fname = f"contract_{addr.lower()}_get_decoded.bin"
    with open(fname, "rb") as f:
        outer_b64 = f.read()
    inner = base64.b64decode(outer_b64 + b"=" * (-len(outer_b64) % 4))
    inner_text = inner.decode("utf-8", errors="replace")

    all_domains, all_commands = set(), set()
    max_depth_seen = 0
    for depth, layer_text in recursive_unwrap(inner_text):
        max_depth_seen = max(max_depth_seen, depth)
        d, c = find_domain_and_command(layer_text)
        all_domains |= d
        all_commands |= c

    results[addr] = {
        "outer_sha256": hashlib.sha256(outer_b64).hexdigest(),
        "inner_sha256": hashlib.sha256(inner).hexdigest(),
        "max_atob_nesting_depth_unwrapped": max_depth_seen,
        "domains_found": sorted(all_domains),
        "commands_found": sorted(all_commands),
    }
    print(f"{addr}")
    print(f"  max_atob_nesting_depth_unwrapped={max_depth_seen}")
    print(f"  domains_found={sorted(all_domains)}")
    for cmd in sorted(all_commands):
        print(f"  command_found: {cmd[:160]}{'...' if len(cmd) > 160 else ''}")
    print()

with open("05_recursive_domain_extraction_all_contracts_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("Full results saved to 05_recursive_domain_extraction_all_contracts_RESULTS.json")
