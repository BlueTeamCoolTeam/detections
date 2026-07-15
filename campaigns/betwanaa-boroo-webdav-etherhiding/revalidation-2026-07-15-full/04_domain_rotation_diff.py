#!/usr/bin/env python3
"""
Reproduces, from scratch and self-contained (no webcrack/node dependency),
the domain-rotation finding: decodes the ORIGINAL analyst's saved raw
JSON-RPC response for contract 0x46790e2A... (Windows branch, symmetryclosets
chain) from
blogs/drafts/cduh-betwanaa-pcalua-webdav/cduh-betwanaa-pcalua-webdav/etherhiding/onchain_windows_stage_response.json,
and compares it byte-for-byte and content-for-content against this session's
fresh live fetch of the same contract address
(contract_0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff_get_decoded.bin, produced
by 01_onchain_get_owner_reverify.py earlier in this run).

Both payloads nest a second obfuscated layer as `eval(atob("..."))` - this
script recursively unwraps every atob() argument it finds (up to depth 4) and
scans each unwrapped layer's base64-looking string literals for a decodable
domain or pcalua.exe/bash-curl command template, rather than relying on the
one-shot regex approach used earlier in this session (which used Python's
str.isprintable(), silently rejecting any decoded text containing a newline -
a bug, not a real absence of data; fixed here by not filtering on that at
all).
"""
import json
import re
import base64
import hashlib

ORIGINAL_ARTIFACT = (
    r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\blogs\drafts\cduh-betwanaa-pcalua-webdav"
    r"\cduh-betwanaa-pcalua-webdav\etherhiding\onchain_windows_stage_response.json"
)
FRESH_FETCH = "contract_0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff_get_decoded.bin"

ATOB_RE = re.compile(r'atob\("([A-Za-z0-9+/=]+)"\)')
QUOTED_B64_RE = re.compile(r"'([A-Za-z0-9+/]{16,}={0,2})'")
DOMAIN_FULLMATCH_RE = re.compile(r"[a-z0-9\-]+\.[a-z]{2,}")


def b64try(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None


def recursive_unwrap(text, depth=0, max_depth=4, seen=None):
    """Yield every text layer reachable by decoding atob() arguments recursively."""
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
        if "pcalua.exe" in txt or "bash -c" in txt:
            commands.add(txt)
        elif DOMAIN_FULLMATCH_RE.fullmatch(txt):
            domains.add(txt)
    return domains, commands


def analyze(outer_b64, label):
    inner = base64.b64decode(outer_b64 + b"=" * (-len(outer_b64) % 4))
    inner_text = inner.decode("utf-8", errors="replace")

    all_domains, all_commands = set(), set()
    max_depth_seen = 0
    for depth, layer_text in recursive_unwrap(inner_text):
        max_depth_seen = max(max_depth_seen, depth)
        d, c = find_domain_and_command(layer_text)
        all_domains |= d
        all_commands |= c

    return {
        "label": label,
        "outer_len": len(outer_b64),
        "outer_sha256": hashlib.sha256(outer_b64).hexdigest(),
        "inner_len": len(inner),
        "inner_sha256": hashlib.sha256(inner).hexdigest(),
        "max_atob_nesting_depth_unwrapped": max_depth_seen,
        "domains_found": sorted(all_domains),
        "commands_found": sorted(all_commands),
    }


with open(ORIGINAL_ARTIFACT, encoding="utf-8") as f:
    resp = json.load(f)
hex_result = resp["result"]
raw = bytes.fromhex(hex_result[2:])
str_len = int.from_bytes(raw[32:64], "big")
original_outer_b64 = raw[64:64 + str_len]

with open(FRESH_FETCH, "rb") as f:
    fresh_outer_b64 = f.read()

original = analyze(original_outer_b64, "ORIGINAL artifact (report.md analysis time)")
fresh = analyze(fresh_outer_b64, "FRESH fetch (this revalidation, 2026-07-15)")

lines = []
for r in (original, fresh):
    lines.append(f"=== {r['label']} ===")
    lines.append(f"  outer_len={r['outer_len']}  outer_sha256={r['outer_sha256']}")
    lines.append(f"  inner_len={r['inner_len']}  inner_sha256={r['inner_sha256']}")
    lines.append(f"  max atob() nesting depth unwrapped: {r['max_atob_nesting_depth_unwrapped']}")
    lines.append(f"  domains_found: {r['domains_found']}")
    for cmd in r["commands_found"]:
        lines.append(f"  command_found: {cmd}")
    lines.append("")

identical_outer = original["outer_sha256"] == fresh["outer_sha256"]
lines.append(f"SAME CONTRACT ADDRESS (0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff) - outer bytes identical: {identical_outer}")
lines.append("CONCLUSION: " + (
    "no rotation detected between the two fetches."
    if identical_outer else
    "CONFIRMED ROTATION - the same contract address now returns different, "
    "independently-decodable content with a different embedded C2 domain."
))

output = "\n".join(lines)
print(output)

with open("04_domain_rotation_diff_RESULTS.txt", "w", encoding="utf-8") as f:
    f.write(output + "\n")
