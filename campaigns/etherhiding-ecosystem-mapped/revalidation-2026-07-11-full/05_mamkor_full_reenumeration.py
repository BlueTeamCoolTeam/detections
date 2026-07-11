#!/usr/bin/env python3
"""
Full, independent, from-scratch re-derivation of mamkor/merabs's C2 rotation
history. Pulls the persistent contract's COMPLETE transaction history fresh
from Blockscout, re-classifies every setter call (method 0x77343408 per the
source REPORT.md), and independently decodes the domain out of each call's
raw calldata using the same from-scratch ABI-tail decoder used for the
BW-sibling re-enumeration (03_bwsibling_full_reenumeration.py) - written
once, reused here rather than re-derived, since the ABI layout is identical
(a single dynamic 'string' argument).

Claim being tested: "127 setter calls, 102 unique historical C2 domains,
2026-03-11 -> 2026-07-10."
"""
import json
import re
import time
import urllib.request
from datetime import datetime, timezone

CONTRACT = "0x08207B087F61d7e95E441E15fd6d40BEfd6eD308"
SETTER_METHOD_ID = "0x77343408"

API_V1 = (
    "https://polygon.blockscout.com/api?module=account&action=txlist"
    f"&address={CONTRACT}&sort=asc"
)


def fetch(url, retries=4):
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            last_err = e
            time.sleep(4)
    raise last_err


OFFSET_WORD = "0" * 62 + "20"


def decode_trailing_string_arg(input_hex):
    h = input_hex[2:] if input_hex.startswith("0x") else input_hex
    candidates = [m.start() for m in re.finditer(OFFSET_WORD, h)]
    for start in reversed(candidates):
        rest = h[start + 64:]
        if len(rest) < 64:
            continue
        try:
            length = int(rest[:64], 16)
        except ValueError:
            continue
        if length <= 0 or length > 200:
            continue
        data_hex = rest[64:64 + length * 2]
        if len(data_hex) < length * 2:
            continue
        try:
            decoded = bytes.fromhex(data_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        printable = sum(1 for c in decoded if c.isprintable())
        if printable == len(decoded) and len(decoded) >= 3:
            return decoded
    return None


DOMAIN_RE = re.compile(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(/.*)?$")


def main():
    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    print(f"Target contract: {CONTRACT} (this is the CONTRACT's own tx history, "
          f"not a wallet - since setter calls arrive TO this contract, unlike "
          f"BW-sibling's per-rotation-contract model where creations come FROM the wallet)")
    print(f"Querying: {API_V1}\n")

    data = fetch(API_V1)
    print(f"API status: {data.get('status')}  message: {data.get('message')}")
    items = data.get("result", [])
    print(f"Total transactions pulled fresh: {len(items)}\n")

    setter_calls = [tx for tx in items if tx.get("methodId", "").lower() == SETTER_METHOD_ID]
    other = [tx for tx in items if tx.get("methodId", "").lower() != SETTER_METHOD_ID]

    print(f"Classified: {len(setter_calls)} setter-call txs ({SETTER_METHOD_ID}), "
          f"{len(other)} other (creation/other methods)\n")

    if other:
        print("=== Non-setter transactions ===")
        for tx in other:
            print(f"  hash={tx['hash']}  methodId={tx.get('methodId')}  "
                  f"contractAddress={tx.get('contractAddress')}  from={tx.get('from')}")
        print()

    decoded = []
    failures = []
    for tx in setter_calls:
        domain = decode_trailing_string_arg(tx["input"])
        ts = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc).isoformat()
        if domain:
            decoded.append((ts, domain, tx["hash"], tx.get("from")))
        else:
            failures.append(tx["hash"])

    unique_domains = set(d for _, d, _, _ in decoded)
    domain_shaped = set(d for d in unique_domains if DOMAIN_RE.match(d))
    not_domain_shaped = unique_domains - domain_shaped

    print(f"=== Independent re-derivation results ===")
    print(f"Setter calls decoded: {len(decoded)} / {len(setter_calls)} "
          f"({len(failures)} decode failures)")
    print(f"Unique decoded values: {len(unique_domains)}")
    print(f"Domain-shaped: {len(domain_shaped)}")
    print(f"NOT domain-shaped: {len(not_domain_shaped)} -> {sorted(not_domain_shaped)}")
    print(f"Decode failure tx hashes: {failures}\n")

    setter_wallets = set(frm for _, _, _, frm in decoded)
    print(f"Distinct wallets that ever called the setter: {len(setter_wallets)} -> {sorted(setter_wallets)}\n")

    print("=== Full chronological decoded C2 history ===")
    for ts, dom, h, frm in decoded:
        print(f"  {ts}  ->  {dom}   (hash={h})")

    print(f"\n=== Comparison against previously published claim ===")
    print("Previously claimed: 127 setter calls, 102 unique historical C2 domains, "
          "2026-03-11 -> 2026-07-10, sole setter wallet 0x34c15320d6e8f59f1b66f6c191aaa7f87b894b66.")
    print(f"Independently re-derived: {len(setter_calls)} setter calls, "
          f"{len(unique_domains)} unique decoded values "
          f"({len(domain_shaped)} domain-shaped), "
          f"date range {decoded[0][0] if decoded else 'n/a'} -> {decoded[-1][0] if decoded else 'n/a'}, "
          f"{len(setter_wallets)} distinct setter wallet(s).")


if __name__ == "__main__":
    main()
