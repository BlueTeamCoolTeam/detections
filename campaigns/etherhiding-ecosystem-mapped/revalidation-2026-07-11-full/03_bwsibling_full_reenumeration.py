#!/usr/bin/env python3
"""
Full, independent, from-scratch re-derivation of the BW-sibling operator's
contract/domain footprint - re-pulls the deployer wallet's COMPLETE
transaction history fresh from Blockscout (not reading any file already on
disk from the prior investigation), re-classifies every transaction by type
(contract creation vs setter call vs other), and independently decodes the
domain string out of each transaction's raw calldata using a from-scratch
ABI-tail decoder (search for the constructor/argument's offset word from the
end of the input, rather than trusting any previously-saved decode).

Claim being tested: "87 distinct contract addresses, 90 distinct C2 domains,
83 creations + 21 setter calls (some overlapping into pre-existing
contracts)."
"""
import json
import re
import time
import urllib.request
from datetime import datetime, timezone

WALLET = "0xb0425bf235a2275735c8c5d668aa0273c65970b9"
SETTER_METHOD_ID = "0xb249cd2d"

API_V1 = (
    "https://polygon.blockscout.com/api?module=account&action=txlist"
    f"&address={WALLET}&sort=asc"
)


def fetch(url, retries=3):
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            last_err = e
            time.sleep(3)
    raise last_err


# Matches a 32-byte word encoding the fixed ABI offset 0x20 (i.e. "this is
# where a single dynamic 'string' argument's [length][data] block begins").
OFFSET_WORD = "0" * 62 + "20"


def decode_trailing_string_arg(input_hex):
    """
    From-scratch decoder: given a tx's full 'input' calldata (init bytecode
    + appended constructor arg, OR a setter call's 4-byte selector + arg),
    find the LAST occurrence of the fixed offset word (0x20), then treat the
    next 64 hex chars as the string length and the following
    length*2 hex chars as the UTF-8 payload. Falls back to trying earlier
    occurrences if the first candidate does not decode to a mostly-printable
    string, since the offset-word bit pattern could theoretically recur
    inside compiled bytecode.
    """
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


def main():
    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    print(f"Target wallet: {WALLET}")
    print(f"Querying: {API_V1}\n")

    data = fetch(API_V1)
    print(f"API status: {data.get('status')}  message: {data.get('message')}")
    items = data.get("result", [])
    print(f"Total transactions pulled fresh: {len(items)}\n")

    creations = []
    setter_calls = []
    other = []
    for tx in items:
        if tx.get("contractAddress"):
            creations.append(tx)
        elif tx.get("methodId", "").lower() == SETTER_METHOD_ID:
            setter_calls.append(tx)
        else:
            other.append(tx)

    print(f"Classified: {len(creations)} contract-creation txs, "
          f"{len(setter_calls)} setter-call txs ({SETTER_METHOD_ID}), "
          f"{len(other)} other/unclassified\n")

    if other:
        print("=== Unclassified transactions (for manual review) ===")
        for tx in other:
            print(f"  hash={tx['hash']}  methodId={tx.get('methodId')}  "
                  f"to={tx.get('to')}  input_len={len(tx.get('input',''))}")
        print()

    contract_domains = {}   # address -> decoded domain (from creation)
    decode_failures_creation = []
    for tx in creations:
        addr = tx["contractAddress"]
        domain = decode_trailing_string_arg(tx["input"])
        if domain:
            contract_domains[addr] = domain
        else:
            decode_failures_creation.append(tx["hash"])

    setter_domains = {}   # address -> list of (timestamp, domain) from setter calls
    decode_failures_setter = []
    for tx in setter_calls:
        addr = tx["to"]
        domain = decode_trailing_string_arg(tx["input"])
        ts = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc).isoformat()
        if domain:
            setter_domains.setdefault(addr, []).append((ts, domain))
        else:
            decode_failures_setter.append(tx["hash"])

    all_contract_addrs = set(contract_domains.keys()) | set(setter_domains.keys())
    all_domains = set(contract_domains.values())
    for hist in setter_domains.values():
        for _, d in hist:
            all_domains.add(d)

    print(f"=== Independent re-derivation results ===")
    print(f"Unique contract addresses (creation OR setter target): {len(all_contract_addrs)}")
    print(f"Unique domains decoded (creation + all setter-call domains): {len(all_domains)}")
    print(f"Creation-tx decode failures: {len(decode_failures_creation)} "
          f"({decode_failures_creation})")
    print(f"Setter-call decode failures: {len(decode_failures_setter)} "
          f"({decode_failures_setter})")
    print()

    print("=== Full decoded creation-tx domain list ===")
    for addr, dom in sorted(contract_domains.items()):
        print(f"  {addr}  ->  {dom}")

    print("\n=== Full decoded setter-call domain list (chronological per contract) ===")
    for addr, hist in sorted(setter_domains.items()):
        for ts, dom in hist:
            print(f"  {addr}  @ {ts}  ->  {dom}")

    print(f"\n=== Comparison against previously published claim ===")
    print("Previously claimed: 87 contract addresses, 90 domains, 83 creations + 21 setter calls.")
    print(f"Independently re-derived: {len(all_contract_addrs)} contract addresses, "
          f"{len(all_domains)} domains, {len(creations)} creations + {len(setter_calls)} setter calls.")


if __name__ == "__main__":
    main()
