"""
Step 5 - full on-chain history for all 3 operators, fresh capture.

Pulls the COMPLETE raw JSON response (not truncated) from Blockscout's public
Polygon API for each operator's contract (updateDomain call history) and
deployer wallet (transaction history), and prints the decoded C2-domain
rotation timeline for each. Full raw JSON is saved to file so anyone can
independently re-parse it without re-querying the chain.

Usage: python 05_onchain_history_all_operators.py
"""
import json, urllib.request, time, os

HERE = os.path.dirname(__file__)

TARGETS = {
    "operator1_contract": ("0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2", "to"),
    "operator1_wallet": ("0xCaf2C54E400437da717cF215181B170F65187aBf", "from"),
    "operator2_contract_current": ("0x83833C5D676cA06E941A32310AE67D0890F657eE", "to"),
    "operator2_wallet": ("0xf1940DDBDA56074ce29bB0b6eA8D62db974870a5", "from"),
    "operator3_contract": ("0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55", "to"),
    "operator3_wallet": ("0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096", "from"),
}


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())


for label, (addr, direction) in TARGETS.items():
    print(f"\n{'=' * 76}\n{label}: {addr}  (filter={direction})\n{'=' * 76}")
    url = f"https://polygon.blockscout.com/api/v2/addresses/{addr}/transactions?filter={direction}"
    print(f"Query: GET {url}")
    try:
        data = get(url)
    except Exception as e:
        print(f"ERROR: {e}")
        continue
    items = data.get("items", [])
    print(f"Items returned: {len(items)}")

    out_file = os.path.join(HERE, f"{label}_transactions_raw.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"wrote FULL raw JSON to {out_file} ({os.path.getsize(out_file)} bytes)")

    print("\nDecoded updateDomain calls (if any):")
    rows = []
    for it in items:
        if it.get("method") == "updateDomain":
            ts = it.get("timestamp")
            params = it.get("decoded_input", {}).get("parameters", [])
            val = params[0]["value"] if params else None
            rows.append((ts, val, it.get("hash")))
    rows.sort()
    if rows:
        for ts, val, h in rows:
            print(f"  {ts}  {val}  tx={h}")
    else:
        print("  (none -- this is not a domain-update-receiving contract, or none decoded)")

    print("\nAll transactions summary (timestamp, method, from, to, value):")
    for it in sorted(items, key=lambda x: x.get("timestamp") or ""):
        print(f"  {it.get('timestamp')}  method={it.get('method')}  from={it.get('from', {}).get('hash')}  to={(it.get('to') or {}).get('hash')}  value={it.get('value')}")

    time.sleep(1)

print(f"\n{'=' * 76}\nDONE\n{'=' * 76}")
