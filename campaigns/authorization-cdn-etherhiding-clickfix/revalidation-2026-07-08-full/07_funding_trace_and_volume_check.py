"""
Step 7 - funding-source trace for all 3 deployer wallets + funder volume check.

Rationale: if two deployer wallets share a funding source, that source could
reveal other wallets funded the same way -- a systematic (non-domain-based)
way to look for undiscovered operators. For each wallet, checks both direct
incoming transactions (filter=to) and internal transactions (contract-relayed
value transfers) since a prior round found operator 2's wallet returns empty
on the direct-transfer endpoint. For any funding source found, checks its own
outgoing transaction volume via eth_getTransactionCount to assess whether it's
a traceable dedicated source or high-volume shared infrastructure.

Usage: python 07_funding_trace_and_volume_check.py
"""
import json, urllib.request, time, os

HERE = os.path.dirname(__file__)
RPCS = ["https://polygon.drpc.org", "https://polygon-bor-rpc.publicnode.com", "https://rpc.ankr.com/polygon"]

WALLETS = {
    "operator1_wallet": "0xCaf2C54E400437da717cF215181B170F65187aBf",
    "operator2_wallet": "0xf1940DDBDA56074ce29bB0b6eA8D62db974870a5",
    "operator3_wallet": "0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096",
}


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())


def rpc_call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    for rpc in RPCS:
        try:
            req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())["result"]
        except Exception:
            time.sleep(1)
            continue
    return None


funders_found = {}

for label, addr in WALLETS.items():
    print(f"\n{'=' * 76}\n{label}: {addr}\n{'=' * 76}")

    print("Direct incoming transactions (filter=to):")
    try:
        d = get(f"https://polygon.blockscout.com/api/v2/addresses/{addr}/transactions?filter=to")
        items = d.get("items", [])
        print(f"  {len(items)} items")
        out_file = os.path.join(HERE, f"{label}_incoming_direct_raw.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        print(f"  wrote FULL raw JSON to {out_file}")
        for it in sorted(items, key=lambda x: x.get("timestamp") or ""):
            print(f"    {it.get('timestamp')}  from={it.get('from', {}).get('hash')}  value={it.get('value')}")
            if it.get("from", {}).get("hash") and label not in funders_found:
                funders_found[label] = it.get("from", {}).get("hash")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(1)

    print("\nInternal transactions (contract-relayed value transfers, both directions):")
    try:
        d = get(f"https://polygon.blockscout.com/api/v2/addresses/{addr}/internal-transactions")
        items = d.get("items", [])
        print(f"  {len(items)} items")
        out_file = os.path.join(HERE, f"{label}_internal_txs_raw.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        print(f"  wrote FULL raw JSON to {out_file}")
        for it in sorted(items, key=lambda x: x.get("timestamp") or ""):
            print(f"    {it.get('timestamp')}  from={it.get('from', {}).get('hash')}  to={(it.get('to') or {}).get('hash')}  value={it.get('value')}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(1)

    bal = rpc_call("eth_getBalance", [addr, "latest"])
    nonce = rpc_call("eth_getTransactionCount", [addr, "latest"])
    print(f"\nCurrent balance (wei, hex): {bal}")
    print(f"Current outgoing tx count (nonce): {int(nonce, 16) if nonce else None}")
    time.sleep(0.5)

print(f"\n{'=' * 76}\nFUNDER VOLUME CHECK\n{'=' * 76}")
print(f"Funders identified: {funders_found}")
for label, funder in funders_found.items():
    nonce = rpc_call("eth_getTransactionCount", [funder, "latest"])
    code = rpc_call("eth_getCode", [funder, "latest"])
    n = int(nonce, 16) if nonce else None
    print(f"  {label}'s funder {funder}: outgoing_tx_count={n}  is_contract={code not in (None, '0x', '0x0')}")
    time.sleep(0.5)

print(f"\nDirect link check -- do any two wallets share the same funder?")
funder_vals = list(funders_found.values())
print(f"  funders: {funders_found}")
print(f"  all distinct: {len(set(funder_vals)) == len(funder_vals)}")
