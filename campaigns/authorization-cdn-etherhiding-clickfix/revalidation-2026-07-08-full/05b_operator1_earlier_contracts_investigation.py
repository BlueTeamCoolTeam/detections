"""
Step 5b (follow-up, triggered by step 5's fresh capture) - investigate two
previously-unknown contracts that operator 1's wallet called updateDomain on,
on 2026-05-24, predating the 2026-06-05 contract this investigation has
treated as operator 1's start date. Domain values look garbled, not plaintext
URLs like every other updateDomain call -- checking whether these are earlier
EtherHiding deployments (encoded differently) or unrelated contract calls
that happen to share the updateDomain function name.

Usage: python 05b_operator1_earlier_contracts_investigation.py
"""
import json, urllib.request, base64, time, os

HERE = os.path.dirname(__file__)
RPCS = ["https://polygon.drpc.org", "https://polygon-bor-rpc.publicnode.com", "https://rpc.ankr.com/polygon"]

CONTRACTS = {
    "may24_contract_A": "0x76fA199B724Bb511BA326BB0400ED89227B39AEF",
    "may24_contract_B": "0xbdC80AdF5944aE01A7a56552A03C507DB1f40dDd",
}
RAW_DOMAIN_VALUES = {
    "may24_contract_A": "wc1:q79uijiUnZGe5eH2x6caZQkaG4Jx2uRYO0Im1bl+nrlyXNh2flqZd/ltVwZt+A0=",
    "may24_contract_B": "BwQFBwQFBwQFBwQFBwQFBwQF",
}


def rpc_call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    for rpc in RPCS:
        try:
            req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())["result"]
        except Exception as e:
            print(f"    (rpc {rpc} failed: {e})")
            time.sleep(1)
            continue
    return None


def get_full_history(addr):
    url = f"https://polygon.blockscout.com/api/v2/addresses/{addr}/transactions"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())


for label, addr in CONTRACTS.items():
    print(f"\n{'=' * 76}\n{label}: {addr}\n{'=' * 76}")

    code = rpc_call("eth_getCode", [addr, "latest"])
    print(f"eth_getCode length: {len(code) if code else 0}  is_contract: {code not in (None, '0x', '0x0')}")
    if code and code not in ("0x", "0x0"):
        print(f"bytecode (first 300 chars): {code[:300]}")

    raw_val = RAW_DOMAIN_VALUES[label]
    print(f"\nRaw 'domain' value from updateDomain call: {raw_val!r}")
    print("Attempting interpretations:")
    try:
        b64_clean = raw_val.split(":", 1)[-1] if ":" in raw_val else raw_val
        decoded = base64.b64decode(b64_clean + "=" * (-len(b64_clean) % 4))
        print(f"  as base64 -> {len(decoded)} bytes, hex: {decoded.hex()}")
        printable = sum(32 <= b < 127 for b in decoded) / max(len(decoded), 1)
        print(f"  printable-ASCII ratio: {printable:.2f}")
    except Exception as e:
        print(f"  base64 decode failed: {e}")

    print(f"\nFull transaction history for this contract:")
    try:
        data = get_full_history(addr)
        items = data.get("items", [])
        print(f"  {len(items)} items")
        out_file = os.path.join(HERE, f"{label}_full_history_raw.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"  wrote FULL raw JSON to {out_file}")
        for it in sorted(items, key=lambda x: x.get("timestamp") or ""):
            print(f"    {it.get('timestamp')}  method={it.get('method')}  from={it.get('from', {}).get('hash')}  to={(it.get('to') or {}).get('hash')}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(1)
