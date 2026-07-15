#!/usr/bin/env python3
"""
Phase 1, steps 4-5:
  4. Fresh eth_getTransactionCount (nonce) for all 3 known operator wallets,
     independent of the report's cited "516,826" figure for the primary.
  5. Attempt a free/keyless BSC-testnet explorer API call to see whether
     contract-creation history is reachable without a paid key. Documented
     honestly either way (this is expected to likely fail/require a key -
     recording the exact failure mode rather than silently skipping it).
"""
import json
import urllib.request
import urllib.error

RPC = "https://bsc-testnet-rpc.publicnode.com"

WALLETS = {
    "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290": "primary (report cites nonce 516,826, ~435 tBNB)",
    "0x25a7625b3c74bb0452333c8d7f463a2f640fa5af": "secondary deployer (report cites nonce 5)",
    "0x09813ef4ab9a7361a8d0455d57e9a81295dae5f8": "secondary deployer (report cites nonce 1)",
}

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}


def rpc_call(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


results = {"nonces": {}, "balances": {}}

print("=== Step 4: fresh nonce + balance pull ===")
for addr, note in WALLETS.items():
    nonce_resp = rpc_call("eth_getTransactionCount", [addr, "latest"])
    bal_resp = rpc_call("eth_getBalance", [addr, "latest"])
    nonce = int(nonce_resp["result"], 16) if "result" in nonce_resp else None
    bal_wei = int(bal_resp["result"], 16) if "result" in bal_resp else None
    bal_bnb = bal_wei / 1e18 if bal_wei is not None else None
    results["nonces"][addr] = {"note": note, "nonce": nonce, "balance_tBNB": bal_bnb,
                                "raw_nonce_resp": nonce_resp, "raw_balance_resp": bal_resp}
    print(f"{addr}  nonce={nonce}  balance={bal_bnb} tBNB  ({note})")

print()
print("=== Step 5: free/keyless BSC-testnet explorer API feasibility ===")
explorer_attempts = [
    ("https://api-testnet.bscscan.com/api?module=account&action=txlist&address="
     + "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290&sort=asc", "bscscan testnet v1 API, no key"),
    ("https://api.etherscan.io/v2/api?chainid=97&module=account&action=txlist&address="
     + "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290&sort=asc", "etherscan v2 unified API, chainid 97, no key"),
]
explorer_results = {}
for url, label in explorer_attempts:
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode()
            explorer_results[label] = {"url": url, "http_status": resp.status, "body_preview": body[:500]}
            print(f"{label}: HTTP {resp.status}")
            print(f"  body preview: {body[:300]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        explorer_results[label] = {"url": url, "http_status": e.code, "body_preview": body[:500]}
        print(f"{label}: HTTP {e.code} (error)")
        print(f"  body preview: {body[:300]}")
    except Exception as e:
        explorer_results[label] = {"url": url, "error": str(e)}
        print(f"{label}: EXCEPTION {e}")
    print()

results["explorer_feasibility"] = explorer_results

with open("03_wallet_nonce_and_explorer_feasibility_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, default=str)

print("Full results saved to 03_wallet_nonce_and_explorer_feasibility_RESULTS.json")
