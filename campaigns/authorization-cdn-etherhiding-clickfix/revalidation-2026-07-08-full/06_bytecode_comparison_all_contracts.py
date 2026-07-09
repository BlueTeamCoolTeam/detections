"""
Step 6 - full bytecode comparison across all known contracts, fresh capture.

Extended from the prior round to include the two newly-discovered May-24
operator-1 test contracts (found in step 5b), alongside the original 7:
operator 1's live contract, operator 2's 5 contracts, operator 3's contract.

Saves the COMPLETE hex bytecode for every contract to file (not just the
hash) so the byte-identical claim is independently checkable without
re-querying the chain.

Usage: python 06_bytecode_comparison_all_contracts.py
"""
import json, urllib.request, hashlib, time, os

HERE = os.path.dirname(__file__)

CONTRACTS = {
    "op1_live_contract_jun05": "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2",
    "op1_test_contract_may24_A": "0x76fA199B724Bb511BA326BB0400ED89227B39AEF",
    "op1_test_contract_may24_B": "0xbdC80AdF5944aE01A7a56552A03C507DB1f40dDd",
    "op2_current": "0x83833C5D676cA06E941A32310AE67D0890F657eE",
    "op2_hist_1_apr13": "0x6C4bECa447067D6452029888AFd56417293F6A1f",
    "op2_hist_2_apr23": "0x623a17677Ed3B95A512c4DD32AB4A6Ba43444FFb",
    "op2_hist_3_may18": "0xF9344f7F9d7954a78D57ae940827126C30C4d678",
    "op2_hist_4_jun04": "0xE762F84B8c509f7DEbDd72Ea4E9BA099DF9b9097",
    "op3_current": "0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55",
}

RPCS = ["https://polygon.drpc.org", "https://polygon-bor-rpc.publicnode.com", "https://rpc.ankr.com/polygon", "https://1rpc.io/matic"]


def get_code(addr):
    body = json.dumps({"jsonrpc": "2.0", "method": "eth_getCode", "params": [addr, "latest"], "id": 1}).encode()
    last_err = None
    for rpc in RPCS:
        try:
            req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())["result"]
        except Exception as e:
            last_err = e
            time.sleep(1)
            continue
    raise last_err


print(f"SESSION START (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
results = {}
for label, addr in CONTRACTS.items():
    code = get_code(addr)
    h = hashlib.sha256(code.encode()).hexdigest()
    results[label] = (addr, len(code), h, code)
    print(f"{label:28s} {addr}  len={len(code):6d}  sha256={h}")
    out_file = os.path.join(HERE, f"bytecode_{label}.hex")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(code)
    time.sleep(0.5)

print("\n--- grouping by identical bytecode (full SHA-256, not truncated) ---")
by_hash = {}
for label, (addr, ln, h, code) in results.items():
    by_hash.setdefault(h, []).append(label)
for h, labels in by_hash.items():
    print(f"  {h}")
    print(f"    -> {labels}")

print(f"\nSESSION END (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
print(f"\nAll {len(CONTRACTS)} full hex bytecodes written to bytecode_<label>.hex in this folder.")
