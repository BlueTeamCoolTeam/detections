import json, urllib.request, hashlib, time

CONTRACTS = {
    "op1_current": "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2",
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

results = {}
for label, addr in CONTRACTS.items():
    code = get_code(addr)
    h = hashlib.sha256(code.encode()).hexdigest()[:16]
    results[label] = (addr, len(code), h, code)
    print(f"{label:20s} {addr}  len={len(code):6d}  sha256[:16]={h}")
    time.sleep(0.5)

print("\n--- grouping by identical bytecode ---")
by_hash = {}
for label, (addr, ln, h, code) in results.items():
    by_hash.setdefault(h, []).append(label)
for h, labels in by_hash.items():
    print(f"  {h}: {labels}")
