import json, urllib.request, time

RPCS = ["https://polygon.drpc.org", "https://polygon-bor-rpc.publicnode.com", "https://rpc.ankr.com/polygon"]

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

ADDRS = {
    "op1_funder": "0xD44a53c0d5Ab8E6C07cB20d482B3d2CB76029dd3",
    "op3_funder": "0x71d4249079684479F2651745fA2fcD79c9b45f53",
}

for label, addr in ADDRS.items():
    nonce_hex = rpc_call("eth_getTransactionCount", [addr, "latest"])
    is_contract = rpc_call("eth_getCode", [addr, "latest"])
    nonce = int(nonce_hex, 16) if nonce_hex else None
    print(f"{label}: {addr}")
    print(f"  outgoing tx count (nonce): {nonce}")
    print(f"  is_contract: {is_contract not in (None, '0x', '0x0')}")
    time.sleep(0.5)
