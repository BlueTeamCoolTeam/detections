#!/usr/bin/env python3
"""
Revalidation of the core claim underpinning the entire "two kit families"
framing of the combined post: mamkor/merabs's contract does NOT implement
the Family A selector (0xb68d1809), and the Family A contracts do NOT
implement mamkor's selector (0x38bcdc1c).

This is a fresh, independent re-run of reproduction-log/01_selector_conflict_check.py
(same logic, re-executed for this revalidation pass with its own timestamped
output) - not a copy of the old output.
"""
import json
import time
import urllib.request
from datetime import datetime, timezone

RPC = "https://polygon-public.nodies.app"

CONTRACTS = [
    ("mamkor/merabs (Family B)", "0x08207B087F61d7e95E441E15fd6d40BEfd6eD308"),
    ("BW-sibling (Family A, new)", "0x926d64543148dB649C4F877fE7ba4c693e01E288"),
    ("xdav / Operator 1 (Family A, published)", "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2"),
    ("Operator 2 (Family A, published)", "0x83833C5D676cA06E941A32310AE67D0890F657eE"),
    ("Operator 3 (Family A, published)", "0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55"),
]

SELECTORS = {
    "38bcdc1c (mamkor's documented getter)": "38bcdc1c",
    "b68d1809 (Family A shared kit selector)": "b68d1809",
}


def eth_call(to, selector):
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": "0x" + selector}, "latest"],
    }).encode()
    req = urllib.request.Request(
        RPC, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def decode_abi_string(hexdata):
    h = hexdata[2:] if hexdata.startswith("0x") else hexdata
    length = int(h[64:128], 16)
    data = h[128:128 + length * 2]
    return bytes.fromhex(data).decode("utf-8", "replace")


def main():
    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    print(f"RPC endpoint: {RPC}\n")
    for label, addr in CONTRACTS:
        print(f"=== {label} :: {addr} ===")
        for sel_label, sel in SELECTORS.items():
            result = eth_call(addr, sel)
            if "error" in result:
                print(f"  selector {sel_label}: REVERTED -> {result['error']['message']}")
            else:
                raw = result["result"]
                try:
                    decoded = decode_abi_string(raw)
                    print(f"  selector {sel_label}: OK -> {decoded!r}")
                except Exception as e:
                    print(f"  selector {sel_label}: OK (raw, undecoded) -> {raw} ({e})")
            time.sleep(0.4)
        print()


if __name__ == "__main__":
    main()
