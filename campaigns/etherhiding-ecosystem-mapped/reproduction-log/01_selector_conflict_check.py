#!/usr/bin/env python3
"""
Settles a direct contradiction found while reviewing the two new investigation
reports (mamkor-pro-iwr-downloader/REPORT.md and bw-panel-926d6454-sibling/REPORT.md)
before this was written up as fact in the combined post.

mamkor's own IOC table lists its EtherHiding getter selector as 0x38bcdc1c, but a
later section of the same report (5a/5b) describes mamkor as "one of at least 5
known operator instances of the same rented 'BW panel' EtherHiding kit (shared
selector 0xb68d1809)" - the same selector used by the xdav / Operator 2 / Operator 3
/ BW-sibling cluster documented in the authorization-cdn-etherhiding-clickfix post.

This script calls eth_call directly against every contract in question, live, with
both selectors, to determine which contracts actually implement which function -
rather than trusting either report's prose.
"""
import json
import time
import urllib.request

RPC = "https://polygon-public.nodies.app"

CONTRACTS = [
    ("mamkor/merabs (Family B candidate)", "0x08207B087F61d7e95E441E15fd6d40BEfd6eD308"),
    ("BW-sibling operator (Family A candidate, new)", "0x926d64543148dB649C4F877fE7ba4c693e01E288"),
    ("xdav / Operator 1 (Family A, published)", "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2"),
]

SELECTORS = {
    "38bcdc1c (mamkor's documented getter)": "38bcdc1c",
    "b68d1809 (Family A / 'BW panel' shared kit selector)": "b68d1809",
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
    for label, addr in CONTRACTS:
        print(f"\n=== {label} :: {addr} ===")
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
            time.sleep(0.5)


if __name__ == "__main__":
    main()
