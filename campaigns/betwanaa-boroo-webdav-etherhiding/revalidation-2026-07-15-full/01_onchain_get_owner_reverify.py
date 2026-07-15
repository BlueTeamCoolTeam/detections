#!/usr/bin/env python3
"""
Phase 1, steps 1-2: live re-verification of every currently-known contract
against the public BSC TESTNET RPC (bsc-testnet-rpc.publicnode.com).

For each contract: call get() (selector 0x6d4ce63c) and owner() (selector
0x8da5cb5b) fresh, independently of anything already saved in the original
report/artifacts. Decodes the ABI-encoded string return of get() from raw
hex, saving both the raw JSON-RPC response and the decoded text.

Independent list of all 12 currently-known contracts (10 from the batch
harvest in artifacts/23_harvested_contracts_sample.json + 2 branch contracts
named only in report.md section 9.1/9.3's manual single-chain decode of
symmetryclosets - these two do not appear in the artifacts/23 harvest, so
they are listed separately here rather than assumed identical).
"""
import json
import re
import base64
import urllib.request

RPC = "https://bsc-testnet-rpc.publicnode.com"

CONTRACTS = {
    "0xA1decFB75C8C0CA28C10517ce56B710baf727d2e": "stage-1 (symmetryclosets) - from artifacts/23 + report 9.3",
    "0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff": "Windows branch - report 9.1/9.3 only, NOT in artifacts/23 batch harvest",
    "0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5": "macOS branch - report 9.1/9.3 only, NOT in artifacts/23 batch harvest",
    "0xf4a32588b50a59a82fbA148d436081A48d80832A": "session-completion gate - from artifacts/22/23",
    "0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437": "rotated stage-1 - from artifacts/22/23",
    "0xfb448d465841c63f3bc433be61eb692b813d469d": "rotated stage-1 - from artifacts/22/23",
    "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f": "from artifacts/22/23",
    "0x0cd58060328e308a43d3c53cfd03a45233ea308a": "from artifacts/22/23",
    "0xaef2ed8b69efb5c1b9e75990a5f90d02eb5f84f8": "from artifacts/22/23",
    "0xeed9e134ce64bf74be001a942ee3e3cb5c12c999": "from artifacts/22/23",
    "0x3d4aa83fe2aceb83a40ae09f03addd560abb5a85": "from artifacts/22/23",
    "0xb72158bb6642c92ef042aaa681e1ffb8b738ef65": "from artifacts/22/23",
}

GET_SELECTOR = "0x6d4ce63c"
OWNER_SELECTOR = "0x8da5cb5b"


def rpc_call(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        RPC,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def eth_call(to, data):
    return rpc_call("eth_call", [{"to": to, "data": data}, "latest"])


def decode_abi_string(hex_result):
    """Decode a standard ABI-encoded dynamic string return value."""
    if not hex_result or hex_result in ("0x", "0x0"):
        return None
    raw = bytes.fromhex(hex_result[2:])
    if len(raw) < 64:
        return None
    str_len = int.from_bytes(raw[32:64], "big")
    str_bytes = raw[64:64 + str_len]
    return str_bytes


def decode_address(hex_result):
    if not hex_result or hex_result in ("0x", "0x0"):
        return None
    raw = hex_result[2:].rjust(64, "0")
    addr = "0x" + raw[-40:]
    return addr


results = {}
for addr, note in CONTRACTS.items():
    entry = {"note": note}

    try:
        get_resp = eth_call(addr, GET_SELECTOR)
        entry["get_raw_response"] = get_resp
        if "error" in get_resp:
            entry["get_status"] = "ERROR: " + json.dumps(get_resp["error"])
        else:
            hex_result = get_resp.get("result")
            decoded_bytes = decode_abi_string(hex_result)
            if decoded_bytes is None:
                entry["get_status"] = "EMPTY/REVERTED"
            else:
                entry["get_status"] = "OK"
                entry["get_decoded_len"] = len(decoded_bytes)
                # try utf-8 first (raw JS), fall back to treating as base64
                try:
                    text = decoded_bytes.decode("utf-8")
                    entry["get_decoded_as_utf8_preview"] = text[:200]
                except UnicodeDecodeError:
                    entry["get_decoded_as_utf8_preview"] = None
                # save full decoded bytes to its own file for downstream stage-3 extraction
                fname = f"contract_{addr.lower()}_get_decoded.bin"
                with open(fname, "wb") as f:
                    f.write(decoded_bytes)
                entry["get_decoded_saved_to"] = fname
    except Exception as e:
        entry["get_status"] = f"EXCEPTION: {e}"

    try:
        owner_resp = eth_call(addr, OWNER_SELECTOR)
        entry["owner_raw_response"] = owner_resp
        if "error" in owner_resp:
            entry["owner_status"] = "NO_OWNER_FN_OR_ERROR: " + json.dumps(owner_resp["error"])
        else:
            hex_result = owner_resp.get("result")
            if not hex_result or hex_result in ("0x", "0x0", "0x" + "0" * 64):
                entry["owner_status"] = "EMPTY/NO_OWNER_FN"
                entry["owner_address"] = None
            else:
                entry["owner_status"] = "OK"
                entry["owner_address"] = decode_address(hex_result)
    except Exception as e:
        entry["owner_status"] = f"EXCEPTION: {e}"

    results[addr] = entry
    print(f"{addr}  get={entry.get('get_status')}  owner={entry.get('owner_status')} -> {entry.get('owner_address')}")

with open("01_onchain_get_owner_reverify_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, default=str)

print()
print("Full results saved to 01_onchain_get_owner_reverify_RESULTS.json")
