#!/usr/bin/env python3
"""
Critical accuracy check before trusting the 37 "new" contracts found by the
Phase 2 harvest: the urlscan query (domain:bsc-testnet-rpc.publicnode.com AND
NOT page.apexDomain:publicnode.com) matches ANY site that calls the shared
public BSC-testnet RPC for ANY reason - not just this campaign's injected
loader. report.md's own confidence note flagged this risk for a small number
of pre-2026 entries; this check found it's broader than that: several new
"contracts" are well-known standard infrastructure addresses (e.g.
0xcA11bde05977b3631167028862bE2a173976CA11 is the universal Multicall3
contract deployed at the same address on most EVM chains; 0x5FbDB2315678...
is Hardhat's default local-deployment placeholder address), and their
associated sites are legitimate Web3/DeFi project sites
(pancakeswap.finance, chaingpt.dev, maticz.in, *.vercel.app/*.pages.dev
crypto demos) - not compromised small-business CMS sites matching the
campaign's actual victim profile.

This script live-tests every new contract for BOTH signals that distinguish
a genuine campaign contract from noise:
  1. owner() resolves to one of the 3 known operator wallets, OR
  2. get() returns a payload whose decoded content contains the campaign's
     own fingerprint markers (isHeadless / navigator.webdriver check,
     ip-info.ff.avast.com, or a pcalua.exe/bash-curl command template)
A contract failing both checks is flagged as a likely false-positive match
on the shared public RPC, not a genuine campaign C2.
"""
import json
import re
import base64
import time
import urllib.request
import urllib.error

RPC = "https://bsc-testnet-rpc.publicnode.com"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}
KNOWN_WALLETS = {
    "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290",
    "0x25a7625b3c74bb0452333c8d7f463a2f640fa5af",
    "0x09813ef4ab9a7361a8d0455d57e9a81295dae5f8",
}
GET_SELECTOR = "0x6d4ce63c"
OWNER_SELECTOR = "0x8da5cb5b"
CAMPAIGN_MARKERS = [
    "isHeadless", "navigator.webdriver", "ip-info.ff.avast.com",
    "pcalua.exe", "HeadlessChrome", "usr_id",
]


def rpc_call(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers=HEADERS)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            if attempt == 2:
                return {"error": str(e)}
            time.sleep(2)


def decode_address(hex_result):
    if not hex_result or hex_result in ("0x", "0x0"):
        return None
    raw = hex_result[2:].rjust(64, "0")
    return "0x" + raw[-40:]


def decode_abi_string(hex_result):
    if not hex_result or hex_result in ("0x", "0x0"):
        return None
    raw = bytes.fromhex(hex_result[2:])
    if len(raw) < 64:
        return None
    str_len = int.from_bytes(raw[32:64], "big")
    return raw[64:64 + str_len]


with open("09_contract_to_sites_map.json", encoding="utf-8") as f:
    contract_to_sites = json.load(f)

KNOWN_12 = {
    "0xa1decfb75c8c0ca28c10517ce56b710baf727d2e", "0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff",
    "0x68dce15c1002a2689e19d33a3ae509dd1feb11a5", "0xf4a32588b50a59a82fba148d436081a48d80832a",
    "0x7fd85c090f2b35071c57a3b9feaf462aaeb0e437", "0xfb448d465841c63f3bc433be61eb692b813d469d",
    "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f", "0x0cd58060328e308a43d3c53cfd03a45233ea308a",
    "0xaef2ed8b69efb5c1b9e75990a5f90d02eb5f84f8", "0xeed9e134ce64bf74be001a942ee3e3cb5c12c999",
    "0x3d4aa83fe2aceb83a40ae09f03addd560abb5a85", "0xb72158bb6642c92ef042aaa681e1ffb8b738ef65",
}
new_contracts = sorted(set(contract_to_sites.keys()) - KNOWN_12)

results = {}
confirmed_campaign = []
likely_false_positive = []

for addr in new_contracts:
    owner_resp = rpc_call("eth_call", [{"to": addr, "data": OWNER_SELECTOR}, "latest"])
    owner_addr = decode_address(owner_resp.get("result")) if "result" in owner_resp else None
    owner_match = owner_addr and owner_addr.lower() in KNOWN_WALLETS

    get_resp = rpc_call("eth_call", [{"to": addr, "data": GET_SELECTOR}, "latest"])
    marker_hit = None
    if "result" in get_resp and get_resp.get("result") not in (None, "0x"):
        outer = decode_abi_string(get_resp["result"])
        if outer:
            try:
                inner = base64.b64decode(outer + b"=" * (-len(outer) % 4))
                text = inner.decode("utf-8", errors="replace")
                for marker in CAMPAIGN_MARKERS:
                    if marker in text:
                        marker_hit = marker
                        break
            except Exception:
                pass

    is_campaign = bool(owner_match or marker_hit)
    n_sites = len(contract_to_sites[addr])
    results[addr] = {
        "n_sites": n_sites,
        "owner_addr": owner_addr,
        "owner_match": owner_match,
        "marker_hit": marker_hit,
        "is_campaign": is_campaign,
        "sample_sites": contract_to_sites[addr][:3],
    }
    (confirmed_campaign if is_campaign else likely_false_positive).append(addr)
    tag = "CAMPAIGN" if is_campaign else "FALSE-POSITIVE?"
    print(f"{addr}  n_sites={n_sites}  owner={owner_addr}  marker={marker_hit}  -> {tag}")

print()
print(f"Confirmed campaign contracts (of {len(new_contracts)} new): {len(confirmed_campaign)}")
print(f"Likely false-positive contracts: {len(likely_false_positive)}")
fp_sites = sum(results[a]["n_sites"] for a in likely_false_positive)
print(f"Sites attached to likely false-positive contracts: {fp_sites}")

with open("10_verify_new_contracts_live_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

with open("10_confirmed_campaign_new_contracts.txt", "w", encoding="utf-8") as f:
    for a in confirmed_campaign:
        f.write(a + "\n")

with open("10_false_positive_contracts_and_sites.json", "w", encoding="utf-8") as f:
    json.dump({a: {"sites": contract_to_sites[a], **results[a]} for a in likely_false_positive}, f, indent=2)

print()
print("Files written: 10_verify_new_contracts_live_RESULTS.json,")
print("10_confirmed_campaign_new_contracts.txt, 10_false_positive_contracts_and_sites.json")
