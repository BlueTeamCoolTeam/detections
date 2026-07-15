#!/usr/bin/env python3
"""
Phase 2 aggregation: build the full contract -> sites map from the
1,816-site checkpoint (08_full_contract_harvest_CHECKPOINT.jsonl), dedupe
against the 12 contracts already known at the start of this revalidation,
and report every genuinely new contract address discovered.
"""
import json
from collections import defaultdict

KNOWN_12 = {
    "0xa1decfb75c8c0ca28c10517ce56b710baf727d2e",
    "0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff",
    "0x68dce15c1002a2689e19d33a3ae509dd1feb11a5",
    "0xf4a32588b50a59a82fba148d436081a48d80832a",
    "0x7fd85c090f2b35071c57a3b9feaf462aaeb0e437",
    "0xfb448d465841c63f3bc433be61eb692b813d469d",
    "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f",
    "0x0cd58060328e308a43d3c53cfd03a45233ea308a",
    "0xaef2ed8b69efb5c1b9e75990a5f90d02eb5f84f8",
    "0xeed9e134ce64bf74be001a942ee3e3cb5c12c999",
    "0x3d4aa83fe2aceb83a40ae09f03addd560abb5a85",
    "0xb72158bb6642c92ef042aaa681e1ffb8b738ef65",
}

contract_to_sites = defaultdict(list)
sites_no_contract = []
sites_errored = []

with open("08_full_contract_harvest_CHECKPOINT.jsonl", encoding="utf-8") as f:
    for line in f:
        rec = json.loads(line)
        if "error" in rec:
            sites_errored.append(rec)
            continue
        contract = rec.get("contract")
        if contract:
            contract_to_sites[contract.lower()].append(rec["apex"])
        else:
            sites_no_contract.append(rec["apex"])

print(f"Total sites processed: {sum(len(v) for v in contract_to_sites.values()) + len(sites_no_contract) + len(sites_errored)}")
print(f"Sites with a contract identified: {sum(len(v) for v in contract_to_sites.values())}")
print(f"Sites with no eth_call/contract found: {len(sites_no_contract)}")
print(f"Sites that errored (fetch/parse failure): {len(sites_errored)}")
print()
print(f"Total distinct contracts found: {len(contract_to_sites)}")

new_contracts = sorted(set(contract_to_sites.keys()) - KNOWN_12)
already_known_found = sorted(set(contract_to_sites.keys()) & KNOWN_12)

print(f"Contracts matching the already-known 12: {len(already_known_found)}")
print(f"GENUINELY NEW contracts discovered by this harvest: {len(new_contracts)}")
print()

# sort by site count descending for the new contracts
new_sorted = sorted(new_contracts, key=lambda c: -len(contract_to_sites[c]))
print("=== New contracts (top 30 by site count) ===")
for c in new_sorted[:30]:
    print(f"  {c}  -> {len(contract_to_sites[c])} sites  (e.g. {contract_to_sites[c][:3]})")

with open("09_contract_to_sites_map.json", "w", encoding="utf-8") as f:
    json.dump({k: v for k, v in contract_to_sites.items()}, f, indent=2)

with open("09_new_contracts_found.txt", "w", encoding="utf-8") as f:
    for c in new_sorted:
        f.write(f"{c}\t{len(contract_to_sites[c])} sites\n")

with open("09_sites_no_contract.txt", "w", encoding="utf-8") as f:
    for s in sorted(sites_no_contract):
        f.write(s + "\n")

with open("09_sites_errored.json", "w", encoding="utf-8") as f:
    json.dump(sites_errored, f, indent=2)

print()
print("Files written: 09_contract_to_sites_map.json, 09_new_contracts_found.txt,")
print("09_sites_no_contract.txt, 09_sites_errored.json")
