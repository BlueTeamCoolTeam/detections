#!/usr/bin/env python3
"""
Builds a clean, per-operator/per-contract breakdown of the confirmed
compromised sites - answering "which sites belong to which operator",
which neither 09_contract_to_sites_map.json (unfiltered, all 44 contracts
mixed together) nor 11_clean_confirmed_sites.txt (flat list, no breakdown)
answers on its own.

Maps each of the 7 confirmed-genuine payload contracts to its operator
wallet and writes one file per operator/wallet, plus a combined summary.
Sites mapped to the 2 utility/gate contracts that were directly called
(0xaef2ed8b..., 0x3d4aa83f...) are included under their owner wallet too.
The 106 sites with no contract identified this round (11 no-eth_call-found
+ 95 fetch/parse errors) are listed separately - they are NOT false
positives (that determination requires a contract to test), just
unconfirmed at the contract level this session.
"""
import json

with open("09_contract_to_sites_map.json", encoding="utf-8") as f:
    contract_to_sites = json.load(f)

with open("10_false_positive_sites_ALL.txt", encoding="utf-8") as f:
    false_positive_sites = set(line.strip().lower() for line in f if line.strip())

# contract -> (operator label, owner wallet)
CONTRACT_INFO = {
    "0xa1decfb75c8c0ca28c10517ce56b710baf727d2e": ("Operator (primary wallet) - stage-1, symmetryclosets chain", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0xdf132e2893824e26ec8ae8014b4f4facd54ed67f": ("Operator (primary wallet) - stage-1, eu.mk chain", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0x46790e2ac7f3ca5a7d1bfce312d11e91d23383ff": ("Operator (primary wallet) - Windows branch, symmetryclosets chain", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0x68dce15c1002a2689e19d33a3ae509dd1feb11a5": ("Operator (primary wallet) - macOS branch, symmetryclosets chain", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0x0cd58060328e308a43d3c53cfd03a45233ea308a": ("Operator (primary wallet) - Windows-equivalent branch, eu.mk chain", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0xaef2ed8b69efb5c1b9e75990a5f90d02eb5f84f8": ("Operator (primary wallet) - utility/gate contract", "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290"),
    "0x7fd85c090f2b35071c57a3b9feaf462aaeb0e437": ("Operator (secondary deployer) - rotated stage-1", "0x25a7625b3c74bb0452333c8d7f463a2f640fa5af"),
    "0xfb448d465841c63f3bc433be61eb692b813d469d": ("Operator (secondary deployer) - rotated stage-1", "0x09813ef4ab9a7361a8d0455d57e9a81295dae5f8"),
    "0x3d4aa83fe2aceb83a40ae09f03addd560abb5a85": ("Operator (unattributed - no owner() function on this utility contract)", None),
}

by_wallet = {}
for contract, (label, wallet) in CONTRACT_INFO.items():
    sites = contract_to_sites.get(contract, [])
    key = wallet or "unattributed"
    by_wallet.setdefault(key, {"label": [], "sites": set()})
    by_wallet[key]["label"].append(f"{contract} ({label}, {len(sites)} sites)")
    by_wallet[key]["sites"].update(s.lower() for s in sites)

print("=== Per-operator (wallet) confirmed site counts ===")
total_attributed = 0
for wallet, info in by_wallet.items():
    n = len(info["sites"])
    total_attributed += n
    print(f"\n{wallet}")
    for l in info["label"]:
        print(f"  contract: {l}")
    print(f"  TOTAL unique sites for this wallet: {n}")

    fname = f"12_operator_{wallet[:12]}_confirmed_sites.txt"
    with open(fname, "w", encoding="utf-8") as f:
        for s in sorted(info["sites"]):
            f.write(s + "\n")
    print(f"  saved to {fname}")

print(f"\nTotal sites attributed to a specific operator/contract: {total_attributed}")

# unconfirmed-at-contract-level sites (not false positives - just not individually
# contract-verified this round)
with open("09_sites_no_contract.txt", encoding="utf-8") as f:
    no_contract = set(line.strip().lower() for line in f if line.strip())
with open("09_sites_errored.json", encoding="utf-8") as f:
    errored = set(rec["apex"].lower() for rec in json.load(f))

unconfirmed = no_contract | errored
print(f"Sites matching the RPC-beacon signature but NOT contract-verified this session: {len(unconfirmed)}")
with open("12_unconfirmed_no_contract_sites.txt", "w", encoding="utf-8") as f:
    for s in sorted(unconfirmed):
        f.write(s + "\n")

# sanity check against the clean total
with open("11_clean_confirmed_sites.txt", encoding="utf-8") as f:
    clean_total = set(line.strip().lower() for line in f if line.strip())

reconciled = set()
for info in by_wallet.values():
    reconciled |= info["sites"]
reconciled |= unconfirmed

print()
print(f"Clean total (11_clean_confirmed_sites.txt): {len(clean_total)}")
print(f"Reconciled (attributed + unconfirmed-no-contract): {len(reconciled)}")
print(f"Match: {clean_total == reconciled}")
if clean_total != reconciled:
    print(f"  only in clean_total: {len(clean_total - reconciled)}")
    print(f"  only in reconciled: {len(reconciled - clean_total)}")
