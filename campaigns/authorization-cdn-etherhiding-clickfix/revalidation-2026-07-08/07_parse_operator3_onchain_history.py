import json, os

# Input files are published alongside this script (operator3_contract_transactions.json,
# operator3_wallet_transactions.json). Regenerate them yourself with:
#   curl -s "https://polygon.blockscout.com/api/v2/addresses/0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55/transactions?filter=to"
#   curl -s "https://polygon.blockscout.com/api/v2/addresses/0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096/transactions?filter=from"
here = os.path.dirname(__file__)

with open(os.path.join(here, "operator3_contract_transactions.json"), encoding="utf-8") as f:
    data = json.load(f)

items = data.get("items", [])
print(f"Total txs to contract: {len(items)}")
for it in items:
    print(it.get("timestamp"), it.get("method"), it.get("from", {}).get("hash"),
          it.get("decoded_input", {}).get("parameters", [{}])[0].get("value") if it.get("decoded_input") else None)

print("\n--- deployer wallet's txs (contract creations) ---")
with open(os.path.join(here, "operator3_wallet_transactions.json"), encoding="utf-8") as f:
    data2 = json.load(f)
items2 = data2.get("items", [])
print(f"Total txs from wallet: {len(items2)}")
for it in items2:
    cc = it.get("created_contract")
    print(it.get("timestamp"), it.get("method"), "created_contract=", cc.get("hash") if cc else None)
