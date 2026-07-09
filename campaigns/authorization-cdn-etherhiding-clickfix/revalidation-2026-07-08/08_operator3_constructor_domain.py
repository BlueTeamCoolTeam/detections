import json, re, os

# Input file published alongside this script (operator3_wallet_transactions.json).
# Regenerate with:
#   curl -s "https://polygon.blockscout.com/api/v2/addresses/0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096/transactions?filter=from"
with open(os.path.join(os.path.dirname(__file__), "operator3_wallet_transactions.json"), encoding="utf-8") as f:
    data = json.load(f)

for it in data.get("items", []):
    cc = it.get("created_contract")
    if cc:
        raw = it.get("raw_input", "")
        # find https:// in hex within the raw input (constructor arg)
        m = re.search(r"(68747470[73][0-9a-f]{20,80})", raw)
        if m:
            hexstr = m.group(1)
            # trim to nearest even length, strip trailing zero-padding
            hexstr = hexstr.rstrip("0")
            if len(hexstr) % 2:
                hexstr += "0"
            try:
                print("Constructor domain (decoded):", bytes.fromhex(hexstr).decode("utf-8", "replace"))
            except Exception as e:
                print("decode error", e, hexstr)
        print("creation timestamp:", it.get("timestamp"))
