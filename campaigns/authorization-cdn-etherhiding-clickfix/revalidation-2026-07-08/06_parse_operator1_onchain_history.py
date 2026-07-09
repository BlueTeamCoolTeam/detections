# Usage: python 06_parse_operator1_onchain_history.py <path-to-json>
# Fetch the input with:
#   curl -s "https://polygon.blockscout.com/api/v2/addresses/0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2/transactions?filter=to" > op1_contract_txs.json
# (the blog post's own one-liner using `jq` does the same job more directly - this script
# is the fuller version that was actually run, for anyone who wants to inspect the logic.)
import json, sys

path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    data = json.load(f)

items = data.get('items', [])
rows = []
for it in items:
    if it.get('method') != 'updateDomain':
        continue
    ts = it.get('timestamp')
    params = it.get('decoded_input', {}).get('parameters', [])
    val = params[0]['value'] if params else None
    rows.append((ts, val, it.get('hash')))

rows.sort()
print(f"Total updateDomain calls: {len(rows)}\n")
for ts, val, h in rows:
    print(f"{ts}  {val}")
