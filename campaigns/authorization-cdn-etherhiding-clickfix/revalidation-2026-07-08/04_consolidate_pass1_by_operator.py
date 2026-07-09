import re, os

# Run from this folder; revalidate_pass1_verification_results.txt is published alongside this script.
path = os.path.join(os.path.dirname(__file__), "revalidate_pass1_verification_results.txt")
with open(path, encoding="utf-8", errors="replace") as f:
    content = f.read()

OP1 = "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2".lower()
OP2_CURRENT = "0x83833C5D676cA06E941A32310AE67D0890F657eE".lower()
OP2_HIST = {x.lower() for x in [
    "0x6C4bECa447067D6452029888AFd56417293F6A1f",
    "0x623a17677Ed3B95A512c4DD32AB4A6Ba43444FFb",
    "0xF9344f7F9d7954a78D57ae940827126C30C4d678",
    "0xE762F84B8c509f7DEbDd72Ea4E9BA099DF9b9097",
]}
OP3 = "0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55".lower()

section = content.split("### CONFIRMED")[1].split("### WRAPPER_NO_MATCH")[0]
lines = [l for l in section.splitlines() if l.strip() and "\t" in l]

buckets = {"op1": [], "op2_current": [], "op2_hist": [], "op3": [], "no_contract": [], "other": []}
for line in lines:
    host, note = line.split("\t", 1)
    m = re.search(r"contract=(\S+)", note)
    c = m.group(1).lower() if m else None
    if c == OP1:
        buckets["op1"].append(host)
    elif c == OP2_CURRENT:
        buckets["op2_current"].append(host)
    elif c in OP2_HIST:
        buckets["op2_hist"].append((host, c))
    elif c == OP3:
        buckets["op3"].append(host)
    elif c is None or c == "?":
        buckets["no_contract"].append((host, note))
    else:
        buckets["other"].append((host, c))

print(f"Total CONFIRMED lines: {len(lines)}")
for k, v in buckets.items():
    print(f"  {k}: {len(v)}")

print("\n-- no_contract entries (cleartext/no regex match) --")
for h, n in buckets["no_contract"]:
    print(" ", h, n)

print("\n-- other/unexpected contracts --")
for h, c in buckets["other"]:
    print(" ", h, c)

print("\n-- op2 historical-contract hits (old injected script, contract not currently active) --")
for h, c in buckets["op2_hist"]:
    print(" ", h, c)
