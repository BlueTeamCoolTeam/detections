import re, os

OP1 = "0xb6bc9e1d0b2fb96ab7c47e04cb0be477410bc1f2"
OP2_CUR = "0x83833c5d676ca06e941a32310ae67d0890f657ee"
OP2_HIST = {x.lower() for x in [
    "0x6C4bECa447067D6452029888AFd56417293F6A1f",
    "0x623a17677Ed3B95A512c4DD32AB4A6Ba43444FFb",
    "0xF9344f7F9d7954a78D57ae940827126C30C4d678",
    "0xE762F84B8c509f7DEbDd72Ea4E9BA099DF9b9097",
]}
OP3 = "0x0c7cb01c83203ac0a50abc3a9aff3c9ca727ef55"

# Run from this folder; the revalidate_pass*_verification_results.txt files are published alongside this script.
base = os.path.dirname(__file__)

def parse(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    section = content.split("### CONFIRMED")[1].split("### WRAPPER_NO_MATCH")[0]
    out = {}
    for line in section.splitlines():
        if "\t" not in line:
            continue
        host, note = line.split("\t", 1)
        m = re.search(r"contract=(\S+)", note)
        c = m.group(1).lower() if m else None
        out[host] = c
    return out

p1 = parse(os.path.join(base, "revalidate_pass1_verification_results.txt"))
p2 = parse(os.path.join(base, "revalidate_pass2_verification_results.txt"))
p3 = parse(os.path.join(base, "revalidate_pass3_verification_results.txt"))

all_hosts = set(p1) | set(p2) | set(p3)
print(f"Per-pass counts: {len(p1)} / {len(p2)} / {len(p3)}")
print(f"3-pass UNION total: {len(all_hosts)}")

by_op = {"op1": set(), "op2_cur": set(), "op2_hist": set(), "op3": set(), "unknown": set()}
for h in all_hosts:
    c = p1.get(h) or p2.get(h) or p3.get(h)
    if c == OP1:
        by_op["op1"].add(h)
    elif c == OP2_CUR:
        by_op["op2_cur"].add(h)
    elif c in OP2_HIST:
        by_op["op2_hist"].add(h)
    elif c == OP3:
        by_op["op3"].add(h)
    else:
        by_op["unknown"].add(h)

for k, v in by_op.items():
    print(f"  {k}: {len(v)}")
    if k == "unknown" and v:
        print("   ", v)
    if k == "op2_hist" and v:
        print("   ", v)

# fold in operator-3's own-domain sweep results
op3_extra = {"apimetrology.com": "CLEAN", "www.motorbeam.com": "CONFIRMED", "greencoalition.pl": "CONFIRMED"}
op3_confirmed_all = by_op["op3"] | {"www.motorbeam.com"}
print(f"\nOperator 3 total confirmed (main pool + own-domain sweep): {len(op3_confirmed_all)} -> {sorted(op3_confirmed_all)}")

op1_final = len(by_op["op1"])
op2_final = len(by_op["op2_cur"]) + len(by_op["op2_hist"])
op3_final = len(op3_confirmed_all)
print(f"\nFINAL: op1={op1_final}  op2={op2_final}  op3={op3_final}  TOTAL={op1_final+op2_final+op3_final}")

with open(os.path.join(base, "revalidate_op1_confirmed_final.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(by_op["op1"])))
with open(os.path.join(base, "revalidate_op2_confirmed_final.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(by_op["op2_cur"] | by_op["op2_hist"])))
with open(os.path.join(base, "revalidate_op3_confirmed_final.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(op3_confirmed_all)))
print("\nWrote final per-operator confirmed lists.")
