"""
Step 4 - three-pass union by operator, plus C2-domain-contamination check.

Unlike the prior round, this session's candidate pool already had each
operator's own C2 domains removed BEFORE verification (step 2), so
contamination should be structurally impossible here -- but this is checked
explicitly anyway rather than assumed, consistent with "test the artifact,
don't trust it."

Attributes each CONFIRMED hit to an operator by the contract address embedded
in its OWN decoded payload (not by which candidate list it came from -- a
site could theoretically appear in one operator's candidate pool but actually
be running a different operator's injection).

Usage: python 04_union_and_contamination_check.py
"""
import re, os

HERE = os.path.dirname(__file__)

OP1 = "0xb6bc9e1d0b2fb96ab7c47e04cb0be477410bc1f2"
OP2 = "0x83833c5d676ca06e941a32310ae67d0890f657ee"
OP3 = "0x0c7cb01c83203ac0a50abc3a9aff3c9ca727ef55"

ALL_C2_DOMAINS = {
    "authorization-cdn-press-enter.info", "authorization-code.beer", "authorization-id-code.info",
    "codeverificatrorcl.info", "authorization-code.info", "idverification-cdn.info",
    "verificationscodes.beer", "code.verification-claude-cdn.beer", "claudverification-id.beer",
    "idverification-code.beer", "codecerification.beer", "code-verification-js.beer",
    "verification-code-js.beer", "svs-verificationdate.beer", "verification-js-cdn.boats",
    "framework-css-styles-js.beer", "ethercdnns.beer", "xdavnode.pro",
    "letsgomakemoneyoncaptcha.beer", "hahletsgoagain.beer", "iwannagetmoremoney.beer",
    "errrkotmlkpoy.xyz", "huishuvish.cc", "pluhabovra.info", "hilacbatoriaaa.cc",
}


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


p1 = parse(os.path.join(HERE, "pass1_verification_results.txt"))
p2 = parse(os.path.join(HERE, "pass2_verification_results.txt"))
p3 = parse(os.path.join(HERE, "pass3_verification_results.txt"))

print(f"Per-pass CONFIRMED counts: pass1={len(p1)}  pass2={len(p2)}  pass3={len(p3)}")

print("\n--- C2-domain contamination check ---")
contamination_found = False
for label, pdict in [("pass1", p1), ("pass2", p2), ("pass3", p3)]:
    hits = ALL_C2_DOMAINS & set(pdict.keys())
    if hits:
        contamination_found = True
        print(f"  *** {label}: C2 domain(s) found in CONFIRMED bucket: {sorted(hits)} ***")
    else:
        print(f"  {label}: clean, no C2 domain in CONFIRMED bucket")
print(f"Contamination found: {contamination_found}")

all_hosts = set(p1) | set(p2) | set(p3)
print(f"\n3-pass UNION total (all operators combined): {len(all_hosts)}")

by_op = {"op1": set(), "op2": set(), "op3": set(), "unknown": set()}
for h in all_hosts:
    c = p1.get(h) or p2.get(h) or p3.get(h)
    if c == OP1:
        by_op["op1"].add(h)
    elif c == OP2:
        by_op["op2"].add(h)
    elif c == OP3:
        by_op["op3"].add(h)
    else:
        by_op["unknown"].add(h)

print("\n--- final per-operator confirmed counts (3-pass union) ---")
for k, v in by_op.items():
    print(f"  {k}: {len(v)}")
    if k == "unknown" and v:
        print(f"    (unattributed hosts -- contract regex did not match cleanly): {sorted(v)}")

for k in ("op1", "op2", "op3"):
    out_file = os.path.join(HERE, f"{k}_confirmed_final.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(by_op[k])))
    print(f"wrote {out_file} ({len(by_op[k])} hosts)")

total = len(by_op["op1"]) + len(by_op["op2"]) + len(by_op["op3"])
print(f"\nTOTAL CONFIRMED (op1+op2+op3, 3-pass union): {total}")
