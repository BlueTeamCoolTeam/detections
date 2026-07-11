#!/usr/bin/env python3
"""Compute the 3-pass union of CONFIRMED hosts across
bwsibling_B_pass{1,2,3}_results.json, and report per-pass agreement/
disagreement so the union isn't a silent average of noisy passes."""
import json

PASS_FILES = [
    "bwsibling_B_pass1_results.json",
    "bwsibling_B_pass2_results.json",
    "bwsibling_B_pass3_results.json",
]
OUT_FILE = "bwsibling_B_final_confirmed_union.txt"


def main():
    passes = []
    for pf in PASS_FILES:
        with open(pf, "r", encoding="utf-8") as f:
            passes.append(json.load(f))

    n_hosts = len(passes[0])
    for p in passes:
        assert len(p) == n_hosts, "pass result files have differing host counts"

    confirmed_sets = []
    verdict_by_pass = []
    for p in passes:
        s = set(r["host"] for r in p if r.get("verdict") == "confirmed")
        confirmed_sets.append(s)
        verdict_by_pass.append({r["host"]: r.get("verdict") for r in p})

    union = sorted(set.union(*confirmed_sets))
    intersection = sorted(set.intersection(*confirmed_sets))

    all_hosts = [r["host"] for r in passes[0]]
    disagreements = []
    for h in all_hosts:
        verdicts = [vp[h] for vp in verdict_by_pass]
        if len(set(verdicts)) > 1:
            disagreements.append((h, verdicts))

    print(f"Total hosts checked (existing 111-list): {n_hosts}")
    print(f"Pass 1 confirmed: {len(confirmed_sets[0])}")
    print(f"Pass 2 confirmed: {len(confirmed_sets[1])}")
    print(f"Pass 3 confirmed: {len(confirmed_sets[2])}")
    print(f"Intersection (confirmed in ALL 3 passes): {len(intersection)}")
    print(f"Union (confirmed in AT LEAST 1 pass): {len(union)}")
    print(f"Hosts with any verdict disagreement across passes: {len(disagreements)}")
    for h, v in disagreements:
        print(f"  {h}: {v}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"3-pass re-confirmation of the existing 111-site BW-sibling confirmed list\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total hosts checked: {n_hosts}\n")
        f.write(f"Pass 1 confirmed: {len(confirmed_sets[0])}\n")
        f.write(f"Pass 2 confirmed: {len(confirmed_sets[1])}\n")
        f.write(f"Pass 3 confirmed: {len(confirmed_sets[2])}\n")
        f.write(f"Intersection (confirmed in ALL 3 passes): {len(intersection)}\n")
        f.write(f"UNION (confirmed in AT LEAST 1 of 3 passes): {len(union)}\n")
        f.write(f"Hosts with any verdict disagreement across the 3 passes: {len(disagreements)}\n")
        for h, v in disagreements:
            f.write(f"  {h}: {v}\n")
        f.write("=" * 70 + "\n\n")
        f.write("Full union list (hosts CONFIRMED as this operator in at least 1 of 3 passes):\n")
        for h in union:
            f.write(h + "\n")

    print(f"\nWrote {OUT_FILE}")


if __name__ == "__main__":
    main()
