#!/usr/bin/env python3
"""Convert a bwsibling_B_confirm_checker.py JSON results file into the plain
text report format required by the task (one line per host: verdict,
scheme, sibling label, status, error if any)."""
import json
import sys


def main():
    in_json = sys.argv[1]
    out_txt = sys.argv[2]
    with open(in_json, "r", encoding="utf-8") as f:
        results = json.load(f)

    counts = {}
    lines = []
    for r in results:
        v = r.get("verdict")
        counts[v] = counts.get(v, 0) + 1
        line = (f"{r.get('host')}\tverdict={v}\tscheme={r.get('scheme')}\t"
                f"sibling={r.get('sibling')}\tstatus={r.get('status')}\t"
                f"reachable={r.get('reachable')}\tdetail={r.get('detail')}")
        if r.get("error"):
            line += f"\terror={r.get('error')}"
        lines.append(line)

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(f"Total hosts: {len(results)}\n")
        f.write(f"Verdict counts: {counts}\n")
        f.write("=" * 70 + "\n")
        for line in lines:
            f.write(line + "\n")

    print(f"Wrote {out_txt}")
    print("Summary:", counts)


if __name__ == "__main__":
    main()
