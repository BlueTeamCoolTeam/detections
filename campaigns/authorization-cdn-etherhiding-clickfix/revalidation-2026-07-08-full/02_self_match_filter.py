"""
Step 2 - self-match filtering.

Each operator's own C2 domains trivially match their own `domain:<X>` urlscan
query (the scan of the C2 site itself gets indexed too). This step removes
those from each operator's raw candidate list, prints exactly what was
removed, and writes the final candidate list each operator will actually be
verified against.

Usage: python 02_self_match_filter.py
"""
import os

HERE = os.path.dirname(__file__)

C2_DOMAINS = {
    "operator1": [
        "authorization-cdn-press-enter.info", "authorization-code.beer", "authorization-id-code.info",
        "codeverificatrorcl.info", "authorization-code.info", "idverification-cdn.info",
        "verificationscodes.beer", "code.verification-claude-cdn.beer", "claudverification-id.beer",
        "idverification-code.beer", "codecerification.beer", "code-verification-js.beer",
        "verification-code-js.beer", "svs-verificationdate.beer", "verification-js-cdn.boats",
        "framework-css-styles-js.beer", "ethercdnns.beer", "xdavnode.pro",
    ],
    "operator2": [
        "letsgomakemoneyoncaptcha.beer", "hahletsgoagain.beer", "iwannagetmoremoney.beer",
    ],
    "operator3": [
        "errrkotmlkpoy.xyz", "huishuvish.cc", "pluhabovra.info", "hilacbatoriaaa.cc",
    ],
}

combined = set()
for op, c2s in C2_DOMAINS.items():
    raw_file = os.path.join(HERE, f"{op}_candidates_raw.txt")
    with open(raw_file, encoding="utf-8", errors="replace") as f:
        raw = set(x.strip() for x in f if x.strip())
    removed = raw & set(c2s)
    final = raw - set(c2s)
    print(f"{op}: raw={len(raw)}  C2 domains matched against own list={sorted(removed)}  final={len(final)}")
    combined |= final
    out_file = os.path.join(HERE, f"{op}_candidates_final.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(final)))
    print(f"  wrote {out_file}")

combined_file = os.path.join(HERE, "combined_candidates_final.txt")
with open(combined_file, "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(combined)))
print(f"\nCombined unique candidate pool across all 3 operators (final, self-matches removed): {len(combined)}")
print(f"wrote {combined_file}")
