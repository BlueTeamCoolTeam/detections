# etherhiding-ecosystem-mapped

Blog post: https://blueteam.cool/posts/etherhiding-ecosystem-mapped/

## Summary

> **Fully revalidated 2026-07-11.** Every number below has been through a
> complete, independent revalidation pass: every on-chain fact re-checked
> against a second live RPC call, all originally-confirmed sites re-fetched
> and re-decoded fresh (three independent passes each), and every operator's
> candidate-host pool rebuilt from scratch. See
> `revalidation-2026-07-11-full/00_REVALIDATION_LOG.md` for the complete,
> timestamped, fully scripted evidence trail - this supersedes the earlier
> `reproduction-log/` folder's numbers for publication purposes (that folder
> is kept as-is; it remains valid evidence of the original 901-figure
> methodology, just not the current numbers). Treat every count as a floor
> on an active set of campaigns, not a fixed fact.

This campaign folder combines every EtherHiding-resolved-C2 website-compromise
operator tracked so far into one picture. It does **not** introduce a new malware
sample of its own - it's the synthesis, cross-check, and companion evidence for a post
that maps two previously-separate investigations onto one another and onto a prior
published post.

**Two distinct kit families, confirmed genuinely separate on-chain** (not one shared
kit, despite one source report's own overclaim to the contrary - see
`reproduction-log/00_REPRODUCTION_LOG.md` Step 1, re-confirmed a second time in
`revalidation-2026-07-11-full/01_selector_conflict_reverify_OUTPUT.txt`, for how
that was settled by direct `eth_call` against both selectors):

- **Family A - "BW panel" kit, selector `0xb68d1809`.** Four confirmed operator
  instances, one financial hub:
  - Operator 1 / "xdav" (`0xB6bC9e1D...`) - 106 of 123 original sites reconfirmed live
  - Operator 2 (`0x83833C5D...`) - 24 of 27 reconfirmed
  - Operator 3 (`0x0C7Cb01C...`) - 2 of 3 reconfirmed
  - BW-sibling, new (`0x926d6454...`, 87 contracts, 90 domains, 2 of the 87
    carrying placeholder/test values not real domains) - 56 of the original
    111 reconfirmed live, **plus 167 further sites confirmed from a
    freshly-rebuilt, 4x-larger candidate pool** - wallet funded directly
    on-chain by xdav's wallet (50 MATIC, 14 minutes before first deployment -
    corrected from an original "one hour" estimate)
  - Family A union (fresh, deduplicated, 14-site Operator-1/BW-sibling overlap
    flagged but not double-counted): **348**
- **Family B - "merabs/mamkor" Go-RunPE kit, selector `0x38bcdc1c`.** One operator
  instance (`0x08207B08...`) - **629 of 638 original sites reconfirmed live,
  plus 870 further sites confirmed from a freshly-rebuilt candidate pool**
  (108 domains, 4,993 candidates; 871 raw single-pass confirmations minus 1
  IP/hostname duplicate caught while building the combined list - see Step
  11) - **1,499 confirmed sites total**.
- **Cross-family overlap, re-checked fresh with both families' rebuilt
  candidate pools: 18 sites** (up from 1 originally found, then 8 once
  BW-sibling's pool was rebuilt, then 18 once mamkor's was too), each
  independently confirmed compromised by both a Family A operator and
  mamkor/merabs.
- **One shared C2 domain across the family boundary: `gppcdnns.beer`.**
  The only overlap found across all 198 domains in both families' full
  lists (BW-sibling's 90 + mamkor/merabs's 108). BW-sibling deployed a
  contract with this domain 2026-05-28 09:46 UTC; mamkor/merabs set it via
  a setter call the same day, 2026-05-28 22:26:45 UTC - ~13 hours apart.
  Not evidence of a shared operator (already ruled out directly by the
  selector test), but consistent with both operators drawing from the same
  upstream domain-supply pipeline. See
  `revalidation-2026-07-11-full/00_REVALIDATION_LOG.md` Step 10.
- **Grand total, unique, fully revalidated: 1,829 confirmed compromised
  websites** across the 5 tracked operator instances. Combined,
  deduplicated per-family lists (both confirmed sites and candidate pools)
  are in `revalidation-2026-07-11-full/family_a_confirmed_FINAL.txt`,
  `family_b_confirmed_FINAL.txt`, `family_a_candidates_FINAL.txt`, and
  `family_b_candidates_FINAL.txt` - not just the per-operator breakdowns.

```
                                FAMILY A -- "BW panel" kit (selector 0xb68d1809)
                                =================================================

   xdav wallet (0xCaf2C54E...)
        |
        |-- owns/updates --> Operator-1 contract (0xB6bC9e1D..., 25 updates) --> 106/123 reconfirmed
        |
        `-- funds (on-chain, 50 MATIC, 14 min before deploy) --> BW-sibling wallet (0xb0425bf2...)
                                                              |
                                                              `-- 87 contracts / 90 domains (2 placeholder)
                                                                  --> 56/111 reconfirmed + 167 newly found

   Operator-2 wallet (0xf1940DDB...) -- 5 contracts --------------------------------> 24/27 reconfirmed
        (domain-name overlap only with BW-sibling -- hahletsgoagain.beer -- NOT a confirmed funding link)

   Operator-3 wallet (0x2F9091AB...) -- 1 contract ---------------------------------> 2/3 reconfirmed

                                                    Family A total: 348 unique confirmed (fresh)


                                FAMILY B -- "merabs/mamkor" Go-RunPE kit (selector 0x38bcdc1c)
                                ==============================================================

   mamkor/merabs wallet (0x34c15320...) -- 1 persistent contract, 127 setter calls
        |-- 629/638 original sites reconfirmed live
        `-- 870 further sites confirmed from a freshly rebuilt candidate pool
                                              (108 domains, 4,993 candidates;
                                               871 raw minus 1 IP/hostname dup)
                                              --> 1,499 confirmed sites total


                    ------------------------------------------------------------------------
                    18 sites both families independently compromised (1 -> 8 -> 18 as each
                    operator's candidate pool was progressively rebuilt):
                    www.beltboutique.co.uk, agluona.lt, belindabuck.com, bigbaer.co,
                    clearskyfarms.com, pathtohomeapproval.com, tractor-shop.ro,
                    www.namathejaljawdah.com, aglimitless.com, careyestatesltd.co.uk,
                    clearlinewebdesign.com, dawgonllc.com, engelspakistan.com,
                    foodclub.ae, nickkyhub.com.ng, nickkyonline.store,
                    noscalpelvasectomy.com, rankandtrack.com
                    ------------------------------------------------------------------------

                                        GRAND TOTAL, UNIQUE, FRESH: 1,829
```

## What is included

| File | Description |
|------|--------------|
| `iocs.csv` | Aggregated indicators across all 5 operator instances: contracts, wallets, selectors, current C2 domains, cross-references to the full domain/site lists |
| `rule.yar` | Two YARA rules for Family B only (Family A's injected-loader-shape YARA already lives in `authorization-cdn-etherhiding-clickfix/rule.yar` - not duplicated here) |
| `family_a_bwsibling_all_contracts.txt` | All 87 contract addresses the BW-sibling operator has deployed or updated |
| `family_a_bwsibling_all_c2_domains.txt` | All 90 C2 domains the BW-sibling operator has used |
| `family_b_mamkor_all_c2_domains.txt` | Full historical C2 rotation list for mamkor/merabs (102 domains per the source report; independent revalidation found 108 once normalized - see below) |
| `reproduction-log/` | Original synthesis evidence (901-figure methodology) - superseded for current numbers, kept as historical record |
| `revalidation-2026-07-11-full/` | **Current, authoritative evidence** - full independent revalidation of every claim: on-chain re-checks, all 5 operators' confirmed-site lists re-fetched fresh (3 passes each), candidate-pool rebuilds, stage-3 cipher reproduction, final dedup, and combined per-family lists. Start with `00_REVALIDATION_LOG.md`. For a quick review of the totals without reading every per-operator file, go straight to `revalidation-2026-07-11-full/family_a_confirmed_FINAL.txt` (348), `family_b_confirmed_FINAL.txt` (1,499), `family_a_candidates_FINAL.txt` (2,241), and `family_b_candidates_FINAL.txt` (4,993) |

## Coverage notes

### What these detections cover

- The on-chain distinction between the two kit families (confirmed by direct `eth_call`, not inferred from JS similarity alone)
- The funding link between xdav and the BW-sibling operator (on-chain, confirmed)
- Full contract/domain enumeration for the BW-sibling operator (87 contracts, 90 domains) and mamkor/merabs (1 contract, 102 domains per the source report, 108 once independently re-normalized)
- Cross-referenced, deduplicated confirmed-compromised-site counts across all 5 operator instances

### What they do NOT cover

- **mamkor/merabs's stage-3 payload capability.** Decrypted and independently re-reproduced byte-for-byte during revalidation (see `revalidation-2026-07-11-full/07_stage3_cipher_reproduction_OUTPUT.txt`), but its own internal strings are separately obfuscated; capability (infostealer/RAT/other) was not established. Marked Unknown, not upgraded to a guess.
- **A possible funding link between xdav and Operator 2.** Only a domain-name overlap (`hahletsgoagain.beer`) was observed; a direct on-chain funding check returned no matching transaction in the window queried. Flagged as an open pivot, not asserted.
- **The 14-site Operator-1/BW-sibling overlap.** Confirmed as compromised by two separate, independently-run decode passes, but not yet manually reconciled - could be a genuine double compromise or a classification gap in one of the two checkers. See `revalidation-2026-07-11-full/00_REVALIDATION_LOG.md` Step 8.
- **The `greencoalition.pl` attribution.** Originally credited to Operator 3; the revalidation's fresh decode puts it under Operator 1's contract instead, across all 3 passes. Not resolved either way in this pack.
- **mamkor/merabs's Part D new-candidate check is single-pass, not 3-pass.** The 870 newly-confirmed sites (871 raw single-pass confirmations, minus 1 IP/hostname duplicate - see Step 11) came from one live fetch each, not three independent passes like the rest of this pack - per the same referrer/geo/UA/cookie-gating caveat noted throughout, this is a floor on this component, not an exact figure. See `revalidation-2026-07-11-full/00_REVALIDATION_LOG.md` Step 7.
- **Any operator beyond these 5.** BW-sibling's own investigation notes at least one further Family A instance (xdav's prior documented 477-candidate history) and other partially-mapped leads not re-verified for this pack - the true ecosystem size is very likely larger than 1,829.

### Fix made during this pack's assembly

The Go-RunPE YARA rule as originally drafted in `mamkor-pro-iwr-downloader/REPORT.md`
had a non-functional condition clause (an empty `not any of ()` and a tautological `for
any i in (...)` block - would not compile as written). `rule.yar` in this folder
carries a corrected, functional version of the same rule (same strings, a real `not
any of ($wpm, $vaex)` remote-hollowing-negative check) rather than the broken original.

## False-positive notes

**`Go_RunPE_Loader_mamkor_family`**: `SetThreadContext`/`GetThreadContext`/`ResumeThread`/`VirtualAlloc`
are common in legitimate process-injection tooling (debuggers, some EDR agents,
game anti-cheat). The `not any of ($wpm, $vaex)` clause narrows this to the specific
local-RunPE-without-remote-hollowing shape this family uses, but is not a guarantee of
malice on its own - corroborate with the on-chain contract/wallet IOCs where possible.

**`EtherHiding_ClickFix_Polygon_Loader_JS_FamilyB`**: Low false-positive risk - the
combination of an `eth_call` to named public Polygon RPC hosts, a `tds_cfg` config
fetch, and a `clipboard-write` iframe grant in one small file is distinctive.

## Confidence

**Kit-family split: high.** Confirmed by direct, live `eth_call` against all 5
contracts with both selectors, **independently re-tested a second time during
revalidation** with an identical result (see
`revalidation-2026-07-11-full/01_selector_conflict_reverify_OUTPUT.txt`) - not
inferred from JavaScript similarity or prose in the source reports.

**xdav-to-BW-sibling funding link: high.** A single, on-chain, timestamped 50 MATIC
transfer, 14 minutes before the BW-sibling operator's first contract deployment
(corrected from an original "one hour" estimate during revalidation - see
`revalidation-2026-07-11-full/02_funding_link_reverify_OUTPUT.txt`).

**Cross-family overlap (18 sites): high.** Present, independently, in both a Family A
operator's and mamkor/merabs's own confirmed-site lists, verified by direct set
intersection against freshly re-fetched data, re-checked again once mamkor's own
candidate pool was rebuilt (see
`revalidation-2026-07-11-full/09_final_cross_family_dedup_with_mamkor_partD_OUTPUT.txt`).

**Grand total (1,829): floor, not ceiling, fully revalidated 2026-07-11.**
See `revalidation-2026-07-11-full/00_REVALIDATION_LOG.md` "Numbers for publication"
for the complete breakdown, including which sites were remediated since original
discovery, which were newly found via a rebuilt candidate pool, and the one
IP/hostname duplicate (Step 11) caught while assembling the combined
per-family lists.

**Attribution to a specific actor, group, or individual: not claimed.** "Operator"
throughout means a wallet with a consistent, distinct on-chain pattern - not an
identified person or group.

## Related detections

- [iocs.csv](iocs.csv) - aggregated indicators, all 5 operators
- [rule.yar](rule.yar) - Family B YARA (Family A's already lives in the linked campaign below)
- [revalidation-2026-07-11-full/](revalidation-2026-07-11-full/) - **current, authoritative evidence** behind every number in this pack and the blog post; start with `00_REVALIDATION_LOG.md`
- [reproduction-log/](reproduction-log/) - original synthesis evidence (the 901 figure) - superseded, kept as historical record
- Related campaign: [authorization-cdn-etherhiding-clickfix](../authorization-cdn-etherhiding-clickfix/) - Family A Operators 1, 2, and 3's full original IOC pack and revalidation evidence
- Related post (different EtherHiding mechanism, not part of the site-compromise total here): [netcon-wmi-etherhiding](../netcon-wmi-etherhiding/)
