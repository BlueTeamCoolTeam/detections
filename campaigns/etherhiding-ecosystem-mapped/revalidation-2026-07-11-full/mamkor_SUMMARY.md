# mamkor/merabs EtherHiding operator - full revalidation summary

Operator: "mamkor/merabs" - Polygon eth_call selector `0x38bcdc1c`, contract
`0x08207B087F61d7e95E441E15fd6d40BEfd6eD308` (confirmed via live on-chain
testing to be a separate contract interface from the "BW panel" kit family).

Revalidation date (UTC): 2026-07-11 (Part A completed 2026-07-11T05:28Z with
a second/fresh urlscan.io API key after the first key exhausted its daily
quota partway through; Part B completed 2026-07-11T03:37Z; Part D completed
2026-07-11T05:42Z).

## Part A - candidate pool re-derivation (urlscan.io domain: pivot)

Source: 111 raw lines in `family_b_mamkor_all_c2_domains.txt`, normalized to
**108 unique bare-hostname search terms** (dedup removed URL-path variants
like `sitepromclop.click/land/` and scheme-prefixed duplicates).

Method: `domain:<c2domain>` search against the urlscan.io Search API for
each of the 108 terms, with correct pagination (paged via `search_after`
while a full 100-result page returned, ignoring the unreliable `has_more`
field, per the known pagination bug that undercounted a sibling campaign).

**Result: FINAL CANDIDATE POOL = 4,993 unique third-party hostnames**
(page.domain values seen across all 108 domain searches, excluding the C2
domains themselves).

Supporting numbers:
- Total raw urlscan results across all 108 searches: 29,453
- Total distinct page.domain values seen (incl. C2 domains as self-hits): 5,098
- C2 domains that showed up as page.domain of their own scans (excluded): 105
- All 108 domains completed cleanly - **zero partial/failed domains** (verified:
  `mamkor_A_checkpoint.jsonl` has exactly 108 entries, none flagged `partial`)

Notable outlier: `ap7.supportly.au` alone contributed 6,377 raw results / 3,515
unique page.domain values (64 pages) - by far the largest single contributor
to the pool (~70% of the raw total). This looks like a shared/generic
third-party SaaS or widget subdomain rather than campaign-dedicated
infrastructure, so a large share of the 4,993-host candidate pool is likely
noise from that one domain rather than genuinely compromised sites. This is
exactly why Part D (below) does a real live decode/confirm check rather than
treating the raw candidate pool as a confirmed-compromise count.

Operational note: the first urlscan API key hit its **daily quota** (1000
searches/day, confirmed via response headers - `X-Rate-Limit-Window: day`,
`X-Rate-Limit-Limit: 1000`, reset at 2026-07-12T00:00:00Z) partway through
pagination (~domain 73/108). The script was rewritten mid-session to add
per-domain JSONL checkpointing and partial-result preservation so a re-run
never re-spends quota on already-completed domains. The user supplied a
second API key, and the full 108-domain sweep completed cleanly on the first
attempt with the fresh key (no rate-limiting encountered).

## Part B - 3-pass live re-confirmation of the existing 638-site list

Source: `reproduction-log/family_b_mamkor_confirmed.txt` (638 hostnames).
Method: fetch each site fresh (https then http fallback, insecure-TLS retry),
check for cleartext contract/selector/RPC-host/config markers, and if absent,
extract inline `<script>` blobs and try all 4 known decode schemes (cleartext,
atob+sub-then-XOR sweep, plain single-byte XOR sweep, 256-byte S-box), with a
20MB read cap (the naive ~600KB default was found in a prior investigation to
truncate the injected script out of many WordPress pages).

| Pass | CONFIRMED | NOT_CONFIRMED | UNREACHABLE | Total |
|---|---|---|---|---|
| 1 | 627 | 6 | 5 | 638 |
| 2 | 627 | 7 | 4 | 638 |
| 3 | 625 | 8 | 5 | 638 |

**3-pass union (CONFIRMED in at least one of the 3 independent passes): 629/638**

9 sites never confirmed in any of the 3 passes:
- 6 consistently NOT_CONFIRMED: divaonline.com.pk, infodehrifcam.com,
  livelaughlovedo.com, munich-trip.com, renaproofficial.com,
  ultrapowerelectrical.com.au
- 3 consistently UNREACHABLE: euronautica.com.br, lands-end-coastguard.com,
  transportsaintfelicien.com

Comparison to previously published 638: 629/638 (98.6%) re-confirmed live via
3 independent passes. This is consistent with the previously-noted caveat
that injection can be gated by referrer/geo/UA/cookie on some backends, so a
small residual of genuine compromises may not re-confirm on every fetch -
this is the expected, not-forced-to-match, true number.

## Part D - additive confirm check on NEW Part A candidates (single pass)

Scope: hosts present in the Part A candidate pool (4,993) that are **not**
already in the existing 638-site list and **not** already in the Part B
3-pass union (629 is a strict subset of 638, so the exclusion set is simply
the 638-site list) = **4,355 new candidate hosts**.

Method: identical fetch/decode logic to Part B, single pass (not a 3-pass
cycle, per the coordinator's instruction - this is an additive discovery
check on top of an already-3x-verified list, not a re-verification of
already-confirmed sites).

| Status | Count |
|---|---|
| CONFIRMED | 871 |
| NOT_CONFIRMED | 2,552 |
| UNREACHABLE | 932 |
| **Total checked** | **4,355** |

**871 of the 4,355 new candidates independently reconfirm as compromised by
this operator's contract/selector on a single live fetch** (cleartext markers
or successful decode of an injected script matching the `08207`/`38bcdc1c`
fingerprint). This number is a single-pass floor, not a 3-pass-verified
figure like Part B's 629 - given the same referrer/geo/UA/cookie-gating
caveat noted above, a single pass will under-count true compromises relative
to a 3-pass union, so 871 should be read as "at least 871," not "exactly."

Combined with Part B's 629, that gives an updated total live-reconfirmed
compromised-site count of **629 + 871 = 1,500** distinct sites across the two
checks (638-list 3-pass union + new-candidate single pass), against a raw
candidate pool of 4,993. The remaining ~3,484 candidates are either false
positives from the urlscan pivot (notably contamination from the
`ap7.supportly.au` outlier), sites that have since been cleaned/taken down,
or sites where the injection is gated in a way this single-pass fetch did not
trigger.

## Files written (all in this directory)

Part A:
- `mamkor_A_candidate_pool_pivot.py` - pivot script (checkpointed, resilient to quota exhaustion)
- `mamkor_A_candidate_pool_pivot_OUTPUT.txt` - full console log of the successful run
- `mamkor_A_checkpoint.jsonl` - per-domain raw/unique counts + full page.domain lists (108 entries)
- `mamkor_A_candidate_hosts.txt` - the 4,993 deduped candidate hostnames, one per line
- `mamkor_A_candidate_hosts.json` - same data plus per-domain breakdown and metadata

Part B:
- `mamkor_B_confirm_checker.py` - 3-pass checker script
- `mamkor_B_pass1_results.txt`, `mamkor_B_pass2_results.txt`, `mamkor_B_pass3_results.txt` - full 638-row results per pass
- `mamkor_B_pass1_console_OUTPUT.txt`, `mamkor_B_pass2_console_OUTPUT.txt`, `mamkor_B_pass3_console_OUTPUT.txt` - console logs
- `mamkor_B_final_confirmed_union.txt` - 629 hostnames confirmed in at least one pass

Part D:
- `mamkor_D_new_candidates.txt` - 4,355 new candidates (Part A pool minus existing 638)
- `mamkor_D_new_candidates_confirm.py` - single-pass additive checker script
- `mamkor_D_new_candidates_confirm_console_OUTPUT.txt` - console log
- `mamkor_D_new_candidates_confirm_results.txt` - full 4,355-row results
- `mamkor_D_new_confirmed_hosts.txt` - 871 newly confirmed hostnames

This summary: `mamkor_SUMMARY.md`
