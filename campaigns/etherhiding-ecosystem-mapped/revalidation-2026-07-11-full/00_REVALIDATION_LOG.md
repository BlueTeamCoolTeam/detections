# Complete forensic revalidation - etherhiding-ecosystem-mapped

Session window (UTC): started 2026-07-11T03:06:46Z. Analyst: blueteam.cool.
Trigger: author requested a complete, from-scratch revalidation of every
claim in the combined post, with full scripts and outputs saved for
independent replication - explicitly for digital-forensics-grade
reproducibility, matching the rigor of
`authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/`.

Every number in this log is a direct read from a saved output file in this
folder - no number here is paraphrased from memory or from chat history.
Nothing was truncated when writing to disk; any truncation below is only in
this log's own excerpting for readability, and always says so.

**Scope note:** with a urlscan.io API key supplied for this session, this
revalidation covers the full pipeline (on-chain facts -> candidate-host
discovery -> confirmed-site decoding -> cross-family dedup), not just the
last-mile decode step.

---

## Step 1 - selector-conflict re-verification (settles the two-kit-family split)

Script: `01_selector_conflict_reverify.py` | Output: `01_selector_conflict_reverify_OUTPUT.txt`

Live, fresh `eth_call` against all 5 known operator contracts, both
selectors (`38bcdc1c` and `b68d1809`), re-run independently of the earlier
check performed while drafting the post.

**Result: fully reconfirmed.** mamkor/merabs's contract reverts on
`b68d1809` and resolves `mamkor.pro` on `38bcdc1c`. All four Family A
contracts (xdav/Operator 1, Operator 2, Operator 3, BW-sibling) revert on
`38bcdc1c` and resolve their current C2 on `b68d1809`. The two-kit-family
split holds under a second, independent test - this is not a fluke of the
first check.

**Side finding (expected, not an error):** current C2 domains have rotated
again since original capture - Operator 1/xdav now resolves
`auth-code-check.info` (was `authorization-cdn-press-enter.info` on
2026-07-08), Operator 2 resolves `iwannagetmoremoney.beer`, Operator 3 now
resolves `hihankidaha.cc` (was `hilacbatoriaaa.cc`). Consistent with the
"active, still-rotating campaign" framing already established.

## Step 2 - funding-link re-verification

Script: `02_funding_link_reverify.py` | Output: `02_funding_link_reverify_OUTPUT.txt`

Fresh pull of the BW-sibling operator wallet's complete transaction history
via Blockscout's etherscan-compatible v1 API (the v2 REST endpoint returned
HTTP 500 and then timed out on retry - noted as a dead end in the script's
own output rather than silently switched).

**Result: fully reconfirmed, with one correction.** Exactly one incoming
transaction, ever, to the BW-sibling wallet: 50.0 MATIC from xdav's wallet
(`0xcaf2c54e...`), tx `0x3fb177082f44050aea0debe7ecce9df56ac092889af475358572dbc2d98ab97b`,
block 83794622, timestamp 2026-03-05T11:14:35Z.

**Correction to the previously published framing:** the prior report
described this as "one hour before its first contract deployment." The
fresh pull shows the wallet's very next transaction - its first-ever
outgoing tx, a contract creation (empty `to` field) - at 2026-03-05T11:28:35Z,
**14 minutes** after the funding transaction, not one hour. The funding
link itself is confirmed exactly as claimed; the timing description in the
original prose was imprecise and is corrected here.

## Step 3 - full independent re-enumeration of BW-sibling's contract/domain set

Scripts: `03_bwsibling_full_reenumeration.py` (raw re-derivation) +
`04_bwsibling_domain_shape_classification.py` (follow-up classification) |
Outputs: `03_bwsibling_full_reenumeration_OUTPUT.txt`,
`04_bwsibling_domain_shape_classification_OUTPUT.txt`

Fresh pull of the deployer wallet's complete 109-transaction history,
independently re-classified (creation vs `0xb249cd2d` setter call vs other)
and every domain independently re-decoded from raw calldata using a
from-scratch ABI-tail decoder (search for the fixed ABI offset word from the
end of the input, not reused from the original investigation's own decode
output).

**Dead end during this step, fixed:** the decoder's offset-word constant was
initially built with one extra leading zero (65 hex chars instead of the
correct 64-char/32-byte word), causing 100% decode failures on the first
run. Fixed and re-run.

**Results:**

| | Previously claimed | Independently re-derived |
|---|---|---|
| Contract addresses | 87 | **87 (exact match)** |
| Transactions: creation / setter call | 83 / 21 | 83 / **25** |
| Domains | 90 | 96 raw decoded values; **91 domain-shaped** |

**Genuine new finding, not previously documented:** of the 87 contract
addresses, **2 carry non-domain, placeholder/test-shaped decoded values**
rather than real C2 domains - `0x8b7bcc472be11f795ebe35ecb37ab648998d0471`
(decodes to long base64-like blobs with an embedded `:`, at both its
creation and 2 later setter calls) and
`0xffde7e80f6b21c6c6fa220b6f58682dfd736cf1f` (decodes to the literal
4-character string `test` at creation, and `RVdARQ==` at its one setter
call). This is structurally identical to a pattern already documented for a
**different** operator (xdav/Operator 1's two abandoned 13-May test
contracts, found in the original `authorization-cdn-etherhiding-clickfix`
revalidation) - but was not previously flagged for the BW-sibling operator.
Excluding these 2 contracts' 5 non-domain entries from the domain count
(91 domain-shaped values, independently re-derived from the SAME 127 raw
setter/creation transactions) is a close, expected match to the previously
published 90 - the 1-value gap is consistent with a genuine new rotation in
the intervening hours, the same pattern already seen and documented in the
authorization-cdn post.

**87 contracts stands confirmed exactly.** 90 domains is confirmed as
essentially accurate (91 domain-shaped independently found) once the 2
non-domain test contracts are correctly excluded - a refinement of the
original claim, not a contradiction of it.

## Step 4 - full independent re-enumeration of mamkor/merabs's C2 rotation history

Script: `05_mamkor_full_reenumeration.py` | Output: `05_mamkor_full_reenumeration_OUTPUT.txt`

Fresh pull of the persistent contract's complete transaction history,
independently re-classified (setter calls via method `0x77343408`) and every
domain independently re-decoded using the same from-scratch decoder built in
Step 3 (reused directly, not re-derived, since the ABI layout is identical -
a single dynamic `string` constructor/argument).

**Results:**

| | Previously claimed | Independently re-derived |
|---|---|---|
| Setter calls | 127 | **127 (exact match)** |
| Date range | 2026-03-11 -> 2026-07-10 | **2026-03-11T19:49:17Z -> 2026-07-10T15:51:13Z (exact match)** |
| Setter wallet | 1 (`0x34c15320...`) | **1 (exact match)** |
| Unique C2 domains | 102 | 111 unique raw decoded strings; **108 unique bare-domain-normalized** (protocol + trailing path stripped) |

All 127 raw calldata payloads decoded cleanly to domain-shaped values - no
non-domain/test entries found on this operator's contract (unlike
BW-sibling). The gap between the previously published 102 and this pass's
independently re-derived 108 (bare-domain-normalized) is flagged honestly:
since every one of the identical 127 setter calls across the identical,
closed date range was independently re-decoded from raw on-chain calldata
in this pass, the 108 figure is judged the more reliable of the two - most
likely explained by a stricter or inconsistent deduplication step in the
original investigation's own methodology (e.g. case-sensitivity or a
missed rotation), not by new campaign activity, since the call count and
date range match exactly. Recommend citing 108 (or 111 unnormalized) rather
than 102 going forward.

## Step 5 - lighter-touch consistency check, Operator 1/2/3

Script: `06_op1op2op3_consistency_check.py` | Output: `06_op1op2op3_consistency_check_OUTPUT.txt`

Per the plan's scoping decision, this operator group's full on-chain history
was already exhaustively rebuilt and revalidated 3 days ago
(`authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/`);
this step only confirms nothing has silently drifted, via a fresh, direct
re-pull of each contract's transaction count.

**Result: consistent, with expected new activity.** Operator 1/xdav: 25
non-creation method calls now (was 23 on 2026-07-08) - **2 new rotations**
since original publication, most recent 2026-07-11T00:58:25Z (today).
Operator 3: 4 now (was 3) - **1 new rotation**, most recent
2026-07-10T15:45:10Z. Operator 2 (which deploys a fresh contract per C2
rather than calling `updateDomain` repeatedly) shows its known single
transaction, unchanged. This is exactly the expected shape of an active,
still-rotating campaign, not a discrepancy.

## Step 6 - stage-3 cipher reproduction

Script: `07_stage3_cipher_reproduction.py` (the original `decrypt_blob.py`,
copied unmodified) | Output: `07_stage3_cipher_reproduction_OUTPUT.txt`

Re-run against the actual sample file
(`blogs/drafts/EtherHiding/mamkor-pro-iwr-downloader/artifacts/stage1_x.exe`,
present locally, never executed - only read), fully offline, no network
dependency.

**Result: byte-for-byte reproduced.**
- Input sample SHA256: `e86d8bb932221ce673a9d4ab7aa883de6290e2bc88b453fbc2880cf7a9d407b7`
  - matches the previously reported loader hash exactly.
- Output (decrypted stage-3) SHA256:
  `448c2d3556557837da6de2973428063e52e90239a021ebf08a4908a5d7ece622`
  - **matches the previously reported stage-3 hash exactly.**
- Output size: 1,098,902 bytes (matches `0x10c496`). Valid PE32+: `MZ` at
  offset 0, `e_lfanew` = `0x280`, `PE\x00\x00` signature confirmed present at
  that offset.

The decrypted stage-3 binary itself was moved to the local session
scratchpad after verification (not retained in this repo folder or
committed anywhere) - it is a live, decrypted malware sample and this
project's convention is to never commit executable payloads, only the
reproducer script and hash verification.

## Step 7 - full live re-verification of all 901 confirmed sites (4 parallel agents)

Four independent subagents ran in parallel, one per operator/operator-pair,
each doing (a) a fresh urlscan.io candidate-pool re-derivation and (b) a
full 3-independent-pass live re-fetch/re-decode of every existing confirmed
site, using each operator's own already-proven decode logic (not a new,
untested checker). Full scripts and per-pass outputs are in this folder,
prefixed `op1_`, `op2op3_`, `bwsibling_`, `mamkor_`.

### Operator 1 / xdav

Files: `op1_A_*`, `op1_B_*`, `op1_SUMMARY.md`.

- **Candidate pool (fresh urlscan pivot, 18 domains, corrected pagination):
  925** (was 851 on 2026-07-08 - expected growth for an active campaign; one
  domain hit a transient HTTP 503 with no retry logic, fixed and re-run
  cleanly before finalizing).
- **3-pass live re-confirmation of the existing 123 sites: 106 reconfirmed**
  (all three passes identical: 106 CONFIRMED / 12 CLEAN / 5 UNREACHABLE
  every time - zero pass-to-pass disagreement). 17 of the original 123 did
  not reconfirm (12 reachable-but-clean, presumably remediated; 5
  unreachable).

### Operator 2 and Operator 3

Files: `op2op3_A_*`, `op2op3_B_*`, `op2op3_SUMMARY.md`.

- **Candidate pools:** Operator 2 **167** (was 150); Operator 3 **9** (was 4).
- **3-pass re-confirmation:** Operator 2 **24 of 27** reconfirmed (2 clean,
  1 persistently unreachable across all 3 passes - `heeleuropa.com`).
  Operator 3 **2 of 3** reconfirmed (`www.motorbeam.com` now clean).

**Anomaly flagged, not resolved:** `greencoalition.pl` - originally
attributed to Operator 3 in the published post - decodes to **Operator 1's
contract** (`0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`) across all 3 fresh
passes this session, not Operator 3's. It still shows the shared kit's
fingerprint (guard variable + marker hits) and is still counted as a
confirmed Family A site either way, but which specific operator compromised
it is now uncertain - noted here for anyone who wants to reconcile it
against on-chain data directly, not silently corrected in either direction.

### BW-sibling

Files: `bwsibling_A_*`, `bwsibling_B_*`, `bwsibling_C_*`, `bwsibling_SUMMARY.md`.

- **Candidate pool (fresh urlscan pivot, all 90 known domains, corrected
  pagination): 1,265** unique hostnames - substantially larger than the
  original investigation's ~285-393 processed items across 78 domains,
  since this pass covers the full corrected 90-domain set and a since-grown
  urlscan index.
- **3-pass re-confirmation of the existing 111 sites: 56 reconfirmed**
  (56 confirmed / 45 now clean / 7 unconfirmed-suspicious - dead C2 domain
  reference only / 3 unreachable, identical across all 3 passes - zero
  disagreement). Mid-run, 4 sites were found to be misclassified as
  unreachable due to expired/self-signed TLS certificates on the target
  sites; fixed with an SSL-fallback and all 3 passes were discarded and
  re-run fresh for consistency once fixed, rather than patching only the
  affected 4 results.
- **NEW sites confirmed from the freshly rebuilt candidate pool: 167**
  (out of 1,159 candidates not already in the original 111-site list).
  11 further candidates from this same pool decoded to a **different**,
  already-known Family A operator's contract (9 to Operator 1/xdav, 2 to
  Operator 2) - correctly excluded from BW-sibling's own count and folded
  into those operators' totals instead (see Step 8).
- **Methodology note:** the adapted checker tests decoded content against
  all 87 of this operator's contract-address prefixes (not just the single
  seed contract) - the same undercounting mistake documented in the
  original BW-sibling investigation was deliberately not repeated here.

### mamkor/merabs

Files: `mamkor_A_*`, `mamkor_B_*`, `mamkor_D_*`, `mamkor_SUMMARY.md`.

- **3-pass live re-confirmation of the existing 638 sites (Part B): 629
  reconfirmed** (Pass 1: 627 confirmed/6 not-confirmed/5 unreachable. Pass
  2: 627/7/4. Pass 3: 625/8/5. Union across all 3 passes: 629. 9 sites never
  confirmed in any of the 3 independent passes - 6 consistently
  not-confirmed, 3 consistently unreachable).
- **Candidate-pool re-derivation (Part A): 4,993 unique candidate
  hostnames**, from a `domain:` pivot across all 108 known C2 domains with
  corrected pagination (paged via `search_after` while a full page
  returned, `has_more` not trusted - the same fix already applied to the
  other operators). All 108 domains completed cleanly, zero partial
  domains. One domain, `ap7.supportly.au`, contributed roughly 70% of the
  raw pool (3,515 of 4,993 unique hostnames) - reads as a shared
  third-party SaaS/widget subdomain rather than campaign-dedicated
  infrastructure, flagged as a likely source of noise in the raw pool
  rather than treated as 4,993 confirmed victims (which is exactly why Part
  D below does a live decode check rather than stopping at the pivot).
- **Additive live confirm on the newly-found candidates (Part D): 871
  confirmed**, out of 4,355 candidates from Part A not already in the
  original 638-site list (2,552 not-confirmed, 932 unreachable, single
  pass). Combined with Part B: **629 + 871 = 1,500 distinct confirmed
  compromised sites** for this operator, verified zero overlap between the
  two sets (disjoint by construction - Part D explicitly excludes anything
  already in the 638-site list or its Part B union).
- **Operational note:** Part A's first attempt, using the session's
  original urlscan.io API key, ran into the account's daily search-API
  quota partway through (confirmed via the API's own rate-limit response
  headers) after BW-sibling's larger candidate-pool rebuild had already
  spent most of it that day. The checker script was rewritten with
  per-domain checkpointing so a resume would never re-spend quota on
  already-completed domains, and the full 108-domain sweep completed
  cleanly once a second API key was supplied - the numbers above are from
  that completed run, not an estimate or a partial result.

## Step 8 - cross-family dedup, first pass (mamkor Part D not yet available)

Script: `08_final_cross_family_dedup.py` | Output:
`08_final_cross_family_dedup_OUTPUT.txt`

An intermediate run of the union/dedup methodology against Step 7's lists,
completed before mamkor's Part A/D finished (see Step 9 below, which
supersedes the totals here) - kept as-is for the audit trail rather than
deleted, since it's a real, valid checkpoint of the numbers at that point
in the session (Family A union 348, mamkor Part B only 629, 8 cross-family
duplicates, grand total 969).

**Family A internal overlap, found at this stage and unchanged by Step 9:**
14 sites appear in BOTH Operator 1/xdav's reconfirmed list AND BW-sibling's
newly-confirmed list (`branchouttreecareltd.co.uk`, `chadiaashtattoo.com`,
`crossmolinaparish.com`, `electriq.se`, `imprentaprintcenter.com`,
`junk-removalguys.com`, `kienthucquocphong.com`, `namaste-bungalows.com`,
`opais.co.mz`, `rockersmovementradio.com`,
`www.forumpolitiquenogentais.asso.fr`, `www.redes-solidarias.org.ar`,
`www.reseaucupidontogo.org`, `www.safehandspro.care`). All 14 were
independently classified as BW-sibling's own contract (`sibling=None` in
BW-sibling's checker) by one agent, and as Operator 1's contract by a
completely separate agent using separate decode logic against Operator 1's
own list. **Flagged, not resolved** - this could mean a genuine dual
compromise (both operators' scripts present on the same site, similar to
the cross-family finding below but within Family A), or a classification
gap in one of the two checkers (e.g. BW-sibling's "known sibling prefix"
list not including every Operator 1 contract variant). Recommend a manual
side-by-side decode of at least 2-3 of these 14 before citing them
individually. All other Family A pairs showed zero overlap.

## Step 9 - final cross-family dedup, mamkor Part A/D included

Script: `09_final_cross_family_dedup_with_mamkor_partD.py` | Output:
`09_final_cross_family_dedup_with_mamkor_partD_OUTPUT.txt`

Once mamkor's candidate-pool rebuild (Part A: 4,993 candidates) and
additive confirm check (Part D: 871 newly confirmed) completed with a
second API key, this re-runs the full union/dedup with mamkor's list
expanded from 629 (Part B only) to 1,500 (Part B + Part D, verified
disjoint). This is the authoritative, final synthesis for this revalidation
- Step 8 above is a real intermediate checkpoint, not an error, but this
step supersedes its totals.

**Family B union: 1,500** (629 reconfirmed of the original 638, plus 871
newly confirmed from the expanded candidate pool, zero overlap between the
two sets).

**Cross-family overlap (Family A vs Family B), re-checked against the
expanded mamkor list: 18 sites** (up from 8 at the Step 8 checkpoint, up
from 1 in the original combined post) - `aglimitless.com`, `agluona.lt`,
`belindabuck.com`, `bigbaer.co`, `careyestatesltd.co.uk`,
`clearlinewebdesign.com`, `clearskyfarms.com`, `dawgonllc.com`,
`engelspakistan.com`, `foodclub.ae`, `nickkyhub.com.ng`,
`nickkyonline.store`, `noscalpelvasectomy.com`, `pathtohomeapproval.com`,
`rankandtrack.com`, `tractor-shop.ro`, `www.beltboutique.co.uk` (the
original finding, reconfirmed a third time), `www.namathejaljawdah.com`.
All 18 are independently confirmed compromised by both a Family A operator
and mamkor/merabs. This growth is expected, not a red flag: the earlier
counts (1, then 8) were measured against progressively smaller candidate
pools for mamkor; now that mamkor's own pool has been rebuilt to the same
standard as BW-sibling's, the same underlying phenomenon - two unrelated
crews landing on the same vulnerable site - shows up at a rate consistent
with the rest of this investigation's findings.

## Step 10 - full domain cross-check, all 5 operators (found during IOC-section assembly)

Discovered while building complete, family-tagged C2 domain tables for
publication (not a dedicated script - a direct set-intersection check
across all 5 operators' full domain lists, cross-referenced against the
on-chain data already pulled in Steps 3-6).

**One shared C2 domain across the family boundary: `gppcdnns.beer`.**
Present in both BW-sibling's (Family A) 90-domain list and mamkor/merabs's
(Family B) 108-domain list - the *only* overlap found checking all 90 x 108
domain pairs, and the *only* overlap across any operator pair when
Operator 1/2/3's 27 known domains are included in the same check (their
only overlap remains the already-documented `hahletsgoagain.beer`, shared
with BW-sibling, unchanged).

Cross-referenced against each family's own on-chain timestamp for this
domain:
- BW-sibling: contract `0xd178801a58072388cae21c8867a88517c7b5d3e7` deployed
  with `gppcdnns.beer` baked into its constructor, **2026-05-28 09:46 UTC**,
  tx `0x534ac59d1218a4207ade3555f2b11b035206968537a5a50b8f226707db1d6ea6`
  (source: `deployer_contract_deployments.json` in the original BW-sibling
  investigation artifacts).
- mamkor/merabs: set via setter call, **2026-05-28 22:26:45 UTC**, tx
  `0xe10cc40502936bbbb18a1a9692e685b710bc18a1d37b236f4c57c00a9a33485f`
  (source: `05_mamkor_full_reenumeration_OUTPUT.txt`, this session's
  independent on-chain re-derivation).

~13 hours apart, same calendar day. Not proof of a shared operator (the
selector-conflict test in Step 1 already rules that out directly, and this
is a single coincidence, not a pattern - zero other overlaps found across
198 total domains checked). Read as evidence of a shared upstream supply
chain (registrar, reseller, or bulletproof hosting pool cycling
freshly-registered throwaway domains to multiple crimeware customers) one
layer behind both kit families - flagged for anyone positioned to pull
domain registration data directly, not resolved further here.

## Step 11 - combined per-family confirmed/candidate lists, and one data-hygiene fix

Script: `10_family_combined_lists.py` | Output:
`10_family_combined_lists_OUTPUT.txt`

Requested directly: every prior step computed Family A's and Family B's
totals in-memory (inside `09_final_cross_family_dedup_with_mamkor_partD.py`)
and only printed the counts - the full deduplicated host lists were never
written to their own reviewable files. This step re-derives the same unions
from the same source files (no new logic, same result) and writes four
clean files: `family_a_confirmed_FINAL.txt` (348), `family_b_confirmed_FINAL.txt`,
`family_a_candidates_FINAL.txt` (2,241 - union of op1/op2/op3's candidate
rechecks plus BW-sibling's rebuilt pool), `family_b_candidates_FINAL.txt`
(4,993 - mamkor's rebuilt pool, already a single clean file, copied here
under a consistent name for parity).

**Building `family_b_confirmed_FINAL.txt` surfaced a genuine, small data
error, not previously caught:** two entries in mamkor's Part D
newly-confirmed list (`100.31.95.216` and `ec2-100-31-95-216.compute-1.amazonaws.com`)
are the same physical host counted twice - a bare IP address and that same
IP's AWS EC2 reverse-DNS hostname, both independently confirmed compromised
by the single-pass Part D checker because it dedupes by exact string match
only, not by IP-vs-hostname identity. Confirmed via the reverse-DNS pattern
itself (`ec2-100-31-95-216.*` decodes directly to `100.31.95.216`), not a
naming coincidence. The bare-IP entry is removed in the combined file;
`mamkor_D_new_confirmed_hosts.txt` (the original per-pass output) is left
unedited as the historical record of what that checker actually produced.
Two other bare-IP entries in the same list (`192.253.248.8`,
`35.207.233.108`) have no matching hostname alias anywhere in the combined
list and are kept as-is - genuinely IP-identified confirmed hosts, not
duplicates.

**Net effect: Family B's total drops from 1,500 to 1,499, and the grand
total from 1,830 to 1,829.** Confirmed the removed entry is not one of the
18 cross-family overlap sites, so that count is unaffected. This is exactly
the kind of small, easy-to-miss error the "build the combined list and
actually look at it" exercise was for - the per-operator pass-by-pass
numbers were never wrong on their own terms, but nobody had cross-checked
IP-vs-hostname identity across the full combined set until now.

## Step 12 - direct evidence for the "BW panel" naming claim (previously unsupported)

Script: `11_cedahr_bwpanel_marker_verification.py` | Output:
`11_cedahr_bwpanel_marker_verification_OUTPUT.txt` | Artifacts:
`cedahr_fresh_fetch.html`, `cedahr_decoded_injected_script.js`

Prompted by a direct question: does this repo actually contain a saved,
decoded copy of the injected script proving the "BW panel" name (used
throughout the post and this log) is real and not just repeated from the
source report's prose? Checked, and the answer was no - the only prior
reference, `investigate_cedahr_mismatch.py` (in the mamkor investigation's
artifacts), requires a `/tmp/cedahr.html` file that only ever existed on
the original analyst's Kali host, was never included in this repo, and no
decoded output was ever saved alongside that script either.

Fixed directly rather than left as a gap: `cedahr.com` is still in this
session's freshly-revalidated confirmed list (see Step 7 / `family_a_confirmed_FINAL.txt`),
so it was re-fetched live and decoded fresh, independent of the original
investigation's session. Confirmed byte-for-byte what the claim asserts:
decoded with the same scheme as before (single-byte XOR, key 223, matching
`var _0xd247ab=223` found live in today's fetch), the resulting script
contains `HANDLER_EXPORT='__BW_MODE_RUN__'`,
`LOCAL_STORAGE_KEY='site_repair_state'`, and the full `v1.js`-`v9.js` mode
map, plus `CONTRACT_ADDRESS:'0x926d64543148dB649C4F877fE7ba4c693e01E288'`
and `FUNCTION_SELECTOR:'b68d1809'` in the same file - independently
reconfirming the contract/selector claim too, not just the naming one.
`cedahr_decoded_injected_script.js` is the full, human-readable decoded
script, saved this time, so anyone can read the actual evidence directly
rather than trust a description of it.

## Numbers for publication

| | Original combined-post claim | Step 8 checkpoint (mamkor Part B only) | Final (Step 9/11, mamkor Part A/D included, IP/hostname dedup applied) |
|---|---|---|---|
| Operator 1/xdav confirmed | 123 | 106 reconfirmed (+9 via BW-sibling's pivot -> 113 total known) | unchanged |
| Operator 2 confirmed | 27 | 24 reconfirmed (+2 via BW-sibling's pivot) | unchanged |
| Operator 3 confirmed | 3 | 2 reconfirmed (greencoalition.pl attribution now uncertain) | unchanged |
| BW-sibling confirmed | 111 | 56 reconfirmed + 167 newly discovered = 223 | unchanged |
| mamkor/merabs confirmed | 638 | 629 reconfirmed (candidate pool not yet rebuilt) | **629 + 871 newly discovered - 1 IP/hostname duplicate = 1,499** |
| Family A union | 264 | 348 | **348** |
| Family B union | 638 | 629 | **1,499** |
| Cross-family duplicates | 1 | 8 | **18** |
| **Grand total, unique** | **901** | **969** | **1,829** |

**This is not a correction of an error in the same sense as the funding-timing
fix earlier - it is what a live, active, multi-operator campaign looks like
when re-measured with a full pipeline (on-chain facts, candidate-pool
rebuild, live re-fetch, and a final data-hygiene pass) rather than a partial
one.** The jump from 969 to 1,829 is almost entirely mamkor's Part D: 871
newly-confirmed sites (870 after the one IP/hostname duplicate found in Step
11) that simply could not be found until the candidate-pool rebuild for that
operator completed, which itself required a second API key after the first
one's daily quota ran out mid-session. This is not several different claims
- it's the same claim (how many sites has this ecosystem compromised)
measured with previously-missing evidence now in hand and a final
consistency pass applied, the same way BW-sibling's rebuilt pool surfaced
167 sites the original narrower pool had missed. **1,829 confirmed unique
compromised websites, as of 2026-07-11, is the number this revalidation
supports** - a floor, not a ceiling, exactly as every prior post in this
series has already established for its own numbers.

**One follow-up flagged for whoever picks this up next, not resolved here:**
the 14-site Operator-1/BW-sibling overlap (Step 8) needs a manual decode to
determine if it's a genuine dual-compromise or a classification gap.

## Files in this folder

| File pattern | Contents |
|---|---|
| `01_*` - `07_*` (`.py` + matching `_OUTPUT.txt`) | On-chain and cipher revalidation, Steps 1-6 above |
| `op1_*`, `op2op3_*`, `bwsibling_*` | Per-operator candidate-pool and 3-pass live re-confirmation work, Step 7 |
| `11_cedahr_bwpanel_marker_verification.*`, `cedahr_fresh_fetch.html`, `cedahr_decoded_injected_script.js` | Direct, saved evidence for the "BW panel" naming claim - full decoded injected script, fetched and decoded fresh, Step 12 |
| `mamkor_A_*`, `mamkor_B_*` | mamkor candidate-pool rebuild and 3-pass reconfirmation, Step 7 |
| `mamkor_D_*`, `mamkor_SUMMARY.md` | mamkor additive confirm check on newly-discovered candidates, Step 7 |
| `08_*` | Intermediate cross-family dedup checkpoint (mamkor Part B only), Step 8 |
| `09_*` | Cross-family dedup with mamkor Part A/D included (before the Step 11 IP/hostname fix), Step 9 |
| `10_*` | **Final, authoritative combined lists** - `family_a_confirmed_FINAL.txt` (348), `family_b_confirmed_FINAL.txt` (1,499), `family_a_candidates_FINAL.txt` (2,241), `family_b_candidates_FINAL.txt` (4,993) - Step 11 |

No API key values are stored in any script or output file in this folder
(scripts read the key from a local scratchpad file path at invocation time
only).
