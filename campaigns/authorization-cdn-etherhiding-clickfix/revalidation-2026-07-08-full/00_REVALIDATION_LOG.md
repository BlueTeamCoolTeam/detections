# Complete fresh end-to-end re-validation - single session

Session window (UTC): **2026-07-08T21:08:31Z to 2026-07-08T21:28:07Z** (approximately 20 minutes, continuous). Analyst: blueteam.cool. Trigger: author requested a complete, fresh, single-session re-validation with full untruncated evidence capture, after an earlier same-day check showed candidate counts drift over just a few hours (815->847 for operator 1) - proving numbers need to be treated as a point-in-time snapshot, not a fixed fact, and that every step needs its own timestamped, complete evidence file rather than a narrative summary.

**This folder supersedes the numbers in `../revalidation_2026-07-08/` for publication purposes.** That earlier folder is kept as-is; it remains valid evidence of the pagination-bug discovery and the initial operator-3 find, just not the currency of its specific counts.

Every number in this log is a direct read from a saved output file - no number here is paraphrased from memory or from chat history. Every script's FULL, untruncated console output and FULL raw API/data output is saved in this folder. Nothing was truncated when writing to disk; any truncation below is only in this log's own excerpting for readability, and always says so.

## Step 1 - candidate list build, all 3 operators, single run

Script: `01_candidate_search_all_operators.py` | Output: `01_candidate_search_all_operators_OUTPUT.txt` (full per-page trace for all 25 domains) | Raw lists: `operator{1,2,3}_candidates_raw.txt`

Queried all 25 known C2 domains (18 operator 1, 3 operator 2, 4 operator 3) with corrected pagination (page while a full 100-result page returns; the `has_more` field is never consulted, per the prior round's finding that it's unreliable). Every domain shows `has_more_field=False` on every page regardless of whether more results existed, reconfirming that finding live.

**Raw results (before self-match filtering):**

| Operator | Domains | Raw unique candidates |
|---|---|---|
| 1 | 18 | 869 |
| 2 | 3 | 153 |
| 3 | 4 | 6 |

Cross-operator overlap (raw): op1^op2=21, op1^op3=0, op2^op3=0. Union (raw): 1,007.

## Step 2 - self-match filtering

Script: `02_self_match_filter.py` | Output: `02_self_match_filter_OUTPUT.txt` | Final lists: `operator{1,2,3}_candidates_final.txt`, `combined_candidates_final.txt`

Removed each operator's own C2 domains from its own raw list (a domain trivially matches its own `domain:` query, so isn't a real candidate victim). Exact domains removed are listed in the output file.

**Final candidate counts (this is the number used everywhere else in this session):**

| Operator | Raw | Self-matches removed | Final |
|---|---|---|---|
| 1 | 869 | 18 | **851** |
| 2 | 153 | 3 | **150** |
| 3 | 6 | 2 | **4** |
| **Combined unique** | | | **984** |

## Step 3 - live verification, 3 passes

Script: `03_live_verification_checker.py` (unmodified proven logic - live fetch, brute-force every `atob()` blob against all 256 single-byte XOR keys, classify by decoded content shape) | Console outputs: `03_pass{1,2,3}_console_OUTPUT.txt` | Full per-site results (all 984 sites, every bucket): `pass{1,2,3}_verification_results.txt` | Confirmed-only: `pass{1,2,3}_confirmed.txt`

| Pass | Runtime | CONFIRMED | WRAPPER_NO_MATCH | CLEAN | UNREACHABLE |
|---|---|---|---|---|---|
| 1 | 94s | 151 (op1=122, op2=26, op3=3) | 2 | 688 | 143 |
| 2 | 78s | 152 (op1=122, op2=27, op3=3) | 2 | 689 | 141 |
| 3 | 78s | 153 (op1=123, op2=27, op3=3) | 2 | 690 | 139 |

All three passes ran back-to-back within the same ~4-minute window (21:13:02Z-21:17:39Z), unlike the prior round's multi-day spread - this maximizes internal consistency of the snapshot at some cost to catching longer-cycle intermittent gating (disclosed, not hidden).

## Step 4 - three-pass union, contamination check

Script: `04_union_and_contamination_check.py` | Output: `04_union_and_contamination_check_OUTPUT.txt` | Final per-operator lists: `op{1,2,3}_confirmed_final.txt`

**C2-domain contamination check: clean on all 3 passes** (structurally near-impossible here since C2 domains were removed from the candidate pool in step 2, but checked explicitly anyway rather than assumed).

**Final confirmed counts (3-pass union, attributed by each hit's own decoded contract address):**

| Operator | Confirmed (3-pass union) |
|---|---|
| 1 | **123** |
| 2 | **27** |
| 3 | **3** |
| **Total** | **153** |

## Step 5 - on-chain history, all operators (+ 5b follow-up)

Script: `05_onchain_history_all_operators.py` | Output: `05_onchain_history_all_operators_OUTPUT.txt` | Full raw JSON per target: `{operator1_contract, operator1_wallet, operator2_contract_current, operator2_wallet, operator3_contract, operator3_wallet}_transactions_raw.json`

Confirmed operator 1's 23 historical `updateDomain` calls (5 June - 6 July 2026) and operator 3's 3 calls (29 June - 8 July 2026), matching the previously published rotation tables.

**New finding, not previously known:** operator 1's wallet (`filter=from`, full history) shows activity from **13 May 2026** onward - earlier than the 5 June 2026 date previously treated as this operator's start - including two `updateDomain` calls on 24 May 2026 to two contracts never previously documented. Follow-up in step 5b.

### Step 5b - investigation of the two May-24 contracts

Script: `05b_operator1_earlier_contracts_investigation.py` | Output: `05b_operator1_earlier_contracts_investigation_OUTPUT.txt` | Full history per contract: `may24_contract_{A,B}_full_history_raw.json`

- `0x76fA199B724Bb511BA326BB0400ED89227B39AEF` ("contract A") and `0xbdC80AdF5944aE01A7a56552A03C507DB1f40dDd` ("contract B"): both **4,864 bytes deployed bytecode** - confirmed in step 6 to be byte-identical to operators 2 and 3's shared template, NOT operator 1's own 2,980-byte live contract.
- Each contract has exactly 2 transactions total, ever: one creation, one single `updateDomain` call, then abandoned.
- The "domain" values passed are not real URLs: contract A's decodes (as base64) to 47 bytes at 0.38 printable-ASCII ratio (not readable text); contract B's ("BwQFBwQFBwQFBwQFBwQFBwQF") decodes to a literal repeating byte pattern `07 04 05` - clearly placeholder/test data, not a domain.

**Interpretation, stated as inference not fact:** this reads as operator 1's wallet testing the shared 4,864-byte kit template on 24 May 2026 with placeholder data, before switching to its own distinct 2,980-byte contract for the actual live campaign starting 5 June 2026. This is not certain from on-chain data alone, but it is a reasonable reading of the evidence, and it strengthens rather than weakens the "shared kit" finding - it means operator 1's wallet has direct, on-chain, dated proof of contact with the exact same template operators 2 and 3 use.

## Step 6 - bytecode comparison, all 9 known contracts

Script: `06_bytecode_comparison_all_contracts.py` | Output: `06_bytecode_comparison_all_contracts_OUTPUT.txt` | Full hex bytecode per contract: `bytecode_<label>.hex` (9 files)

Full, untruncated SHA-256 (not just first 16 hex, unlike the prior round) computed for all 9 contracts:

| Group | Contracts | Bytecode length | Full SHA-256 |
|---|---|---|---|
| A | Operator 1's live contract only | 2,980 bytes | `a38bc4251391ff706f48217c14fb2b8d3379cb3065b3466584cd0b5db5f5afa9` |
| B | Operator 1's 2 May-24 test contracts + operator 2's 5 contracts + operator 3's contract (**8 of 9 total**) | 4,864 bytes | `473d49db1b57434ad2f08d43361f5d73b5ea864a408afb052645f5d5c63db3d3` |

**This is a stronger finding than the prior round published** (which only knew of the operator-2/operator-3 overlap, 6 of 9 contracts, based on a truncated 16-hex hash). With the May-24 discovery, 8 of 9 known contracts across all three operators are byte-identical; only operator 1's actual live contract differs.

## Step 7 - funding trace + funder volume check

Script: `07_funding_trace_and_volume_check.py` | Output: `07_funding_trace_and_volume_check_OUTPUT.txt` | Full raw JSON: `operator{1,2,3}_wallet_{incoming_direct,internal_txs}_raw.json`

- **Operator 1's wallet**: far more active than previously documented - 934 total outgoing transactions (nonce), history back to October 2024, multiple funding sources over 20+ months (not a single-purpose wallet).
- **Operator 2's wallet**: confirmed again, via both direct-transfer and internal-transaction endpoints, **zero incoming transactions visible** via Blockscout's public API. 8 total outgoing transactions ever. This is a real, twice-confirmed data-availability gap, not an effort gap.
- **Operator 3's wallet**: funded once (29 June 2026, same day as its contract deployment), 4 total transactions ever.
- Funders identified for operators 1 and 3 are distinct addresses, both high-volume (2,229 and 294,077 outgoing transactions respectively) - consistent with shared exchange/gas infrastructure, not a traceable dedicated source. **Dead end, confirmed a second time.**

**Operational contrast worth noting:** operator 1 reuses a heavily-active, long-lived general-purpose wallet; operators 2 and 3 use fresh, minimal, single-purpose wallets (8 and 4 total transactions respectively).

## Step 8 - WRAPPER_NO_MATCH re-investigation

Script: `08_wrapper_no_match_investigation.py` | Output: `08_wrapper_no_match_investigation_OUTPUT.txt` | Full page content: `wrapper_investigation_*_full_page.html` | Full decode logs: `wrapper_investigation_*_decode_log.txt`

Same two sites as the prior round appeared in all 3 fresh passes: `offertic.net`, `www.cartolibreriabisceglia.it`. Neither decodes to any of the three known operators' contracts, wallets, or selector.

**Correction to the prior round's characterization:** `offertic.net`'s blob, decoded in full this time (not excerpted), is NOT a cryptocurrency wallet-drainer as previously described - full context shows a fake-CAPTCHA/traffic-distribution-system (TDS) redirect gate that resolves its own configuration via a *different* Polygon contract (`0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`, confirmed distinct from all three known operator contracts). This is a separate actor also using blockchain-based config resolution, not related to this campaign's operators, and not a wallet drainer. The prior characterization was based on an incomplete ~400-character excerpt; the full decode (now saved in full) tells a different, more precise story. `www.cartolibreriabisceglia.it` did not produce a clean high-confidence decode via the generic printable-ratio scan used this round; its full page and partial decode attempts are saved for anyone who wants to pursue it further, but per explicit scope direction this was not chased further, since neither site affects the operator 1/2/3 candidate or confirmed counts either way.

## Step 9 - independent spot-check

Script: `09_independent_spotcheck.py` (separately written, does not reuse `03`'s reported keys) | Console output: `09_independent_spotcheck_console_OUTPUT.txt` | Full decode log: `09_independent_spotcheck_full_log.txt`

Sample: 3 sites from operator 1 (reproducible `shuf --random-source=<(yes 42)`), 2 from operator 2 (same method), all 3 from operator 3 (small pool, used in full). **8/8 independently reconfirmed**, each with a freshly-derived XOR key from a fresh live fetch.

## Step 10 - cookie and page.content field re-checks

Output: `10_cookie_and_pagecontent_checks_OUTPUT.txt` (raw `curl` commands and full HTTP responses, captured to file for the first time - previously chat-only)

- `xdv_sess` cookie confirmed set (with a different session value each time) on 403-blocked requests to the C2's root path and to the raw IP with a forged Host header. **Correction to the prior round:** a bare `api.php` request without valid token parameters returns HTTP 200 with `Content-Type: image/gif` (a decoy image) and does **not** set the cookie - the earlier claim that the cookie is set "on every request including api.php" was imprecise; it's set on the general/blocked paths, not confirmed on a bare unauthenticated api.php hit.
- `page.content` field re-tested with a properly verified control this time (the original attempt's control page returned zero results too, invalidating it - caught and redone). Control: `killtonyticket.com`, title confirmed live via `page.title` search (8 results, matching known title text). `page.content` search for the same confirmed-present phrase "Kill Tony Tour": **zero results.** Confirms the field does not function on this API, independent of authentication tier, with a methodologically sound comparison this time.

## Final numbers for publication

| | Candidates (final, self-match filtered) | Confirmed (3-pass union) |
|---|---|---|
| Operator 1 | 851 | 123 |
| Operator 2 | 150 | 27 |
| Operator 3 | 4 | 3 |
| **Combined unique** | **984** | **153** |

**Captured (UTC): 2026-07-08T21:08:31Z - 2026-07-08T21:28:07Z.** This is a live, ongoing campaign. Re-running the exact same scripts and queries in this folder at a later date will very likely show different (most likely higher) numbers - this is not a caveat added to soften the claim, it's a directly observed fact: a same-day, few-hours-apart re-run during this investigation already showed the candidate pool grow from 815 to 847 for operator 1 alone. Treat every number above as a floor, correct as of the timestamp shown, not a permanent fact.

## Files in this folder

| File pattern | Contents |
|---|---|
| `01_*` through `10_*` (`.py` + matching `_OUTPUT.txt`) | Every script run this session, paired with its full captured output |
| `operator{1,2,3}_candidates_{raw,final}.txt`, `combined_candidates_final.txt` | Candidate lists at each filtering stage |
| `pass{1,2,3}_verification_results.txt`, `pass{1,2,3}_confirmed.txt` | Full per-site results, every one of 984 sites, all 3 passes |
| `op{1,2,3}_confirmed_final.txt` | Final 3-pass-union confirmed lists per operator |
| `*_transactions_raw.json`, `may24_contract_*_full_history_raw.json` | Full raw Blockscout API responses, on-chain history |
| `bytecode_*.hex` | Full deployed bytecode, all 9 known contracts |
| `wrapper_investigation_*` | Full page content + decode logs for the 2 non-operator anomaly sites |
| `09_independent_spotcheck_full_log.txt` | Full independent re-verification decode output |

No API key values are stored in any script or output file (all scripts take the key as a command-line argument at invocation time only; output files record the command with a `<URLSCAN_API_KEY>` placeholder).
