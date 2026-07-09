# Re-validation Log - 2026-07-08

Analyst: blueteam.cool (@btcoolteam) | Date: 2026-07-08 | Trigger: author requested full re-validation of the urlscan-derived candidate/confirmed counts before publication, given the scale of the claim.

This log documents a second pass over the original investigation's numbers, run with live urlscan.io and Shodan API access (author-provided keys, never written to any file - see Step 0). Every script referenced here is saved in this folder alongside this log. Every raw output file is saved in `../../artifacts/` with a `revalidate_` prefix. Nothing in this log is paraphrased from memory - every number below is either the literal output of a saved script or a byte-for-byte quote of an API response.

## Step 0 - API access

Two API keys were provided by the author directly in-session (Shodan, urlscan.io) after environment-variable propagation into the tool-call shell proved impractical (`setx` does not update an already-running parent process). Verified both keys functional via `GET https://api.shodan.io/api-info` and `GET https://urlscan.io/user/quotas/` before use. **Neither key value is written to this log, any script, or any published artifact** - scripts take the key as a command-line argument at invocation time only. Both keys were flagged to the author for rotation after this session, since the Shodan key transited the chat transcript via a `setx` echo.

## Step 1 - Shodan re-check (`http.set_cookie:"xdv_sess"`)

Ran the query with a working key: `{"matches": [], "total": 0}` - zero results, no tier error. Checked whether Shodan has any record of the C2 IP at all: `GET /shodan/host/178.16.52.101` returned a clean 404. Conclusion: Shodan has never crawled this host; the cookie pivot is real (independently re-confirmed live against the host itself, see Step 2) but not currently discoverable via Shodan. Not a flaw in the pivot, a coverage gap on Shodan's side.

## Step 2 - `xdv_sess` cookie re-confirmation

Direct `curl` to `https://authorization-cdn-press-enter.info/`, `/api.php`, and the bare IP `178.16.52.101` with a forged `Host` header, four separate requests: all four returned `Set-Cookie: xdv_sess=<random>` with a different value each time (session-scoped, as expected) but the same cookie name every time. Confirms the cookie is backend-wide, not `api.php`-specific as originally assumed.

## Step 3 - `page.content` field investigation

Anonymous query for the operator-1 contract address returned the documented 403 ("Regular Expressions and leading wildcard searches are not supported for anonymous users"). Authenticated retry: `{"results": [], "total": 0, "took": 440, "has_more": false}` - no error, but zero. Control test: ran `page.title:"<known title>"` against a page already confirmed in urlscan's index (via an earlier `domain:` search) - returned the page immediately. Ran `page.content:` for a plain word from that *same* title, on that *same* page - zero. Conclusion: `page.content` is not a functioning full-text field on this API, independent of authentication tier. `01_candidate_list_corrected_pagination.py` and the post's own code blocks show the exact queries.

## Step 4 - the pagination bug

Re-ran `domain:verificationscodes.beer` (one of the 18 historical operator-1 domains) as a routine part of re-validating the candidate list: `{"total": 636, "has_more": false}`, 100 results returned. Tested whether `search_after` still worked despite `has_more: false`: fed the last result's `sort` value back in manually - got a genuine second page of 100 new hostnames never seen before. **The `has_more` field is unreliable on this account tier.** Rewrote the candidate-list builder (`01_candidate_list_corrected_pagination.py`) to paginate on "did I get a full page back" instead, with a 15-page safety cap per domain (1,500 results). Re-ran all 18 operator-1 domains and all 3 operator-2 domains with the fix.

Raw output saved to console log; unique hostnames per operator saved to `../../artifacts/revalidate_op1_hosts_v2.txt` (833 hosts, self-matching C2 domains still included at this stage) and `revalidate_op2_hosts_v2.txt` (144 hosts, same caveat).

**Self-match check.** Confirmed all 18 operator-1 C2 domains and all 3 operator-2 C2 domains appear in their own respective corrected lists (a domain trivially matches its own `domain:` query). Filtered these out (`grep -vxFf`) to get the final candidate counts used in the post: **815** (operator 1) and **141** (operator 2), saved to `revalidate_op1_final_candidates.txt` / `revalidate_op2_final_candidates.txt`.

**Regression check.** Diffed the corrected operator-1 list against the original `compromised_sites_all.txt` (477 entries): zero entries present in the original that are absent from the corrected list. This rules out "urlscan indexed more over the intervening two days" as an alternative explanation - the boring explanation (silent pagination failure on the original pass) is the correct one.

## Step 5 - live re-verification (three passes)

Combined the corrected operator-1 (815) and operator-2 (141) candidate lists, including the still-present self-matching C2 domains at this point (959 total, unfiltered) into `../../artifacts/revalidate_combined_candidates.txt`, and ran `03_live_verification_checker.py` - the same polymorphic-aware, per-site-XOR-brute-force methodology already documented in the post, unmodified logic - three times:

| Pass | Confirmed | Wrapper-no-match | Clean | Unreachable |
|---|---|---|---|---|
| 1 | 119 | 2 | 662 | 176 |
| 2 | 121 | 2 | 690 | 146 |
| 3 | 120 | 2 | 690 | 147 |

Raw per-site results: `revalidate_pass{1,2,3}_verification_results.txt`. Confirmed-only lists: `revalidate_pass{1,2,3}_confirmed.txt`.

**Deviation from original methodology, disclosed:** the original three-pass verification ran over several days to catch referrer/geo/UA/cookie-based gating. These three passes ran in one working session (~20 minutes apart), because of the scope of what was already being re-validated. This is a real, acknowledged reduction in temporal sampling diversity versus the original approach - stated explicitly in the post rather than presented as equivalent.

**C2-domain contamination check.** Grepped all three `_confirmed.txt` files for the 21 C2 domains that were still present in the input pool at this stage: zero matches in all three passes. No C2 domain was ever classified as a confirmed victim.

## Step 6 - three-pass union, by operator

`04_consolidate_pass1_by_operator.py` and `05_three_pass_union_final_counts.py` parse the three `_verification_results.txt` files, take the union of hostnames across all three, and attribute each to an operator by the contract address embedded in its own decoded payload (not by which candidate list it came from). Result:

- Operator 1 (contract `0xB6bC9e1D...`): **103** confirmed
- Operator 2 (contract `0x83833C5D...` plus its 4 historical contracts): **19** confirmed, all against the current contract - zero hits against any historical operator-2 contract
- Operator 3 (see Step 7): **1** confirmed inside this same 959-site pool

Per-operator confirmed lists: `revalidate_op{1,2,3}_confirmed_final.txt`.

## Step 7 - the operator-3 discovery

While consolidating pass-1 results (Step 6), the contract-address breakdown showed a third value never seen before: `0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55`, attributed to one site, `greencoalition.pl`. Before accepting this:

1. Fetched `greencoalition.pl` fresh, independently, outside the checker script.
2. Extracted the matching `atob()` blob by hand and decoded it with the reported key (114) using a standalone one-off script (`11_operator3_manual_decode_verification.py`), not the checker's own code path.
3. Confirmed the decoded content has the identical guard-variable shape, the identical 8+ Polygon RPC endpoint list structure, and the identical `b68d1809` selector as operators 1 and 2 - genuinely the same kit, a third deployment.

On-chain follow-up (`07_parse_operator3_onchain_history.py`, `08_operator3_constructor_domain.py`, both against Blockscout's public API, no key required):

- Deployer wallet: `0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096` - **exactly four transactions, ever** (one contract creation, three `updateDomain` calls). This wallet's entire on-chain footprint was read in full.
- Contract created 2026-06-29T14:45:08Z, constructor domain `errrkotmlkpoy.xyz` (decoded from the raw creation bytecode, not from a `decoded_input` field, since Blockscout does not decode constructor arguments the same way it decodes function calls).
- Rotation: `errrkotmlkpoy.xyz` -> `huishuvish.cc` (2026-07-06 03:58) -> `pluhabovra.info` (2026-07-06 22:10) -> `hilacbatoriaaa.cc` (2026-07-08 08:33, current at time of writing).

**Operator-3's own candidate search** (`02_operator3_own_domain_search.py`, same corrected-pagination methodology as Step 4, applied to operator 3's own four domains): found only 2 additional candidate sites beyond the 4 domains matching themselves - `apimetrology.com` and `www.motorbeam.com`. Live-checked both (`12_operator3_candidate_livecheck.py`): `apimetrology.com` clean, `www.motorbeam.com` confirmed (same contract, xor=114).

**Open question, stated honestly:** `greencoalition.pl` did not appear in operator 3's own-domain search results, meaning it was found purely by chance - it happened to already be sitting in the operator 1/2 candidate pool for a reason not established here (possibly a multi-compromise site, possibly a urlscan indexing artifact). Operator 3's *true* candidate population was not swept the way operators 1 and 2 were; 2 confirmed sites is very likely a significant undercount of this operator's actual footprint.

## Step 8 - independent spot-check

To avoid trusting a single script's classification logic across all 124 confirmed results, drew a random sample (5 sites: 3 operator-1, 2 operator-2, selected via `shuf --random-source=<(yes 42)` for reproducibility) and re-verified each with `13_independent_spotcheck_random_sample.py` - a separately-written script, fresh HTTP fetch, no reuse of the original checker's reported key. Result: **5/5 independently reconfirmed**, identical XOR key recovered in every case as the original run reported. Raw output saved in `13_independent_spotcheck_OUTPUT.txt`.

**Side finding from the spot-check:** several sites' decoded loaders list Polygon RPC endpoints beyond the 8 originally documented from `injected_lure.js` (`polygon.therpc.io`, `polygon.rpc.hypersync.xyz`, `polygon.lava.build`, `polygon.rpc.subquery.network/public`, `polygon-mainnet.gateway.tatum.io` observed across the 5-site sample alone). The kit's RPC failover list is longer and/or more variable across compromised sites than the single 8-endpoint list captured from one site's decoded loader. This does not affect any candidate/confirmed count - it's a correction owed to the "How it works" section's RPC-list description, noted here for follow-up.

## Final numbers (superseding the original investigation's 477/86/555/60/18/78)

| | Candidates | Confirmed |
|---|---|---|
| Operator 1 | 815 | 103 |
| Operator 2 | 141 | 19 |
| Operator 3 | 2 (partial sweep only) | 2 |
| Combined (deduplicated) | 941 | 124 |

Operator 1/2 candidate overlap: 17 (was reported as 8 under the original undercounted lists).

## Phase 2 - fresh end-to-end re-validation (same day, second pass)

Everything above re-tested the existing pipeline's *output* (pagination, live verification, a random-sample spot-check). This phase asks a different question, at the author's explicit request: not "is the pipeline's math right," but "does the pipeline's *shape* have a blind spot that would hide additional campaigns." The existing methodology only finds an operator by searching for domains I already know - operator 3 was found by luck, not by design. This phase tries approaches that don't depend on already knowing a domain.

### Step 9 - contract bytecode comparison

Fetched the deployed runtime bytecode of all 7 known contracts (operator 1's current contract, operator 2's current plus 4 historical contracts, operator 3's contract) via `eth_getCode` against 4 independent public RPC endpoints with failover (`14_bytecode_comparison_all_contracts.py`), and SHA-256 hashed each:

| Contract | Bytecode length | SHA-256 (first 16 hex) |
|---|---|---|
| Operator 1 (`0xB6bC9e1D...`) | 2,980 bytes | `a38bc4251391ff70` |
| Operator 2 current (`0x83833C5D...`) | 4,864 bytes | `473d49db1b57434a` |
| Operator 2 historical x4 (Apr 13 - Jun 04) | 4,864 bytes each | `473d49db1b57434a` (all four) |
| Operator 3 (`0x0C7Cb01C...`) | 4,864 bytes | `473d49db1b57434a` |

**Finding: operator 2's five contracts and operator 3's contract are byte-for-byte identical deployments of the same compiled bytecode.** Operator 1's contract is a different, shorter compiled artifact (2,980 vs 4,864 bytes) that shares the same four function selectors in the same dispatch order (`b249cd2d`/`updateDomain`, `b68d1809`/read, `e096a091`, `f851a440`) but is not the same bytecode - the opcode-level pattern differs in a way consistent with a different Solidity compiler version (operator 1's contract uses the pre-0.8.20 `PUSH1 0x00 DUP1 REVERT` pattern; operators 2 and 3 use the `PUSH0`-based pattern that requires Solidity >=0.8.20 targeting Shanghai).

This is a stronger and more precise claim than "same kit" based on JS/selector similarity alone: **operators 2 and 3 are provably using the exact same deployment artifact**, spanning six deployments over more than two and a half months (13 April - 29 June 2026). Operator 1 is running a compatible but distinct implementation - consistent with either an earlier version of the same toolkit before a compiler upgrade, or a separately-built clone of the same interface. The post's framing of "three operators, one shared kit" is revised to reflect this: operators 2 and 3 are more tightly linked to each other on the evidence than either is to operator 1.

### Step 10 - funding-source tracing (systematic operator discovery attempt)

Rationale: if two deployer wallets were funded from the same source, that source could reveal other wallets funded the same way - a way to find operators that don't already appear in a domain-based candidate pool. Traced the earliest funding transaction for all three deployer wallets (`15_wallet_funding_trace.py`):

- **Operator 1** (`0xCaf2...`): funded 2024-10-17 by `0xD44a53c0d5Ab8E6C07cB20d482B3d2CB76029dd3`, 25.2 MATIC.
- **Operator 2** (`0xf1940D...`): no incoming top-level or internal transaction found via Blockscout's public API (`transactions?filter=to` and `internal-transactions` both empty; the aggregate `counters` endpoint also incorrectly reports `transactions_count: 0` despite the wallet having made 5 confirmed contract-creation transactions). This is a disclosed data-availability gap in Blockscout's public internal-transaction indexing for this wallet, not a claim that the wallet was never funded.
- **Operator 3** (`0x2F9091...`): funded 2026-06-29 (same day as its contract deployment) by `0x71d4249079684479F2651745fA2fcD79c9b45f53`, 684.85 MATIC.

The two identified funders are different addresses (`0xD44a53c0...` != `0x71d42490...`). Checked whether either funder is itself a small, traceable wallet worth pivoting on (`16_funder_volume_check.py`, via `eth_getTransactionCount`): operator 1's funder has sent **2,229** outgoing transactions; operator 3's funder has sent **293,888**. Both are high-volume addresses consistent with exchange withdrawal wallets or shared liquidity/gas-station infrastructure, not dedicated per-operator funding sources. **This lead does not pan out**: enumerating "other wallets funded by this address" would surface thousands of unrelated legitimate transactions, not a clean list of other campaign operators. Reported as a negative result rather than omitted.

### Step 11 - bytecode-similarity search (attempted, blocked by tooling)

Attempted to search Polygon directly for other deployments of the exact bytecode shared by operators 2 and 3, which would be the most direct way to find undiscovered operators. Blockscout's public API general search (`/api/v2/search`) does not index raw contract bytecode (confirmed: querying the bytecode hash returns zero results), and its smart-contract search only covers contracts with verified/published source code, which none of these are. **This is a genuine platform limitation**, not a shortcut - a full bytecode-similarity search across all of Polygon would require a specialized indexer (e.g. Dune Analytics with historical contract-creation data, or a paid multi-chain analysis tool) that was out of scope for what's accessible here. Disclosed rather than silently dropped.

### Step 12 - investigating the WRAPPER_NO_MATCH bucket for a possible undiscovered operator

Two sites (`offertic.net`, `www.cartolibreriabisceglia.it`) appeared consistently across all three verification passes with the injected-loader *shape* (`atob()` + `new Function`) but did not decode to a known-kit match at any of 256 XOR keys. Before dismissing these as noise, manually investigated both (`17_wrapper_no_match_investigation.py`), since a fourth operator using a sufficiently different obfuscation approach could plausibly land here rather than in CONFIRMED:

- **`offertic.net`**: brute-forcing the printable-text ratio across all 256 XOR keys (rather than the kit-specific keyword check) found a clean decode at key=50: a script referencing a different-format wallet/contract address (`0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`), `debugger`-based timing anti-analysis checks, and `typeof Proxy` detection - characteristic of a browser-based cryptocurrency wallet-drainer script, not the EtherHiding kit. No Polygon RPC references, no `api.php`, no shared selector.
- **`www.cartolibreriabisceglia.it`**: decoded content plainly referenced `webanalytics-cdn.sbs`, `.cyou`, `.cfd`, `.icu` - a multi-TLD fake-analytics/redirect infrastructure pattern, unrelated to Polygon/EtherHiding.

**Conclusion: both are different, unrelated malware families coexisting on the same compromised CMS sites, confirmed by content, not a fourth EtherHiding operator.** This is common - a vulnerable WordPress/CMS install is frequently compromised by multiple unrelated threat actors over time. Both sites are correctly excluded from the EtherHiding candidate and confirmed counts; no revision to the 815/141/2 or 103/19/2 figures results from this step. This is reported as a real, checked lead that was ruled out, not silently ignored.

### Phase 2 summary

No fourth EtherHiding operator was found. Two systematic search techniques were attempted beyond the original domain-based methodology (funding-source clustering, bytecode-similarity search); one hit a genuine dead end (high-volume shared funding infrastructure), the other hit a genuine tooling/platform limitation (no bytecode search available). One concrete anomaly (the WRAPPER_NO_MATCH bucket) was manually investigated and ruled out with positive evidence of a different cause, not assumed away. The one substantive new finding from this phase is technical, not a new operator: **operators 2 and 3 share byte-identical contract bytecode; operator 1 does not**, which sharpens (and revises) the "shared kit" claim into something more precise and independently checkable.

## Files in this folder

| File | Purpose |
|---|---|
| `01_candidate_list_corrected_pagination.py` | Corrected-pagination candidate-list builder for operators 1 and 2 |
| `02_operator3_own_domain_search.py` | Same methodology applied to operator 3's own 4 domains |
| `03_live_verification_checker.py` | Live brute-force polymorphic-XOR verification checker (3 passes) |
| `04_consolidate_pass1_by_operator.py` | Attributes pass-1 confirmed hits to an operator by embedded contract address |
| `05_three_pass_union_final_counts.py` | Computes the 3-pass union per operator |
| `06_parse_operator1_onchain_history.py` | Parses operator 1's full `updateDomain` history from Blockscout |
| `07_parse_operator3_onchain_history.py` | Parses operator 3's full transaction history from Blockscout |
| `08_operator3_constructor_domain.py` | Extracts operator 3's constructor-set initial domain from raw creation bytecode |
| `09_abi_hex_decoder.py` | Generic ABI string decoder used throughout |
| `10_pe_export_table_parser.py` | Standalone PE export-table parser (used to verify the `curl_easy_cleanup` export gap) |
| `11_operator3_manual_decode_verification.py` | One-off manual decode of the operator-3 discovery hit |
| `12_operator3_candidate_livecheck.py` | Live-checks operator 3's 2 own-domain-search candidates |
| `13_independent_spotcheck_random_sample.py` + `_OUTPUT.txt` | Independent re-verification of a random sample of confirmed hits |
| `14_bytecode_comparison_all_contracts.py` | Compares deployed bytecode of all 7 known contracts by hash |
| `15_wallet_funding_trace.py` | Traces each deployer wallet's earliest funding transaction |
| `16_funder_volume_check.py` | Checks funder wallets' outgoing transaction volume (rules out funding-source clustering) |
| `17_wrapper_no_match_investigation.py` | Manually investigates the 2 WRAPPER_NO_MATCH anomaly sites |

Also re-ran the corrected pagination logic live, fresh, against 9 of the highest-volume domains as a Phase 2 sanity check (not saved as a separate script - same logic as `01_candidate_list_corrected_pagination.py`): raw results retrieved matched the API's own reported `total` exactly for all 9 domains, and no domain hit the 15-page safety cap. No truncation found on re-test.

All raw per-site output referenced above lives in `../../artifacts/revalidate_*` - not duplicated here to avoid drift between two copies of the same data.
