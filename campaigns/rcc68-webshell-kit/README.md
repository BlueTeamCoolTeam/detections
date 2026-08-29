# rcc68-webshell-kit

Blog post: https://blueteam.cool/posts/rcc68-webshell-kit/

## Summary

An IIS/ASP.NET site was compromised through a successful admin-panel login on
the very first attempt -- no brute force is visible anywhere in the ~31 hours
of IIS logs available, so the credential's source is unconfirmed. Once
authenticated, the actor used an unrestricted file upload feature in the
admin panel's image-management endpoint (CWE-434) to drop ASP.NET web shells
directly into the web root.

Six distinct shells were recovered, all disguised as innocuous static assets
(a lightbox overlay, a theme bundler, a Google Analytics proxy, a tracking
pixel, a resource preloader, and a sitemap ping endpoint) and all gated by the
same hardcoded auth token, `rcc68` -- strong evidence of a single toolkit
rather than independent actors. Five of the six execute commands via
`cmd.exe` through an identical `ProcessStartInfo` code skeleton; the sixth
(`sitemap-ping.aspx`) is a file manager offering direct filesystem
read/write/delete with no `cmd.exe` involvement at all.

After confirming the first shell was live, the actor ran a methodical
discovery sequence: host identity, network configuration, AV/EDR/RMM
discovery via two independent methods (process/service enumeration and
registry uninstall-key checks), local accounts and shares, IIS site
inventory, and a ping/reverse-DNS sweep of an internal /24. The intrusion
closed with a five-shell burst-upload in six seconds, immediately followed by
a verification sweep testing all six shells with `whoami`.

```
1. Initial access    -- valid admin-panel credentials, first login attempt succeeds
2. Execution         -- unrestricted file upload (admin image-management endpoint)
                        accepts a .aspx payload into the web root
3. Persistence       -- six disguised web shells, planted across five admin
                        sessions; last five in a six-second burst
4. Command/control    -- none -- every shell is GET/POST-parameter or
                        header-driven, output returns in the HTTP response
5. Objective         -- hands-on-keyboard recon: host identity, AV/EDR
                        discovery, accounts/shares, IIS inventory, internal
                        /24 ping+DNS sweep
```

## What is included

| File | Description |
|---|---|
| `iocs.csv` | All indicators: actor IP, shell filenames, shared auth token, header name, and the reused code skeleton |
| `rule.yar` | YARA rule matching the shared `rcc68` token and shell code skeleton across all six files |
| `sigma-iis-worker-spawns-shell.yml` | Sigma rule for `w3wp.exe` spawning `cmd.exe` or `powershell.exe` |
| `sigma-iis-query-rcc68-token.yml` | Sigma rule for IIS requests carrying the `rcc68` token, in the query string or the `X-RCC-Key` header |
| `kql.md` | KQL queries for Sentinel/Defender XDR: process creation, IIS query-string matching, new script files, security-software discovery |

## Coverage notes

**What these detections cover:**
- All six web shell files, via the shared `rcc68` token and the reused `ProcessStartInfo`/file-manager code skeleton
- IIS worker process spawning a command interpreter (the primary host-based indicator, and the only one of the group with no known legitimate cause)
- Web requests carrying the shared auth token, whether delivered as a query parameter or the `X-RCC-Key` header
- Security software (AV/EDR/RMM) discovery via PowerShell process/service/registry enumeration

**What they do NOT cover:**
- The specific file-upload bypass mechanism -- IIS W3C logs do not capture POST body content, so how the `.aspx` extension slipped past the upload form's validation (double extension, content-type spoofing, no filtering at all) could not be determined from the available evidence
- The source of the compromised admin credential -- no brute force, phishing artifact, or credential-stuffing evidence is present in the log window provided
- Command output / response bodies -- IIS W3C logs record response size, not content, so the actual results of the AV/EDR discovery commands are inferred (from response size) rather than confirmed
- Any activity after the last logged event -- the provided logs end at the final shell-verification request; if the intrusion continued, it is not captured here

## False-positive notes

- **`Webshell_ASPX_RCC68_ShellKit` (YARA):** The `rcc68` string match is a high-confidence, low-FP anchor -- this exact value has no legitimate use. The `ProcessStartInfo`/`ComSpec` combination alone is common in legitimate small ASP.NET utilities, which is why the rule requires it alongside the token, the header, or the file-manager API calls.
- **`sigma-iis-worker-spawns-shell`:** `w3wp.exe` spawning `cmd.exe` or `powershell.exe` has no normal cause on a stock IIS site, but some third-party IIS management extensions or diagnostic tooling can trigger it. Review `ParentCommandLine`/`CommandLine` before escalating.
- **`sigma-iis-query-rcc68-token`:** No known legitimate use for `rcc68` as a query value or header. Low FP risk. Requires custom request headers to be included in your IIS log field configuration to catch the header-based variant (`bundle-theme.aspx`) -- see the blog post's "log coverage gap" takeaway.
- **Actor IP `126[.]66[.]36[.]68`:** SoftBank BBTEC residential broadband (Japan). Treat as likely proxy/compromised-host infrastructure rather than a confirmed point of origin; block/monitor but pivot primarily on the shell-kit fingerprint (token + code skeleton) for detection elsewhere.

## Confidence

**Overall: High for file-based and token-based detections; medium for behavioural inference.**

All six shell files were recovered as plaintext ASP.NET source and read
directly -- there is no obfuscation defeating analysis, so the YARA and Sigma
rules match on confirmed code and confirmed log fields rather than inferred
behaviour. Confidence is not "high" across the board because:
- The file-upload bypass technique itself is unconfirmed (log limitation, not an analysis gap)
- AV/EDR discovery command *results* are inferred from response size only
- The credential-compromise vector is entirely unconfirmed -- no evidence of brute force, phishing, or credential theft was found, and none should be assumed

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-iis-worker-spawns-shell.yml](sigma-iis-worker-spawns-shell.yml)
- [sigma-iis-query-rcc68-token.yml](sigma-iis-query-rcc68-token.yml)
- [kql.md](kql.md)
