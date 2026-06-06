# finger-lolbin-ironpython

Blog post: https://blueteam.cool/posts/finger-lolbin-ironpython/

## Summary

A likely ClickFix campaign using `finger.exe` -- yes, the 1970s protocol,
still present on Windows 11 -- as a malware dropper. The chain runs:

```
cmd.exe (ClickFix paste)
  -> finger.exe (TCP/79) -> livnesticity.com
    -> batch script (served in the finger "Plan" section)
      -> renamed curl.exe downloads IronPython.3.4.2.zip (saved as .pdf)
        -> IronPython runs inline downloader (zlib + UTF-32, not UTF-16LE)
          -> Cyrillic-obfuscated shellcode injector (ctypes, XOR-decrypts 8912 bytes)
            -> in-process x86 beacon -> noidoret.com/<uuid>/callback1AB
```

Seven stages, zero PowerShell, zero AMSI surface. The shellcode never spawns
a new process -- it runs inside the IronPython interpreter's address space.

Full analysis: https://blueteam.cool/posts/finger-lolbin-ironpython/

## What is included

| File | Description |
|---|---|
| `iocs.csv` | 12 indicators: hashes (x4), domains (x2), campaign UUID, build marker, XOR key, file paths, lure string |
| `rule.yar` | YARA: multi-stage campaign artifacts (UUID, build marker, domains, lure text, ctypes patterns, IronPython path) |
| `rule-shellcode-peb.yar` | YARA: x86 shellcode (PEB walk pattern, HTTPS stack-string, campaign XOR key) |
| `sigma-finger-exe.yml` | Sigma: finger.exe execution (process_creation, Windows) |
| `sigma-ironpython-drop.yml` | Sigma: IronPython drop under user AppData (file_event, Windows) |
| `kql.md` | KQL queries for Microsoft Sentinel and Defender XDR (6 queries) |

## Coverage notes

**What these detections cover:**

- Execution of `finger.exe` on any Windows host (near-zero false positives)
- Creation of the IronPython drop directory in user AppData
- Campaign UUID and build marker across any stage that lands on disk
- The x86 shellcode payload if scanned directly (post-XOR)
- Network indicators for both the finger server and C2 domain

**What these detections do NOT cover:**

- The originating ClickFix lure page (not captured in available telemetry)
- The renamed `curl.exe` copy by filename alone (the campaign uses a 4-word
  random name; the `kql.md` file provides a behavioral approach instead)
- Stage-5 IronPython downloader if it never touches disk (it runs in-memory
  via `exec()`)
- The final HTTPS beacon payload (the shellcode contacts C2 in-process; only
  network-layer detection applies at that point)

## False-positive notes

- `sigma-finger-exe.yml`: False positives are essentially unknown in modern
  enterprise environments. `finger.exe` execution should be treated as
  malicious until proven otherwise. The only expected FP sources are security
  researchers or red teams deliberately testing LOLBIN coverage.

- `sigma-ironpython-drop.yml`: Developers who install IronPython manually
  into their user profile will trigger this rule. Legitimate IronPython
  installations typically go to `Program Files`, not `AppData\Local`. If
  your environment has IronPython developers, create an exception scoped to
  their machines.

- `rule.yar`: The `$uuid` and `$marker` strings are campaign-specific and
  have no known false positives. The `$lure` string (`---Verify ---press ENTER---`)
  has no known false positives outside ClickFix campaigns.

## Confidence

**High** across all artifacts.

The full chain was decoded through all seven stages. The shellcode was
disassembled to PEB walk + stack-string C2 construction. All indicators
(UUID, build marker, XOR key, domains) were directly observed in cleartext
or binary analysis.

The only uncertainty is around the originating lure page: the initial access
vector is consistent with ClickFix social engineering based on the command-line
shape (Explorer-parented `cmd.exe`, visible lure text), but the lure URL was
not captured in available telemetry.

## Related detections

- [rule.yar](rule.yar) -- multi-stage campaign artifacts
- [rule-shellcode-peb.yar](rule-shellcode-peb.yar) -- x86 shellcode
- [sigma-finger-exe.yml](sigma-finger-exe.yml) -- process creation
- [sigma-ironpython-drop.yml](sigma-ironpython-drop.yml) -- file event
- [kql.md](kql.md) -- Microsoft Sentinel / Defender XDR queries
- [iocs.csv](iocs.csv) -- all indicators
