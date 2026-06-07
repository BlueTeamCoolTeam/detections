# superlork-ton-rat

Detection artefacts for a Node.js RAT campaign using the TON blockchain
as a dead-drop C2 resolver with AES-encrypted payload delivery.

Blog post: https://blueteam.cool/posts/superlork-ton-rat/

---

## Campaign summary

The attacker used a PowerShell loader (`kcngo.ps1`) to download and
decrypt a Node.js RAT payload (`Ii2LW7rMXWB.js`) using AES-256-CBC.
The loader also downloaded the Node.js runtime itself from the internet
(`node-v24.13.0-win-x64`) -- a Bring Your Own Interpreter (BYOI) technique
-- dropping it to `%LOCALAPPDATA%\Nodejs\`. This is a non-standard path;
Node.js is not a Windows inbox binary.

Before executing the RAT, the loader added node.exe to Microsoft Defender's
process exclusion list via `Add-MpPreference -ExclusionProcess`. The RAT
persisted via a Run registry key (`HKCU\...\Run`) containing a `node -e`
spawn command.

For C2 resolution, the RAT queried the TON blockchain (via `tonapi.io`)
reading a smart contract at address
`0:c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9`
to retrieve the current active hostname. The RAT then connected to the
resolved host (`superlork[.]info`) over WebSocket (`wss://`), establishing
an encrypted command channel using per-session ECDH + AES-256-CBC.

---

## Attack chain

```
Lure / initial access -> kcngo.ps1 to %TEMP%
  -> Add-MpPreference -ExclusionProcess node.exe (Defender exclusion)
  -> Download node-v24.13.0-win-x64 to %LOCALAPPDATA%\Nodejs\ (BYOI)
  -> AES-256-CBC decrypt -> Ii2LW7rMXWB.js to %LOCALAPPDATA%\Nodejs\
  -> Run key set: node -e "spawn(Ii2LW7rMXWB.js)"
  -> RAT reads TON smart contract via tonapi.io -> resolves active C2 host
  -> WebSocket connection wss://superlork[.]info/w (ECDH + AES-256-CBC)
  -> RAT accepts commands: exec, exfil, screen capture, persistence ops
```

---

## Key techniques

| ATT&CK | Technique | Notes |
|--------|-----------|-------|
| T1059.001 | PowerShell | AES loader stage |
| T1218 | System Binary Proxy Execution (BYOI) | node.exe downloaded from internet, not a Windows inbox binary |
| T1562.001 | Disable or Modify Tools | Add-MpPreference exclusion for node.exe |
| T1547.001 | Registry Run Keys / Startup Folder | HKCU Run key persistence |
| T1102 | Web Service | TON blockchain dead-drop for C2 resolution |
| T1071.001 | Web Protocols | WebSocket over TLS (wss://) C2 |
| T1573.001 | Encrypted Channel: Symmetric | Per-session ECDH key exchange + AES-256-CBC |

---

## Files in this folder

| File | Purpose |
|------|---------|
| `rule.yar` | Two YARA rules: AES loader artifacts (RijndaelManaged, Nodejs path, AES key); RAT payload artifacts (TON API string, contract address, alpha identifier) |
| `sigma-node-from-user-path.yml` | Sigma (process_creation): node.exe executing from AppData or Temp |
| `sigma-add-mppreference-exclusion.yml` | Sigma (ps_script EID 4104): Add-MpPreference + ExclusionProcess |
| `iocs.csv` | Indicators of compromise (defanged network IOCs, AES key, TON contract address) |
| `kql.md` | Microsoft Sentinel / Defender XDR KQL queries |

---

## Detection notes

- **This is BYOI, not LOLBin.** `node.exe` is downloaded from the internet --
  it is not a signed Windows inbox binary. The detection hook is the
  non-standard path (`%LOCALAPPDATA%\Nodejs\`) and the download behaviour,
  not abuse of a trusted system binary.
- The TON smart contract address is the strongest long-term pivot. The
  blockchain record is immutable and cannot be taken down. Querying
  `tonapi.io` or `toncenter.com` from endpoint processes that have no
  legitimate reason to do so is a high-signal indicator.
- The AES key and IV in `iocs.csv` are campaign-specific. If the loader
  variant is reused, these will match in 4104 logs.
- The Defender exclusion (`Add-MpPreference -ExclusionProcess`) in a
  4104 event is catch-all and catches many campaigns beyond this one;
  treat it as a medium-confidence alert that warrants triage.
