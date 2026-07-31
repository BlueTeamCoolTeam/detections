# KQL Queries -- clickfix-elevation-map-credential-stealer
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/
> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. ClickFix PowerShell paste-and-run stager

Hidden-window `iex(irm ...)` PowerShell parented by `explorer.exe` -- the
Run-dialog paste pattern.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "explorer.exe"
| where ProcessCommandLine has "iex" and ProcessCommandLine has "irm"
| where ProcessCommandLine has_any ("-w h", "-windowstyle hidden", "-WindowStyle Hidden")
| where ProcessCommandLine !has "microsoft.com"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## 2. Non-browser process spawning Edge/Chrome for App-Bound Encryption abuse

The highest-fidelity single detection in the chain: a non-browser process
launching a throwaway Edge/Chrome instance with `--no-first-run` and
`about:blank`.

```kql
DeviceProcessEvents
| where FileName in~ ("msedge.exe", "chrome.exe")
| where ProcessCommandLine has "--no-first-run" and ProcessCommandLine has "about:blank"
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

Pivot from a hit above to confirm the `elevation_service.exe` activation
that follows within a few seconds:

```kql
let spawnTimes = DeviceProcessEvents
| where FileName in~ ("msedge.exe", "chrome.exe")
| where ProcessCommandLine has "--no-first-run" and ProcessCommandLine has "about:blank"
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe")
| project DeviceName, SpawnTime = Timestamp;
DeviceProcessEvents
| where FileName =~ "elevation_service.exe"
| where InitiatingProcessFileName =~ "services.exe"
| join kind=inner (spawnTimes) on DeviceName
| where Timestamp between (SpawnTime .. (SpawnTime + 5s))
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, SpawnTime
| order by Timestamp desc
```

## 3. Staged browser-DB files in a random TEMP subfolder

Matches the `%TEMP%\<8hex>\<8hex>` staging pattern used to copy locked
Chromium SQLite databases before exfiltration.

```kql
DeviceFileEvents
| where FolderPath matches regex @"\\AppData\\Local\\Temp\\[0-9a-f]{8}\\[0-9a-f]{8}$"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

Correlate with a same-file deletion within a couple of seconds, which is
the anti-forensic wipe:

```kql
let staged = DeviceFileEvents
| where FolderPath matches regex @"\\AppData\\Local\\Temp\\[0-9a-f]{8}\\[0-9a-f]{8}$"
| where ActionType == "FileCreated"
| project DeviceName, FolderPath, FileName, CreateTime = Timestamp, InitiatingProcessFileName;
DeviceFileEvents
| where ActionType == "FileDeleted"
| join kind=inner (staged) on DeviceName, FolderPath, FileName
| where Timestamp between (CreateTime .. (CreateTime + 5s))
| project CreateTime, DeleteTime = Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by CreateTime desc
```

## 4. Network connections to known campaign infrastructure

```kql
let domains = dynamic(["enter-code-cdn.info", "coronadoferrylanding.com", "m36.akasia988.net", "peluangsm188.top"]);
let ips = dynamic(["178.16.52.101", "74.208.53.82", "172.67.187.150", "104.21.7.141", "104.21.58.99", "172.67.203.42"]);
DeviceNetworkEvents
| where RemoteUrl has_any (domains) or RemoteIP in (ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

## 5. Dead-drop resolver hits from a non-browser process

Both dead-drops (Telegram profile, Steam profile) are legitimate platforms,
so scope this to processes that have no business fetching them -- i.e. not
an actual browser.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("t.me/gk6p2s", "steamcommunity.com/profiles/76561198667588759")
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| order by Timestamp desc
```

## 6. Oversized-PE heuristic (binary-padding evasion)

Hunt for executables well past typical AV/sandbox scan-size ceilings landing
in user-writable paths -- the file-bloating trick used to smuggle
`cloudflare.exe` past size-limited scanners.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where FileSize > 500000000  // ~500MB
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Users\Public\", @"\ProgramData\")
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessFileName
| order by Timestamp desc
```
