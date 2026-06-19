# KQL Queries -- star-rmm-turf-war
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/star-rmm-turf-war/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## Hunt: Hash-named scheduled task creation (TG_Send_* or BHS_*)

Catches the self-deleting exfil task at creation time. The task name pattern
is deterministic: `TG_Send_<md5hash>` or `BHS_<12-char-uid>`.

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields has "TG_Send_" or AdditionalFields has "BHS_"
| project Timestamp, DeviceName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

## Hunt: PowerShell connecting to Telegram Bot API

Outbound HTTPS to api.telegram.org from powershell.exe or scheduled task
contexts is anomalous.

```kql
DeviceNetworkEvents
| where RemoteUrl contains "api.telegram.org"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessCommandLine,
    RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

---

## Hunt: Script Block Logging -- Telegram + BHS class in same script

Matches PowerShell script content containing both the Telegram API endpoint
and the BHS runtime-compiled C# class.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "api.telegram.org"
    and AdditionalFields has "BHS"
| project Timestamp, DeviceName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

## Hunt: Known STAR bot tokens in PowerShell script content

Matches any PowerShell command block containing a known STAR campaign bot token.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any (
    "8561959266:AAEI32HfP40cKQwtAtSyS6o9Srcjd7W7B9A",
    "8638944609:AAECv0FW5fCFPxp4cNz-Mp856SyocgfEgdA",
    "8662428383:AAE7q7noOfH_12SZJPCQNB1A98DqnyAn344"
    )
| project Timestamp, DeviceName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

## Hunt: Rogue ScreenConnect instance ID in registry

Detects creation of a SC service entry matching known STAR actor-owned panels.

```kql
DeviceRegistryEvents
| where RegistryKey contains @"SYSTEM\CurrentControlSet\Services\ScreenConnect Client ("
| where RegistryKey has_any (
    "8df439ea69ba1ba8",
    "bafd0ea8d422c32c",
    "e64730829b489fd7",
    "534179a8e5dac2c9",
    "7fc846f428209093",
    "d9a10039878302f6"
    )
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Hunt: Event log cleared (Security log -- Event ID 1102)

Broad alert for any security log clear event. High confidence on production hosts.

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
| order by TimeGenerated desc
```

---

## Hunt: File activity in C:\H\ staging directory

Any process writing to the actor's staging directory.

```kql
DeviceFileEvents
| where FolderPath startswith @"C:\H\"
| project Timestamp, DeviceName, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Hunt: Hidden PowerShell from SC temp delivery path

Matches the exact execution pattern used to run delivered scripts.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "ExecutionPolicy Bypass"
    and ProcessCommandLine has "WindowStyle Hidden"
    and ProcessCommandLine has "SystemTemp\\ScreenConnect"
| project Timestamp, DeviceName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Fleet audit: All ScreenConnect instance IDs (diff against approved list)

Run this across your fleet to surface any SC client not in your approved list.
Adapt the exclusion list to your known-good instance IDs.

```kql
DeviceRegistryEvents
| where RegistryKey contains @"SYSTEM\CurrentControlSet\Services\ScreenConnect Client ("
| extend InstanceID = extract(@"ScreenConnect Client \(([^)]+)\)", 1, RegistryKey)
| where InstanceID != ""
// Exclude your approved instance IDs here:
// | where InstanceID !in ("your-approved-id-1", "your-approved-id-2")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    DeviceCount=dcount(DeviceName) by InstanceID, RegistryKey
| order by DeviceCount desc
```
