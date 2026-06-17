# KQL Queries -- clickfix-finger-lolbin-campaign
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## Query 1 -- finger.exe execution with @ in arguments (any family)

```kql
// Detects any finger.exe process with @ in the command line argument.
// finger.exe has no legitimate enterprise use case. Near-zero expected FP.
DeviceProcessEvents
| where FileName =~ "finger.exe"
| where ProcessCommandLine contains "@"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

---

## Query 2 -- Family 1 campaign GUID in proxy/network traffic (CRITICAL)

```kql
// Detects the campaign GUID in HTTP traffic via DeviceNetworkEvents or proxy logs.
// Any hit = victim reached stage 2 of the Family 1 IronPython chain.
// Expected false positive rate: zero.
DeviceNetworkEvents
| where RemoteUrl contains "6d6d2d17-d270-59c6-8b75-df011af08e58"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp desc
```

---

## Query 3 -- Family 1 IronPython batch loader chain (multi-signal)

```kql
// Detects multiple indicators from the Family 1 batch loader within a short window on the same device.
// Covers: IronPython.3.4.2 directory creation, tar.exe extracting .pdf files, taskkill on explorer,
// ipyw32.exe execution.
let lookback = 30m;
let finger_processes = DeviceProcessEvents
| where FileName =~ "finger.exe" and ProcessCommandLine contains "@"
| project DeviceName, FingerTime = Timestamp;
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (
    (FileName =~ "tar.exe" and ProcessCommandLine contains ".pdf") or
    (FileName =~ "taskkill.exe" and ProcessCommandLine contains "IMAGENAME eq explor") or
    (FileName =~ "ipyw32.exe") or
    (ProcessCommandLine contains "IronPython.3.4.2")
)
| join kind=inner finger_processes on DeviceName
| where abs(datetime_diff('minute', Timestamp, FingerTime)) <= 30
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FingerTime
| sort by Timestamp desc
```

---

## Query 4 -- Family 1 C2 domain connections

```kql
// Detects outbound connections to Family 1 C2 domains.
DeviceNetworkEvents
| where RemoteUrl has_any ("youndor.com", "noidoret.com")
    or RemoteIP in ("38.146.25.181", "50.114.167.195")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp desc
```

---

## Query 5 -- Family 2 lspy RAT: pythonw.exe in ProgramData

```kql
// Detects pythonw.exe executing from C:\ProgramData\, which is the Family 2 lspy RAT pattern.
// Legitimate software almost never runs pythonw.exe from ProgramData.
DeviceProcessEvents
| where FileName =~ "pythonw.exe"
| where FolderPath startswith @"C:\ProgramData\"
| project Timestamp, DeviceName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp desc
```

---

## Query 6 -- Family 2 lspy RAT: mutex and named pipe

```kql
// Detects the Family 2 lspy mutex and named pipe in process events or named pipe events.
// MerlinMonroeBlond (mutex) and \\.\pipe\PipingMet (named pipe) -- near-zero expected FP.
union DeviceProcessEvents, DeviceEvents
| where ProcessCommandLine has_any ("MerlinMonroeBlond", "PipingMet")
    or AdditionalFields contains "MerlinMonroeBlond"
    or AdditionalFields contains "PipingMet"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AdditionalFields
| sort by Timestamp desc
```

---

## Query 7 -- Family 2 lspy: Startup folder LNK persistence

```kql
// Detects Python_*.lnk file creation in the Startup folder, the Family 2 persistence mechanism.
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
| where FileName startswith "Python_" and FileName endswith ".lnk"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, AccountName
| sort by Timestamp desc
```

---

## Query 8 -- Family 2 C2 connections (staruxasosiska/starayadaet)

```kql
// Detects outbound connections to Family 2 C2 domains.
DeviceNetworkEvents
| where RemoteUrl has_any ("staruxasosiska.com", "starayadaet.com")
    or RemoteIP == "95.133.228.65"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp desc
```

---

## Query 9 -- BunnyCDN staging download (Family 2 build.zip)

```kql
// Detects download of the Family 2 payload from BunnyCDN.
DeviceNetworkEvents
| where RemoteUrl contains "valval-cloud.b-cdn.net"
    or RemoteUrl contains "build.zip"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| sort by Timestamp desc
```

---

## Query 10 -- Family 3 staging cluster connections

```kql
// Detects outbound connections to Family 3 linked* DigitalOcean staging infrastructure.
// These domains served no payloads during triage but the infrastructure is confirmed campaign-affiliated.
let family3_ips = dynamic(["162.243.34.41", "64.225.52.81", "162.243.213.197", "162.243.16.117", "162.243.82.232", "167.71.102.121"]);
let family3_domains = dynamic(["linkedngo.com", "linked4x.com", "linkedwiz.com", "linkedlet.com", "ilinkedx.com", "claudefos.com"]);
DeviceNetworkEvents
| where RemoteIP in (family3_ips)
    or RemoteUrl has_any (family3_domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp desc
```

---

## Query 11 -- Outbound TCP/79 (any family -- block and alert)

```kql
// Detects any outbound TCP/79 connection. finger.exe has no legitimate enterprise use case.
// This is the highest-impact alert for all three families.
DeviceNetworkEvents
| where RemotePort == 79
| where ActionType == "ConnectionSuccess" or ActionType == "ConnectionRequest"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| sort by Timestamp desc
```

---

## Query 12 -- Chrome/143.0.0.0 User-Agent (Family 1 shellcode)

```kql
// Detects the hardcoded User-Agent string in Family 1 shellcode.
// Chrome/143.0.0.0 is not a real Chrome release.
DeviceNetworkEvents
| where AdditionalFields contains "Chrome/143.0.0.0"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, AdditionalFields
| sort by Timestamp desc
```
