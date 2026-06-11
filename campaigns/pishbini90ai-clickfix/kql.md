# KQL Queries -- pishbini90ai-clickfix

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/pishbini90ai-clickfix/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. ClickFix cmd paste -- delayed expansion + WebDAV @SSL pattern

Detects `cmd.exe` invoked with `/v:on` or `/v` (delayed expansion) containing the
`@SSL\` WebDAV-over-HTTPS UNC path pattern alongside `rundll32`. This is the exact
ClickFix delivery mechanism. Near-zero false positives in production environments.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents (Defender XDR)

```kql
// Microsoft Sentinel -- SecurityEvent (requires Process Creation auditing + cmdline logging)
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\cmd.exe"
| where CommandLine has "/v"
  and CommandLine has "@SSL\\"
  and CommandLine has "rundll32"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "/v"
  and ProcessCommandLine has "@SSL\\"
  and ProcessCommandLine has "rundll32"
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. Rundll32 executing a file with non-DLL extension

Detects `rundll32.exe` with a commandline referencing a file whose extension is not
`.dll`, `.ocx`, or `.cpl`. The pishbini90ai campaign used `rundll32 google.cl,#1`
where `.cl` masquerades as an OpenCL source file.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\rundll32.exe"
| where CommandLine matches regex @'\.(?!(dll|ocx|cpl|exe))[a-z0-9]{1,6},(#\d+|[A-Za-z])'
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine matches regex @'\.(?!(dll|ocx|cpl|exe))[a-z0-9]{1,6},(#\d+|[A-Za-z])'
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3. Campaign domain pivot (DNS / proxy / network)

Hunt for the C2 domain and all subdomains. Any hit on this domain in DNS or proxy
logs should be treated as a confirmed infection. The subdomain `iyrxs` is specific
to observed infrastructure; the apex pattern catches pivots.

**Log source:** CommonSecurityLog (proxy/DNS) or DeviceNetworkEvents

```kql
// Microsoft Sentinel -- CommonSecurityLog (proxy/DNS)
CommonSecurityLog
| where DestinationHostName has "pishbini90ai.com"
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName,
          RequestURL, Activity
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has "pishbini90ai.com"
  or RemoteHostname has "pishbini90ai.com"
| project Timestamp, DeviceName, AccountName, ActionType,
          RemoteUrl, RemoteHostname, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. GUID delivery path pivot (prior infections -- 14-day lookback)

The GUID `bc1fc622-be49-4978-a48c-fa728a19b9df` appears in the WebDAV URL and UNC
path. Searching for it across proxy, DNS, and network logs identifies any machines
that loaded the payload before detection. Run as a one-time threat hunt across
your available log retention window.

```kql
// Microsoft Sentinel -- search across all tables
search "bc1fc622-be49-4978-a48c-fa728a19b9df"
| project TimeGenerated, Type, _Raw = tostring(pack_all())
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- process + network events
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where ProcessCommandLine contains "bc1fc622-be49-4978-a48c-fa728a19b9df"
  or AdditionalFields contains "bc1fc622-be49-4978-a48c-fa728a19b9df"
  or RemoteUrl contains "bc1fc622-be49-4978-a48c-fa728a19b9df"
| project Timestamp, DeviceName, AccountName, ActionType,
          ProcessCommandLine, AdditionalFields, RemoteUrl
| order by Timestamp desc
```

---

## 5. Fiber + VirtualProtect anomaly within rundll32 (API telemetry)

If your EDR exposes API call telemetry, this query detects the characteristic
post-decode behaviour: `VirtualProtect` called within ~10 seconds of `CreateFiber`
or `SwitchToFiber` inside a `rundll32.exe` process. The 7-second sleep delay makes
this window predictable (~1-10 seconds after process start).

**Log source:** EDR API telemetry (vendor-specific; adapt field names)

```kql
// Microsoft Defender XDR -- DeviceEvents (API call telemetry, where available)
DeviceEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
| where ActionType in ("CreateFiberApiCall", "VirtualProtectApiCall",
                       "SwitchToFiberApiCall")
| summarize ApiCalls = make_set(ActionType), FirstCall = min(Timestamp),
            LastCall = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
       bin(Timestamp, 30s)
| where ApiCalls has "VirtualProtect"
  and (ApiCalls has "CreateFiber" or ApiCalls has "SwitchToFiber")
| project FirstCall, LastCall, DeviceName, InitiatingProcessCommandLine, ApiCalls
| order by FirstCall desc
```

---

## 6. WebDAV PROPFIND to external host over HTTPS (delivery confirmation)

Detects outbound WebDAV `PROPFIND` requests to external HTTPS hosts. This is the
network-layer fingerprint of the `pushd \\host@SSL\path` command that maps the
remote WebDAV share as a drive letter. The Windows WebDAV client user-agent is
distinctive.

**Log source:** Proxy logs / NGFW with SSL inspection / CommonSecurityLog

```kql
// Microsoft Sentinel -- CommonSecurityLog (proxy with method visibility)
CommonSecurityLog
| where RequestMethod == "PROPFIND"
| where DeviceVendor != "Microsoft"   // exclude internal SharePoint/Exchange
| where DestinationPort == 443
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName,
          RequestURL, RequestMethod, Activity
| order by TimeGenerated desc
```
