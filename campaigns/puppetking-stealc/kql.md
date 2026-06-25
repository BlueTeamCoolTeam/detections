# KQL Queries -- puppetking-stealc

Microsoft Sentinel / Microsoft Defender XDR queries for the PuppetKing ClickFix campaign delivering StealC v2 infostealer.

Blog post: https://blueteam.cool/posts/puppetking-stealc/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. ClickFix iex+irm PowerShell stager (Defender XDR - DeviceProcessEvents)

Detects the Win+R paste-and-run ClickFix pattern: PowerShell spawned by explorer.exe with iex+irm+UseBasicParsing combination.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "explorer.exe"
| where ProcessCommandLine has_all ("iex", "irm", "UseBasicParsing")
| where not(ProcessCommandLine has "microsoft.com")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2. LOLBin process-hollowing candidates (Defender XDR - DeviceProcessEvents)

Detects MSBuild, RegSvcs, or vbc.exe running without a recognisable project file argument. High FP on dev boxes -- tune by excluding known build hosts.

```kql
DeviceProcessEvents
| where FileName in~ ("msbuild.exe", "regsvcs.exe", "vbc.exe")
| where not(ProcessCommandLine has_any (".csproj", ".vbproj", ".proj", ".targets", ".sln"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3. StealC C2 network beacon (Defender XDR - DeviceNetworkEvents)

Hunts for HTTP connections to the known StealC C2 IP. The .php path with hex filename is distinctive.

```kql
DeviceNetworkEvents
| where RemoteIP == "151.243.18.28"
| where RemotePort in (80, 443, 8080)
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. Blockchain C2 resolution (Defender XDR - DeviceNetworkEvents)

Detects endpoints querying Polygon RPC nodes -- unusual from non-developer workstations and consistent with the PuppetKing JS lure resolving the active C2 domain.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("polygon.drpc.org", "polygon-rpc.com", "rpc-mainnet.matic.network", "polygon.llamarpc.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "node.exe", "electron.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 5. Run-key persistence write (Sentinel - SecurityEvent / Sysmon)

Detects writes to the CurrentVersion\Run registry key, consistent with the StealC loader establishing persistence.

```kql
// Sysmon Event ID 13 (Registry value set)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend TargetObject = tostring(parse_xml(EventData).DataItem.Data[4])
| where TargetObject has_all ("CurrentVersion", "Run")
| where TargetObject !has "MachineGuid"
| project TimeGenerated, Computer, TargetObject
| order by TimeGenerated desc
```

---

## 6. Non-browser access to browser credential stores (Defender XDR - DeviceFileEvents)

Detects processes other than browsers reading Login Data or Local State -- the primary StealC credential-theft telemetry.

```kql
DeviceFileEvents
| where FileName in~ ("Login Data", "Local State", "Cookies", "Web Data")
| where FolderPath has_any ("Chrome", "Edge", "Brave", "Opera")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 7. Infrastructure hunt -- .beer TLD DNS (Sentinel - DnsEvents)

Detects DNS queries for .beer TLD domains from endpoints. The PuppetKing operator shows strong preference for this TLD across 130+ domains.

```kql
DnsEvents
| where Name endswith ".beer"
| project TimeGenerated, Computer, ClientIP, Name, IPAddresses
| order by TimeGenerated desc
```
