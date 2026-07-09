# KQL Queries -- authorization-cdn-etherhiding-clickfix

Microsoft Sentinel / Microsoft Defender XDR queries for the authorization-cdn-press-enter.info ClickFix / EtherHiding campaign.

Blog post: https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. ClickFix iex+irm PowerShell stager (Defender XDR - DeviceProcessEvents)

Detects the paste-and-run ClickFix pattern: PowerShell run with a hidden window, iex+irm+UseBasicParsing, and the "Verification ID" comment this kit stamps onto the command line.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("iex", "irm", "UseBasicParsing")
   or ProcessCommandLine has "Verification ID"
| where not(ProcessCommandLine has "microsoft.com")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2. cmutil.dll loaded outside System32 (Defender XDR - DeviceImageLoadEvents)

The legitimate Microsoft Connection Manager cmutil.dll only ships in System32. A load from anywhere else is the trojanised side-load.

```kql
DeviceImageLoadEvents
| where FileName =~ "cmutil.dll"
| where not(FolderPath has @"\Windows\System32\")
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## 3. Randomly-named 7-Zip extraction from %TEMP% (Defender XDR - DeviceProcessEvents)

Detects a process running from a %TEMP% subfolder with 7-Zip's silent-extract argument shape, spawned by PowerShell.

```kql
DeviceProcessEvents
| where FolderPath has @"\AppData\Local\Temp\"
| where ProcessCommandLine has_all ("x ", "-y", "-o")
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. C2 network beacon - operator 1 infrastructure (Defender XDR - DeviceNetworkEvents)

Hunts for connections to the current and recently-rotated operator-1 C2 IP/domains. Update the domain list as the on-chain contract rotates; the IP has been stable across multiple domain rotations.

```kql
DeviceNetworkEvents
| where RemoteIP == "178.16.52.101"
   or RemoteUrl has_any ("authorization-cdn-press-enter.info", "authorization-code.info", "authorization-id-code.info", "authorization-code.beer")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 5. Blockchain C2 resolution - Polygon RPC calls (Defender XDR - DeviceNetworkEvents)

Detects endpoints making JSON-RPC eth_call requests to public Polygon RPC nodes. Unusual outside developer/web3 workstations, and this is exactly how the injected loader resolves the current C2 before a victim ever hits the ClickFix page.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("polygon.drpc.org", "1rpc.io", "rpc.ankr.com", "polygon-bor-rpc.publicnode.com", "matic.quiknode.pro", "nodies.app", "tenderly.co", "blastapi.io")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "node.exe", "electron.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 6. Injected-loader token mint follow-through (Defender XDR - DeviceNetworkEvents)

Detects the browser loading /api.php?s=<hex> immediately after resolving a C2 from the contract - the step that mints the per-victim token and renders the ClickFix overlay.

```kql
DeviceNetworkEvents
| where RemoteUrl matches regex @"/api\.php\?s=[0-9a-f]{20,}&_v=\d+"
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7. Operator 2 infrastructure hunt (Sentinel - DnsEvents)

Operator 2's C2 naming theme is distinctive enough to hunt as a set.

```kql
DnsEvents
| where Name has_any ("letsgomakemoneyoncaptcha.beer", "hahletsgoagain.beer", "iwannagetmoremoney.beer")
| project TimeGenerated, Computer, ClientIP, Name, IPAddresses
| order by TimeGenerated desc
```

---

## 8. Operator 3 infrastructure hunt (Sentinel - DnsEvents)

Operator 3 was found post-publication during a re-validation pass; its domain set is smaller and newer (first C2 on-chain 29 June 2026) than the other two, and its full candidate-site population has not been mapped.

```kql
DnsEvents
| where Name has_any ("hilacbatoriaaa.cc", "pluhabovra.info", "huishuvish.cc", "errrkotmlkpoy.xyz")
| project TimeGenerated, Computer, ClientIP, Name, IPAddresses
| order by TimeGenerated desc
```
