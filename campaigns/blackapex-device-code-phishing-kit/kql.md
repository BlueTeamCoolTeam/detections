# KQL Queries -- blackapex-device-code-phishing-kit
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/blackapex-device-code-phishing-kit/
> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. Device code sign-ins (baseline, then alert)

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode"
| summarize Count = count(), Apps = make_set(AppDisplayName), IPs = make_set(IPAddress)
    by UserPrincipalName
| order by Count desc
```

## 2. Device registration followed by a Windows Hello for Business key

The kit registered a device and added a key within 15 seconds of each capture.

```kql
let window = 2m;
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Register device"
| extend User = tostring(InitiatedBy.user.userPrincipalName), RegTime = TimeGenerated
| join kind=inner (
    AuditLogs
    | where OperationName has "Windows Hello for Business"
    | extend User = tostring(InitiatedBy.user.userPrincipalName), KeyTime = TimeGenerated
  ) on User
| where KeyTime between (RegTime .. RegTime + window)
| project User, RegTime, KeyTime, CorrelationId
```

## 3. Several devices registered to one user in an hour

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Register device"
| extend User = tostring(InitiatedBy.user.userPrincipalName)
| summarize Devices = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by User, bin(TimeGenerated, 1h)
| where Devices > 1
```

## 4. Sign-ins from known backend addresses

Load the `ip` rows of `iocs.csv` (refang first) as a watchlist named `BlackApexBackends`.

```kql
let backends = _GetWatchlist('BlackApexBackends') | project IPAddress = tostring(SearchKey);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where IPAddress in (backends)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, AuthenticationProtocol, ResultType
```
