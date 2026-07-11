/*
  Family B (mamkor/merabs) rules only. Family A ("BW panel", selector
  0xb68d1809) has no new YARA in this pack - that side of the investigation
  was network/on-chain-only by design (see each source REPORT.md), and the
  authorization-cdn-etherhiding-clickfix campaign folder already carries the
  injected-loader-shape YARA for that kit family. Stated here rather than
  padded out with a rule that would just duplicate that folder's coverage.
*/

rule EtherHiding_ClickFix_Polygon_Loader_JS_FamilyB
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        description = "Injected EtherHiding ClickFix loader resolving C2 from a Polygon contract (Family B / mamkor-merabs kit, selector 38bcdc1c)"
        reference = "https://github.com/BlueTeamCoolTeam/detections/tree/main/campaigns/etherhiding-ecosystem-mapped"
        date = "2026-07-11"
    strings:
        $eth   = "eth_call" ascii
        $sel   = "38bcdc1c" ascii
        $rpc1  = "polygon.drpc.org" ascii
        $rpc2  = "polygon-bor-rpc.publicnode.com" ascii
        $cfg   = "a=tds_cfg" ascii
        $land  = "_landing" ascii
        $cook  = "_cf_verified=v" ascii
        $clip  = "clipboard-write" ascii
        $fn    = "new Function(" ascii
    condition:
        filesize < 50KB and $eth and $sel and $cfg and 3 of ($rpc1,$rpc2,$land,$cook,$clip,$fn)
}

rule Go_RunPE_Loader_mamkor_family
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        description = "Go 1.25.4 in-process RunPE loader (mamkor.pro/merabs.pro EtherHiding campaign, Family B)"
        date = "2026-07-11"
    strings:
        $go     = "go1.25.4" ascii
        $mz     = { 4D 5A }
        $ctx1   = "SetThreadContext" ascii
        $ctx2   = "GetThreadContext" ascii
        $res    = "ResumeThread" ascii
        $va     = "VirtualAlloc" ascii
        // remote-hollowing negatives - absence of these distinguishes this
        // family's LOCAL RunPE from remote process hollowing
        $wpm    = "WriteProcessMemory" ascii
        $vaex   = "VirtualAllocEx" ascii
    condition:
        $mz at 0 and $go and all of ($ctx1,$ctx2,$res,$va) and not any of ($wpm,$vaex)
}
