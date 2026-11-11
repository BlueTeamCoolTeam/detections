rule ClickFix_QuantAI_Stage1_IRM_Hop
{
    meta:
        description = "First-hop one-liner served by the Quant AI lure: irm hop to the dropper host with the computer name in the Dio parameter"
        author = "blueteam.cool"
        date = "2026-11-11"
        reference = "https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/"
        sha256 = "97c7c44e0bc3a2f76022fd3dea0b74485ee957b5c34b31e75ba72bd02b809d03"
    strings:
        $a = "quant.php?Dio=$($env:COMPUTERNAME)" ascii
        $b = "chartsgpt.com" ascii nocase
        $c = "| iex" ascii nocase
    condition:
        filesize < 2KB and ($a or ($b and $c))
}

rule ClickFix_QuantAI_Stage2_NetSupport_Dropper
{
    meta:
        description = "PowerShell dropper: password-protected 7z archives into LOCALAPPDATA Supports or Stoservice, NetSupport client start, icacls deny, Startup shortcut, decoy app"
        author = "blueteam.cool"
        date = "2026-11-11"
        reference = "https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/"
        sha256 = "a7e68c023130cb8090dbcfb5552c3b63db3689f571e94a75e130fa72813657b1"
    strings:
        $v1 = "$gagarik" ascii
        $v2 = "$xaxaxar" ascii
        $s1 = "supportn.7z" ascii
        $s2 = "icos.7z" ascii
        $s3 = "vh.exe\" x" ascii
        $s4 = "-pkim -aoa -y" ascii
        $s5 = "-pico -aoa -y" ascii
        $s6 = "*S-1-3-4:(OI)(CI)(RX)" ascii
        $s7 = "(WD,AD,WA,WEA,DE,DC)" ascii
        $s8 = "\\Supports" ascii
        $s9 = "Quant.lnk" ascii
    condition:
        filesize < 10KB and (any of ($v*) or 4 of ($s*))
}

rule NetSupport_RAT_Config_sonosarcsounds
{
    meta:
        description = "NetSupport Manager client32.ini set to a sonosarcsounds gateway on port 2084, or a gateway address with four hidden-mode flags"
        author = "blueteam.cool"
        date = "2026-11-11"
        reference = "https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/"
        sha256 = "0561bed36686c0324e93ac7a1f015e3d8055bffca83533918d224b467c8c884d"
    strings:
        $gw1 = "sonosarcsounds.com:2084" ascii
        $gw2 = "sonosarcsounds.net:2084" ascii
        $key = "GC<GAJEL;A?MDI9L>DBMHA=AABFE;H" ascii
        $path = "Filename=C:\\kk\\client32.ini" ascii
        $addr = "GatewayAddress=" ascii
        $f1 = "silent=1" ascii
        $f2 = "SysTray=0" ascii
        $f3 = "ShowUIOnConnect=0" ascii
        $f4 = "DisableClientConnect=1" ascii
    condition:
        filesize < 20KB and (any of ($gw*) or $key or $path or ($addr and all of ($f*)))
}

rule QuantAI_Decoy_WebView2_Shell
{
    meta:
        description = "Quant AI decoy: .NET WebView2 shell pointing at the lure site's app.php page"
        author = "blueteam.cool"
        date = "2026-11-11"
        reference = "https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/"
        sha256 = "c3910877eca0b9b2975588cb25d654155d58168114e00aa072899eccf62b35fb"
    strings:
        $url = "https://quantai.io/app.php" wide
        $guid = "bce06385-6be6-4093-afe2-80c3dfe1bd3d" ascii nocase
        $n1 = "Quant AI" wide
        $n2 = "LL.runtimes.win_x86.native.WebView2Loader.dll" ascii
        $signer = "Sylabiz Software OU" ascii
    condition:
        uint16(0) == 0x5A4D and ($url or $guid or ($n1 and $n2) or $signer)
}

rule NetSupport_Licence_NSM1234
{
    meta:
        description = "NetSupport licence file with licensee NSM1234 as shipped in this kit. This licence string is widely reused and is not unique to this campaign."
        author = "blueteam.cool"
        date = "2026-11-11"
        reference = "https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/"
        sha256 = "5b3c03d15e910a4439cd8e3868f5110accdf0ff3130bceadcd2d795206161fc7"
    strings:
        $hdr = "NetSupport License File" ascii
        $lic = "licensee=NSM1234" ascii
    condition:
        filesize < 5KB and $hdr and $lic
}
