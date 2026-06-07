rule PS_SharePointAssist_LocalHTTP_RAT
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-06"
        description = "Fileless PowerShell localhost HTTP-RAT (sharepoint-assist.ps1): string-method obfuscation on disk, AMSI bypass, localhost HttpListener on 127.0.0.1:58172, generic memory patcher, HVNC window hiding."
        reference   = "https://blueteam.cool/posts/sharepoint-assist-localhost-rat/"
        sha256      = "f1767aaebb55347153c56e21adbf3a41e48663d139279ec8e3b1f1be1db63a53"
        severity    = "high"
        confidence  = "high"

    strings:
        $o1 = ".Substring(" ascii
        $o2 = ".Insert("    ascii
        $o3 = ".TrimEnd("   ascii
        $a1 = "Global\\explorer_wide_thumbcache" ascii wide
        $a2 = "127.0.0.1:58172" ascii wide
        $a3 = "DynWin32_1"      ascii wide
        $a4 = "class W32API"    ascii wide
        $a5 = "FindPattern"     ascii wide
        $a6 = "HttpListener"    ascii wide

    condition:
        // cleartext artifacts (in logs or deobfuscated file)
        (2 of ($a*))
        or
        // obfuscated on disk: large file with heavy string-method churn
        (filesize > 100KB and filesize < 2MB and #o1 > 100 and #o2 > 10 and #o3 > 10)
}
