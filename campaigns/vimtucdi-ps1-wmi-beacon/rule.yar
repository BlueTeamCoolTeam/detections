rule PS_VolumeSerial_IEX_Beacon
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "PowerShell HTTP beacon: C: volume-serial bot ID, DownloadString->IEX loop, AMSI amsiInitFailed flip, and ETW provider null via reflection."
        reference   = "https://blueteam.cool/posts/vimtucdi-ps1-wmi-beacon/"
        sha256      = "8c8c40ea3023a9ca4e59a1e72b8464e0f8089cf5f94c4237c46757fb7e900214"
        severity    = "high"
        confidence  = "high"

    strings:
        $s1   = "Scripting.FileSystemObject" ascii nocase
        $s2   = ".SerialNumber" ascii nocase
        $s3   = "DownloadString" ascii nocase
        $s4   = "amsiInitFailed" ascii nocase
        $s5   = "etwProvider" ascii nocase
        $pass = "pEctAiwaWzmsNCHIPuGV" ascii
        $ip   = "77.221.155.150" ascii

    condition:
        $pass or $ip or (3 of ($s*))
}

rule SCT_WMI_PowerShell_Launcher
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "JScript .sct scriptlet using WMI Win32_Process.Create to spawn a hidden powershell.exe -ep bypass -file. Parent-process laundering via WmiPrvSE.exe."
        reference   = "https://blueteam.cool/posts/vimtucdi-ps1-wmi-beacon/"
        severity    = "high"
        confidence  = "high"

    strings:
        $a = "Win32_Process" ascii nocase
        $b = "Win32_ProcessStartup" ascii nocase
        $c = "ShowWindow" ascii nocase
        $d = "powershell.exe -ep bypass -file" ascii nocase
        $e = "<scriptlet>" ascii nocase

    condition:
        4 of them
}
