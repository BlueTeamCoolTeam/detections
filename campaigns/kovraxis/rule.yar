rule Kovraxis_PowerShell_Downloader
{
    meta:
        description = "PowerShell downloader: string-split domain, SEE_MASK_NOZONECHECKS MOTW bypass, drops and runs a fetched EXE"
        author = "blueteam.cool"
        date = "2026-07-16"
        reference = "https://blueteam.cool/posts/kovraxis/"

    strings:
        $a = "SEE_MASK_NOZONECHECKS" ascii wide
        $b = "Invoke-WebRequest" ascii wide
        $c = "-UseBasicParsing" ascii wide
        $d = "kovraxis" ascii wide nocase

    condition:
        2 of ($a,$b,$c) or $d
}

rule Kovraxis_Go_Implant_8845e127
{
    meta:
        description = "Go-compiled Windows implant dropped by the kovraxis[.]com PowerShell downloader; stdlib-only HTTP/TLS/JSON + local account/share management API strings; steals Edge browser profile data via a Telegram/Steam dead-drop C2 resolver"
        author = "blueteam.cool"
        date = "2026-07-16"
        reference = "https://blueteam.cool/posts/kovraxis/"
        sha256 = "a3714081253eee3bf9d64e58e6967a66362d02a443c2fa06a337949c69bbc2a1"

    strings:
        $buildid = "EfNHLACDlOuyogU/main.go" ascii
        $api1 = "NetUserAdd" ascii
        $api2 = "NetShareAdd" ascii
        $api3 = "RevertToSelf" ascii
        $cert = "anthropic.com" ascii wide
        $go   = "go1.25.4" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
