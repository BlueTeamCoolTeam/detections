rule ClickFix_EnterCodeCdn_Loader_Chain
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        date = "2026-07-29"
        description = "ClickFix multi-stage XOR/Base64 PowerShell loader for enter-code-cdn[.]info -> bloated Go implant"
        reference = "https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/"
        sha256 = "678d92dac07362312135fa5a81d528322d2f4671d0632d26d572f5d86cf9692a"
    strings:
        $u1 = "enter-code-cdn.info" ascii wide
        $tag = "967b5773df7f334c" ascii wide
        $winhttp = "WinHttp.WinHttpRe" ascii wide
        $p1 = "-bxor113" ascii wide
        $p2 = "-bxor118" ascii wide
        $iex = "iex(irm" ascii wide nocase
        $cf = "cloudflare.exe" ascii wide
        $pw = "lehpffsr" ascii wide
    condition:
        ($u1 and ($tag or $iex)) or (2 of ($p1,$p2,$winhttp)) or ($cf and $pw)
}

rule Go_Garble_Bloated_ElevationMap_Implant
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        date = "2026-07-29"
        description = "Garble-obfuscated Go implant masquerading as an Elevation Map topography tool; NULL-padded to ~842MB"
        reference = "https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/"
        sha256 = "5e1b57d0a56d2befa3f786a6cf3b38072454c2a7751e291f38d68448f89607fa"
    strings:
        $go   = "go1.25.4" ascii
        $mod  = "vyimLwwQcaHWg" ascii
        $d1   = "--- Elevation Map ---" ascii
        $d2   = "Highest peak:" ascii
        $d3   = "Total relief:" ascii
        $bid  = "lJR0dC7X1EoIIEUyHcUB" ascii
    condition:
        uint16(0)==0x5A4D and $go and (($mod and 1 of ($d*)) or $bid or 2 of ($d*))
}

rule EnterCodeCdn_Go_Stealer_C2_Confirmed
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        date = "2026-07-31"
        description = "Network/host indicators confirmed via dynamic detonation: Telegram dead-drop resolver + m36.akasia988[.]net C2"
        reference = "https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/"
        sha256 = "678d92dac07362312135fa5a81d528322d2f4671d0632d26d572f5d86cf9692a"
    strings:
        $c2 = "akasia988.net" ascii wide
        $dropper = "t.me/gk6p2s" ascii wide
        $ua = "Safari/537.36 Edg/144.0.0.0" ascii wide
        $post = "POST / HTTP/1.1" ascii
    condition:
        any of them
}

rule EnterCodeCdn_Stealer_Module_Runtime
{
    meta:
        author = "blueteam.cool (@btcoolteam)"
        date = "2026-07-31"
        description = "Native stealer module strings recovered from process memory (round 3 detonation). Memory-scan rule - these are runtime-decrypted, NOT present in the on-disk PE."
        reference = "https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/"
        sha256 = "678d92dac07362312135fa5a81d528322d2f4671d0632d26d572f5d86cf9692a"
        scan_context = "memory"
    strings:
        // exfil protocol
        $p1 = "file_data" ascii
        $p2 = "file_name" ascii
        $p3 = "build_id" ascii
        // internal report format
        $r1 = "information.txt" ascii
        $r2 = "Work Dir: In memory" ascii
        $r3 = "Uploaded %lu/%lu files" ascii
        $r4 = "[social] steam..." ascii
        $r5 = "apc method: %s" ascii
        // credential-source tagging (distinctive)
        $s1 = "from_IndexedDB" ascii
        $s2 = "from_sync" ascii
        // grabber roots
        $g1 = "%DRIVE_REMOVABLE%" ascii
        $g2 = "%PROGRAMFILES_86%" ascii
    condition:
        (all of ($p*)) or (2 of ($r*)) or (all of ($s*)) or (all of ($g*))
}
