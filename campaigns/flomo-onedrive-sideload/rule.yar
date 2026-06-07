rule OneDrive_Sideload_TrojanLoggingPlatform
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "Trojanized OneDrive LoggingPlatform.dll loader (AES-CBC decrypt of signal_config.meta). Signature blob copied from a genuine Microsoft DLL but digest fails verification."
        reference   = "https://blueteam.cool/posts/flomo-onedrive-sideload/"
        sha256      = "656fb0ce773fdfb745263deb1492170f9b332778a33ee3b15ee0adc33110cff7"
        severity    = "high"
        confidence  = "high"

    strings:
        $meta = ".signal_config.meta" ascii
        $od   = "Microsoft OneDrive" wide
        $pdb  = "LoggingPlatform.pdb" ascii
        $cbc  = "ChainingModeCBC" wide

    condition:
        // a "OneDrive" DLL referencing the planted payload = trojanized
        $meta and ($od or $pdb) and $cbc
}

rule ClickFix_Flomo_Chain_Artifacts
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "ClickFix flomo campaign artifacts: delivery panel, ZIP host, Electron RAT C2, install path, and sideload kit co-indicator."
        reference   = "https://blueteam.cool/posts/flomo-onedrive-sideload/"
        severity    = "high"
        confidence  = "high"

    strings:
        $a = "clacndjsvulnarbi.beer" ascii nocase
        $b = "devltd.top/flomotg3.zip" ascii nocase
        $c = "finework.top" ascii nocase
        $d = "\\ExFiles\\flomo.exe" ascii nocase
        $e = "signal_config.meta" ascii nocase

    condition:
        any of them
}
