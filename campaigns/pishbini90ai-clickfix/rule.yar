rule ClickFix_pishbini90ai_WebDAV_Stager
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "Detects ClickFix cmd stager delivering a DLL via WebDAV-over-HTTPS from pishbini90ai.com. Covers the cmd paste, the DLL on disk, and the @SSL UNC path pattern."
        reference   = "https://blueteam.cool/posts/pishbini90ai-clickfix/"
        sha256      = "f39bf61a139f0571e4a6624d68d284d67e38875f8ddc648d914323aeadb4b9e1"
        severity    = "critical"
        confidence  = "high"

    strings:
        // C2 domain -- left fanged so rule matches real content
        $domain  = "pishbini90ai.com" ascii wide nocase
        // @SSL WebDAV-over-HTTPS UNC path pattern (generic to this delivery technique)
        $webdav  = "@SSL\\" ascii wide nocase
        // Randomised DLL export name at ordinal 1
        $export  = "aeertfdd" ascii
        // Word-list cipher alphabet fragment from .rdata (fiber_buf)
        $word1   = "enforcement" ascii
        $word2   = "bother" ascii
        $word3   = "wealthy" ascii
        $word4   = "literary" ascii
        // rundll32 ordinal invocation of the payload
        $rundll  = "google.cl,#1" ascii wide nocase

    condition:
        $domain or $webdav or $export or
        (3 of ($word*)) or $rundll
}


rule ClickFix_WordSubstitutionCipher_DLL
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "PE DLL with a 256-word English substitution cipher encoding a shellcode payload in .data; fiber-based execution via CreateFiber/SwitchToFiber. pishbini90ai campaign."
        reference   = "https://blueteam.cool/posts/pishbini90ai-clickfix/"
        sha256      = "f39bf61a139f0571e4a6624d68d284d67e38875f8ddc648d914323aeadb4b9e1"
        severity    = "critical"
        confidence  = "high"

    strings:
        // Null-separated word list from .rdata: \x00enforcement\x00bother\x00secret\x00
        $wordlist = { 00 65 6e 66 6f 72 63 65 6d 65 6e 74 00 62 6f 74 68 65 72 00 73 65 63 72 65 74 00 }
        // Fiber-based shellcode execution -- both imports together is unusual
        $fiber1  = "CreateFiber" ascii
        $fiber2  = "SwitchToFiber" ascii
        // DLL export name (randomised but present in this sample)
        $export  = "aeertfdd" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($wordlist or ($fiber1 and $fiber2)) and
        filesize > 2MB and filesize < 4MB
}
