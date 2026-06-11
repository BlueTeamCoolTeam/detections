rule ClickFix_CaptchaCode_PS_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "ClickFix RC4+GZip PowerShell loader (captcha-code[.]lol)"
        reference   = "https://blueteam.cool/posts/clickfix-captcha-code-lol/"
        sha256      = "ff2f74cc198a07ea7bf4457dd9e5c0e0adc5b073b5e50d4f13d32b753d7be744"
        severity    = "critical"
        confidence  = "high"

    strings:
        // RC4 PRGA keystream XOR -- distinctive inline implementation
        $rc4  = "-bxor $S[($S[$i] + $S[$j]) % 256]" ascii
        // GZip decompression class used after RC4 decode
        $gz   = "IO.Compression.GzipStream" ascii
        // Invoke-Expression split across string concat to evade string matching
        $iex  = "'I' + 'nv' + 'ok' + 'e-E' + 'xpr' + 'ess' + 'ion'" ascii
        $junk = "Random junk" ascii
        // C2 beacon domain -- left fanged so rule matches real content
        $beac = "captcha-code.lol" ascii
        // WORKGROUP victim tag used in beacon POST body
        $tagA = "ABCD111" ascii
        // Domain-joined victim tag used in beacon POST body
        $tagB = "BCDA222" ascii

    condition:
        2 of ($rc4,$gz,$iex,$junk) or $beac or any of ($tagA,$tagB)
}


rule ClickFix_CaptchaCode_AntiAnalysis_List
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "Stage-5 sandbox/VM process check (decoded anti-analysis tool list)"
        reference   = "https://blueteam.cool/posts/clickfix-captcha-code-lol/"
        sha256      = "bc25823b5a15b3fd607eba3e716d4bfab05391bc3a73c7603fba5d43ee25deab"
        severity    = "high"
        confidence  = "medium"

    strings:
        // Analysis tools from the decoded 50-item process check list
        $a = "detectiteasy" ascii nocase
        $b = "cheatengine" ascii nocase
        $c = "qemu-ga" ascii nocase
        $d = "prl_cc" ascii nocase
        $e = "VMwareTray" ascii nocase
        $f = "processhacker" ascii nocase

    condition:
        4 of them
}


rule Stealer_Rust_chapter_BrowserExt
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "Rust infostealer: extension force-install + LSA enum (captcha-code[.]lol campaign)"
        reference   = "https://blueteam.cool/posts/clickfix-captcha-code-lol/"
        sha256      = "372df5bac7bce42e403cd024589eec0f76c2b3ed92bd30a5cb34948a0662c2a1"
        severity    = "critical"
        confidence  = "high"

    strings:
        // Build path leaks developer username; pivot for cross-sample clustering
        $dev  = "/Users/chapter/.cargo/registry" ascii
        // Secure Preferences HMAC tamper logic (bypass developer mode guard)
        $pref = "src/internal/secureprefs" ascii
        // Run key value name used for persistence
        $reg  = "ibrowser" ascii
        // C2 checkin API path
        $chk  = "/api/v1/checkin" ascii
        // Direct LSA API import for full logon session enumeration
        $lsa  = "LsaEnumerateLogonSessions" ascii
        // MZ header
        $mz   = { 4D 5A }

    condition:
        $mz at 0 and 2 of ($dev,$pref,$reg,$chk,$lsa)
}


rule Lunex_Panel_JS_Bundle
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-11"
        description = "Lunex C2 panel JS bundle (bilingual EN/RU; detect during IR or threat hunting)"
        reference   = "https://blueteam.cool/posts/clickfix-captcha-code-lol/"
        severity    = "critical"
        confidence  = "high"

    strings:
        // Panel brand name
        $brand   = "LUNEX" ascii
        // Bilingual i18n key unique to this panel
        $i18n    = "lunex_i18n_lang" ascii
        // Bot list API path
        $remote  = "/api/v1/bots/" ascii
        // Injection rule URL pattern key
        $inject  = "url_pattern" ascii
        // Domain spoof source handle
        $spoof   = "spoof.sourcePh" ascii
        // WebSocket URL construction for remote browser control
        $ws      = "replace(/^http/i" ascii

    condition:
        4 of them
}


rule Shellcode_Loader_Multiplier83_Hash
{
    meta:
        author           = "Luke Wilkinson"
        date             = "2026-06-11"
        description      = "PIC shellcode loader using imul-0x83 API-hash resolver (captcha-code[.]lol campaign)"
        reference        = "https://blueteam.cool/posts/clickfix-captcha-code-lol/"
        sha256_encrypted = "475a242cdd832aa43b562ffb6abf3fee1e7f0479425b9c00434a4a44b5c60f14"
        severity         = "critical"
        confidence       = "high"
        note             = "sha256_encrypted: file as-recovered (XOR 0x3B transport cipher); inner payload runtime-encrypted, family not recovered statically"

    strings:
        // imul eax,eax,0x83 -- multiplier-83 hash accumulator (custom API resolver)
        $hash83  = { 69 C0 83 00 00 00 }
        // Force-lowercase: cmp r8b,0x60; jg; add r8d,0x20 (normalise API name before hashing)
        $lcase   = { 41 80 F8 60 7F ?? 41 83 C0 20 }
        // 4-byte disk header magic for XOR 0x3B encoded file (lol\x0a = 0x6C 0x0A 0xFB 0x82 after XOR)
        $disk_hdr = { 6C 0A FB 82 }

    condition:
        ($hash83 and $lcase) or $disk_hdr at 0
}
