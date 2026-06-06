/*
 * Shellcode_HTTPS_Beacon_StackString_PEB
 *
 * Detects the x86 shellcode payload from the finger.exe / IronPython campaign.
 * The shellcode resolves kernel32 via PEB walk and constructs the C2 URL
 * character-by-character on the stack using single-char word-sized writes.
 *
 * Blog post: https://blueteam.cool/posts/finger-lolbin-ironpython/
 * Repo:      https://github.com/blueteamcoolteam/detections/tree/main/campaigns/finger-lolbin-ironpython/
 */

rule Shellcode_HTTPS_Beacon_StackString_PEB
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "x86 shellcode that resolves kernel32 via PEB walk and builds C2 URL on the stack via single-char word-sized writes. Associated with the finger.exe / IronPython campaign."
        reference   = "https://blueteam.cool/posts/finger-lolbin-ironpython/"
        sha256      = "b10b14c401bb553a8c49c0a4c8bcb9e3a01c347397e666a5b683394d26ad4df2"
        severity    = "high"
        confidence  = "high"

    strings:
        // PEB walk on x86: mov eax, fs:[0x30]
        $peb_walk = { 64 A1 30 00 00 00 }

        // Stack-string pattern for 'h' in "https" (mov reg, 0x68; mov word [ebp+x], reg)
        $https_h  = { B? 68 00 00 00 66 89 }

        // 22-byte XOR key from this campaign
        $xor_key  = { A5 44 AA E9 30 C2 84 2D 3E 12 99 11 CA 92 11 03 5B CB 19 71 94 37 }

    condition:
        uint16(0) == 0x8B55 and $peb_walk and ($https_h or $xor_key)
}
