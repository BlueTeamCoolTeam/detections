/*
 * ClickFix_Finger_IronPython_Loader
 *
 * Detects artifacts from a ClickFix campaign that uses finger.exe as a LOLBIN
 * to deliver IronPython, which runs a Cyrillic-obfuscated shellcode injector
 * delivering an in-process x86 HTTPS beacon to noidoret.com.
 *
 * Blog post: https://blueteam.cool/posts/finger-lolbin-ironpython/
 * Repo:      https://github.com/blueteamcoolteam/detections/tree/main/campaigns/finger-lolbin-ironpython/
 */

rule ClickFix_Finger_IronPython_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "ClickFix campaign: finger.exe LOLBIN + IronPython interpreter abuse delivering an in-process x86 shellcode beacon. C2 at noidoret.com."
        reference   = "https://blueteam.cool/posts/finger-lolbin-ironpython/"
        sha256_s2   = "67f4eb14aca5aa26836ab6dcb8a81ab70c24fafbca98f83eb2afb4e6b5042b9f"
        sha256_s3   = "62410859cf8b160cd0cb57ec972e8e77ec6d379fa1fd5b69f7d75d54d10ab5e4"
        severity    = "high"
        confidence  = "high"

    strings:
        // Campaign UUID across all stages
        $uuid          = "6d6d2d17-d270-59c6-8b75-df011af08e58" ascii

        // Stage 3 build marker
        $marker        = "#sNMat9" ascii

        // C2 + finger delivery domains (fanged so the rule matches real content)
        $c2            = "noidoret.com" ascii
        $finger_apex   = "livnesticity.com" ascii

        // Stage 4 Cyrillic substitution fingerprint (one pair shown)
        $cyrillic_pair = ".replace('\xd0\x9c', 'p').replace('\xd1\x85', 'a')" ascii

        // ctypes heap exec pattern
        $heap_exec     = "HeapCreate(0x00040000" ascii
        $rtl_move      = "RtlMoveMemory" ascii

        // IronPython drop directory artifact
        $ironpy_dir    = "IronPython.3.4.2" ascii

        // ClickFix lure text from cmd.exe command line
        $lure          = "---Verify ----------------press ENTER---" ascii

    condition:
        any of ($uuid, $marker, $finger_apex, $lure)
        or ($c2 and ($cyrillic_pair or $heap_exec or $ironpy_dir))
        or all of ($rtl_move, $heap_exec)
}
