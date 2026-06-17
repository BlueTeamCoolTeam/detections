/*
 * ClickFix finger LOLBIN campaign -- YARA detection rules
 * Blog post: https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/
 * Date: 2026-06-17
 * Author: Luke Wilkinson
 *
 * Three families operating over the same TCP/79 ClickFix delivery vector:
 *   Family 1 -- IronPython loader + XOR shellcode (8 live delivery domains, 2 C2 domains)
 *   Family 2 -- Python RAT "lspy" (ChaCha20 .pyc, BunnyCDN staging, WebSocket C2)
 *   Family 3 -- Pre-positioned DigitalOcean staging cluster (no payloads served during triage)
 *
 * Static analysis only -- Family 1 final payload (~297 KB encrypted blob) was not recovered.
 */

/*
 * RULE 1 -- Campaign GUID (highest-fidelity)
 *
 * The GUID 6d6d2d17-d270-59c6-8b75-df011af08e58 appears verbatim in every Family 1
 * C2 URL path across all delivery domains and both C2 endpoints.
 * Expected false positive rate in any production environment: zero.
 */
rule ClickFix_Family1_CampaignGUID {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-17"
        description = "Family 1: campaign GUID present in every C2 URL path -- single highest-fidelity cross-domain pivot"
        reference   = "https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/"
        c2_1        = "youndor[.]com"
        c2_2        = "noidoret[.]com"
    strings:
        $guid = "6d6d2d17-d270-59c6-8b75-df011af08e58" ascii wide
    condition:
        $guid
}

/*
 * RULE 2 -- Family 1 batch loader template
 *
 * Five strings that appear unchanged across every Family 1 batch script
 * regardless of delivery domain. Variable names and finger nonces rotate;
 * these do not. Three-of-five condition reduces FP risk from partial hits.
 */
rule ClickFix_Family1_BatchLoader {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-17"
        description = "Family 1: IronPython batch loader template -- five constant strings from finger Plan field"
        reference   = "https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/"
        sha256_ref  = "2e90bc34f65407ec989ed385e051b00a56831de57ef57f95bd2e93fccfca11a8"
    strings:
        $s1 = "IronPython.3.4.2" ascii wide
        $s2 = "IronLanguages/ironpython3/releases/download/v3.4.2" ascii wide
        $s3 = "ipyw32.exe" ascii
        $s4 = "IMAGENAME eq explor" ascii
        $s5 = ".decode('utf-32')" ascii
    condition:
        3 of them
}

/*
 * RULE 3 -- Family 1 shellcode XOR keys
 *
 * Two XOR key variants. Each maps to one C2 domain. Both decrypt 8,912 bytes
 * of x86 shellcode that runs in executable heap memory inside the IronPython
 * interpreter process.
 */
rule ClickFix_Family1_ShellcodeXORKeys {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-17"
        description = "Family 1: shellcode XOR key bytes (version7/youndor.com and version2/noidoret.com paths)"
        reference   = "https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/"
    strings:
        $key_a = { 70 ce 4f 76 a3 9b 31 5c bc 1e e2 01 e9 dc 8d 87 cc 21 43 6c e3 }
        $key_b = { a1 c0 87 fe f5 19 ea a4 93 78 6a 46 61 }
    condition:
        any of them
}

/*
 * RULE 4 -- Family 2 Python RAT (lspy)
 *
 * High-fidelity strings extracted from the decrypted RAT source after
 * ChaCha20 decryption of install.pyc. Any single match is campaign-confirmed.
 */
rule ClickFix_Family2_lspy_PythonRAT {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-17"
        description = "Family 2: lspy Python RAT -- high-fidelity strings from decrypted ChaCha20 .pyc payload"
        reference   = "https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/"
        sha256_ref  = "c9ab438796cf4c720fd9129ca3b0c3b55b96849770dd9e5d8a86f9ee6923b3fd"
        c2_1        = "staruxasosiska[.]com"
        c2_2        = "starayadaet[.]com"
    strings:
        $mutex    = "MerlinMonroeBlond" ascii wide
        $pipe     = "\\\\.\\pipe\\PipingMet" ascii wide
        $authkey  = "1n9YT@Kia!enROr=" ascii
        $devpath  = "memchacharunpy" ascii wide
        $c2_a     = "staruxasosiska.com" ascii wide
        $c2_b     = "starayadaet.com" ascii wide
        $lspy_dir = "lspy" ascii wide
    condition:
        any of them
}

/*
 * RULE 5 -- Family 2 build.zip dropper (BunnyCDN)
 *
 * The PowerShell dropper response from wegrefamou.com contains these strings.
 */
rule ClickFix_Family2_BunnyCDN_Dropper {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-17"
        description = "Family 2: PowerShell dropper downloading lspy from BunnyCDN pull-zone"
        reference   = "https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/"
        sha256_ref  = "b1e2d43782d1e6f947eb93526b4fe4009d24d211730644f1f8a5a4e9a7597a5a"
    strings:
        $cdn_url  = "valval-cloud.b-cdn.net/build.zip" ascii wide
        $lspy_dir = "C:\\ProgramData\\lspy\\" ascii wide
        $install  = "install.pyc" ascii
        $pythonw  = "pythonw.exe" ascii
    condition:
        2 of them
}
