rule PrismVertex_Polyglot_HTA_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "Polyglot ZIP/MSIX-camouflaged HTA loader from prism-vertex[.]com - JS -> VBS -> PowerShell chain with RC4 AMSI bypass."
        reference   = "https://blueteam.cool/posts/prism-vertex-clickfix/"
        sha256      = "da9bd932ffea3bde1243750c092a6f8c6440d4f6380f71e662f37889a5c92c89"
        severity    = "high"
        confidence  = "high"

    strings:
        // Polyglot decoy ZIP entry names
        $decoy_msix    = "WidgetsPlatformRuntime-ARM64.msix" ascii
        $decoy_splash  = "Images/SplashScreen.scale-200.png" ascii

        // JScript decoder fingerprint
        $tfsep_def     = "function tfsep(){var bike=\"\""
        $arr_signature = "panamaVal=[\""
        $lcg_seed      = "handlerCnet=(240+256)"           // = 496
        $lcg_mul       = "jimPaym2=(17973+27)"              // = 18000

        // VBScript stage - IE COM moniker hex-encoded
        $ie_clsid_hex  = "6e65773a39424130353937322d463641382d313143462d413434322d3030413043393041" ascii

        // PowerShell final stage
        $rc4_key       = "BWJFEesMEqRvjQbm" ascii
        $glob_ps       = "gi C:\\W*\\S*4\\W*\\v*\\p*ell.exe" ascii
        $de_morgan_xor = "-bnot(" ascii

        // C2 strings (left fanged so the rule matches real content)
        $stage5_apex   = "creativecommunityinfo.art" ascii
        $stage1_apex   = "prism-vertex.com" ascii

    condition:
        // Polyglot on disk
        (uint32(0) == 0x04034B50 and $decoy_msix and $decoy_splash and ($tfsep_def or $arr_signature) and ($lcg_seed or $lcg_mul))
        or
        // Decrypted PowerShell stage if it ever lands
        ($rc4_key and $glob_ps and $de_morgan_xor)
        or
        // Cleartext C2 strings together
        ($stage1_apex and $stage5_apex)
}
