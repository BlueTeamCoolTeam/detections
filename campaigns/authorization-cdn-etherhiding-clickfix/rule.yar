/*
   authorization-cdn-press-enter.info ClickFix / EtherHiding campaign YARA rules
   Blog post: https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/
   Author: Luke Wilkinson
   Date: 2026-07-08
   TLP: TLP:WHITE
*/

rule EtherHiding_Injected_Loader_Shape {
    meta:
        description = "Detects the injected browser-side EtherHiding loader shell on a compromised web page. The XOR key and variable names are polymorphic per site; this matches the loader shape, not the encoded payload."
        author      = "Luke Wilkinson"
        date        = "2026-07-08"
        reference   = "https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/"
        tlp         = "TLP:WHITE"

    strings:
        $wrap    = "new Function(new TextDecoder" ascii
        $atob    = "atob(" ascii
        $rpc1    = "polygon-bor-rpc.publicnode.com" ascii
        $rpc2    = "1rpc.io/matic" ascii
        $rpc3    = "polygon.drpc.org" ascii
        $rpc4    = "rpc.ankr.com/polygon" ascii
        $api     = "/api.php?s=" ascii

    condition:
        $wrap and $atob and (1 of ($rpc*) or $api)
}

rule EtherHiding_Shared_Kit_Blockchain_C2 {
    meta:
        description = "Detects the on-chain constants (contract addresses, deployer wallets, read selector) shared by all three operators running the EtherHiding ClickFix kit observed in this campaign. Operator 3 (contract3/wallet3) was discovered during a re-validation pass after publication."
        author      = "Luke Wilkinson"
        date        = "2026-07-08"
        reference   = "https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/"
        tlp         = "TLP:WHITE"

    strings:
        $contract1 = "B6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2" ascii nocase
        $contract2 = "83833C5D676cA06E941A32310AE67D0890F657eE" ascii nocase
        $contract3 = "0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55" ascii nocase
        $wallet1   = "caf2c54e400437da717cf215181b170f65187abf" ascii nocase
        $wallet2   = "f1940ddbda56074ce29bb0b6ea8d62db974870a5" ascii nocase
        $wallet3   = "2f9091ab4ec91c0daa67a7660c81a922328a8096" ascii nocase
        $selector  = "b68d1809" ascii nocase

    condition:
        any of ($contract*) or any of ($wallet*) or $selector
}

rule ClickFix_AuthCDN_PressEnter_Chain {
    meta:
        description = "Detects host and script artefacts of the authorization-cdn-press-enter.info ClickFix chain: the 5-stage PowerShell loader shape and the trojanised cmutil.dll side-load."
        author      = "Luke Wilkinson"
        date        = "2026-07-08"
        reference   = "https://blueteam.cool/posts/authorization-cdn-etherhiding-clickfix/"
        sha256      = "acdeca64b1328b6e0aab9ab0839c770cb40f370ba9857a01ab104d8c73b28064"
        tlp         = "TLP:WHITE"

    strings:
        // PowerShell decode chain shape
        $ps_stager = "iex(irm '" ascii nocase
        $ps_param  = "-UseBasicParsing" ascii nocase
        $ps_bxor   = "-bxor" ascii
        $ps_refl   = ".GetType().Assembly" ascii
        $comment   = "<#Verification ID:" ascii
        // Trojanised cmutil.dll exports
        $exp1      = "qrclfw1_nom08o" ascii
        $exp2      = "t3cclj_t58rlx" ascii
        $exp3      = "ygeui0_ew9f94" ascii
        $cm_curl   = "curl_easy_perform" ascii
        $cm_real   = "SzToWzWithAlloc" ascii
        // Decoy filler / config tokens bundled with the DLL
        $dec1      = "threshold_window" ascii
        $dec2      = "window_metric" ascii

    condition:
        (($ps_stager and $ps_param) or ($ps_bxor and $ps_refl) or $comment)
        or (2 of ($exp1,$exp2,$exp3))
        or ($cm_curl and $cm_real and any of ($dec1,$dec2))
}
