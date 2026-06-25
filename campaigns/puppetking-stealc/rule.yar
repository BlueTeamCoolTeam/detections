/*
   PuppetKing / ClickFix campaign YARA rules
   Blog post: https://blueteam.cool/posts/puppetking-stealc/
   Author: Luke Wilkinson
   Date: 2026-06-25
   TLP: TLP:WHITE
*/

rule StealC_v2_PuppetKing_chain {
    meta:
        description  = "StealC v2 payload from the PuppetKing/ClickFix chain"
        author       = "Luke Wilkinson"
        date         = "2026-06-25"
        reference    = "https://blueteam.cool/posts/puppetking-stealc/"
        sha256       = "a718feaaaa975fc1b9aa069be3cd7ddfff84a7b9ff0e2dd58b0cd94929a43398"
        tlp          = "TLP:WHITE"

    strings:
        $build  = "C:\\builder_v2\\stealc" ascii
        $abe    = "app_bound_encrypted_key" ascii
        $rc4key = "SdrHT8fDmGQz9AKgYb" ascii
        $steam  = "steam_tokens.txt" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PuppetKing_ClickFix_PS_Stager {
    meta:
        description = "Detects PuppetKing ClickFix PowerShell delivery pattern"
        author      = "Luke Wilkinson"
        date        = "2026-06-24"
        reference   = "https://blueteam.cool/posts/puppetking-stealc/"
        tlp         = "TLP:WHITE"

    strings:
        // IEX+IRM stager pattern with UseBasicParsing
        $ps_stager = "iex(irm '" ascii nocase
        $ps_param  = "-UseBasicParsing" ascii nocase
        // Verification ID comment pattern
        $comment   = "<#Verification ID:" ascii
        // .beer TLD C2 domains
        $c2_1      = "verification-claude-cdn.beer" ascii nocase
        $c2_2      = "verification-js.beer" ascii nocase
        // 16-hex victim token pattern
        $token_fmt = /[0-9a-f]{16}/

    condition:
        ($ps_stager and $ps_param) or
        ($comment and $token_fmt) or
        any of ($c2_*)
}

rule PuppetKing_Blockchain_C2 {
    meta:
        description = "Detects PuppetKing Polygon blockchain C2 resolver pattern"
        author      = "Luke Wilkinson"
        date        = "2026-06-24"
        reference   = "https://blueteam.cool/posts/puppetking-stealc/"
        tlp         = "TLP:WHITE"

    strings:
        $contract = "B6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2" ascii nocase
        $selector = "b68d1809" ascii nocase
        $wallet   = "caf2c54e400437da717cf215181b170f65187abf" ascii nocase

    condition:
        any of them
}
