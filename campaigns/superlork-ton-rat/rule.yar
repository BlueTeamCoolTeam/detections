rule TON_C2_NodeJS_RAT_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "PowerShell AES loader for superlork[.]info Node.js RAT: downloads genuine Node.js runtime, decrypts JS payload, hides windows. TON blockchain dead-drop C2."
        reference   = "https://blueteam.cool/posts/superlork-ton-rat/"
        sha256      = "f50ebfff5370025b933ced98def534bdce4e27cbbf15dde3e4b79a85944b554e"
        severity    = "high"
        confidence  = "high"

    strings:
        $a = "RijndaelManaged" ascii nocase
        $b = "\\Nodejs" ascii
        $c = "node-v24.13.0-win-x64" ascii
        $d = "AIwc5o4UeuzKdS6kc7r4W2FO0701tRZ3BU9l7Bs3H7g=" ascii
        $e = "ShowWindow" ascii

    condition:
        3 of them
}

rule TON_C2_NodeJS_RAT_Payload
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-30"
        description = "Node.js RAT using TON blockchain get_domain dead-drop to resolve C2, ECDH+AES-256 encrypted WebSocket, and Add-MpPreference exclusion for next-stage payload."
        reference   = "https://blueteam.cool/posts/superlork-ton-rat/"
        sha256      = "da24e09777bacc92e5deafb80c446c23810c450871a295166cd54df541e9bf6d"
        severity    = "high"
        confidence  = "high"

    strings:
        $ton   = "/methods/get_domain" ascii
        $acct  = "c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9" ascii
        $alpha = "gXldcExbCIjweVsOF0PK1N2iQkpBmfuH/oYWS9atJ6nZqh38MRGy+T5zD74LArUv" ascii
        $mpref = "Add-MpPreference -ExclusionProcess" ascii
        $hs    = "completeHandshake" ascii

    condition:
        2 of them
}
