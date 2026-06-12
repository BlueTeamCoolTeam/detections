rule sindikat_webshell_stage1 {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-12"
        description = "toolbar-processor-428 WordPress plugin dropper -- matches on embedded Telegram handles or unauthenticated file upload function"
        reference   = "https://blueteam.cool/posts/wordpress-webshell-gsocket/"
        sha256      = "N/A -- file hash not available for this sample"
    strings:
        $tg1 = "@WebshellSR" ascii
        $tg2 = "@Devco1"     ascii
        $tg3 = "@BIBIL0DAY"  ascii
        $up  = "copy($_FILES['__']['tmp_name'], $_FILES['__']['name'])" ascii
    condition:
        any of ($tg*) or $up
}

rule sindikat_webshell_stage2 {
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-06-12"
        description = "byp.php binary-encoded webshell -- matches binary-blob encoding pattern or unique parameter/helper names, encoded or decoded"
        reference   = "https://blueteam.cool/posts/wordpress-webshell-gsocket/"
        sha256      = "N/A -- file hash not available for this sample"
    strings:
        $enc  = /\$binary_data\s*=\s*"[01]{8},[01]{8}/  // binary blob variable start
        $p1   = "sindikat777" ascii
        $p2   = "c0m99nd"     ascii
        $h1   = "chDxzZ"      ascii
        $h2   = "chDxXZ"      ascii
    condition:
        $enc or (2 of ($p1, $p2, $h1, $h2))
}
