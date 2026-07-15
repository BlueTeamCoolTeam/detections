rule Betwanaa_Boroo_WebDAV_RunDLL32_Loader_CmdLine
{
    meta:
        author      = "blueteam.cool"
        date        = "2026-07-15"
        description = "Detects the betwanaa.com/boroo.bet/1bet1yek.bet/site-shartbandi-farsi.com/casinomhub.bet-cluster WebDAV@SSL->rundll32 gc.key loader command line (pcalua.exe proxy layer optional)"
        reference   = "https://blueteam.cool/posts/betwanaa-boroo-webdav-etherhiding/"
    strings:
        $lolbin      = "pcalua.exe" ascii wide nocase
        $webdav_ssl  = "@SSL\\" ascii wide nocase
        $rundll_ord  = "rundll32" ascii wide nocase
        $ord_call    = ",#1" ascii wide
        $delayexp    = /set [a-d]=[a-z0-9]{2,6}&set/ ascii nocase
        $payload     = "gc.key" ascii wide nocase
        $domain1     = "betwanaa.com" ascii wide nocase
        $domain2     = "boroo.bet" ascii wide nocase
        $domain3     = "1bet1yek.bet" ascii wide nocase
        $domain4     = "shartbandi" ascii wide nocase
        $domain5     = "casinomhub.bet" ascii wide nocase
    condition:
        ( $webdav_ssl and $ord_call and $delayexp ) or
        ( $lolbin and $webdav_ssl and $rundll_ord ) or
        ( $webdav_ssl and $payload ) or
        any of ($domain*)
}

rule Betwanaa_Boroo_MacOS_CurlBash_Loader_CmdLine
{
    meta:
        author      = "blueteam.cool"
        date        = "2026-07-15"
        description = "Detects the macOS-branch curl-pipe-bash variant of this same campaign (bahigo90bet.com) - a distinct execution mechanism from the Windows WebDAV/rundll32 pattern, decoded independently during this campaign's revalidation, not documented anywhere previously"
        reference   = "https://blueteam.cool/posts/betwanaa-boroo-webdav-etherhiding/"
    strings:
        $bash      = "/bin/bash -c" ascii wide
        $curl_ua   = "Mac OS X 10_15_7" ascii wide
        $ublib     = "?ublib=" ascii wide
        $domain    = "bahigo90bet.com" ascii wide nocase
        $botguard  = "BotGuard: Answer the protector challenge" ascii wide
    condition:
        ( $bash and $curl_ua ) or ( $bash and $ublib ) or $domain or $botguard
}

rule Betwanaa_Boroo_gckey_PE_Hash
{
    meta:
        author      = "blueteam.cool"
        date        = "2026-07-15"
        description = "Known gc.key payload build recovered via OSINT (urlscan file index), 1bet1yek.bet 2026-07-06 - not independently re-obtained during revalidation (all remote copies already retired)"
        reference   = "https://blueteam.cool/posts/betwanaa-boroo-webdav-etherhiding/"
    condition:
        hash.sha256(0, filesize) == "f11057ab58bef936d98ba189829c64260a6a540cdaa046f93613138e820c98c6"
}

rule EtherHiding_ClickFix_JS_Injection_BSCTestnet
{
    meta:
        author      = "blueteam.cool"
        date        = "2026-07-15"
        description = "EtherHiding fake-CAPTCHA ClickFix injection (BSC-testnet loader) seen on compromised WordPress sites feeding the gc.key/WebDAV or curl-bash loader - independently re-decoded and reconfirmed against 7 live contracts during revalidation"
        reference   = "https://blueteam.cool/posts/betwanaa-boroo-webdav-etherhiding/, symmetryclosets.com"
    strings:
        $rpc     = "bsc-testnet-rpc.publicnode.com" ascii wide
        $sel     = "0x6d4ce63c" ascii wide          // get() selector
        $eas     = "id=\"_ea_s\"" ascii wide
        $avast   = "ip-info.ff.avast.com/v2/info" ascii wide
        $gate    = "0x24513bb6" ascii wide          // session-goal gate selector
        $ym      = "99162160" ascii wide            // Yandex Metrika campaign id
        $ethcall = "eth_call" ascii wide
        $clip    = "clipboard" ascii wide
        $headless = "isHeadless" ascii wide
    condition:
        ($rpc and $sel) or ($eas) or ($rpc and $ethcall and $clip) or
        (2 of ($avast,$gate,$ym,$headless))
}
