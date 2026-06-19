/*
  STAR Campaign YARA Rules
  Author:    Luke Wilkinson
  Date:      2026-06-19
  Reference: https://blueteam.cool/posts/star-rmm-turf-war/
  Coverage:  QBO/wallet stealer scripts and competitor eviction script
*/

rule STAR_QBO_TelegramStealer {
    meta:
        description  = "STAR campaign QBO/wallet harvester -- Telegram bot exfiltration"
        author       = "Luke Wilkinson"
        date         = "2026-06-19"
        reference    = "https://blueteam.cool/posts/star-rmm-turf-war/"
    strings:
        // Bot tokens -- one per data stream
        $tok1   = "8561959266:AAEI32HfP40cKQwtAtSyS6o9Srcjd7W7B9A"   // @Check12899_bot (QBO)
        $tok2   = "8638944609:AAECv0FW5fCFPxp4cNz-Mp856SyocgfEgdA"   // @AndrewTateSigma_bot (wallets)
        $tok3   = "8662428383:AAE7q7noOfH_12SZJPCQNB1A98DqnyAn344"   // @botbybost_bot (browser history)
        // Chat IDs
        $chat1  = "-1003277400990"     // Checker Channel
        $chat2  = "-5212689198"        // APPLY group
        // Host artefacts
        $log    = "C:\\H\\telegram_bg.log"
        $dir    = "C:\\H\\tg_send_"
        // Panel identifiers
        $panel  = "dentalfaxgateSTAR"
        $panel2 = "digitalacces_Star"
        // Runtime-compiled BHS class
        $bhs    = "public static class BHS"
    condition:
        any of ($tok*) or
        any of ($chat*) or
        $log or $dir or
        any of ($panel*) or
        $bhs
}

rule STAR_CompetitorEviction_v3 {
    meta:
        description  = "STAR campaign Star_v3 competitor cleanup and trace-wipe script"
        author       = "Luke Wilkinson"
        date         = "2026-06-19"
        reference    = "https://blueteam.cool/posts/star-rmm-turf-war/"
    strings:
        // Whitelist instance IDs (actor-owned panels)
        $wl1    = "8df439ea69ba1ba8"   // digitalacces_Star
        $wl2    = "bafd0ea8d422c32c"   // office101_VIP
        $wl3    = "dentalfaxgateSTAR"
        $wl4    = "office101_VIP"
        $wl5    = "digitalacces_Star"
        // Protected RMM pattern (never removed -- exemption logic)
        $prot   = "SimpleHelp|JWrapper|Remote Access|TacticalRMM"
        // Trace wipe signature
        $wevt   = "wevtutil cl"
        // Competitor persistence task name (one of 18 removed)
        $scht   = "BabaiMazai"
    condition:
        (2 of ($wl*)) or
        ($prot and $wevt) or
        $scht
}

rule STAR_WalletScanner_SYSTEM {
    meta:
        description  = "STAR campaign SYSTEM-level crypto wallet scanner"
        author       = "Luke Wilkinson"
        date         = "2026-06-19"
        reference    = "https://blueteam.cool/posts/star-rmm-turf-war/"
    strings:
        // Bot token (wallet data channel)
        $tok    = "8638944609:AAECv0FW5fCFPxp4cNz-Mp856SyocgfEgdA"
        // Wallet extension IDs checked by scanner
        $meta   = "nkbihfbeogaeaoehlefnkodbefgpgknn"    // MetaMask
        $phant  = "bfnaelmomeimhlpmgjnjophhpkkoljpa"    // Phantom
        $okx    = "mcohilncbfahbmgdjkbpemcciiolgcge"    // OKX Wallet
        // SYSTEM scan comment in source
        $sys    = "# Designed to run as SYSTEM - scans all user profiles"
        // Recipient user IDs (DM targets)
        $uid1   = "7423684294"    // @sadfewego
        $uid2   = "8238936394"    // @head_exp
    condition:
        $tok or
        (2 of ($meta, $phant, $okx)) or
        $sys or
        ($uid1 and $uid2)
}
