rule WMI_NetCon_EtherHiding_JScript_Backdoor
{
    meta:
        description = "Fileless WMI ActiveScriptEventConsumer JScript backdoor resolving C2 via Ethereum smart-contract storage (EtherHiding), RC4-decrypting tasking, and eval()-executing it"
        date        = "2026-07-10"
        author      = "blueteam.cool"
        reference   = "https://blueteam.cool/posts/netcon-wmi-etherhiding/"
        sha256      = "59e9efb252e12a8c634b126aa5d49e38b5137e03110b4327974852d3f4872541"
    strings:
        $consumer_name  = "NetCon" ascii wide
        $eth_method     = "eth_getStorageAt" ascii
        $rpc_endpoint   = "ethereum.publicnode.com" ascii
        $signin_path    = "/signin?e=1" ascii
        $clb_path       = "/clb?uuid=" ascii
        $callback_hdr   = "X-Callback-Id" ascii
        $rc4_ksa        = "for(i=0;i<256;i++)s[i]=i" ascii
        $xhr_obj        = "Msxml2.ServerXMLHTTP.6.0" ascii wide
        $uuid_sample    = "15aee2fa-27bc-4322-942c-144f35dc7bda" ascii
    condition:
        3 of ($consumer_name, $eth_method, $rpc_endpoint, $signin_path, $clb_path, $callback_hdr, $rc4_ksa, $xhr_obj)
        or $uuid_sample
}
