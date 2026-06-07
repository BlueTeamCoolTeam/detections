rule WMail_Service_Steganographic_Carrier
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-23"
        description = "Carrier file (often .sys, lives in System32\\drivers\\<rand>\\) padded with repeated SSRS log lines and a Base64 PowerShell beacon for counter[.]wmail-service[.]com hidden at a fixed offset."
        reference   = "https://blueteam.cool/posts/wmail-service-stego-beacon/"
        sha256      = "e780a5c6284d89bb35d506ee31fcad09435a34838c4844acf87ba26124aaa538"
        severity    = "high"
        confidence  = "high"

    strings:
        $filler1 = "Failed to load dependency Microsoft.AnalysisServices.AdomdClient of assembly Microsoft.ReportingServices.DataExtensions"
        $filler2 = "Die gefundene Manifestdefinition der Assembly stimmt nicht mit dem Assemblyverweis"
        $filler3 = "0x80131040"

        // base64 substrings of stable parts of the decoded loop
        $b64_uri   = "aHR0cDovL2NvdW50ZXIud21haWwtc2VydmljZS5jb20"     // hxxp://counter[.]wmail-service[.]com
        $b64_block = "U2NyaXB0QmxvY2tdOjpDcmVhdGUo"                     // ScriptBlock]::Create(
        $b64_job   = "U3RhcnQtSm9i"                                      // Start-Job

        // cleartext fallback if the decoded stage hits disk
        $ct_uri  = "counter.wmail-service.com"
        $ct_tag  = "DownloadsCounter_"
        $ct_loop = "[ScriptBlock]::Create($r)" ascii

    condition:
        (2 of ($filler*) and 1 of ($b64_*))
        or (2 of ($ct_*))
}
