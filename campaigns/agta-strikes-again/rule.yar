// Agta strikes again - https://blueteam.cool/posts/agta-strikes-again/

rule Agta_VBS_FragmentArray_MSI_Stager
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-26"
        description = "VBScript that rebuilds a URL from an indexed fragment array, relaunches itself via ShellExecute runas, then silently installs an MSI from that URL (Agta stager)"
        reference = "https://blueteam.cool/posts/agta-strikes-again/"
        sha256 = "91c5665f5adcbc05e7e78314870a3f1f82512dca049697dddf4f03083794434c"

    strings:
        $arr   = /Dim [A-Za-z]{2,6}:[A-Za-z]{2,6}=Array\("/
        $elev  = "Named.Exists(\"elevate\")" nocase
        $sa    = "Shell.Application" nocase
        $runas = "\"runas\"" nocase
        $msi   = "msiexec /i" nocase
        $qn    = "/qn /norestart" nocase

    condition:
        filesize < 10KB and $arr and $msi and $qn and 2 of ($elev, $sa, $runas)
}

rule Agta_Backup_Panel_Response
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-09"
        description = "Agta Backup RMM C2 panel HTTP response - title fragments, four known Vite bundle hashes, version endpoint"
        reference = "https://blueteam.cool/posts/agta-strikes-again/"

    strings:
        $title_a = "Agta Backup" ascii wide
        $title_b = "Remote Sessions" ascii wide
        $bundle1 = "index-Bzqpb2VG.js" ascii
        $bundle2 = "index-Bi4rgMi_.js" ascii
        $bundle3 = "index-SxLNmN5n.js" ascii
        $bundle4 = "index-BL66RI8n.js" ascii
        $css     = "index-COWMyWXE.css" ascii
        $ver_ep  = "/AgtaBackupAgent.version" ascii
        $api     = "/api/auth/login" ascii
        $api_err = "Invalid username or password" ascii

    condition:
        ($title_a and $title_b)
        or any of ($bundle*)
        or ($css and $title_a)
        or ($ver_ep and ($api or $api_err))
}
