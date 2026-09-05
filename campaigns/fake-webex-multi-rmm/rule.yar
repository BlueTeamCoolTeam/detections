rule RMM_RockyRMM_Go_Client
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-05"
        description = "Detects the 'rocky-rmm' Go-based RAT/RMM client delivered via GitHub-Releases-hosted zip masquerading as Webex/ClientSetup installer"
        reference = "https://blueteam.cool/posts/fake-webex-multi-rmm/"
        sha256 = "b2d4a28d676567dfbc292c89e1528393c9d6e3823ef31ae68cbc1d51373734a0"

    strings:
        $mod1 = "rocky-rmm/client" ascii
        $mod2 = "rocky-rmm/client/persistence" ascii
        $mod3 = "rocky-rmm/client/handlers" ascii
        $mod4 = "rocky-rmm/client/connection" ascii
        $devpath = "ROCKY_RMM/client" ascii

        $c2 = "ws://rockytomholland.casacam.net:5222/ws/client" ascii

        $vbs1 = "Set oWS = WScript.CreateObject(\"WScript.Shell\")" ascii
        $vbs2 = "Set oLink = oWS.CreateShortcut(sLinkFile)" ascii
        $vbs3 = "oLink.Description = \"Rocky RMM Client\"" ascii
        $lnkname = "RockyRMMClient.lnk" ascii

        $msg1 = "Rocky RMM Client starting..." ascii
        $msg2 = "Installing persistence (startup folder)..." ascii
        $msg3 = "Warning: Failed to install persistence: %v" ascii
        $cleanup = "rmm_cleanup.bat" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($mod*) or
            $c2 or
            2 of ($vbs*) or
            ($lnkname and $msg1) or
            $devpath or
            $msg2 or
            $msg3 or
            $cleanup
        )
}

rule RMM_Generic_VBScript_Shortcut_Persistence_Template
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-05"
        description = "Detects the specific WScript.Shell CreateShortcut VBScript template embedded in the rocky-rmm loader for Startup-folder LNK persistence -- broader hunt for the same builder/technique in other samples"
        reference = "https://blueteam.cool/posts/fake-webex-multi-rmm/"

    strings:
        $a = "Set oWS = WScript.CreateObject(\"WScript.Shell\")" ascii
        $b = "sLinkFile = \"%s\"" ascii
        $c = "Set oLink = oWS.CreateShortcut(sLinkFile)" ascii
        $d = "oLink.TargetPath = \"%s\"" ascii
        $e = "oLink.WorkingDirectory = \"%s\"" ascii

    condition:
        all of them
}

rule webex_firewallapi_sideload_screenconnect_loader
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-05"
        description = "MinGW FirewallAPI.dll sideload crypter: XOR-0xB8 drop of ScreenConnect popesc.msi (Leg 2b of the fake-Webex multi-RMM campaign)"
        reference = "https://blueteam.cool/posts/fake-webex-multi-rmm/"
        sha256 = "e34d536310e864bf62e8119a9465027b3a654662b8ade3d301f588fb01b1f578"
    strings:
        $exp1 = "NetworkIsolationEnumAppContainers" ascii
        $exp2 = "NetworkIsolationSetAppContainerConfig" ascii
        $drop = "popesc.msi" ascii
        $tmp  = "C:\\temp" ascii
        $xor  = { 0F B6 14 01 83 F2 B8 88 14 03 }
    condition:
        uint16(0) == 0x5A4D and 2 of ($exp*) and ($drop or $xor or $tmp)
}

rule screenconnect_relay_167_94_158_48
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-05"
        description = "Config strings tying a ScreenConnect client to the shared fake-Webex campaign relay/instance (Legs 2a/2b/2c)"
        reference = "https://blueteam.cool/posts/fake-webex-multi-rmm/"
    strings:
        $r = "h=167.94.158.48&p=8041" ascii wide
        $i = "sc-d08195f142b8bd3b" ascii wide
    condition:
        any of them
}

rule AgtaBackupAgent_DotNet_RAT_Components
{
    meta:
        author = "blueteam.cool"
        date = "2026-09-05"
        description = "Detects the 5 .NET 8 single-file components dropped by the Agta Backup Agent MSI (Leg 4) -- custom RAT with hVNC, keylogger, and browser-profile theft masquerading as security tooling"
        reference = "https://blueteam.cool/posts/fake-webex-multi-rmm/"
        sha256 = "08fd986e5b54bbd56419df4a4a23a39ec2b176f224b76a6743d3a364049e6ab0"
    strings:
        $c2_url = "155.254.99.248" ascii
        $c2_secret = "agta-enroll-7f3a1c2d9e" ascii
        $checkin = "/api/agents/checkin" ascii
        $svc_flag = "--install-service" ascii
        $watchdog = "--keep-watchdog" ascii
        $desktop = "AgtaBackstage" ascii wide
        $pipe1 = "agta-keylog-drain" ascii wide
        $pipe2 = "agta-ws-stream" ascii wide
        $masq1 = "Credential Guard" ascii wide
        $masq2 = "Dell.Virus.Guard" ascii wide
        $masq3 = "Window Security Health Services" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (
            ($c2_url and $checkin) or
            $c2_secret or
            2 of ($pipe*) or
            (2 of ($masq*) and ($svc_flag or $watchdog or $desktop))
        )
}
