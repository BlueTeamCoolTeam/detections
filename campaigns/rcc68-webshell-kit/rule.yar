rule Webshell_ASPX_RCC68_ShellKit
{
    meta:
        description = "ASP.NET inline web shell using shared 'rcc68' auth token, disguised as static asset files"
        author = "Luke Wilkinson"
        date = "2026-08-29"
        reference = "https://blueteam.cool/posts/rcc68-webshell-kit/"

    strings:
        $token1 = "rcc68" ascii
        $psi1   = "ProcessStartInfo" ascii
        $psi2   = "ComSpec" ascii
        $psi3   = "RedirectStandardOutput" ascii wide
        $psi4   = "CreateNoWindow=true" ascii
        $b64    = "FromBase64String" ascii
        $hdr    = "X-RCC-Key" ascii
        $fileop = /Directory\.GetFileSystemEntries|File\.ReadAllText|File\.WriteAllText/ ascii

    condition:
        filesize < 5KB
        and $token1
        and ( (2 of ($psi1,$psi2,$psi3,$psi4) and $b64) or $hdr or $fileop )
}
