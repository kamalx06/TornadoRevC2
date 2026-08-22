"""Windows certificate store enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_certificate_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'

$start='{PLUGIN_MARK_START}'
$end='{PLUGIN_MARK_END}'

$now = Get-Date
$expiryThreshold = $now.AddDays(30)

$stores = @(
    @{{ location='LocalMachine'; store='My' }},
    @{{ location='LocalMachine'; store='Root' }},
    @{{ location='LocalMachine'; store='CA' }},
    @{{ location='LocalMachine'; store='TrustedPublisher' }},
    @{{ location='LocalMachine'; store='AuthRoot' }},
    @{{ location='LocalMachine'; store='Remote Desktop' }},
    @{{ location='CurrentUser';  store='My' }},
    @{{ location='CurrentUser';  store='Root' }},
    @{{ location='CurrentUser';  store='CA' }},
    @{{ location='CurrentUser';  store='TrustedPublisher' }},
    @{{ location='CurrentUser';  store='AuthRoot' }}
)

$certs = @()

function Get-EkuInfo {{
    param($Certificate)

    $items = @()

    foreach ($extension in $Certificate.Extensions) {{
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {{
            foreach ($oid in $extension.EnhancedKeyUsages) {{
                $items += [ordered]@{{
                    oid  = $oid.Value
                    name = $oid.FriendlyName
                }}
            }}
        }}
    }}

    return ,$items
}}

function Get-KeyUsageInfo {{
    param($Certificate)

    $items = @()

    foreach ($extension in $Certificate.Extensions) {{
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {{
            $flags = $extension.KeyUsages

            foreach ($flag in [Enum]::GetValues([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags])) {{
                if ($flag -ne 0 -and ($flags -band $flag) -eq $flag) {{
                    $items += $flag.ToString()
                }}
            }}
        }}
    }}

    return ,($items | Select-Object -Unique)
}}

function Get-BasicConstraintsInfo {{
    param($Certificate)

    foreach ($extension in $Certificate.Extensions) {{
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {{
            return [ordered]@{{
                is_ca             = [bool]$extension.CertificateAuthority
                has_path_length   = [bool]$extension.HasPathLengthConstraint
                path_length       = if ($extension.HasPathLengthConstraint) {{ $extension.PathLengthConstraint }} else {{ $null }}
            }}
        }}
    }}

    return [ordered]@{{
        is_ca           = $false
        has_path_length = $false
        path_length     = $null
    }}
}}

function Get-SanInfo {{
    param($Certificate)

    $dns = @()
    $ip = @()
    $email = @()
    $uri = @()
    $upn = @()

    foreach ($extension in $Certificate.Extensions) {{
        if ($extension.Oid.Value -eq '2.5.29.17') {{
            $formatted = $extension.Format($false)

            foreach ($line in ($formatted -split "`r?`n")) {{
                $value = $line.Trim()

                if ($value -match '^DNS Name=(.+)$') {{
                    $dns += $Matches[1].Trim()
                }}
                elseif ($value -match '^IP Address=(.+)$') {{
                    $ip += $Matches[1].Trim()
                }}
                elseif ($value -match '^RFC822 Name=(.+)$') {{
                    $email += $Matches[1].Trim()
                }}
                elseif ($value -match '^URL=(.+)$') {{
                    $uri += $Matches[1].Trim()
                }}
                elseif ($value -match '^Other Name=.*UPN.*=(.+)$') {{
                    $upn += $Matches[1].Trim()
                }}
            }}
        }}
    }}

    return [ordered]@{{
        dns   = @($dns | Select-Object -Unique)
        ip    = @($ip | Select-Object -Unique)
        email = @($email | Select-Object -Unique)
        uri   = @($uri | Select-Object -Unique)
        upn   = @($upn | Select-Object -Unique)
    }}
}}

function Get-KeyInfo {{
    param($Certificate)

    $algorithm = $null
    $keySize = $null

    try {{
        $publicKey = $Certificate.PublicKey

        if ($publicKey) {{
            $algorithm = $publicKey.Oid.FriendlyName
            if (-not $algorithm) {{
                $algorithm = $publicKey.Oid.Value
            }}

            try {{
                $keySize = $publicKey.Key.KeySize
            }} catch {{}}
        }}
    }} catch {{}}

    return [ordered]@{{
        algorithm = $algorithm
        key_size  = $keySize
    }}
}}

function Get-SignatureAlgorithm {{
    param($Certificate)

    try {{
        if ($Certificate.SignatureAlgorithm) {{
            return [ordered]@{{
                name = $Certificate.SignatureAlgorithm.FriendlyName
                oid  = $Certificate.SignatureAlgorithm.Value
            }}
        }}
    }} catch {{}}

    return [ordered]@{{
        name = $null
        oid  = $null
    }}
}}

function Get-ValidityState {{
    param($Certificate)

    if ($Certificate.NotAfter -lt $now) {{
        return 'expired'
    }}

    if ($Certificate.NotBefore -gt $now) {{
        return 'not_yet_valid'
    }}

    if ($Certificate.NotAfter -le $expiryThreshold) {{
        return 'expiring_soon'
    }}

    return 'valid'
}}

function Get-HasPrivateKey {{
    param($Certificate)

    try {{
        return [bool]$Certificate.HasPrivateKey
    }} catch {{
        return $false
    }}
}}

foreach ($entry in $stores) {{
    $location = $entry.location
    $store = $entry.store

    Get-ChildItem "Cert:\\$location\\$store" -ErrorAction SilentlyContinue |
        ForEach-Object {{

            $cert = $_

            $eku = @(Get-EkuInfo $cert)
            $keyUsage = @(Get-KeyUsageInfo $cert)
            $basicConstraints = Get-BasicConstraintsInfo $cert
            $san = Get-SanInfo $cert
            $keyInfo = Get-KeyInfo $cert
            $signature = Get-SignatureAlgorithm $cert
            $validity = Get-ValidityState $cert
            $hasPrivateKey = Get-HasPrivateKey $cert

            $selfSigned = ($cert.Subject -eq $cert.Issuer)

            $ekuNames = @(
                $eku |
                ForEach-Object {{
                    if ($_.name) {{ $_.name }} else {{ $_.oid }}
                }}
            )

            $isCodeSigning = (
                ($ekuNames -join ',') -match 'Code Signing' -or
                $cert.Subject -match 'Code Signing'
            )

            $isServerAuth = (
                ($eku | Where-Object {{ $_.oid -eq '1.3.6.1.5.5.7.3.1' }}).Count -gt 0
            )

            $isClientAuth = (
                ($eku | Where-Object {{ $_.oid -eq '1.3.6.1.5.5.7.3.2' }}).Count -gt 0
            )

            $isEnterprise = (
                $cert.Issuer -match 'Enterprise|Corp|ADCS|CA' -or
                $cert.Subject -match 'Enterprise|Corp|ADCS|CA'
            )

            $weakSignature = (
                $signature.name -match 'SHA1|MD5' -or
                $signature.oid -in @(
                    '1.2.840.113549.1.1.5',
                    '1.2.840.113549.1.1.4'
                )
            )

            $weakKey = (
                ($keyInfo.algorithm -match 'RSA' -and
                 $keyInfo.key_size -and
                 $keyInfo.key_size -lt 2048)
            )

            $certs += [ordered]@{{
                store_location      = $location
                store_name          = $store

                subject             = $cert.Subject
                issuer              = $cert.Issuer
                thumbprint          = $cert.Thumbprint
                serial_number       = $cert.SerialNumber

                not_before          = $cert.NotBefore.ToString('s')
                not_after           = $cert.NotAfter.ToString('s')
                validity_state      = $validity

                self_signed         = $selfSigned
                has_private_key     = $hasPrivateKey

                public_key          = $keyInfo
                signature_algorithm = $signature

                eku                 = $eku
                key_usage           = $keyUsage

                basic_constraints   = $basicConstraints
                san                 = $san

                is_ca               = [bool]$basicConstraints.is_ca
                is_code_signing     = $isCodeSigning
                is_server_auth      = $isServerAuth
                is_client_auth      = $isClientAuth
                is_enterprise       = $isEnterprise

                weak_signature      = $weakSignature
                weak_key            = $weakKey
            }}
        }}
}}

$expired = @(
    $certs | Where-Object {{ $_.validity_state -eq 'expired' }}
)

$expiringSoon = @(
    $certs | Where-Object {{ $_.validity_state -eq 'expiring_soon' }}
)

$notYetValid = @(
    $certs | Where-Object {{ $_.validity_state -eq 'not_yet_valid' }}
)

$valid = @(
    $certs | Where-Object {{ $_.validity_state -eq 'valid' }}
)

$selfSigned = @(
    $certs | Where-Object {{ $_.self_signed }}
)

$caCerts = @(
    $certs | Where-Object {{ $_.is_ca }}
)

$rootCaCerts = @(
    $certs | Where-Object {{
        $_.is_ca -and $_.store_name -eq 'Root'
    }}
)

$codeSigning = @(
    $certs | Where-Object {{ $_.is_code_signing }}
)

$serverAuth = @(
    $certs | Where-Object {{ $_.is_server_auth }}
)

$clientAuth = @(
    $certs | Where-Object {{ $_.is_client_auth }}
)

$enterprise = @(
    $certs | Where-Object {{ $_.is_enterprise }}
)

$privateKeyAssociated = @(
    $certs | Where-Object {{ $_.has_private_key }}
)

$weakSignature = @(
    $certs | Where-Object {{ $_.weak_signature }}
)

$weakKey = @(
    $certs | Where-Object {{ $_.weak_key }}
)

$result = [ordered]@{{
    summary = [ordered]@{{
        total                       = $certs.Count
        valid                       = $valid.Count
        expired                     = $expired.Count
        expiring_soon               = $expiringSoon.Count
        not_yet_valid               = $notYetValid.Count
        self_signed                 = $selfSigned.Count
        ca_certificates             = $caCerts.Count
        root_ca_certificates        = $rootCaCerts.Count
        code_signing                = $codeSigning.Count
        server_authentication       = $serverAuth.Count
        client_authentication       = $clientAuth.Count
        enterprise_certificates     = $enterprise.Count
        certificates_with_private_key = $privateKeyAssociated.Count
        weak_signature              = $weakSignature.Count
        weak_key                    = $weakKey.Count
    }}

    certificates = @(
        $certs | Select-Object -First 100
    )

    expired = @(
        $expired | Select-Object -First 30
    )

    expiring_soon = @(
        $expiringSoon | Select-Object -First 30
    )

    not_yet_valid = @(
        $notYetValid | Select-Object -First 30
    )

    self_signed = @(
        $selfSigned | Select-Object -First 30
    )

    ca_certificates = @(
        $caCerts | Select-Object -First 30
    )

    root_ca_certificates = @(
        $rootCaCerts | Select-Object -First 30
    )

    code_signing = @(
        $codeSigning | Select-Object -First 30
    )

    server_authentication = @(
        $serverAuth | Select-Object -First 30
    )

    client_authentication = @(
        $clientAuth | Select-Object -First 30
    )

    enterprise_certs = @(
        $enterprise | Select-Object -First 30
    )

    private_key_associated = @(
        $privateKeyAssociated | Select-Object -First 30
    )

    weak_signature = @(
        $weakSignature | Select-Object -First 30
    )

    weak_key = @(
        $weakKey | Select-Object -First 30
    )
}}

Write-Output (
    $start +
    (ConvertTo-Json $result -Depth 8 -Compress) +
    $end
)
"""


@plugin.command(
    name='certificates',
    platforms=['windows'],
    description='Enumerate Windows certificate stores, certificate metadata, trust anchors, CA certificates, authentication certificates, code-signing certificates, and passive certificate findings'
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'certificates',
        None,
        build_command,
        format_certificate_report,
        timeout=70.0
    )