"""Remote Python/shell command builders shared by handler modules."""

import base64
import hashlib

from .sysinfo import _b64_exec_cmd

_INLINE_LIMIT = 4000
_CHUNK_SIZE = 400


def build_chunked_python_command(source: str, argv=None) -> str:
    """Write base64-encoded Python to a temp file, execute, and remove."""
    argv = argv or []
    argv_literal = ' '.join(f"'{a.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'" for a in argv)
    payload = base64.b64encode(source.encode('utf-8')).decode('ascii')
    tag = hashlib.sha256(payload.encode('ascii')).hexdigest()[:10]
    b64_path = f'/tmp/.tornado_{tag}.b64'
    py_path = f'/tmp/.tornado_{tag}.py'
    parts = [f": > '{b64_path}'"]
    for i in range(0, len(payload), _CHUNK_SIZE):
        chunk = payload[i:i + _CHUNK_SIZE].replace("'", "'\\''")
        parts.append(f"printf '%s' '{chunk}' >> '{b64_path}'")
    run_argv = f" {argv_literal}" if argv_literal else ''
    decode_run = (
        f"for p in python3 python python2; do "
        f"command -v $p >/dev/null 2>&1 || continue; "
        f"$p -c \"import base64;open('{py_path}','wb').write(base64.b64decode(open('{b64_path}').read()))\" "
        f"&& $p '{py_path}'{run_argv} && break; "
        f"done"
    )
    parts.append(decode_run)
    parts.append(f"rm -f '{b64_path}' '{py_path}' 2>/dev/null")
    return ' ; '.join(parts)


def build_inline_python_command(source: str) -> str:
    wrapped = source.strip()
    encoded_len = len(base64.b64encode(wrapped.encode('utf-8')))
    if encoded_len > _INLINE_LIMIT:
        return build_chunked_python_command(wrapped)
    body = _b64_exec_cmd(wrapped, (
        ('python3', 'python'),
        ('python', 'python'),
        ('python2', 'python'),
    ))
    return f"({body}) 2>/dev/null; true"
