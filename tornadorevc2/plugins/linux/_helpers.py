"""Linux plugin collector command builder."""

import base64
import hashlib

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _b64_exec_cmd

_INLINE_LIMIT = 20000
_CHUNK_SIZE = 2000


def _wrap_collector(source: str) -> str:
    """Ensure collector always emits marked JSON, even on failure."""
    start = PLUGIN_MARK_START
    end = PLUGIN_MARK_END
    return (
        f"import json,sys,traceback\n"
        f"MS={start!r}\nME={end!r}\n"
        f"def _emit(obj):\n"
        f"    sys.stdout.write(MS + json.dumps(obj, separators=(',', ':')) + ME)\n"
        f"    sys.stdout.flush()\n"
        f"try:\n"
    ) + _indent_source(source.strip()) + (
        f"\nexcept Exception as e:\n"
        f"    _emit({{'error': str(e), 'traceback': traceback.format_exc()[-800:]}})\n"
    )


def _indent_source(source: str) -> str:
    lines = source.splitlines()
    if not lines:
        return "    pass"
    return '\n'.join('    ' + line if line.strip() else line for line in lines)


def _chunked_command(source: str) -> str:
    payload = base64.b64encode(source.encode('utf-8')).decode('ascii')
    tag = hashlib.sha256(payload.encode('ascii')).hexdigest()[:10]
    b64_path = f'/tmp/.tornado_{tag}.b64'
    py_path = f'/tmp/.tornado_{tag}.py'
    parts = [f": > '{b64_path}'"]
    for i in range(0, len(payload), _CHUNK_SIZE):
        chunk = payload[i:i + _CHUNK_SIZE].replace("'", "'\\''")
        parts.append(f"printf '%s' '{chunk}' >> '{b64_path}'")
    decode_run = (
        f"for p in python3 python python2; do "
        f"command -v $p >/dev/null 2>&1 || continue; "
        f"$p -c \"import base64;open('{py_path}','wb').write(base64.b64decode(open('{b64_path}').read()))\" "
        f"&& $p '{py_path}' && break; "
        f"done"
    )
    parts.append(decode_run)
    parts.append(f"rm -f '{b64_path}' '{py_path}' 2>/dev/null")
    return ' ; '.join(parts)


def build_linux_collector_command(source: str) -> str:
    wrapped = _wrap_collector(source)
    encoded = base64.b64encode(wrapped.encode('utf-8'))

    # Worst-case inline command embeds the payload N times, once per
    # interpreter. Budget for the worst case.
    worst_case_inline = len(encoded) * len([
        ('python3', 'python'), ('python', 'python'), ('python2', 'python'),
    ]) + 200

    # 4 KB is safe on busybox, dash, ksh, zsh, and bash.
    # 8 KB is safe on most modern systems.
    # 30 KB+ is only safe on bash with a raised limit.
    if worst_case_inline <= 3500:
        body = _b64_exec_cmd(wrapped, [('python3', 'python')])
        return f"({body}) 2>/dev/null; true"

    return _chunked_command(wrapped)


def linux_markers():
    return PLUGIN_MARK_START, PLUGIN_MARK_END
