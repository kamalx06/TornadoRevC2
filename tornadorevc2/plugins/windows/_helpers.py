"""Windows plugin collector helpers."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def wrap_ps_collector(body: str) -> str:
    """Wrap collector logic so marked JSON is always emitted, even on failure."""
    start = PLUGIN_MARK_START
    end = PLUGIN_MARK_END
    indented = '\n'.join(
        ('    ' + line if line.strip() else line) for line in body.strip().splitlines()
    )
    return f"""
$ErrorActionPreference='SilentlyContinue'
$start='{start}'
$end='{end}'
try {{
{indented}
    Write-Output ($start+$json+$end)
}} catch {{
    $err=@{{error=$_.Exception.Message;traceback=$_.ScriptStackTrace}}
    Write-Output ($start+(ConvertTo-Json $err -Compress)+$end)
}}
""".strip()
