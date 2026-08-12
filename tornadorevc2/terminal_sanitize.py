"""Strip terminal control sequences from text written to logs and exports."""

import re

# CSI (Control Sequence Introducer) — safe for marker/payload parsing.
_CSI = re.compile(r'(?:\x1b|\x9b)\[[\?0-9;]*[ -/]*[@-~]')

# OSC (Operating System Command): ESC ] payload terminated by BEL or ST (ESC \).
# Covers shell integration (633, 3008), terminal title (0;), hyperlinks, etc.
_OSC = re.compile(r'\x1b\][^\x07\x1b\\]*(?:\x07|\x1b\\)?')

# DCS / SOS / PM / APC sequences terminated by ST (never to end-of-string).
_OTHER_ESC = re.compile(r'\x1b[PX^_][^\x1b\\]*\x1b\\')

# Legacy two-character ESC sequences (e.g. ESC M reverse index).
_ESC_TWO_CHAR = re.compile(r'\x1b[@-Z\\-_]')


def strip_csi_sequences(text):
    """Remove CSI/ANSI color and cursor sequences (for structured output parsing)."""
    if not text:
        return text
    return _CSI.sub('', text)


def sanitize_terminal_output(text):
    """Return *text* with ANSI, OSC, and related terminal control sequences removed."""
    if not text:
        return text
    text = _OSC.sub('', text)
    text = _OTHER_ESC.sub('', text)
    text = _CSI.sub('', text)
    text = _ESC_TWO_CHAR.sub('', text)
    return text
