"""Strip terminal control sequences from text written to logs and exports."""

import re

# OSC (Operating System Command): ESC ] payload terminated by BEL or ST (ESC \).
# Covers shell integration (633, 3008), terminal title (0;), hyperlinks, etc.
_OSC = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?')

# CSI (Control Sequence Introducer): colors, cursor movement, bracketed paste (?2004h/l), etc.
_CSI = re.compile(r'(?:\x1b|\x9b)\[[\?0-9;]*[ -/]*[@-~]')

# DCS / SOS / PM / APC sequences terminated by ST.
_OTHER_ESC = re.compile(r'\x1b[PX^_][^\x1b]*(?:\x1b\\|$)')

# Legacy two-character ESC sequences (e.g. ESC M reverse index).
_ESC_TWO_CHAR = re.compile(r'\x1b[@-Z\\-_]')


def sanitize_terminal_output(text):
    """Return *text* with ANSI, OSC, and related terminal control sequences removed."""
    if not text:
        return text
    text = _OSC.sub('', text)
    text = _OTHER_ESC.sub('', text)
    text = _CSI.sub('', text)
    text = _ESC_TWO_CHAR.sub('', text)
    return text
