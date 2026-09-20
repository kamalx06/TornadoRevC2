import os
import signal
import struct
import sys
import threading

try:
    import termios
except ImportError:
    termios = None


def get_terminal_size():
    try:
        import shutil
        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.lines, size.columns
    except Exception:
        return 24, 80


def _ioctl_tty_size(fd):
    if termios is None:
        return get_terminal_size()
    try:
        import fcntl
        data = fcntl.ioctl(fd, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
        rows, cols, _, _ = struct.unpack('HHHH', data)
        if rows > 0 and cols > 0:
            return rows, cols
    except Exception:
        pass
    return get_terminal_size()


class TerminalManager:
    """PTY/TTY helpers: sizing, resize propagation, and signal forwarding."""

    def __init__(self, send_fn, shell_type, pty_active=False):
        self.send_fn = send_fn
        self.shell_type = shell_type
        self.pty_active = pty_active
        self._resize_lock = threading.Lock()
        self._sigwinch_installed = False
        self._previous_handler = None
        self.rows, self.cols = get_terminal_size()

    def unix_pty_upgrade_cmd(self):
        rows, cols = self.rows, self.cols
        return (
            # History suppression first, before anything else runs.
            f"unset HISTFILE; export HISTFILE=/dev/null; "
            f"export HISTSIZE=0; export HISTFILESIZE=0; "
            f"export HISTCONTROL=ignorespace; "
            f"set +o history 2>/dev/null; "
            f"export TERM=xterm-256color; "
            f" stty rows {rows} cols {cols} 2>/dev/null; "

            # Prefer socat on Debian-family systems. --noprofile --norc
            # prevents login files from resetting HISTFILE or installing
            # command-logging hooks.
            f"if command -v socat >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then "
            f"  socat file:`tty`,raw,echo=0 "
            f"EXEC:'/bin/bash --noprofile --norc -i',"
            f"pty,stderr,setsid,sigint,sane; "
            f"fi; "

            # Fallback: script with explicit terminal allocation.
            f"if command -v script >/dev/null 2>&1; then "
            f"  script -qfc '/bin/bash --noprofile --norc -i' /dev/null; "
            f"fi; "

            # Last resort: run bash directly.
            f"/bin/bash --noprofile --norc -i "
            f"|| /bin/sh -i"
        )

    def apply_size(self, rows=None, cols=None):
        rows = rows or self.rows
        cols = cols or self.cols
        self.rows, self.cols = rows, cols
        if self.shell_type == 'unix':
            # OPSEC: leading space so HISTCONTROL=ignorespace does not log it.
            cmd = (
                f" stty rows {rows} cols {cols} 2>/dev/null; "
                f"export LINES={rows} COLUMNS={cols}"
            )
            return self.send_fn(cmd)
        if self.shell_type == 'windows':
            # OPSEC: do not spawn powershell.exe on every SIGWINCH event.
            # The process-creation telemetry cost outweighs the cosmetic
            # benefit of matching the local terminal size.
            return False
        return False

    def send_interrupt(self):
        try:
            return self.send_fn('\x03')
        except Exception:
            return False

    def install_resize_handler(self):
        if self._sigwinch_installed or sys.platform == 'win32':
            return
        try:
            sigwinch = signal.SIGWINCH
        except AttributeError:
            return

        def _on_sigwinch(signum, frame):
            fd = sys.stdin.fileno()
            if os.isatty(fd):
                rows, cols = _ioctl_tty_size(fd)
            else:
                rows, cols = get_terminal_size()
            with self._resize_lock:
                if rows != self.rows or cols != self.cols:
                    self.apply_size(rows, cols)

        self._previous_handler = signal.getsignal(sigwinch)
        signal.signal(sigwinch, _on_sigwinch)
        self._sigwinch_installed = True

    def restore_resize_handler(self):
        if not self._sigwinch_installed:
            return
        try:
            signal.signal(signal.SIGWINCH, self._previous_handler)
        except Exception:
            pass
        self._sigwinch_installed = False

    def setup_session(self):
        if self.shell_type == 'unix' and self.pty_active:
            self.apply_size()
        self.install_resize_handler()

    def teardown_session(self):
        self.restore_resize_handler()
