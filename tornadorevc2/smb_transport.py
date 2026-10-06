"""
SMB named-pipe secondary transport for TornadoRevC2.

The handler connects to a named pipe hosted on the target (\\.\pipe\<name>)
through SMB (port 445). Frames are length-prefixed on the wire so that
partial reads and writes are handled deterministically.

Requires: smbprotocol (pip install smbprotocol)
"""

import socket
import threading
import struct
import time

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open, CreateDisposition, CreateOptions
    from smbprotocol.open import FilePipePrinterAccessMask, ImpersonationLevel
    from smbprotocol.exceptions import SMBResponseException
    _SMB_AVAILABLE = True
except ImportError:
    _SMB_AVAILABLE = False


class SmbPipeSessionSocket:
    """
    Socket-shaped adapter over an SMB named-pipe connection.

    The caller's expectations match Http2SessionSocket and Http1SessionSocket:
    fileno(), getpeername(), sendall(bytes), recv(n), close(), reset().
    Internally the pipe carries length-prefixed frames (4-byte little-endian
    length, then payload) so that partial reads are unambiguous.
    """

    def __init__(self, host, pipe_name, username, password, domain=''):
        self.host       = host
        self.pipe_name  = pipe_name
        self.username   = username
        self.password   = password
        self.domain     = domain

        self.connection = None
        self.session    = None
        self.tree       = None
        self.pipe       = None

        self.rfd, self.wfd = socket.socketpair()
        self.closed     = False
        self.send_lock  = threading.Lock()

    # ---- lifecycle ----------------------------------------------------
    def connect(self, timeout=10.0):
        if not _SMB_AVAILABLE:
            raise OSError("smbprotocol not installed")

        try:
            # Each stage is printed so the operator can see exactly where
            # an SMB connection failed. If the pipe name is wrong, or the
            # target has SMB signing/encryption requirements the library
            # cannot satisfy, the failure happens at a specific stage.
            print(f"[SMB] TCP 445 → {self.host}")

            # smbprotocol pre-1.0 required a `guid` positional argument;
            # 1.0+ dropped it. Try the modern call first and fall back to
            # the legacy signature only if the constructor rejects the
            # modern one for missing `guid`.
            import uuid as _uuid
            try:
                self.connection = Connection(
                    server_name=self.host,
                    port=445,
                    require_signing=False,
                )
            except TypeError as _e:
                if 'guid' not in str(_e):
                    raise
                self.connection = Connection(
                    guid=_uuid.uuid4(),
                    server_name=self.host,
                    port=445,
                    require_signing=False,
                )
            self.connection.connect(timeout=timeout)

            # Some smbprotocol releases expose `dialect` as a Dialect
            # enum (with a `.name`); older ones store the raw integer
            # dialect constant. Read it defensively — accessing `.name`
            # on an int raises AttributeError and aborts the connect.
            try:
                _dialect = self.connection.dialect.name
            except AttributeError:
                _dialect = str(self.connection.dialect)
            print(f"[SMB]     negotiated SMB {_dialect}")

            print(f"[SMB] session as "
                  f"{self.domain}\\{self.username}" if self.domain
                  else f"[SMB] session as {self.username}")
            self.session = Session(
                self.connection,
                self.username,
                self.password,
                require_encryption=False,
            )
            self.session.connect()

            # IPC$ is the tree that hosts named pipes.
            print(f"[SMB] tree \\\\{self.host}\\IPC$")
            self.tree = TreeConnect(self.session, rf"\\{self.host}\IPC$")
            self.tree.connect()

            # Open the pipe as a file with duplex access. The path here is
            # the BARE pipe name (no \\.\pipe\ prefix, no \\host\pipe\
            # prefix). smbprotocol prepends those for us.
            print(f"[SMB] open \\\\.\\pipe\\{self.pipe_name}")
            self.pipe = Open(self.tree, self.pipe_name)
            self.pipe.open(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA
                | FilePipePrinterAccessMask.FILE_WRITE_DATA,
                create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
                create_disposition=CreateDisposition.FILE_OPEN,
            )
            print(f"[SMB] pipe open — session attached")
        except Exception as exc:
            print(f"[SMB] connect failed: {type(exc).__name__}: {exc}")
            # Clean up whatever was allocated before the failure so we
            # don't leave a dangling SMB session on the target.
            try:
                if self.pipe is not None:
                    self.pipe.close()
            except Exception:
                pass
            try:
                if self.tree is not None:
                    self.tree.disconnect()
            except Exception:
                pass
            try:
                if self.session is not None:
                    self.session.disconnect()
            except Exception:
                pass
            try:
                if self.connection is not None:
                    self.connection.disconnect()
            except Exception:
                pass
            raise

        # Background reader: drains the pipe into the socketpair.
        threading.Thread(target=self._reader_loop, daemon=True).start()
        return True

    # ---- socket-shaped API -------------------------------------------

    def fileno(self):
        return self.rfd.fileno()

    def getpeername(self):
        return (self.host, 445)

    def setsockopt(self, *args, **kwargs):
        pass

    def sendall(self, data: bytes):
        if self.closed:
            raise OSError("smb pipe closed")
        if not data:
            return
        with self.send_lock:
            # Length-prefixed framing. The pipe server reads 4 bytes,
            # then exactly that many bytes of payload.
            frame = struct.pack('<I', len(data)) + data
            offset = 0
            while offset < len(frame):
                chunk = frame[offset:offset + 65536]
                try:
                    # Open.write() returns the number of bytes actually
                    # written, which may be less than the chunk size on
                    # a busy or slow link. Loop until the chunk is done.
                    written = self.pipe.write(chunk)
                except Exception as e:
                    self.closed = True
                    raise OSError(f"smb pipe write failed: {e!r}")
                if not written:
                    self.closed = True
                    raise OSError("smb pipe write returned 0 bytes")
                offset += written

    def recv(self, n: int) -> bytes:
        if self.closed:
            return b''
        try:
            return self.rfd.recv(n)
        except Exception:
            return b''

    def shutdown(self, how):
        self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.pipe is not None:
                self.pipe.close()
        except Exception:
            pass
        try:
            if self.tree is not None:
                self.tree.disconnect()
        except Exception:
            pass
        try:
            if self.session is not None:
                self.session.disconnect()
        except Exception:
            pass
        try:
            if self.connection is not None:
                self.connection.disconnect()
        except Exception:
            pass
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass

    def reset(self):
        self.closed = True
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass

    # ---- reader ------------------------------------------------------

    def _read_exact(self, n):
        """Read exactly n bytes from the pipe, or return None on EOF."""
        buf = b''
        while len(buf) < n:
            try:
                chunk = self.pipe.read(n - len(buf))
            except SMBResponseException:
                return None
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _reader_loop(self):
        try:
            while not self.closed:
                header = self._read_exact(4)
                if header is None:
                    break
                (length,) = struct.unpack('<I', header)
                if length == 0 or length > 16 * 1024 * 1024:
                    break
                payload = self._read_exact(length)
                if payload is None:
                    break
                try:
                    self.wfd.sendall(payload)
                except Exception:
                    break
        finally:
            self.reset()