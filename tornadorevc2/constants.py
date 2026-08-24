XFER_MARK_START = '__T_START__'
XFER_MARK_END = '__T_END__'
SYSINFO_MARK_START = '__T_SINFO_START__'
SYSINFO_MARK_END = '__T_SINFO_END__'
EXEC_MARK_START = '__T_EXEC_START__'
EXEC_MARK_END = '__T_EXEC_END__'
TUNNEL_MARK_START = '__T_TUN_START__'
TUNNEL_MARK_END = '__T_TUN_END__'
TUNNEL_REGISTER_MAGIC = 'TornadoRevC2'
IDENT_MARK_START = '__T_ID_START__'
IDENT_MARK_END = '__T_ID_END__'
PLUGIN_MARK_START = '__T_PLUGIN_START__'
PLUGIN_MARK_END = '__T_PLUGIN_END__'

# Shell-based transfers send one revshell command per chunk (base64 decode + file write).
# Windows is capped by the ~8190-char cmd.exe / inline PowerShell limit; Unix can use
# much larger payloads per round trip (ARG_MAX is typically ~2 MB).
CHUNK_SIZE = {'windows': 5632, 'unix': 262144, 'unknown': 65536}

MAIN_COMMANDS = (
    'switch', 'kill', 'status', 'ls', 'sessions', 'reconnects', 'payloads',
    'rename', 'rn', 'upload', 'download', 'verify', 'hash', 'sysinfo',
    'clear', 'cls',
    'socks', 'tunnels', 'export', 'plugins', 'run', 'update', 'jobs',
    'help', 'exit', 'quit', 'e', 'q',
)
CLIENT_COMMANDS = (
    'upload', 'download', 'verify', 'hash', 'sysinfo', 'help',
    'socks', 'tunnels', 'export', 'plugins', 'run',
    'exit', 'quit', 'e', 'q',
)
ID_COMMANDS = {
    'switch', 'kill', 'rename', 'rn', 'upload', 'download', 'verify',
    'hash', 'sysinfo',
    'socks', 'export',
}

# In-memory execution (inmemory plugin)
INMEMORY_FILETYPES = ('py', 'ps', 'exe', 'elf', 'bat', 'sh')
INMEMORY_FILETYPE_ALIASES = {
    'py': 'python',
    'ps': 'powershell',
    'exe': 'pe',
    'elf': 'elf',
    'bat': 'bat',
    'cmd': 'bat',
    'sh': 'shell',
    'bash': 'shell',
    'python': 'python',
    'powershell': 'powershell',
    'pe': 'pe',
}
INMEMORY_EXT_TYPES = {
    '.py': 'python',
    '.ps1': 'powershell',
    '.exe': 'pe',
    '.bat': 'bat',
    '.cmd': 'bat',
    '.sh': 'shell',
    '.bash': 'shell',
}
PAYLOAD_EXEC_TYPES = ('python', 'powershell', 'pe', 'elf')
STREAMING_EXEC_TYPES = ('shell', 'bat')
STREAM_EXIT_MARK = '[exit:'

SYSINFO_MODES = ('stealth', 'full')

LOGS_DIR = 'logs'
XFER_STATE_SUFFIX = '.tornado_xfer.state'
