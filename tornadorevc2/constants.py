XFER_MARK_START = '__T_START__'
XFER_MARK_END = '__T_END__'
SYSINFO_MARK_START = '__T_SINFO_START__'
SYSINFO_MARK_END = '__T_SINFO_END__'
EXEC_MARK_START = '__T_EXEC_START__'
EXEC_MARK_END = '__T_EXEC_END__'
CLIP_MARK_START = '__T_CLIP_START__'
CLIP_MARK_END = '__T_CLIP_END__'
TUNNEL_MARK_START = '__T_TUN_START__'
TUNNEL_MARK_END = '__T_TUN_END__'

CHUNK_SIZE = {'windows': 4096, 'unix': 32768, 'unknown': 8192}

MAIN_COMMANDS = (
    'switch', 'kill', 'status', 'ls', 'sessions', 'reconnects', 'payloads',
    'rename', 'rn', 'upload', 'download', 'verify', 'hash', 'sysinfo',
    'clear', 'cls', 'runpy', 'runps', 'runexe', 'runelf', 'clipboard',
    'socks', 'tunnels',
    'help', 'exit', 'quit', 'e', 'q',
)
CLIENT_COMMANDS = (
    'upload', 'download', 'verify', 'hash', 'sysinfo', 'help',
    'runpy', 'runps', 'runexe', 'runelf', 'clipboard',
    'socks', 'tunnels',
    'exit', 'quit', 'e', 'q',
)
ID_COMMANDS = {
    'switch', 'kill', 'rename', 'rn', 'upload', 'download', 'verify',
    'hash', 'sysinfo', 'runpy', 'runps', 'runexe', 'runelf', 'clipboard',
    'socks',
}

PAYLOAD_EXEC_TYPES = ('python', 'powershell', 'pe', 'elf')
SYSINFO_MODES = ('stealth', 'full')

LOGS_DIR = 'logs'
XFER_STATE_SUFFIX = '.tornado_xfer.state'
