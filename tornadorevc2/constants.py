XFER_MARK_START = '__T_START__'
XFER_MARK_END = '__T_END__'
SYSINFO_MARK_START = '__T_SINFO_START__'
SYSINFO_MARK_END = '__T_SINFO_END__'

CHUNK_SIZE = {'windows': 4096, 'unix': 32768, 'unknown': 8192}

MAIN_COMMANDS = (
    'switch', 'kill', 'status', 'ls', 'payloads', 'rename', 'rn',
    'upload', 'download', 'verify', 'hash', 'sysinfo', 'clear', 'cls',
    'help', 'exit', 'quit', 'e', 'q',
)
CLIENT_COMMANDS = (
    'upload', 'download', 'verify', 'hash', 'sysinfo', 'help',
    'exit', 'quit', 'e', 'q',
)
ID_COMMANDS = {
    'switch', 'kill', 'rename', 'rn', 'upload', 'download', 'verify',
    'hash', 'sysinfo',
}

LOGS_DIR = 'logs'
XFER_STATE_SUFFIX = '.tornado_xfer.state'
