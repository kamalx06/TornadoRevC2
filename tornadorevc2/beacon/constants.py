"""Tunable defaults for the beacon subsystem.

Values are conservative: sleep intervals long enough to avoid looking
like a live socket, task timeouts generous enough to tolerate two or
three missed check-ins before declaring failure.
"""

# Scheduling
DEFAULT_SLEEP        = 60           # seconds between check-ins
DEFAULT_JITTER       = 0.3          # 0.0 - 1.0, proportion of sleep
MIN_SLEEP            = 0
MAX_SLEEP            = 86400        # 24 h

# Lifecycle
DEFAULT_KILL_DAYS    = 30
BEACON_TTL_FACTOR    = 4            # dead after sleep * factor seconds

# Chunked file transfer
# Chunk size chosen so a base64-encoded chunk plus JSON envelope
# stays well under common proxy body-size limits, and so a poll
# carrying the full batch stays close to a mid-size image load in
# bytes on the wire.
UPLOAD_CHUNK_SIZE    = 32768         # raw bytes per chunk
UPLOAD_CHUNK_BATCH   = 10           # chunks per /tasks poll

# Download uses a slightly smaller base size. A download chunk travels
# as a task *result* payload, which is larger on the wire than a task
# *request* because of the base64 wrapper and the surrounding JSON
# envelope. 24 KiB keeps each result under the response padding
# threshold so the padding step does not add unnecessary bytes.
DOWNLOAD_CHUNK_SIZE  = 24576         # raw bytes per download chunk

EXPORTS_DIR = 'exports'

# Task machinery
TASK_TIMEOUT         = 300          # seconds to wait for a result
TASK_HISTORY_LIMIT   = 1000         # results kept per session
TASK_QUEUE_LIMIT     = 1000         # outstanding tasks per session
TASK_BATCH_MAX       = 10           # tasks returned per /tasks call

# Protocol
PROTO_VERSION        = 1