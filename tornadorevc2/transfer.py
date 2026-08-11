import hashlib
import json
import os
import time

from .constants import CHUNK_SIZE, XFER_MARK_END, XFER_MARK_START, XFER_STATE_SUFFIX


class FileTransfer:
    """Chunked file upload/download with integrity checks and resume support."""

    def __init__(self, handler):
        self.h = handler

    def _chunk_size_for(self, shell_type):
        return CHUNK_SIZE.get(shell_type, CHUNK_SIZE['unknown'])

    def _state_path(self, local_path, remote_path, direction):
        key = f"{direction}|{os.path.abspath(local_path)}|{remote_path}"
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        base = os.path.dirname(os.path.abspath(local_path)) or '.'
        return os.path.join(base, f".tornado_{digest}{XFER_STATE_SUFFIX}")

    def _load_state(self, path):
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def _save_state(self, path, state):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
        except OSError:
            pass

    def _clear_state(self, path):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    def _format_size(self, nbytes):
        return self.h._format_size(nbytes)

    def _print_progress(self, transferred, total, start_time, label='Transfer'):
        self.h._print_progress(transferred, total, start_time, label)

    def _log_transfer(self, client_sock, direction, local_path, remote_path, status, detail=''):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_transfer(direction, local_path, remote_path, status, detail)

    def upload_file(self, client_sock, local_path, remote_path, resume=False):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')
        if not os.path.isfile(local_path):
            print(f"{self.h.colors['red']}Local file not found: {local_path}{self.h.colors['end']}")
            return False

        total = os.path.getsize(local_path)
        local_hash = self.h._sha256_file(local_path)
        chunk_size = self._chunk_size_for(shell_type)
        state_path = self._state_path(local_path, remote_path, 'upload')
        state = self._load_state(state_path)
        transferred = 0
        first = True

        if resume and state:
            if (state.get('local_path') == os.path.abspath(local_path)
                    and state.get('remote_path') == remote_path
                    and state.get('direction') == 'upload'
                    and state.get('total') == total
                    and state.get('sha256') == local_hash):
                transferred = min(state.get('transferred', 0), total)
                if transferred > 0:
                    print(
                        f"{self.h.colors['yellow']}Resuming upload from "
                        f"{self._format_size(transferred)}{self.h.colors['end']}"
                    )
                    first = False
            else:
                print(f"{self.h.colors['yellow']}Stale resume state ignored{self.h.colors['end']}")
                self._clear_state(state_path)
        elif resume:
            remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
            if remote_size and 0 < remote_size < total:
                transferred = remote_size
                print(
                    f"{self.h.colors['yellow']}Resuming upload from remote offset "
                    f"{self._format_size(transferred)}{self.h.colors['end']}"
                )
                first = False

        print(
            f"{self.h.colors['yellow']}Uploading {local_path} -> {remote_path} "
            f"({self._format_size(total)}, chunk={self._format_size(chunk_size)}){self.h.colors['end']}"
        )
        print(f"{self.h.colors['blue']}Local SHA256: {local_hash}{self.h.colors['end']}")
        self.h._flush_shell(client_sock)

        if transferred == 0:
            if not self.h._remote_truncate(client_sock, remote_path, shell_type):
                print(f"\n{self.h.colors['red']}Failed to prepare remote file{self.h.colors['end']}")
                self._log_transfer(client_sock, 'upload', local_path, remote_path, 'failed', 'truncate')
                return False
            self.h.recv_output(client_sock, timeout=2.0)
        else:
            self.h.recv_output(client_sock, timeout=1.0)

        start = time.time()
        try:
            with open(local_path, 'rb') as f:
                f.seek(transferred)
                while transferred < total:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    if not self.h._remote_write_chunk(
                        client_sock, remote_path, data, shell_type, truncate=first
                    ):
                        self._save_state(state_path, {
                            'direction': 'upload',
                            'local_path': os.path.abspath(local_path),
                            'remote_path': remote_path,
                            'transferred': transferred,
                            'total': total,
                            'sha256': local_hash,
                            'shell_type': shell_type,
                            'chunk_size': chunk_size,
                        })
                        print(
                            f"\n{self.h.colors['red']}Upload failed at "
                            f"{self._format_size(transferred)} — resume with: "
                            f"upload --resume <local> <remote>{self.h.colors['end']}"
                        )
                        self._log_transfer(
                            client_sock, 'upload', local_path, remote_path,
                            'interrupted', f"offset={transferred}"
                        )
                        return False
                    first = False
                    transferred += len(data)
                    self._save_state(state_path, {
                        'direction': 'upload',
                        'local_path': os.path.abspath(local_path),
                        'remote_path': remote_path,
                        'transferred': transferred,
                        'total': total,
                        'sha256': local_hash,
                        'shell_type': shell_type,
                        'chunk_size': chunk_size,
                    })
                    self._print_progress(transferred, total, start, 'Upload')
        except OSError as e:
            print(f"\n{self.h.colors['red']}Upload error: {e}{self.h.colors['end']}")
            self._log_transfer(client_sock, 'upload', local_path, remote_path, 'error', str(e))
            return False

        self.h._flush_shell(client_sock, timeout=1.0)
        print(f"\n{self.h.colors['yellow']}Verifying remote integrity...{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash == local_hash:
            print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match{self.h.colors['end']}          ")
            print(f"{self.h.colors['green']}Upload complete: {remote_path}{self.h.colors['end']}")
            self._clear_state(state_path)
            self._log_transfer(client_sock, 'upload', local_path, remote_path, 'complete')
            return True
        print(f"\r{self.h.colors['red']}Integrity mismatch!{self.h.colors['end']}                          ")
        print(f"  Local:  {local_hash}")
        print(f"  Remote: {remote_hash or 'unavailable'}")
        self._log_transfer(client_sock, 'upload', local_path, remote_path, 'hash_mismatch')
        return False

    def download_file(self, client_sock, remote_path, local_path, resume=False):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')
        remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
        if remote_size is None:
            print(f"{self.h.colors['red']}Remote file not found or unreadable: {remote_path}{self.h.colors['end']}")
            return False

        chunk_size = self._chunk_size_for(shell_type)
        state_path = self._state_path(local_path, remote_path, 'download')
        state = self._load_state(state_path)
        transferred = 0
        mode = 'wb'

        if resume and state:
            if (state.get('local_path') == os.path.abspath(local_path)
                    and state.get('remote_path') == remote_path
                    and state.get('direction') == 'download'
                    and state.get('total') == remote_size):
                transferred = min(state.get('transferred', 0), remote_size)
                if transferred > 0:
                    print(
                        f"{self.h.colors['yellow']}Resuming download from "
                        f"{self._format_size(transferred)}{self.h.colors['end']}"
                    )
                    mode = 'r+b'
            else:
                print(f"{self.h.colors['yellow']}Stale resume state ignored{self.h.colors['end']}")
                self._clear_state(state_path)
        elif resume and os.path.isfile(local_path):
            local_partial = os.path.getsize(local_path)
            if 0 < local_partial < remote_size:
                transferred = local_partial
                mode = 'r+b'
                print(
                    f"{self.h.colors['yellow']}Resuming download from local offset "
                    f"{self._format_size(transferred)}{self.h.colors['end']}"
                )

        print(
            f"{self.h.colors['yellow']}Downloading {remote_path} -> {local_path} "
            f"({self._format_size(remote_size)}, chunk={self._format_size(chunk_size)}){self.h.colors['end']}"
        )
        print(f"{self.h.colors['yellow']}Computing remote SHA256...{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash:
            print(f"\r{self.h.colors['blue']}Remote SHA256: {remote_hash}{self.h.colors['end']}          ")
        else:
            print(f"\r{self.h.colors['red']}Could not compute remote hash — aborting{self.h.colors['end']}")
            return False

        if state and state.get('sha256') and state.get('sha256') != remote_hash:
            print(f"{self.h.colors['yellow']}Remote file changed — restarting download{self.h.colors['end']}")
            transferred = 0
            mode = 'wb'
            self._clear_state(state_path)

        self.h._flush_shell(client_sock)
        local_dir = os.path.dirname(os.path.abspath(local_path))
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        start = time.time()
        chunk_index = transferred // chunk_size if chunk_size else 0
        try:
            with open(local_path, mode) as f:
                if transferred > 0:
                    f.seek(transferred)
                while transferred < remote_size:
                    read_size = min(chunk_size, remote_size - transferred)
                    data = self.h._remote_read_chunk(
                        client_sock, remote_path, transferred, read_size, shell_type, chunk_index
                    )
                    if data is None:
                        self._save_state(state_path, {
                            'direction': 'download',
                            'local_path': os.path.abspath(local_path),
                            'remote_path': remote_path,
                            'transferred': transferred,
                            'total': remote_size,
                            'sha256': remote_hash,
                            'shell_type': shell_type,
                            'chunk_size': chunk_size,
                        })
                        print(
                            f"\n{self.h.colors['red']}Download failed at "
                            f"{self._format_size(transferred)} — resume with: "
                            f"download --resume <remote> <local>{self.h.colors['end']}"
                        )
                        self._log_transfer(
                            client_sock, 'download', local_path, remote_path,
                            'interrupted', f"offset={transferred}"
                        )
                        return False
                    f.write(data)
                    transferred += len(data)
                    chunk_index += 1
                    self._save_state(state_path, {
                        'direction': 'download',
                        'local_path': os.path.abspath(local_path),
                        'remote_path': remote_path,
                        'transferred': transferred,
                        'total': remote_size,
                        'sha256': remote_hash,
                        'shell_type': shell_type,
                        'chunk_size': chunk_size,
                    })
                    self._print_progress(transferred, remote_size, start, 'Download')
        except OSError as e:
            print(f"\n{self.h.colors['red']}Download error: {e}{self.h.colors['end']}")
            self._log_transfer(client_sock, 'download', local_path, remote_path, 'error', str(e))
            return False

        print(f"\n{self.h.colors['yellow']}Verifying local integrity...{self.h.colors['end']}", end='', flush=True)
        local_hash = self.h._sha256_file(local_path)
        if local_hash == remote_hash:
            print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match{self.h.colors['end']}          ")
            print(f"{self.h.colors['green']}Download complete: {local_path}{self.h.colors['end']}")
            self._clear_state(state_path)
            self._log_transfer(client_sock, 'download', local_path, remote_path, 'complete')
            return True
        print(f"\r{self.h.colors['red']}Integrity mismatch!{self.h.colors['end']}                          ")
        print(f"  Remote: {remote_hash}")
        print(f"  Local:  {local_hash}")
        self._log_transfer(client_sock, 'download', local_path, remote_path, 'hash_mismatch')
        return False

    def verify_file(self, client_sock, remote_path):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return
        shell_type = info.get('type', 'unknown')
        remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
        if remote_size is None:
            print(f"{self.h.colors['red']}Remote file not found: {remote_path}{self.h.colors['end']}")
            return
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        print(f"{self.h.colors['green']}Remote file:{self.h.colors['end']} {remote_path}")
        print(f"  Size:   {self._format_size(remote_size)} ({remote_size} bytes)")
        print(f"  SHA256: {remote_hash or 'unavailable'}")
