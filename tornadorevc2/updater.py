"""Self-update from the official TornadoRevC2 Git repository."""

import os
import shutil
import subprocess
import sys

OFFICIAL_REPO_URL = 'https://github.com/kamalx06/TornadoRevC2/'

GIT_TIMEOUT_QUICK = 30
GIT_TIMEOUT_FETCH = 120
GIT_TIMEOUT_PULL = 180

GIT_NOT_AVAILABLE_MSG = (
    'Git is not available on this system. Please install Git or manually check '
    f'for updates from {OFFICIAL_REPO_URL}'
)
NOT_GIT_REPO_MSG = (
    'This TornadoRevC2 installation is not a Git repository. Please update manually '
    f'from {OFFICIAL_REPO_URL}'
)
UP_TO_DATE_MSG = 'TornadoRevC2 is already running the latest version.'
UPDATE_SUCCESS_MSG = 'Update installed successfully. Restarting TornadoRevC2...'


def _install_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_env():
    env = os.environ.copy()
    # Prevent credential / terminal prompts that block indefinitely.
    env['GIT_TERMINAL_PROMPT'] = '0'
    env['GIT_ASKPASS'] = ''
    env['SSH_ASKPASS'] = ''
    env['GCM_INTERACTIVE'] = 'Never'
    return env


def _run_git(*args, cwd, timeout=GIT_TIMEOUT_QUICK):
    try:
        return subprocess.run(
            ['git', *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b'').decode('utf-8', errors='replace')
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b'').decode('utf-8', errors='replace')
        return subprocess.CompletedProcess(
            args=['git', *args],
            returncode=-1,
            stdout=out or '',
            stderr=(err or f'Git command timed out after {timeout}s').strip(),
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=['git', *args],
            returncode=-1,
            stdout='',
            stderr=str(exc),
        )


def git_available():
    return shutil.which('git') is not None


def get_repo_root():
    install_root = _install_root()
    result = _run_git('rev-parse', '--show-toplevel', cwd=install_root)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def is_git_repo(cwd):
    result = _run_git('rev-parse', '--is-inside-work-tree', cwd=cwd)
    return result.returncode == 0 and result.stdout.strip() == 'true'


def _upstream_ref(repo_root):
    result = _run_git('rev-parse', '--abbrev-ref', '@{u}', cwd=repo_root)
    if result.returncode == 0:
        return result.stdout.strip()
    branch = _run_git('rev-parse', '--abbrev-ref', 'HEAD', cwd=repo_root)
    if branch.returncode != 0:
        return None
    branch_name = branch.stdout.strip()
    if branch_name == 'HEAD':
        return None
    candidate = f'origin/{branch_name}'
    check = _run_git('rev-parse', candidate, cwd=repo_root)
    if check.returncode == 0:
        return candidate
    return None


def _git_error(result, fallback='Git command failed'):
    return (result.stderr or result.stdout or fallback).strip()


def _restart_process():
    argv = [sys.executable, *sys.argv]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == 'nt':
        # os.execv is unreliable on Windows with attached consoles; spawn and exit.
        subprocess.Popen(argv, close_fds=False)
        os._exit(0)
    os.execv(sys.executable, argv)


class Updater:
    """Operator-facing self-update from the configured Git remote."""

    def __init__(self, handler):
        self.h = handler
        self._busy = False

    def handle_command(self, cmd_parts):
        if not cmd_parts or cmd_parts[0].lower() != 'update':
            return False
        self.run_update()
        return True

    def run_update(self):
        if self._busy:
            print(f"{self.h.colors['yellow']}Update already in progress.{self.h.colors['end']}")
            return

        colors = self.h.colors
        self._busy = True
        try:
            if not git_available():
                print(f"{colors['yellow']}{GIT_NOT_AVAILABLE_MSG}{colors['end']}")
                return

            repo_root = get_repo_root()
            if not repo_root or not is_git_repo(repo_root):
                print(f"{colors['yellow']}{NOT_GIT_REPO_MSG}{colors['end']}")
                return

            print(f"{colors['cyan']}Fetching updates from remote...{colors['end']}")
            fetch = _run_git('fetch', '--quiet', '--no-tags', cwd=repo_root, timeout=GIT_TIMEOUT_FETCH)
            if fetch.returncode != 0:
                print(f"{colors['red']}{_git_error(fetch, 'git fetch failed')}{colors['end']}")
                return

            upstream = _upstream_ref(repo_root)
            if not upstream:
                print(
                    f"{colors['red']}No upstream tracking branch configured. "
                    f"Set an upstream branch or update manually from {OFFICIAL_REPO_URL}{colors['end']}"
                )
                return

            local = _run_git('rev-parse', 'HEAD', cwd=repo_root)
            remote = _run_git('rev-parse', upstream, cwd=repo_root)
            if local.returncode != 0 or remote.returncode != 0:
                print(
                    f"{colors['red']}"
                    f"{_git_error(remote if remote.returncode != 0 else local, 'Unable to compare local and remote revisions')}"
                    f"{colors['end']}"
                )
                return

            if local.stdout.strip() == remote.stdout.strip():
                print(f"{colors['green']}{UP_TO_DATE_MSG}{colors['end']}")
                return

            print(f"{colors['yellow']}An update is available for TornadoRevC2.{colors['end']}")
            print(
                f"{colors['yellow']}Updating will restart TornadoRevC2 and terminate all active sessions, "
                f"SOCKS proxies, tunnels, and other runtime state.{colors['end']}"
            )

            try:
                answer = input(f"{colors['cyan']}Continue with the update? [y/N]: {colors['end']}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"{colors['yellow']}Update cancelled.{colors['end']}")
                return

            if answer not in ('y', 'yes'):
                print(f"{colors['yellow']}Update cancelled.{colors['end']}")
                return

            print(f"{colors['cyan']}Applying update (fast-forward only)...{colors['end']}")
            pull = _run_git('pull', '--ff-only', '--quiet', cwd=repo_root, timeout=GIT_TIMEOUT_PULL)
            if pull.returncode != 0:
                print(f"{colors['red']}{_git_error(pull, 'git pull --ff-only failed')}{colors['end']}")
                return

            print(f"{colors['green']}{UPDATE_SUCCESS_MSG}{colors['end']}")
            sys.stdout.flush()
            try:
                self.h.shutdown_for_restart()
                _restart_process()
            except Exception as exc:
                print(f"{colors['red']}Failed to restart TornadoRevC2: {exc}{colors['end']}")
        finally:
            self._busy = False
