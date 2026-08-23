"""Self-update from the official TornadoRevC2 Git repository."""

import os
import shutil
import subprocess
import sys

from .update_audit import UpdateAuditLogger
from .update_lock import UpdateLock, UpdateLockError
from .update_policy import (
    OFFICIAL_BRANCH,
    OFFICIAL_REPO_URL,
    check_working_tree,
    format_working_tree_changes,
    get_origin_url,
    get_trusted_branch_tip,
    verify_origin_remote,
    verify_trusted_branch,
)
from .update_state import (
    STATE_APPLYING,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_ROLLED_BACK,
    STATE_ROLLING_BACK,
    STATE_VALIDATING,
    begin_update,
    clear_state,
    is_interrupted_state,
    load_state,
    rollback_to_revision,
    set_state,
)
from .update_validate import validate_installation

OFFICIAL_REPO_URL = OFFICIAL_REPO_URL  # re-export for backward compatibility

GIT_TIMEOUT_QUICK = 30
GIT_TIMEOUT_FETCH = 120
GIT_TIMEOUT_APPLY = 180

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

WRONG_REMOTE_MSG = (
    'The configured Git remote is not the official TornadoRevC2 repository.\n'
    'Expected: {expected}\n'
    'Actual:   {actual}\n\n'
    'Update aborted for security reasons.'
)
WRONG_BRANCH_MSG = (
    'Updates are only permitted from the trusted branch {branch}.\n'
    'Current branch: {current}\n\n'
    'Update aborted for security reasons.'
)
DIRTY_TREE_HEADER = (
    'Update aborted: the installation has uncommitted local changes.\n\n'
    'Updates require a clean working tree.'
)
DIRTY_TREE_FOOTER = (
    '\nDiscard or stash your changes, then run update again:\n'
    '  git stash push -u -m "local changes"\n'
    '  git checkout -- .'
)
INTERRUPTED_UPDATE_MSG = (
    'A previous update did not complete successfully.\n'
    'Recorded state: {state}\n'
    'Previous revision: {previous}\n'
    'Target revision: {target}\n\n'
    'Resolve the repository state manually or retry the update after inspection.'
)


def _install_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_env():
    env = os.environ.copy()
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


def _git_error(result, fallback='Git command failed'):
    return (result.stderr or result.stdout or fallback).strip()


def _short_revision(revision):
    return revision[:7] if revision else 'unknown'


def _collect_update_preview(repo_root, current_revision, target_revision):
    count_result = _run_git(
        'rev-list', '--count', f'{current_revision}..{target_revision}',
        cwd=repo_root,
    )
    commit_count = count_result.stdout.strip() if count_result.returncode == 0 else '?'

    log_result = _run_git(
        'log', '--oneline', '--no-decorate', f'{current_revision}..{target_revision}',
        cwd=repo_root,
        timeout=GIT_TIMEOUT_QUICK,
    )
    commits = []
    if log_result.returncode == 0:
        commits = log_result.stdout.strip().splitlines()[:10]

    stat_result = _run_git(
        'diff', '--shortstat', current_revision, target_revision,
        cwd=repo_root,
        timeout=GIT_TIMEOUT_QUICK,
    )
    shortstat = stat_result.stdout.strip() if stat_result.returncode == 0 else ''

    return commit_count, commits, shortstat


def _format_dirty_tree_message(status_lines):
    changes = format_working_tree_changes(status_lines)
    lines = [DIRTY_TREE_HEADER, '', 'Local changes:']
    for entry in changes[:20]:
        lines.append(f'  {entry}')
    if len(changes) > 20:
        lines.append(f'  ... and {len(changes) - 20} more')
    lines.append(DIRTY_TREE_FOOTER)
    return '\n'.join(lines)


def _restart_process():
    argv = [sys.executable, *sys.argv]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == 'nt':
        subprocess.Popen(argv, close_fds=False)
        os._exit(0)
    os.execv(sys.executable, argv)


class Updater:
    """Operator-facing secure self-update from the official Git repository."""

    def __init__(self, handler):
        self.h = handler
        self._busy = False
        self.audit = UpdateAuditLogger()
        self._run_git = _run_git

    def handle_command(self, cmd_parts):
        if not cmd_parts or cmd_parts[0].lower() != 'update':
            return False
        self.run_update()
        return True

    def _print_error(self, message):
        print(f"{self.h.colors['red']}{message}{self.h.colors['end']}")

    def _print_warning(self, message):
        print(f"{self.h.colors['yellow']}{message}{self.h.colors['end']}")

    def _print_info(self, message):
        print(f"{self.h.colors['cyan']}{message}{self.h.colors['end']}")

    def _print_success(self, message):
        print(f"{self.h.colors['green']}{message}{self.h.colors['end']}")

    def _report_interrupted_update(self):
        state = load_state()
        if not is_interrupted_state(state):
            return
        self._print_warning(
            INTERRUPTED_UPDATE_MSG.format(
                state=state.get('state', 'unknown'),
                previous=state.get('previous_revision', 'unknown'),
                target=state.get('target_revision', 'unknown'),
            )
        )
        self.audit.log(
            'UPDATE_INTERRUPTED_DETECTED',
            state=state.get('state'),
            previous_revision=state.get('previous_revision'),
            target_revision=state.get('target_revision'),
        )

    def run_update(self):
        if self._busy:
            self._print_warning('Update already in progress.')
            return

        colors = self.h.colors
        self._busy = True
        repo_root = None
        previous_revision = None
        target_revision = None
        operator_confirmed = 'no'

        try:
            with UpdateLock():
                self._report_interrupted_update()

                if not git_available():
                    self._print_warning(GIT_NOT_AVAILABLE_MSG)
                    self.audit.log('UPDATE_ABORTED', reason='git_unavailable')
                    return

                repo_root = get_repo_root()
                if not repo_root or not is_git_repo(repo_root):
                    self._print_warning(NOT_GIT_REPO_MSG)
                    self.audit.log('UPDATE_ABORTED', reason='not_git_repo')
                    return

                remote_ok, expected, actual = verify_origin_remote(repo_root, self._run_git)
                if not remote_ok:
                    self._print_error(WRONG_REMOTE_MSG.format(expected=expected, actual=actual or 'unknown'))
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='wrong_remote',
                        repository=actual,
                        expected_repository=expected,
                    )
                    return

                branch_ok, current_branch = verify_trusted_branch(repo_root, self._run_git)
                if not branch_ok:
                    self._print_error(
                        WRONG_BRANCH_MSG.format(branch=OFFICIAL_BRANCH, current=current_branch)
                    )
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='wrong_branch',
                        trusted_branch=OFFICIAL_BRANCH,
                        current_branch=current_branch,
                    )
                    return

                clean, status_lines = check_working_tree(repo_root, self._run_git)
                working_tree_status = 'clean' if clean else 'dirty'
                self.audit.log('UPDATE_WORKING_TREE', status=working_tree_status)
                if not clean:
                    self._print_error(_format_dirty_tree_message(status_lines))
                    self.audit.log('UPDATE_ABORTED', reason='dirty_working_tree')
                    return

                self._print_info(
                    f'Fetching updates from {OFFICIAL_REPO_URL} ({OFFICIAL_BRANCH})...'
                )
                fetch = self._run_git(
                    'fetch', '--quiet', 'origin', OFFICIAL_BRANCH,
                    cwd=repo_root,
                    timeout=GIT_TIMEOUT_FETCH,
                )
                if fetch.returncode != 0:
                    self._print_error(_git_error(fetch, 'git fetch failed'))
                    self.audit.log('UPDATE_ABORTED', reason='fetch_failure')
                    return

                local = self._run_git('rev-parse', 'HEAD', cwd=repo_root)
                if local.returncode != 0:
                    self._print_error(_git_error(local, 'Unable to read current revision'))
                    self.audit.log('UPDATE_ABORTED', reason='read_current_revision_failed')
                    return
                previous_revision = local.stdout.strip()

                target_revision = get_trusted_branch_tip(repo_root, self._run_git)
                if target_revision is None:
                    self._print_error(
                        f'Unable to determine the trusted branch tip for origin/{OFFICIAL_BRANCH}.'
                    )
                    self.audit.log('UPDATE_ABORTED', reason='target_identification_failed')
                    return

                self.audit.log(
                    'UPDATE_STARTED',
                    current_revision=previous_revision,
                    target_revision=target_revision,
                    repository=get_origin_url(repo_root, self._run_git),
                    trusted_branch=OFFICIAL_BRANCH,
                )

                if previous_revision == target_revision:
                    self._print_success(UP_TO_DATE_MSG)
                    self.audit.log(
                        'UPDATE_COMPLETED',
                        previous_revision=previous_revision,
                        new_revision=target_revision,
                        final_result='already_current',
                    )
                    clear_state()
                    return

                commit_count, commits, shortstat = _collect_update_preview(
                    repo_root, previous_revision, target_revision
                )

                print(f"{colors['yellow']}An update is available for TornadoRevC2.{colors['end']}")
                print(f"Current commit: {_short_revision(previous_revision)}")
                print(f"Target commit:  {_short_revision(target_revision)}")
                print(f"Source branch:  {OFFICIAL_BRANCH}")
                print(f"Commits:        {commit_count}")
                if shortstat:
                    print(f"Changes:        {shortstat}")
                if commits:
                    print('Summary:')
                    for entry in commits:
                        print(f"  {entry}")
                print(
                    f"{colors['yellow']}Updating will restart TornadoRevC2 and terminate all active sessions, "
                    f"SOCKS proxies, tunnels, and other runtime state.{colors['end']}"
                )

                try:
                    answer = input(
                        f"{colors['cyan']}Proceed with update? [y/N]: {colors['end']}"
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    self._print_warning('Update cancelled.')
                    self.audit.log('UPDATE_ABORTED', reason='operator_cancelled', operator_confirmed='no')
                    return

                if answer not in ('y', 'yes'):
                    self._print_warning('Update cancelled.')
                    self.audit.log('UPDATE_ABORTED', reason='operator_declined', operator_confirmed='no')
                    return
                operator_confirmed = 'yes'

                begin_update(
                    previous_revision=previous_revision,
                    target_revision=target_revision,
                    repository=get_origin_url(repo_root, self._run_git),
                    branch=OFFICIAL_BRANCH,
                )

                set_state(STATE_APPLYING)
                self._print_info('Applying update...')
                apply_result = self._run_git(
                    'merge', '--ff-only', target_revision,
                    cwd=repo_root,
                    timeout=GIT_TIMEOUT_APPLY,
                )
                if apply_result.returncode != 0:
                    set_state(STATE_FAILED, failure_reason=_git_error(apply_result, 'apply failed'))
                    self._print_error(_git_error(apply_result, 'Failed to apply update'))
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='apply_failure',
                        operator_confirmed=operator_confirmed,
                    )
                    return

                self.audit.log('UPDATE_APPLIED', target_revision=target_revision)

                set_state(STATE_VALIDATING)
                ok, detail = validate_installation(repo_root)
                self.audit.log('UPDATE_VALIDATION', result='success' if ok else 'failure', detail=detail)
                if not ok:
                    set_state(STATE_FAILED, failure_reason=detail, validation_result='failure')
                    self._print_error(f'Post-update validation failed: {detail}')
                    set_state(STATE_ROLLING_BACK)
                    rolled_back, rollback_detail = rollback_to_revision(
                        repo_root, previous_revision, self._run_git
                    )
                    rollback_result = 'success' if rolled_back else 'failure'
                    self.audit.log(
                        'UPDATE_ROLLBACK',
                        result=rollback_result,
                        detail=rollback_detail,
                        previous_revision=previous_revision,
                    )
                    if rolled_back:
                        rollback_ok, rollback_validation_detail = validate_installation(repo_root)
                        self.audit.log(
                            'UPDATE_ROLLBACK_VALIDATION',
                            result='success' if rollback_ok else 'failure',
                            detail=rollback_validation_detail,
                        )
                        set_state(STATE_ROLLED_BACK)
                        if rollback_ok:
                            self._print_warning(
                                'Update validation failed. The installation was rolled back to the '
                                'previous known-good revision.'
                            )
                        else:
                            self._print_error(
                                'Update validation failed and rollback validation also failed: '
                                f'{rollback_validation_detail}'
                            )
                    else:
                        self._print_error(f'Rollback failed: {rollback_detail}')
                    self.audit.log(
                        'UPDATE_COMPLETED',
                        previous_revision=previous_revision,
                        new_revision=previous_revision,
                        final_result='validation_failed',
                    )
                    return

                set_state(STATE_COMPLETED, validation_result='success')
                self._print_success(UPDATE_SUCCESS_MSG)
                self.audit.log(
                    'UPDATE_COMPLETED',
                    previous_revision=previous_revision,
                    new_revision=target_revision,
                    final_result='success',
                    operator_confirmed=operator_confirmed,
                )
                clear_state()
                sys.stdout.flush()
                try:
                    self.h.shutdown_for_restart()
                    _restart_process()
                except Exception as exc:
                    self._print_error(f'Failed to restart TornadoRevC2: {exc}')
                    self.audit.log('UPDATE_ABORTED', reason='restart_failure', detail=str(exc))

        except UpdateLockError as exc:
            self._print_warning(str(exc))
            self.audit.log('UPDATE_ABORTED', reason='lock_acquisition_failure')
        except Exception as exc:
            self._print_error(f'Unexpected update failure: {exc}')
            self.audit.log('UPDATE_ABORTED', reason='unexpected_exception', detail=str(exc))
            if repo_root and previous_revision and target_revision:
                set_state(STATE_ROLLING_BACK)
                rolled_back, rollback_detail = rollback_to_revision(
                    repo_root, previous_revision, self._run_git
                )
                self.audit.log(
                    'UPDATE_ROLLBACK',
                    result='success' if rolled_back else 'failure',
                    detail=rollback_detail,
                )
                if rolled_back:
                    set_state(STATE_ROLLED_BACK)
        finally:
            self._busy = False
