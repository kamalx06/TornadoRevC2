"""Post-update installation validation."""

import ast
import compileall
import importlib.util
import os
import sys


def _install_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _required_paths(repo_root):
    return (
        os.path.join(repo_root, 'tornadorevc2.py'),
        os.path.join(repo_root, 'tornadorevc2', 'handler.py'),
        os.path.join(repo_root, 'tornadorevc2', 'updater.py'),
    )


def validate_python_syntax(repo_root):
    package_dir = os.path.join(repo_root, 'tornadorevc2')
    if not os.path.isdir(package_dir):
        return False, 'Missing tornadorevc2 package directory'

    failures = []
    for root, _, files in os.walk(package_dir):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, 'r', encoding='utf-8') as handle:
                    ast.parse(handle.read(), filename=path)
            except SyntaxError as exc:
                failures.append(f'{path}: {exc.msg}')

    if failures:
        return False, '; '.join(failures[:5])
    return True, ''


def validate_required_files(repo_root):
    missing = [path for path in _required_paths(repo_root) if not os.path.isfile(path)]
    if missing:
        return False, 'Missing required files: ' + ', '.join(missing)
    return True, ''


def validate_handler_import(repo_root):
    handler_path = os.path.join(repo_root, 'tornadorevc2', 'handler.py')
    spec = importlib.util.spec_from_file_location('tornadorevc2_update_validate_handler', handler_path)
    if spec is None or spec.loader is None:
        return False, 'Unable to load handler module spec'

    module = importlib.util.module_from_spec(spec)
    previous_path = list(sys.path)
    inserted = repo_root not in sys.path
    if inserted:
        sys.path.insert(0, repo_root)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        return False, f'Handler import failed: {exc}'
    finally:
        if inserted:
            sys.path[:] = previous_path
    return True, ''


def validate_installation(repo_root=None):
    """Run meaningful installation checks before restart."""
    repo_root = repo_root or _install_root()

    ok, detail = validate_required_files(repo_root)
    if not ok:
        return False, detail

    ok, detail = validate_python_syntax(repo_root)
    if not ok:
        return False, detail

    ok, detail = validate_handler_import(repo_root)
    if not ok:
        return False, detail

    if not compileall.compile_dir(
        os.path.join(repo_root, 'tornadorevc2'),
        quiet=1,
        legacy=False,
    ):
        return False, 'Bytecode compilation failed for one or more modules'

    return True, ''
