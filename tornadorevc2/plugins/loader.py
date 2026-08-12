"""Dynamic plugin discovery and loading."""

import importlib
import importlib.util
import os
import sys
import threading
from typing import Dict, List, Optional

from .api import PluginCommand, get_registry


EXTERNAL_PLUGIN_DIR = os.environ.get(
    'TORNADOREVC2_PLUGIN_DIR',
    os.path.join(os.getcwd(), 'plugins'),
)


def _discover_builtin_plugin_modules() -> tuple:
    root = os.path.dirname(os.path.abspath(__file__))
    skip_shared = {'common', 'runner', '__init__'}
    modules = []
    shared_dir = os.path.join(root, 'shared')
    if os.path.isdir(shared_dir):
        for fn in sorted(os.listdir(shared_dir)):
            if fn.endswith('.py') and fn[:-3] not in skip_shared:
                modules.append(f'tornadorevc2.plugins.shared.{fn[:-3]}')
    for sub in ('linux', 'windows'):
        subdir = os.path.join(root, sub)
        if not os.path.isdir(subdir):
            continue
        for fn in sorted(os.listdir(subdir)):
            if fn.endswith('.py') and fn != '__init__.py' and not fn.startswith('_'):
                modules.append(f'tornadorevc2.plugins.{sub}.{fn[:-3]}')
    return tuple(dict.fromkeys(modules))


BUILTIN_PLUGIN_MODULES = _discover_builtin_plugin_modules()


def _external_spec_name(path: str) -> str:
    name = os.path.splitext(os.path.basename(path))[0]
    if os.path.isdir(path):
        name = os.path.basename(path.rstrip(os.sep))
    return f'tornado_ext_plugin_{name}'


class PluginLoader:
    """Discover and import plugin modules at runtime."""

    def __init__(self):
        self._lock = threading.Lock()
        self._loaded_modules: Dict[str, str] = {}
        self._external_paths: Dict[str, str] = {}

    def discover_builtin_modules(self) -> List[str]:
        return list(BUILTIN_PLUGIN_MODULES)

    def discover_external_modules(self) -> List[str]:
        found = []
        if not os.path.isdir(EXTERNAL_PLUGIN_DIR):
            return found
        for entry in sorted(os.listdir(EXTERNAL_PLUGIN_DIR)):
            if entry.startswith('_') or entry.startswith('.'):
                continue
            path = os.path.join(EXTERNAL_PLUGIN_DIR, entry)
            if entry.endswith('.py') and os.path.isfile(path):
                found.append(path)
            elif os.path.isdir(path) and os.path.isfile(os.path.join(path, '__init__.py')):
                found.append(path)
        return found

    def load_module(self, module_path: str, source: str = 'builtin') -> bool:
        with self._lock:
            if module_path in self._loaded_modules:
                return True
            try:
                if source == 'builtin':
                    importlib.import_module(module_path)
                    self._loaded_modules[module_path] = source
                    return True
                return self._load_external(module_path)
            except Exception as exc:
                print(f"[plugins] failed to load {module_path}: {exc}", file=sys.stderr)
                return False

    def _load_external(self, path: str) -> bool:
        name = os.path.splitext(os.path.basename(path))[0]
        if os.path.isdir(path):
            name = os.path.basename(path.rstrip(os.sep))
        spec_name = _external_spec_name(path)
        if spec_name in sys.modules:
            module = sys.modules[spec_name]
            self._loaded_modules[path] = 'external'
            self._external_paths[name] = path
            for cmd in get_registry().all_commands().values():
                if cmd.module == module.__name__:
                    cmd.source = 'external'
            return True
        try:
            if os.path.isdir(path):
                init_path = os.path.join(path, '__init__.py')
                spec = importlib.util.spec_from_file_location(spec_name, init_path)
            else:
                spec = importlib.util.spec_from_file_location(spec_name, path)
            if spec is None or spec.loader is None:
                return False
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec_name] = module
            spec.loader.exec_module(module)
            self._loaded_modules[path] = 'external'
            self._external_paths[name] = path
            for cmd in get_registry().all_commands().values():
                if cmd.module == module.__name__:
                    cmd.source = 'external'
            return True
        except Exception as exc:
            sys.modules.pop(spec_name, None)
            print(f"[plugins] failed to load external {path}: {exc}", file=sys.stderr)
            return False

    def _unregister_module_commands(self, module_name: str) -> List[str]:
        return get_registry().unregister_module(module_name)

    def reload_module(self, module_path: str, source: str = 'builtin') -> bool:
        with self._lock:
            self._loaded_modules.pop(module_path, None)
            registry = get_registry()
            if source == 'builtin':
                if module_path not in sys.modules:
                    return self.load_module(module_path, source)
                mod = sys.modules[module_path]
                self._unregister_module_commands(mod.__name__)
                try:
                    importlib.reload(mod)
                    self._loaded_modules[module_path] = source
                    return True
                except Exception as exc:
                    print(f"[plugins] failed to reload {module_path}: {exc}", file=sys.stderr)
                    return False

            name = os.path.splitext(os.path.basename(module_path))[0]
            if os.path.isdir(module_path):
                name = os.path.basename(module_path.rstrip(os.sep))
            spec_name = _external_spec_name(module_path)
            self._unregister_module_commands(spec_name)
            sys.modules.pop(spec_name, None)
            self._external_paths.pop(name, None)
        return self.load_module(module_path, source)

    def unload_external(self, name: str) -> bool:
        path = self._external_paths.get(name)
        if not path:
            return False
        spec_name = _external_spec_name(path)
        with self._lock:
            self._loaded_modules.pop(path, None)
            self._external_paths.pop(name, None)
            sys.modules.pop(spec_name, None)
            self._unregister_module_commands(spec_name)
        return True

    def external_name_for_command(self, cmd: PluginCommand) -> Optional[str]:
        if not cmd or cmd.source != 'external' or not cmd.module:
            return None
        prefix = 'tornado_ext_plugin_'
        if cmd.module.startswith(prefix):
            return cmd.module[len(prefix):]
        for ext_name, path in self._external_paths.items():
            if cmd.module == _external_spec_name(path):
                return ext_name
        return None

    def loaded_modules(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._loaded_modules)

    def module_for_plugin(self, plugin_name: str) -> Optional[str]:
        cmd = get_registry().get(plugin_name)
        if cmd and cmd.module:
            return cmd.module
        return None

    def find_external_path(self, name: str) -> Optional[str]:
        cached = self._external_paths.get(name)
        if cached:
            return cached
        for path in self.discover_external_modules():
            base = os.path.splitext(os.path.basename(path))[0]
            if os.path.isdir(path):
                base = os.path.basename(path.rstrip(os.sep))
            if base == name:
                return path
        return None

    def builtin_path_for_name(self, plugin_name: str) -> Optional[str]:
        matches = [
            mod for mod in BUILTIN_PLUGIN_MODULES
            if mod.endswith(f'.{plugin_name}')
        ]
        if not matches:
            return None
        cmd = get_registry().get(plugin_name)
        if cmd and cmd.module:
            for mod in matches:
                if cmd.module == mod:
                    return mod
        for mod in matches:
            if '.shared.' in mod:
                return mod
        return matches[0]

    def commands_for_module_path(self, module_path: str, source: str) -> List[str]:
        if source == 'builtin':
            module_name = module_path
        else:
            module_name = _external_spec_name(module_path)
        return [
            name for name, cmd in get_registry().all_commands().items()
            if cmd.module == module_name
        ]
