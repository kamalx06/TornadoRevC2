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
    modules = ['tornadorevc2.plugins.shared.virtualization']
    for sub in ('linux', 'windows'):
        subdir = os.path.join(root, sub)
        if not os.path.isdir(subdir):
            continue
        for fn in sorted(os.listdir(subdir)):
            if fn.endswith('.py') and fn != '__init__.py' and not fn.startswith('_'):
                modules.append(f'tornadorevc2.plugins.{sub}.{fn[:-3]}')
    return tuple(dict.fromkeys(modules))


BUILTIN_PLUGIN_MODULES = _discover_builtin_plugin_modules()


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
            except Exception:
                return False

    def _load_external(self, path: str) -> bool:
        name = os.path.splitext(os.path.basename(path))[0]
        if os.path.isdir(path):
            name = os.path.basename(path.rstrip(os.sep))
        spec_name = f'tornado_ext_plugin_{name}'
        if spec_name in sys.modules:
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
        except Exception:
            sys.modules.pop(spec_name, None)
            return False

    def reload_module(self, module_path: str, source: str = 'builtin') -> bool:
        with self._lock:
            self._loaded_modules.pop(module_path, None)
            if source == 'builtin':
                if module_path in sys.modules:
                    try:
                        importlib.reload(sys.modules[module_path])
                        self._loaded_modules[module_path] = source
                        return True
                    except Exception:
                        return False
            else:
                name = os.path.splitext(os.path.basename(module_path))[0]
                if os.path.isdir(module_path):
                    name = os.path.basename(module_path.rstrip(os.sep))
                spec_name = f'tornado_ext_plugin_{name}'
                sys.modules.pop(spec_name, None)
                self._external_paths.pop(name, None)
                registry = get_registry()
                to_remove = [
                    n for n, c in registry.all_commands().items()
                    if c.source == 'external' and name in (c.module or '')
                ]
                for n in to_remove:
                    registry.unregister(n)
        return self.load_module(module_path, source)

    def unload_external(self, name: str) -> bool:
        path = self._external_paths.get(name)
        if not path:
            return False
        spec_name = f'tornado_ext_plugin_{name}'
        with self._lock:
            self._loaded_modules.pop(path, None)
            self._external_paths.pop(name, None)
            sys.modules.pop(spec_name, None)
            registry = get_registry()
            for cmd_name in list(registry.all_commands().keys()):
                cmd = registry.get(cmd_name)
                if cmd and cmd.source == 'external':
                    registry.unregister(cmd_name)
        return True

    def loaded_modules(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._loaded_modules)

    def module_for_plugin(self, plugin_name: str) -> Optional[str]:
        cmd = get_registry().get(plugin_name)
        if cmd and cmd.module:
            return cmd.module
        return None

    def find_external_path(self, name: str) -> Optional[str]:
        for path in self.discover_external_modules():
            base = os.path.splitext(os.path.basename(path))[0]
            if os.path.isdir(path):
                base = os.path.basename(path.rstrip(os.sep))
            if base == name:
                return path
        return None

    def builtin_path_for_name(self, plugin_name: str) -> Optional[str]:
        for mod in BUILTIN_PLUGIN_MODULES:
            if mod.endswith(f'.{plugin_name}') or plugin_name in mod:
                return mod
        return None
