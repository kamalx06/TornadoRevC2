"""Plugin manager — runtime loading, listing, and execution."""

import os
import threading
from typing import List, Optional, Set

from .api import SessionContext, get_registry
from .loader import EXTERNAL_PLUGIN_DIR, PluginLoader
from .shared.common import platform_supported


class PluginManager:
    """Manages plugin discovery, loading, and execution."""

    def __init__(self, handler):
        self.h = handler
        self._lock = threading.Lock()
        self._loader = PluginLoader()
        self._enabled: Set[str] = set()
        self._load_builtin_plugins()

    def _load_builtin_plugins(self):
        for module_path in self._loader.discover_builtin_modules():
            if self._loader.load_module(module_path, source='builtin'):
                for name in get_registry().all_commands().keys():
                    self._enabled.add(name)

    def _colors(self):
        return self.h.colors

    def list_plugins(self, show_all: bool = False):
        c = self._colors()
        registry = get_registry()
        all_cmds = registry.all_commands()
        loaded = self._loader.loaded_modules()

        print(f"\n{c['cyan']}PLUGINS | Loaded: {len(self._enabled)}{c['end']}")
        if not all_cmds:
            print(f"{c['yellow']}No plugins registered{c['end']}")
            return

        print(f"{c['green']}Registered:{c['end']}")
        for name in sorted(all_cmds.keys()):
            cmd = all_cmds[name]
            status = f"{c['green']}enabled{c['end']}" if name in self._enabled else f"{c['red']}disabled{c['end']}"
            platforms = ', '.join(cmd.platforms)
            print(
                f"  {c['bold']}{name}{c['end']} [{status}] "
                f"({platforms}) — {cmd.description}"
            )
            if show_all:
                print(f"    module: {cmd.module or '?'} | source: {cmd.source}")

        external = self._loader.discover_external_modules()
        if external:
            print(f"\n{c['green']}External plugin paths ({EXTERNAL_PLUGIN_DIR}):{c['end']}")
            for path in external:
                print(f"  {path}")

        if show_all and loaded:
            print(f"\n{c['green']}Loaded modules:{c['end']}")
            for path, source in loaded.items():
                print(f"  [{source}] {path}")

    def plugin_info(self, name: str) -> bool:
        c = self._colors()
        cmd = get_registry().get(name)
        if not cmd:
            print(f"{c['red']}Plugin '{name}' not found{c['end']}")
            return False
        enabled = name in self._enabled
        print(f"\n{c['cyan']}PLUGIN: {name}{c['end']}")
        print(f"  Description: {cmd.description}")
        print(f"  Platforms:   {', '.join(cmd.platforms)}")
        print(f"  Module:      {cmd.module or 'unknown'}")
        print(f"  Source:      {cmd.source}")
        print(f"  Status:      {'enabled' if enabled else 'disabled'}")
        return True

    def load_plugin(self, name: str) -> bool:
        c = self._colors()
        if get_registry().get(name) and name in self._enabled:
            print(f"{c['yellow']}Plugin '{name}' is already loaded{c['end']}")
            return True

        mod = self._loader.builtin_path_for_name(name)
        source = 'builtin'
        if not mod:
            ext = self._loader.find_external_path(name)
            if ext:
                mod = ext
                source = 'external'
            else:
                for candidate in self._loader.discover_external_modules():
                    if self._loader.load_module(candidate, source='external'):
                        if get_registry().get(name):
                            mod = candidate
                            source = 'external'
                            break

        if mod and self._loader.load_module(mod, source=source):
            if get_registry().get(name):
                with self._lock:
                    self._enabled.add(name)
                print(f"{c['green']}Plugin '{name}' loaded{c['end']}")
                return True

        print(f"{c['red']}Failed to load plugin '{name}'{c['end']}")
        return False

    def unload_plugin(self, name: str) -> bool:
        c = self._colors()
        cmd = get_registry().get(name)
        if not cmd:
            print(f"{c['red']}Plugin '{name}' not found{c['end']}")
            return False
        if cmd.source == 'builtin':
            with self._lock:
                self._enabled.discard(name)
            print(f"{c['yellow']}Built-in plugin '{name}' disabled (cannot unload module){c['end']}")
            return True
        with self._lock:
            self._enabled.discard(name)
            get_registry().unregister(name)
        self._loader.unload_external(name)
        print(f"{c['green']}Plugin '{name}' unloaded{c['end']}")
        return True

    def reload_plugin(self, name: str) -> bool:
        c = self._colors()
        cmd = get_registry().get(name)
        mod = self._loader.module_for_plugin(name) if cmd else self._loader.builtin_path_for_name(name)
        if not mod:
            ext = self._loader.find_external_path(name)
            mod = ext
        if not mod:
            print(f"{c['red']}Cannot resolve module for plugin '{name}'{c['end']}")
            return False
        source = 'external' if os.path.isfile(mod) or os.path.isdir(mod) else 'builtin'
        with self._lock:
            self._enabled.discard(name)
        if self._loader.reload_module(mod, source=source):
            if get_registry().get(name):
                with self._lock:
                    self._enabled.add(name)
                print(f"{c['green']}Plugin '{name}' reloaded{c['end']}")
                return True
        print(f"{c['red']}Failed to reload plugin '{name}'{c['end']}")
        return False

    def run_plugin(self, name: str, client_sock, args: Optional[List[str]] = None) -> bool:
        c = self._colors()
        args = args or []

        if name not in self._enabled:
            if not self.load_plugin(name):
                return True

        cmd = get_registry().get(name)
        if not cmd:
            print(f"{c['red']}Plugin '{name}' not found{c['end']}")
            return True

        info = self.h._client_info(client_sock)
        if not info:
            print(f"{c['red']}Client disconnected{c['end']}")
            return True

        platform = info.get('type', 'unknown')
        if not platform_supported(cmd.platforms, platform):
            print(
                f"{c['red']}Plugin '{name}' does not support platform "
                f"'{platform}' (supports: {', '.join(cmd.platforms)}){c['end']}"
            )
            return True

        ctx = SessionContext(self.h, client_sock)
        try:
            with self._lock:
                result = cmd.handler(ctx, args)
            if result not in (0, None):
                print(f"{c['yellow']}Plugin '{name}' returned code {result}{c['end']}")
        except Exception as exc:
            print(f"{c['red']}Plugin '{name}' error: {exc}{c['end']}")
            logger = info.get('logger')
            if logger:
                logger.log_event(f"Plugin {name} error: {exc}")
        return True

    def handle_command(self, cmd_parts: List[str]) -> bool:
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()

        if cmd == 'run':
            if len(cmd_parts) < 3:
                print(f"{self._colors()['red']}Usage: run <plugin> <session_id>{self._colors()['end']}")
                return True
            plugin_name = cmd_parts[1]
            try:
                session_id = int(cmd_parts[2])
            except ValueError:
                print(f"{self._colors()['red']}Invalid session ID{self._colors()['end']}")
                return True
            client_sock = self.h._get_client_by_id(session_id)
            if not client_sock:
                print(f"{self._colors()['red']}Client #{session_id} not active{self._colors()['end']}")
                return True
            return self.run_plugin(plugin_name, client_sock, cmd_parts[3:])

        if cmd != 'plugins':
            return False

        sub = cmd_parts[1].lower() if len(cmd_parts) > 1 else 'list'
        if sub in ('list', 'ls', ''):
            self.list_plugins(show_all=(len(cmd_parts) > 2 and cmd_parts[2] == '--verbose'))
        elif sub == 'load' and len(cmd_parts) >= 3:
            self.load_plugin(cmd_parts[2])
        elif sub == 'unload' and len(cmd_parts) >= 3:
            self.unload_plugin(cmd_parts[2])
        elif sub == 'reload' and len(cmd_parts) >= 3:
            self.reload_plugin(cmd_parts[2])
        elif sub == 'info' and len(cmd_parts) >= 3:
            self.plugin_info(cmd_parts[2])
        elif sub == 'help':
            self._print_plugins_help()
        else:
            self._print_plugins_help()
        return True

    def _print_plugins_help(self):
        c = self._colors()
        print(f"""
    {c['green']}PLUGIN MANAGEMENT:{c['end']}
    plugins / plugins list              List registered plugins
    plugins list --verbose              Show module paths
    plugins load <name>                 Load a plugin at runtime
    plugins unload <name>               Unload/disable a plugin
    plugins reload <name>               Reload a plugin module
    plugins info <name>                 Show plugin details
    run <plugin> <session_id>           Execute plugin on a session

    {c['yellow']}External plugins: place modules in ./{EXTERNAL_PLUGIN_DIR}{c['end']}""")

    def completion_plugins(self) -> List[str]:
        return sorted(get_registry().all_commands().keys())
