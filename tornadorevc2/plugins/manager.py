"""Plugin manager — runtime loading, listing, and execution."""



import os

import threading

from typing import List, Optional, Set



from .api import SessionContext, get_registry

from .loader import EXTERNAL_PLUGIN_DIR, PluginLoader

from .shared.common import filter_commands_by_platform, platform_supported





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

                for name in self._loader.commands_for_module_path(module_path, 'builtin'):

                    self._enabled.add(name)



    def _colors(self):

        return self.h.colors



    def _session_platform(self, client_sock) -> str:

        info = self.h._client_info(client_sock)

        if not info:

            return 'unknown'

        return self.h.resolve_shell_type(client_sock, info)



    def _commands_for_session(self, client_sock):

        platform = self._session_platform(client_sock)

        return filter_commands_by_platform(get_registry().all_commands(), platform)



    def list_plugins(self, show_all: bool = False, client_sock=None):

        c = self._colors()

        registry = get_registry()

        session_platform = None

        if client_sock is not None:

            session_platform = self._session_platform(client_sock)

            all_cmds = filter_commands_by_platform(registry.all_commands(), session_platform)

        else:

            all_cmds = registry.all_commands()

        loaded = self._loader.loaded_modules()



        loaded_count = sum(1 for name in all_cmds if name in self._enabled)

        header = f"\n{c['cyan']}PLUGINS | Loaded: {loaded_count}{c['end']}"

        if session_platform is not None:

            header += f" | Platform: {session_platform}"

        print(header)

        if not all_cmds:

            if session_platform is not None:

                print(f"{c['yellow']}No plugins available for this session platform{c['end']}")

            else:

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



    def plugin_info(self, name: str, client_sock=None) -> bool:

        c = self._colors()

        cmd = get_registry().get(name)

        if not cmd:

            print(f"{c['red']}Plugin '{name}' not found{c['end']}")

            return False

        if client_sock is not None:

            platform = self._session_platform(client_sock)

            if not platform_supported(cmd.platforms, platform):

                print(

                    f"{c['red']}Plugin '{name}' is not available for "

                    f"{platform} sessions (supports: {', '.join(cmd.platforms)}){c['end']}"

                )

                return False

        enabled = name in self._enabled

        print(f"\n{c['cyan']}PLUGIN: {name}{c['end']}")

        print(f"  Description: {cmd.description}")

        print(f"  Platforms:   {', '.join(cmd.platforms)}")

        print(f"  Module:      {cmd.module or 'unknown'}")

        print(f"  Source:      {cmd.source}")

        print(f"  Status:      {'enabled' if enabled else 'disabled'}")

        if cmd.module:
            try:
                import importlib
                mod = importlib.import_module(cmd.module)
                extra = getattr(mod, 'PLUGIN_INFO', None)
                if extra:
                    print(f"\n{c['green']}Info:{c['end']}\n{extra}")
            except Exception:
                pass

        return True



    def load_plugin(self, name: str) -> bool:

        c = self._colors()

        cmd = get_registry().get(name)

        if cmd and name in self._enabled:

            print(f"{c['yellow']}Plugin '{name}' is already loaded{c['end']}")

            return True



        mod = self._loader.builtin_path_for_name(name)

        source = 'builtin'

        if not mod:

            ext = self._loader.find_external_path(name)

            if not ext:

                print(f"{c['red']}Plugin '{name}' not found{c['end']}")

                return False

            mod = ext

            source = 'external'



        if not self._loader.load_module(mod, source=source):

            print(f"{c['red']}Failed to load plugin '{name}'{c['end']}")

            return False



        if not get_registry().get(name):

            print(f"{c['red']}Plugin module loaded but command '{name}' not registered{c['end']}")

            return False



        with self._lock:

            self._enabled.add(name)

        print(f"{c['green']}Plugin '{name}' loaded{c['end']}")

        return True



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



        ext_name = self._loader.external_name_for_command(cmd) or name

        with self._lock:

            self._enabled.discard(name)

            get_registry().unregister(name)

        self._loader.unload_external(ext_name)

        print(f"{c['green']}Plugin '{name}' unloaded{c['end']}")

        return True



    def _resolve_plugin_module(self, name: str):

        cmd = get_registry().get(name)

        if cmd and cmd.source == 'external':

            ext_name = self._loader.external_name_for_command(cmd) or name

            path = self._loader.find_external_path(ext_name)

            if path:

                return path, 'external'

        mod = self._loader.builtin_path_for_name(name)

        if mod:

            return mod, 'builtin'

        path = self._loader.find_external_path(name)

        if path:

            return path, 'external'

        return None, None



    def reload_plugin(self, name: str) -> bool:

        c = self._colors()

        was_enabled = name in self._enabled

        mod, source = self._resolve_plugin_module(name)

        if not mod:

            print(f"{c['red']}Cannot resolve module for plugin '{name}'{c['end']}")

            return False



        with self._lock:

            self._enabled.discard(name)



        if not self._loader.reload_module(mod, source=source):

            if was_enabled:

                with self._lock:

                    self._enabled.add(name)

            print(f"{c['red']}Failed to reload plugin '{name}'{c['end']}")

            return False



        if not get_registry().get(name):

            print(

                f"{c['red']}Plugin '{name}' reloaded but command is no longer registered "

                f"(check @plugin.command name){c['end']}"

            )

            return False



        with self._lock:

            self._enabled.add(name)

        print(f"{c['green']}Plugin '{name}' reloaded{c['end']}")

        return True



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



        platform = self.h.resolve_shell_type(client_sock, info)

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



    def handle_command(self, cmd_parts: List[str], client_sock=None) -> bool:

        if not cmd_parts:

            return False

        cmd = cmd_parts[0].lower()



        if cmd == 'run':

            if client_sock is not None:

                if len(cmd_parts) < 2:

                    print(f"{self._colors()['red']}Usage: run <plugin> [args...]{self._colors()['end']}")

                    return True

                return self.run_plugin(cmd_parts[1], client_sock, cmd_parts[2:])



            if len(cmd_parts) < 3:

                print(f"{self._colors()['red']}Usage: run <plugin> <session_id> [args...]{self._colors()['end']}")

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

            self.list_plugins(

                show_all=(len(cmd_parts) > 2 and cmd_parts[2] == '--verbose'),

                client_sock=client_sock,

            )

        elif sub == 'load' and len(cmd_parts) >= 3:

            self.load_plugin(cmd_parts[2])

        elif sub == 'unload' and len(cmd_parts) >= 3:

            self.unload_plugin(cmd_parts[2])

        elif sub == 'reload' and len(cmd_parts) >= 3:

            self.reload_plugin(cmd_parts[2])

        elif sub == 'info' and len(cmd_parts) >= 3:

            self.plugin_info(cmd_parts[2], client_sock=client_sock)

        elif sub == 'help':

            self._print_plugins_help(client_sock=client_sock)

        else:

            self._print_plugins_help(client_sock=client_sock)

        return True



    def _print_plugins_help(self, client_sock=None):

        c = self._colors()

        if client_sock is not None:

            platform = self._session_platform(client_sock)

            print(f"""

    {c['green']}PLUGIN MANAGEMENT (session — {platform}):{c['end']}

    plugins / plugins list              List plugins for this session

    plugins list --verbose              Show module paths

    plugins load <name>                 Load a plugin at runtime

    plugins unload <name>               Unload/disable a plugin

    plugins reload <name>               Reload a plugin module

    plugins info <name>                 Show plugin details

    run <plugin> [args...]              Execute a plugin on this session

                                          inmemory:  run inmemory <filetype> <local_file> [-- args] [--save-output <file>]
                                                     filetypes: py, ps, exe, elf, bat, sh

                                          quickenum: run quickenum

                                          clipboard: run clipboard

                                          wiper:     run wiper <remote_file_path>



    {c['yellow']}Only plugins compatible with {platform} are listed and runnable here.{c['end']}



    {c['yellow']}External plugins: place modules in ./{EXTERNAL_PLUGIN_DIR}{c['end']}""")

            return



        print(f"""

    {c['green']}PLUGIN MANAGEMENT:{c['end']}

    plugins / plugins list              List registered plugins

    plugins list --verbose              Show module paths

    plugins load <name>                 Load a plugin at runtime

    plugins unload <name>               Unload/disable a plugin

    plugins reload <name>               Reload a plugin module

    plugins info <name>                 Show plugin details

    run <plugin> <session_id> [args...]   Execute plugin on a session

                                          inmemory:  run inmemory <ID> <filetype> <local_file> [-- args] [--save-output <file>]
                                                     filetypes: py, ps, exe, elf, bat, sh

                                          quickenum: run quickenum <ID>

                                          clipboard: run clipboard <ID>

                                          wiper:     run wiper <ID> <remote_file_path>



    {c['yellow']}Inside a client shell, omit session_id: run <plugin> [args...]{c['end']}



    {c['yellow']}External plugins: place modules in ./{EXTERNAL_PLUGIN_DIR}{c['end']}""")



    def completion_plugins(self, client_sock=None) -> List[str]:

        if client_sock is None:

            return sorted(get_registry().all_commands().keys())

        return sorted(self._commands_for_session(client_sock).keys())

