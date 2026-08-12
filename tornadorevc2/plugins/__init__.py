"""TornadoRevC2 plugin system."""

from .api import SessionContext, plugin, get_registry, PluginCommand
from .manager import PluginManager

__all__ = [
    'plugin',
    'SessionContext',
    'PluginManager',
    'PluginCommand',
    'get_registry',
]
