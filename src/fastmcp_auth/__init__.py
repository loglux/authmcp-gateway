"""FastMCP Auth Gateway - Universal Authentication for MCP Servers."""

__version__ = "1.0.0"
__author__ = "loglux"
__license__ = "MIT"

from .app import app
from .config import load_config, get_config

__all__ = ["app", "load_config", "get_config", "__version__"]
