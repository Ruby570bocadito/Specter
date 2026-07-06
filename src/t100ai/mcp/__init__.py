"""MCP - Model Context Protocol"""

from .tool import MCPTool, ToolParameter, ToolResult
from .advanced_registry import AdvancedToolRegistry
from .registry import ToolRegistry as LegacyToolRegistry

# AdvancedToolRegistry es la implementación canonical (templates, chains, parsers)
ToolRegistry = AdvancedToolRegistry

__all__ = [
    "MCPTool",
    "ToolParameter",
    "ToolResult",
    "ToolRegistry",
    "AdvancedToolRegistry",
    "LegacyToolRegistry",
]
