"""MCP server adapter for sealedplan (SPEC §12)."""

from sealedplan_mcp.server import (
    EXTENSION_ID,
    SPEC_VERSION,
    PlanApply,
    create_server,
    tool_annotations,
    tool_name,
)

__all__ = [
    "EXTENSION_ID",
    "SPEC_VERSION",
    "PlanApply",
    "create_server",
    "tool_annotations",
    "tool_name",
]
