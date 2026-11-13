"""Veil as an MCP server, so Claude Desktop (or any MCP client) can mask documents before reasoning
over them and unmask its own drafts. Add to claude_desktop_config.json:
  {"mcpServers": {"veil": {"command": "veil-mcp"}}}
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from .audit import AuditLog
from .detect import build_detector
from .policy import Policy
from .pseudonym import Pseudonymizer, summarize
from .restore import restore
from .vault import Vault

mcp = FastMCP("veil")
_db = os.getenv("VEIL_DB_PATH", "veil.db")
_pz: Pseudonymizer | None = None
_log = AuditLog(_db)


def pz() -> Pseudonymizer:
    global _pz
    if _pz is None:
        _pz = Pseudonymizer(build_detector(), Vault(_db), Policy.load())
    return _pz


@mcp.tool()
def mask_text(text: str, session: str = "mcp") -> dict:
    """Replace PII/PHI in text with consistent realistic pseudonyms. Returns masked text and entity counts."""
    masked, reps = pz().mask(session, text)
    _log.append({"event": "mcp_mask", "session": session, "masked": summarize(reps)})
    return {"masked": masked, "entities": summarize(reps), "session": session}


@mcp.tool()
def unmask_text(text: str, session: str = "mcp") -> str:
    """Swap pseudonyms produced by mask_text back to the original values."""
    _log.append({"event": "mcp_unmask", "session": session})
    return restore(text, pz().restore_map(session))


@mcp.tool()
def verify_audit_log() -> dict:
    """Check the hash chain of the audit log; ok=false means an entry was altered or removed."""
    return _log.verify()


def main():
    mcp.run()


if __name__ == "__main__":
    main()
