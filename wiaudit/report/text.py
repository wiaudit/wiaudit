from __future__ import annotations

import os
import sys
import textwrap
from typing import Any

from ..models import Finding

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def render_text(findings: list[Finding], summary: dict[str, int], meta: dict[str, Any]) -> str:
    color = _use_color()
    lines = [f"wiaudit {meta.get('version', '')} - workload identity audit"]
    if meta.get("tenantId"):
        lines.append(f"tenant: {meta['tenantId']}  identities: {meta.get('identities', 0)}  workflows: {meta.get('workflows', 0)}")
    lines.append("summary: " + ", ".join(f"{k} {v}" for k, v in summary.items()))
    if meta.get("byRule"):
        lines.append("by rule: " + ", ".join(f"{r} x{n}" for r, _s, _t, n in meta["byRule"]))
    lines.append("")
    if not findings:
        lines.append("No findings.")
    for f in findings:
        sev = f.severity.label.upper()
        if color:
            sev = f"{_COLORS[f.severity.label]}{sev}{_RESET}"
        loc = f"{f.location}:{f.line}" if f.location and f.line else f.target
        lines.append(f"[{sev}] {f.rule_id} {f.title}")
        lines.append(f"  where: {loc}")
        lines.extend("  " + l for l in textwrap.wrap(f.message, 100))
        fix = f.remediation.splitlines()
        lines.append("  fix:   " + (fix[0] if fix else ""))
        lines.extend("         " + l for l in fix[1:])
        lines.append("")
    for err in meta.get("errors", []):
        lines.append(f"warning: {err}")
    return "\n".join(lines)
