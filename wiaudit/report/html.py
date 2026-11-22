"""Self-contained HTML report, suitable to hand to an auditor."""

from __future__ import annotations

from html import escape
from typing import Any

from ..models import Finding

_CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--line:#e7e5e4;--card:#fff;
--critical:#b91c1c;--high:#dc2626;--medium:#d97706;--low:#0e7490;--info:#78716c}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--line:#44403c;--card:#292524}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px}.meta{color:var(--muted);font-size:13px;margin-bottom:24px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:28px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.tile b{display:block;font-size:26px}.tile span{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.f h3{margin:0 0 6px;font-size:15px}.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-right:8px}
.where{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted);word-break:break-all}
.fix{white-space:pre-wrap;background:var(--bg);border-radius:6px;padding:8px 10px;font-size:13px;margin-top:8px}
"""


def render_html(findings: list[Finding], summary: dict[str, int], meta: dict[str, Any]) -> str:
    tiles = "".join(
        f'<div class="tile" style="border-top:3px solid var(--{k})"><b>{v}</b><span>{k}</span></div>'
        for k, v in summary.items()
    )
    items = []
    for f in findings:
        sev = f.severity.label
        where = f"{f.location}:{f.line}" if f.location and f.line else f.target
        items.append(
            f'<div class="f" style="border-left-color:var(--{sev})">'
            f'<h3><span class="sev" style="color:var(--{sev})">{sev}</span>{escape(f.rule_id)} · {escape(f.title)}</h3>'
            f'<div class="where">{escape(where)}</div>'
            f"<p>{escape(f.message)}</p>"
            f'<div class="fix"><b>Fix:</b> {escape(f.remediation)}</div></div>'
        )
    body = "".join(items) or "<p>No findings.</p>"
    meta_line = " · ".join(
        escape(str(x))
        for x in [
            f"tenant {meta['tenantId']}" if meta.get("tenantId") else None,
            f"{meta.get('identities', 0)} identities",
            f"{meta.get('workflows', 0)} workflows",
            f"generated {meta.get('generatedAt', '')}",
            f"wiaudit {meta.get('version', '')}",
        ]
        if x
    )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Workload identity audit</title><style>{_CSS}</style></head><body><main>"
        f"<h1>Workload identity audit</h1><div class='meta'>{meta_line}</div>"
        f"<div class='tiles'>{tiles}</div>{body}</main></body></html>"
    )
