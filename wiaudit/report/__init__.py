"""Report renderers: text, json, sarif, html."""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, Severity
from .html import render_html
from .sarif import render_sarif
from .text import render_text


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.rule_id, f.target))


def summary(findings: list[Finding]) -> dict[str, int]:
    out = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        out[f.severity.label] += 1
    return out


def render(fmt: str, findings: list[Finding], meta: dict[str, Any]) -> str:
    findings = sort_findings(findings)
    if fmt == "json":
        return json.dumps(
            {"meta": meta, "summary": summary(findings), "findings": [f.to_dict() for f in findings]},
            indent=2,
            ensure_ascii=False,
        )
    if fmt == "sarif":
        return render_sarif(findings, meta)
    if fmt == "html":
        return render_html(findings, summary(findings), meta)
    return render_text(findings, summary(findings), meta)
