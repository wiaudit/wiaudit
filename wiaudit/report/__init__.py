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


def by_rule(findings: list[Finding]) -> list[tuple[str, str, str, int]]:
    """(rule_id, worst severity label, title, count), most severe and most frequent first."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.rule_id, []).append(f)
    rows = [(rid, max(fs, key=lambda x: x.severity).severity, fs[0].title, len(fs)) for rid, fs in groups.items()]
    rows.sort(key=lambda r: (-int(r[1]), -r[3], r[0]))
    return [(rid, sev.label, title, n) for rid, sev, title, n in rows]


def render(fmt: str, findings: list[Finding], meta: dict[str, Any]) -> str:
    findings = sort_findings(findings)
    if fmt == "json":
        return json.dumps(
            {"meta": meta, "summary": summary(findings), "byRule": [
                {"ruleId": r, "severity": sv, "title": t, "count": n} for r, sv, t, n in by_rule(findings)
            ], "findings": [f.to_dict() for f in findings]},
            indent=2,
            ensure_ascii=False,
        )
    if fmt == "sarif":
        return render_sarif(findings, meta)
    if fmt == "html":
        return render_html(findings, summary(findings), {**meta, "byRule": by_rule(findings)})
    return render_text(findings, summary(findings), {**meta, "byRule": by_rule(findings)})
