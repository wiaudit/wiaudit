"""SARIF 2.1.0 output for GitHub code scanning."""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, Severity
from ..rules import RULES

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(findings: list[Finding], meta: dict[str, Any]) -> str:
    fallback_file = meta.get("firstWorkflow")
    results = []
    for f in findings:
        res: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.message}\nFix: {f.remediation}"},
            "properties": {"security-severity": _SCORE[f.severity], "target": f.target},
        }
        uri = f.location or fallback_file
        if uri:
            region = {"startLine": f.line} if f.line and f.location else {"startLine": 1}
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wiaudit",
                        "version": meta.get("version", "0"),
                        "informationUri": "https://github.com/wiaudit/wiaudit",
                        "rules": [
                            {
                                "id": rid,
                                "name": rid,
                                "shortDescription": {"text": title},
                                "properties": {"tags": ["security", "oidc", "workload-identity"]},
                            }
                            for rid, title in RULES.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
