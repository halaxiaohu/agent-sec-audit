from __future__ import annotations

import json
from typing import Any, Dict, List

from agent_sec_audit import __version__
from agent_sec_audit.models import Finding, ScanResult, Severity
from agent_sec_audit.rules import RULES_CATALOG

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # Bold Red
    Severity.HIGH: "\033[31m",      # Red
    Severity.MEDIUM: "\033[33m",    # Yellow
    Severity.LOW: "\033[36m",       # Cyan
}


def format_text_report(
    result: ScanResult,
    findings: List[Finding],
    use_color: bool = True,
) -> str:
    lines: List[str] = []
    bold = ANSI_BOLD if use_color else ""
    dim = ANSI_DIM if use_color else ""
    reset = ANSI_RESET if use_color else ""

    lines.append(f"{bold}========================================================================{reset}")
    lines.append(f"{bold} agent-sec-audit v{__version__} — AI Agent & MCP Security Scanner{reset}")
    lines.append(f"{bold}========================================================================{reset}")
    lines.append(
        f"Target: {result.target_path} | Files scanned: {result.files_scanned} | Duration: {result.duration_ms:.1f} ms"
    )
    lines.append("")

    if not findings:
        green = "\033[32m" if use_color else ""
        lines.append(f"{green}{bold}✔ No security issues detected.{reset}")
        return "\n".join(lines)

    for idx, f in enumerate(findings, start=1):
        sev_color = SEVERITY_COLORS.get(f.severity, "") if use_color else ""
        lines.append(
            f"{idx}. [{sev_color}{f.severity.value}{reset}] {bold}{f.rule_id}: {f.title}{reset} ({f.cwe} | {f.owasp_llm})"
        )
        lines.append(f"   Location   : {f.file_path}:{f.line_number}:{f.column}")
        lines.append(f"   Category   : {f.category.value}")
        lines.append(f"   Detail     : {f.message}")
        if f.snippet:
            lines.append(f"   Snippet    : {dim}{f.snippet}{reset}")
        lines.append(f"   Remediation: {f.remediation}")
        if f.llm_verdict:
            lines.append(f"   LLM Verdict: {bold}{f.llm_verdict}{reset} — {f.llm_explanation or ''}")
            if f.llm_suggested_patch:
                lines.append(f"   Suggested  : {f.llm_suggested_patch}")
        lines.append("")

    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    lines.append(f"{bold}------------------------------------------------------------------------{reset}")
    lines.append(
        f"{bold}Summary:{reset} {len(findings)} finding(s) "
        f"[CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, "
        f"MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']}]"
    )
    lines.append(f"{bold}------------------------------------------------------------------------{reset}")
    return "\n".join(lines)


def format_json_report(result: ScanResult, findings: List[Finding]) -> str:
    payload: Dict[str, Any] = {
        "tool": "agent-sec-audit",
        "version": __version__,
        "target_path": result.target_path,
        "files_scanned": result.files_scanned,
        "duration_ms": result.duration_ms,
        "summary": {
            "total": len(findings),
            "by_severity": {
                s.value: sum(1 for f in findings if f.severity == s) for s in Severity
            },
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def format_sarif_report(findings: List[Finding]) -> str:
    sarif_rules = []
    for r in RULES_CATALOG:
        sarif_rules.append(
            {
                "id": r.rule_id,
                "name": r.title.replace(" ", ""),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.description},
                "help": {"text": f"{r.description}\n\nRemediation: {r.remediation}"},
                "defaultConfiguration": {"level": r.severity.sarif_level},
                "properties": {
                    "tags": ["security", "ai-agent", "mcp", r.cwe, r.owasp_llm],
                    "precision": "high",
                },
            }
        )

    sarif_results = []
    for f in findings:
        norm_uri = f.file_path.replace("\\", "/")
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f"{f.message} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": norm_uri},
                            "region": {
                                "startLine": max(1, f.line_number),
                                "startColumn": max(1, f.column),
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-sec-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/halaxiaohu/agent-sec-audit",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
