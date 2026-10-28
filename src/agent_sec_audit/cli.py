from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Set

from agent_sec_audit import __version__
from agent_sec_audit.llm_auditor import audit_findings_with_openai
from agent_sec_audit.models import Severity
from agent_sec_audit.reporters import (
    format_json_report,
    format_sarif_report,
    format_text_report,
)
from agent_sec_audit.rules import RULES_CATALOG, get_rule
from agent_sec_audit.scanners.engine import scan_path


def _cmd_list_rules() -> int:
    print(f"agent-sec-audit v{__version__} — Built-in Security Rules ({len(RULES_CATALOG)} rules)\n")
    print(f"{'ID':<9} {'SEVERITY':<10} {'CWE':<9} {'CATEGORY':<38} {'TITLE'}")
    print("-" * 105)
    for r in RULES_CATALOG:
        print(f"{r.rule_id:<9} {r.severity.value:<10} {r.cwe:<9} {r.category.value:<38} {r.title}")
    return 0


def _cmd_explain(rule_id: str) -> int:
    rule = get_rule(rule_id)
    if not rule:
        print(f"Error: Unknown rule ID '{rule_id}'. Run `agent-sec-audit list-rules` to view all rules.", file=sys.stderr)
        return 2

    print(f"Rule ID     : {rule.rule_id}")
    print(f"Title       : {rule.title}")
    print(f"Severity    : {rule.severity.value}")
    print(f"Category    : {rule.category.value}")
    print(f"CWE         : {rule.cwe}")
    print(f"OWASP LLM   : {rule.owasp_llm}")
    print(f"\nDescription :\n  {rule.description}")
    print(f"\nRemediation :\n  {rule.remediation}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sec-audit",
        description=(
            "Static & semantic security scanner for AI Coding Agents (AGENTS.md, SKILL.md), "
            "MCP Server configurations, and LLM tool definitions."
        ),
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"agent-sec-audit {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_p = subparsers.add_parser("scan", help="Scan a directory or file for AI Agent & MCP vulnerabilities")
    scan_p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to repository directory or file to scan (default: current directory)",
    )
    scan_p.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output report format (default: text)",
    )
    scan_p.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write report output to a file instead of stdout",
    )
    scan_p.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity level to report (default: LOW)",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"],
        default="HIGH",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: HIGH)",
    )
    scan_p.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        help="Rule ID(s) to disable (can be specified multiple times or comma-separated)",
    )
    scan_p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in text output",
    )
    scan_p.add_argument(
        "--llm-audit",
        action="store_true",
        help="Verify findings and generate remediation patches using OpenAI API (requires OPENAI_API_KEY)",
    )
    scan_p.add_argument(
        "--llm-model",
        type=str,
        default="gpt-4o-mini",
        help="OpenAI model to use with --llm-audit (default: gpt-4o-mini)",
    )

    # list-rules subcommand
    subparsers.add_parser("list-rules", help="List all built-in security rules")

    # explain subcommand
    explain_p = subparsers.add_parser("explain", help="Show detailed documentation for a specific rule ID")
    explain_p.add_argument("rule_id", help="Rule identifier (e.g. ASA-001)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args_list = list(argv if argv is not None else sys.argv[1:])

    # Default to `scan` if user passes a path or flags directly
    known_subcommands = {"scan", "list-rules", "explain", "-h", "--help", "-v", "--version"}
    if not args_list:
        args_list = ["scan", "."]
    elif args_list[0] not in known_subcommands:
        args_list = ["scan"] + args_list

    parser = build_parser()
    args = parser.parse_args(args_list)

    if args.command == "list-rules":
        return _cmd_list_rules()

    if args.command == "explain":
        return _cmd_explain(args.rule_id)

    # Otherwise execute `scan`
    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    disabled_rules: Set[str] = set()
    for item in args.ignore_rule:
        for part in item.split(","):
            if part.strip():
                disabled_rules.add(part.strip().upper())

    result = scan_path(target_path, disabled_rules=disabled_rules)
    min_sev = Severity(args.min_severity)
    filtered_findings = result.filter_by_min_severity(min_sev)

    if args.llm_audit and filtered_findings:
        try:
            audit_findings_with_openai(filtered_findings, model=args.llm_model)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    if args.format == "json":
        report_str = format_json_report(result, filtered_findings)
    elif args.format == "sarif":
        report_str = format_sarif_report(filtered_findings)
    else:
        use_color = (not args.no_color) and (args.output is None) and sys.stdout.isatty()
        report_str = format_text_report(result, filtered_findings, use_color=use_color)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_str + "\n", encoding="utf-8")
    else:
        # Ensure UTF-8 safe printing on Windows consoles
        try:
            print(report_str)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((report_str + "\n").encode("utf-8", errors="replace"))

    if args.fail_on != "NONE":
        fail_sev = Severity(args.fail_on)
        if any(f.severity.rank >= fail_sev.rank for f in filtered_findings):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
