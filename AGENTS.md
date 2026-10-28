# AGENTS.md — Coding Agent Instructions for `agent-sec-audit`

## Project Overview
`agent-sec-audit` is a zero-dependency Python static & semantic security analyzer for AI Coding Agents (`AGENTS.md`, `SKILL.md`, `CLAUDE.md`), Model Context Protocol (`mcp.json`) server configurations, and LLM tool definitions.

## Architecture
- `src/agent_sec_audit/models.py`: Data structures (`Rule`, `Finding`, `Severity`, `ScanResult`).
- `src/agent_sec_audit/rules.py`: Built-in rule catalog (`ASA-001` through `ASA-015`) mapped to CWE and OWASP LLM Top 10 (2025).
- `src/agent_sec_audit/scanners/`:
  - `mcp_scanner.py`: Audits MCP JSON configurations for hardcoded secrets, unpinned packages, root filesystem mounts, and raw shell wrappers.
  - `markdown_scanner.py`: Audits agent instruction files for Unicode Tag smuggling, Bidi overrides, HTML comment prompt injections, and sandbox evasion flags.
  - `code_scanner.py`: Python AST & regex analyzer for unsafe `subprocess`/`eval`/SSRF/deserialization in agent tool functions.
  - `engine.py`: File discovery and scan orchestration.
- `src/agent_sec_audit/llm_auditor.py`: Optional OpenAI API semantic triage (`--llm-audit`) using structured JSON outputs.
- `src/agent_sec_audit/reporters.py`: Console text, JSON, and SARIF v2.1.0 formatters.

## Development & Verification Commands
Run all unit tests before submitting changes:
```bash
python -m unittest discover -s tests -v
```

Run a self-audit on the `src/` directory (must produce 0 findings):
```bash
python -m agent_sec_audit scan src --fail-on LOW
```

## Guidelines for Adding New Rules
1. Register the `Rule` metadata in `src/agent_sec_audit/rules.py` with an incremental `ASA-XXX` identifier, CWE mapping, and OWASP LLM category.
2. Implement detection in the appropriate scanner module under `src/agent_sec_audit/scanners/`.
3. Add both positive (vulnerable) and negative (safe) test cases in `tests/test_scanners.py`.
