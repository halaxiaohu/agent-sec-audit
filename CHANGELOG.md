# Changelog

All notable changes to `agent-sec-audit` are documented in this file.

## [0.4.2] - 2026-10-28
### Added
- **OpenAI Semantic Security Auditor (`--llm-audit`)**: Optional second-stage triage using OpenAI Structured Outputs (`gpt-4o-mini` / `gpt-4o` / `o3-mini`) to verify static findings and generate minimal remediation patches.
- **Unicode Tag Smuggling Detection (`ASA-006`)**: Automatically decodes hidden ASCII payloads embedded via Unicode Tag characters (`U+E0000`..`U+E007F`) in `AGENTS.md` and `SKILL.md`.
- **SARIF v2.1.0 Reporter (`--format sarif`)**: Native integration with GitHub Code Scanning and Security advisories.

### Fixed
- Improved scoped npm package version parsing (`@scope/pkg@x.y.z`) in `ASA-002` to prevent false positives on pinned MCP servers.

## [0.3.0] - 2026-09-14
### Added
- **Agent Sandbox Bypass Rule (`ASA-008`)**: Detects instructions or scripts invoking `--dangerously-bypass-approvals-and-sandbox`, `--dangerously-skip-permissions`, or disabling `.git/hooks`.
- **Markdown Image Exfiltration Detection (`ASA-009`)**: Flags external image tags interpolating environment variables or tokens.
- Added composite `action.yml` for one-step GitHub Actions integration.

## [0.2.0] - 2026-08-03
### Added
- **Python AST Tool Scanner (`ASA-011`..`ASA-015`)**: Detects `subprocess(..., shell=True)`, `eval()`/`exec()`, unvalidated SSRF in agent web-fetch tools, and `pickle.loads()` deserialization.
- Added inline `# asa-ignore` comment suppression support.

## [0.1.0] - 2026-06-19
### Added
- Initial release featuring MCP configuration auditing (`ASA-001`..`ASA-005`) for `mcp.json` and `claude_desktop_config.json`.
