# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Reporting a Vulnerability or False Negative

If you discover a security vulnerability in `agent-sec-audit` itself, or a critical bypass technique (such as a novel Unicode smuggling encoding or MCP command injection vector) that should be handled privately before public rule disclosure:

1. **Do not open a public GitHub issue** for active zero-day bypasses.
2. Use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the repository's **Security** tab).
3. Include a minimal reproducible payload (`mcp.json`, `AGENTS.md`, or tool snippet) and expected CWE/OWASP LLM classification.

We aim to triage all reports within 48 hours and release rule updates promptly.
