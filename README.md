# 🛡️ agent-sec-audit

[![CI & Security Self-Audit](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![OWASP LLM 2025](https://img.shields.io/badge/OWASP%20LLM-2025%20Aligned-orange.svg)](https://genai.owasp.org/)
[![SARIF v2.1.0](https://img.shields.io/badge/output-SARIF%20v2.1.0-purple.svg)](#github-code-scanning-sarif-integration)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**`agent-sec-audit`** is a fast, zero-dependency static & semantic security scanner built for the modern AI Coding Agent ecosystem. It audits **`AGENTS.md` / `SKILL.md` / `CLAUDE.md` instruction files**, **Model Context Protocol (`mcp.json`) server configurations**, and **LLM tool definitions** for prompt injection, invisible Unicode smuggling, sandbox bypass directives, supply-chain risks, and Remote Code Execution (RCE).

---

## 🚨 Why `agent-sec-audit`?

Modern repositories increasingly include machine-read instructions (`AGENTS.md`, `SKILL.md`, `.cursorrules`), MCP server manifests (`mcp.json`), and custom agent tools. Adversaries actively target these surfaces through:

1. **Unicode Tag & Bidi Smuggling (`ASA-006`)**: Hiding invisible instructions (`U+E0000`–`U+E007F`) inside documentation or PR descriptions that hijack coding agents (Codex, Claude Code, Cursor) while remaining invisible to human reviewers.
2. **Covert Comment Overrides & Sandbox Evasion (`ASA-007`, `ASA-008`)**: Embedding `<!-- ignore previous instructions -->` or tricking agents into running `--dangerously-bypass-approvals-and-sandbox`.
3. **Insecure MCP Server Configurations (`ASA-001`–`ASA-005`)**: Mounting `/` root filesystems, executing unpinned `npx -y` packages vulnerable to upstream poisoning, or hardcoding `sk-proj-...` keys in `mcp.json`.
4. **Unsafe LLM Tool Implementations (`ASA-011`–`ASA-015`)**: Exposing `subprocess.run(..., shell=True)`, `eval()`, or unvalidated SSRF endpoints directly to model tool calls.

---

## ⚡ Quickstart

### Run Instantly with `uvx` or `pipx` (Zero Install)
```bash
uvx agent-sec-audit scan .
# or
pipx run agent-sec-audit scan .
```

### Install via `pip`
```bash
pip install agent-sec-audit

# Scan current repository
agent-sec-audit scan .

# Scan and export GitHub Code Scanning SARIF report
agent-sec-audit scan . --format sarif --output results.sarif
```

### Try Against the Included Vulnerable Demo Repository
```bash
git clone https://github.com/halaxiaohu/agent-sec-audit.git
cd agent-sec-audit
pip install -e .
agent-sec-audit scan examples/vulnerable_agent_repo
```

---

## 🧠 Semantic Triage & Auto-Remediation with OpenAI (`--llm-audit`)

Static rules are fast (<30ms per repo), but edge cases in complex agent workflows sometimes benefit from deep semantic reasoning. When `--llm-audit` is enabled, `agent-sec-audit` uses **OpenAI Structured Outputs** (`gpt-4o-mini` / `gpt-4o` / `o3-mini`) to verify static findings in context, filter out false positives, and generate minimal remediation patches:

```bash
export OPENAI_API_KEY="sk-..."
agent-sec-audit scan . --llm-audit --llm-model gpt-4o-mini
```

---

## 📋 Built-in Security Rules (`ASA-001` – `ASA-015`)

All rules are mapped to **CWE** and the **OWASP Top 10 for LLM Applications (2025)**:

| Rule ID | Severity | CWE | OWASP LLM 2025 | Target Surface | Title |
| :--- | :---: | :---: | :--- | :--- | :--- |
| **`ASA-001`** | `CRITICAL` | CWE-798 | LLM02 Sensitive Info | `mcp.json` | Hardcoded Secret in MCP Configuration |
| **`ASA-002`** | `HIGH` | CWE-829 | LLM03 Supply Chain | `mcp.json` | Unpinned Auto-Install Package in MCP Command (`npx -y`) |
| **`ASA-003`** | `CRITICAL` | CWE-250 | LLM06 Excessive Agency | `mcp.json` | Unrestricted Root Filesystem Mount in MCP Server |
| **`ASA-004`** | `CRITICAL` | CWE-78 | LLM06 Excessive Agency | `mcp.json` | Arbitrary Shell Interpreter Exposed as MCP Server |
| **`ASA-005`** | `MEDIUM` | CWE-319 | LLM02 Sensitive Info | `mcp.json` | Insecure Plaintext HTTP Remote MCP Transport |
| **`ASA-006`** | `CRITICAL` | CWE-116 | LLM01 Prompt Injection | `AGENTS.md` / `SKILL.md` | Invisible Unicode / ASCII Smuggling in Agent Instructions |
| **`ASA-007`** | `HIGH` | CWE-74 | LLM01 Prompt Injection | `AGENTS.md` / `*.md` | Covert Prompt Injection in HTML/Markdown Comments |
| **`ASA-008`** | `CRITICAL` | CWE-693 | LLM06 Excessive Agency | `AGENTS.md` / `SKILL.md` | Agent Sandbox & Permission Bypass Directive |
| **`ASA-009`** | `HIGH` | CWE-200 | LLM05 Improper Output | `AGENTS.md` / `SKILL.md` | Markdown Image / Webhook Data Exfiltration Vector |
| **`ASA-010`** | `HIGH` | CWE-522 | LLM02 Sensitive Info | `AGENTS.md` / `SKILL.md` | Sensitive Credential File Access (`~/.ssh`, `~/.aws`) |
| **`ASA-011`** | `CRITICAL` | CWE-78 | LLM05 Improper Output | `.py` / `.ts` / `.js` | Unsafe Shell Execution (`shell=True`) in LLM Tool |
| **`ASA-012`** | `CRITICAL` | CWE-95 | LLM05 Improper Output | `.py` / `.ts` / `.js` | Dynamic Code Evaluation (`eval` / `exec`) in Agent Tool |
| **`ASA-013`** | `MEDIUM` | CWE-918 | LLM06 Excessive Agency | `.py` | Unvalidated SSRF in Agent Web Fetch Tool |
| **`ASA-014`** | `HIGH` | CWE-502 | LLM05 Improper Output | `.py` | Unsafe Deserialization (`pickle` / `yaml.load`) |
| **`ASA-015`** | `CRITICAL` | CWE-798 | LLM02 Sensitive Info | `.py` / `.ts` / `.js` | Hardcoded API Key in Agent Source Code |

Run `agent-sec-audit list-rules` or `agent-sec-audit explain ASA-006` for detailed remediation guidance.

---

## 🔄 GitHub Code Scanning (SARIF) Integration

Add `agent-sec-audit` to `.github/workflows/agent-security.yml` to block malicious prompt injections or unsafe MCP changes in Pull Requests:

```yaml
name: AI Agent & MCP Security Audit

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  agent-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run agent-sec-audit
        uses: halaxiaohu/agent-sec-audit@v0.4.2
        with:
          target: "."
          format: "sarif"
          output: "agent-sec-audit.sarif"
          fail-on: "HIGH"

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agent-sec-audit.sarif
```

---

## 🔕 Inline Suppression

To suppress a verified false positive on a specific line, add `# asa-ignore` (Python/YAML) or `<!-- asa-ignore -->` (Markdown):

```python
result = eval(trusted_constant_expr)  # asa-ignore
```

---

## 📄 License

Distributed under the [MIT License](LICENSE).
