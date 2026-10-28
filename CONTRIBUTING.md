# Contributing to `agent-sec-audit`

Thank you for helping secure the AI Coding Agent and Model Context Protocol (MCP) ecosystem!

## How to Contribute

### 1. Proposing New Security Rules
The AI agent ecosystem evolves rapidly. We welcome new detection rules covering:
- Model Context Protocol (`mcp.json`, SSE/Streamable HTTP servers, OAuth misconfigurations)
- Coding agent instruction files (`AGENTS.md`, `SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`)
- Prompt injection & invisible character smuggling (Unicode Tags, Bidi overrides, homoglyphs)
- Unsafe tool definitions in Python, TypeScript, and JavaScript

### 2. Local Development Setup
```bash
git clone https://github.com/halaxiaohu/agent-sec-audit.git
cd agent-sec-audit
pip install -e ".[dev]"
```

### 3. Running Tests & Self-Audit
Before submitting a Pull Request, ensure all unit tests pass and the codebase passes its own security audit:
```bash
python -m unittest discover -s tests -v
agent-sec-audit scan src --fail-on LOW
```
