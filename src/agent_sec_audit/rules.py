from __future__ import annotations

from typing import Dict, List, Optional
from agent_sec_audit.models import Rule, Severity, Category


RULES_CATALOG: List[Rule] = [
    Rule(
        rule_id="ASA-001",
        title="Hardcoded Secret in MCP Configuration",
        severity=Severity.CRITICAL,
        category=Category.SECRET_EXPOSURE,
        description=(
            "Detects plaintext API keys, personal access tokens, or bearer credentials "
            "embedded directly inside MCP server configuration files (e.g., mcp.json, "
            "claude_desktop_config.json)."
        ),
        remediation=(
            "Reference environment variables dynamically (e.g., '${OPENAI_API_KEY}') or use "
            "a system keychain manager instead of storing plaintext secrets in JSON configs."
        ),
        cwe="CWE-798",
        owasp_llm="LLM02:2025 Sensitive Information Disclosure",
    ),
    Rule(
        rule_id="ASA-002",
        title="Unpinned Auto-Install Package in MCP Command",
        severity=Severity.HIGH,
        category=Category.MCP_CONFIG,
        description=(
            "Detects MCP servers launched via `npx -y`, `uvx`, or `pipx run` without an explicit "
            "pinned version tag (e.g., `@1.2.3`). Attackers who compromise upstream registries "
            "or typosquat package names can execute arbitrary code on the host machine."
        ),
        remediation=(
            "Pin the exact package version or commit SHA in your MCP command arguments "
            "(e.g., `npx -y @modelcontextprotocol/server-filesystem@0.6.2`)."
        ),
        cwe="CWE-829",
        owasp_llm="LLM03:2025 Supply Chain",
    ),
    Rule(
        rule_id="ASA-003",
        title="Unrestricted Root Filesystem Mount in MCP Server",
        severity=Severity.CRITICAL,
        category=Category.MCP_CONFIG,
        description=(
            "Detects filesystem MCP servers granted access to the entire root filesystem (`/`, `C:\\`), "
            "user home directory (`~`), or sensitive credential directories (`.ssh`, `.aws`, `.gnupg`)."
        ),
        remediation=(
            "Scope filesystem MCP server arguments strictly to the minimum required project workspace directory."
        ),
        cwe="CWE-250",
        owasp_llm="LLM06:2025 Excessive Agency",
    ),
    Rule(
        rule_id="ASA-004",
        title="Arbitrary Shell Interpreter Exposed as MCP Server",
        severity=Severity.CRITICAL,
        category=Category.MCP_CONFIG,
        description=(
            "Detects MCP server configurations invoking raw shell interpreters (`bash -c`, `sh -c`, "
            "`cmd.exe /c`, `powershell -EncodedCommand`) or piping remote scripts (`curl ... | sh`)."
        ),
        remediation=(
            "Replace raw shell wrappers with purpose-built MCP servers that enforce strict parameter schemas."
        ),
        cwe="CWE-78",
        owasp_llm="LLM06:2025 Excessive Agency",
    ),
    Rule(
        rule_id="ASA-005",
        title="Insecure Plaintext HTTP Remote MCP Transport",
        severity=Severity.MEDIUM,
        category=Category.MCP_CONFIG,
        description=(
            "Detects remote SSE/HTTP MCP server endpoints configured over unencrypted `http://` "
            "(excluding localhost/127.0.0.1), exposing tool calls and context to MITM interception."
        ),
        remediation="Enforce `https://` TLS encryption for all non-local remote MCP endpoints.",
        cwe="CWE-319",
        owasp_llm="LLM02:2025 Sensitive Information Disclosure",
    ),
    Rule(
        rule_id="ASA-006",
        title="Invisible Unicode / ASCII Smuggling in Agent Instructions",
        severity=Severity.CRITICAL,
        category=Category.PROMPT_INJECTION,
        description=(
            "Detects invisible Unicode Tag characters (U+E0000..U+E007F), bidirectional text overrides "
            "(U+202A..U+202E, U+2066..U+2069), or zero-width joiners hiding covert instructions inside "
            "AGENTS.md, SKILL.md, CLAUDE.md, or .cursorrules files."
        ),
        remediation=(
            "Strip all non-printable Unicode tag and bidirectional control characters from agent instruction files."
        ),
        cwe="CWE-116",
        owasp_llm="LLM01:2025 Prompt Injection",
    ),
    Rule(
        rule_id="ASA-007",
        title="Covert Prompt Injection in HTML/Markdown Comments",
        severity=Severity.HIGH,
        category=Category.PROMPT_INJECTION,
        description=(
            "Detects HTML comments (`<!-- ... -->`) or hidden markdown blocks containing adversarial "
            "instruction override patterns such as 'ignore previous instructions', 'system prompt', "
            "or 'do not mention this to the user'."
        ),
        remediation=(
            "Remove hidden instruction overrides from markdown comments and audit untrusted documentation before indexing."
        ),
        cwe="CWE-74",
        owasp_llm="LLM01:2025 Prompt Injection",
    ),
    Rule(
        rule_id="ASA-008",
        title="Agent Sandbox & Permission Bypass Directive",
        severity=Severity.CRITICAL,
        category=Category.SANDBOX_EVASION,
        description=(
            "Detects instructions or scripts directing coding agents (Codex, Claude Code, Cursor) to disable "
            "safety sandboxes or approval prompts (e.g., `--dangerously-bypass-approvals-and-sandbox`, "
            "`--dangerously-skip-permissions`, `--no-verify`, or modifying `.git/hooks`)."
        ),
        remediation=(
            "Remove sandbox-bypass flags from repository skills and instructions; rely on scoped allowlists instead."
        ),
        cwe="CWE-693",
        owasp_llm="LLM06:2025 Excessive Agency",
    ),
    Rule(
        rule_id="ASA-009",
        title="Markdown Image / Webhook Data Exfiltration Vector",
        severity=Severity.HIGH,
        category=Category.EXFILTRATION,
        description=(
            "Detects agent instructions or skill templates that instruct the LLM to render dynamic external "
            "Markdown images (`![...](https://...?data=...)`) or send environment variables/files to external webhooks."
        ),
        remediation=(
            "Disallow external image query-string interpolation and restrict outbound network requests in agent skills."
        ),
        cwe="CWE-200",
        owasp_llm="LLM05:2025 Improper Output Handling",
    ),
    Rule(
        rule_id="ASA-010",
        title="Sensitive Credential File Access in Agent Skill",
        severity=Severity.HIGH,
        category=Category.SECRET_EXPOSURE,
        description=(
            "Detects agent instructions or skill scripts that explicitly read sensitive host credential stores "
            "such as `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.npmrc`, `~/.pypirc`, or `/etc/shadow`."
        ),
        remediation=(
            "Never instruct coding agents to read raw private keys or global credential files directly."
        ),
        cwe="CWE-522",
        owasp_llm="LLM02:2025 Sensitive Information Disclosure",
    ),
    Rule(
        rule_id="ASA-011",
        title="Unsafe Shell Execution in LLM Tool Definition",
        severity=Severity.CRITICAL,
        category=Category.TOOL_EXECUTION,
        description=(
            "Detects Python/JS agent tool functions executing `subprocess.run(..., shell=True)`, `os.system()`, "
            "or `os.popen()` using LLM-supplied arguments, enabling direct Command Injection (RCE)."
        ),
        remediation=(
            "Use `subprocess.run([cmd, arg1, ...], shell=False)` with strict allowlist validation on tool inputs."
        ),
        cwe="CWE-78",
        owasp_llm="LLM05:2025 Improper Output Handling",
    ),
    Rule(
        rule_id="ASA-012",
        title="Dynamic Code Evaluation (`eval` / `exec`) in Agent Tool",
        severity=Severity.CRITICAL,
        category=Category.TOOL_EXECUTION,
        description=(
            "Detects `eval()`, `exec()`, or `compile()` inside agent tool handlers or MCP server implementations "
            "without sandboxed isolation."
        ),
        remediation=(
            "Avoid `eval()`/`exec()` on model-generated payloads; use `ast.literal_eval()` for data parsing or run "
            "code inside an isolated container/microVM."
        ),
        cwe="CWE-95",
        owasp_llm="LLM05:2025 Improper Output Handling",
    ),
    Rule(
        rule_id="ASA-013",
        title="Unvalidated SSRF in Agent Web Fetch Tool",
        severity=Severity.MEDIUM,
        category=Category.TOOL_EXECUTION,
        description=(
            "Detects HTTP request calls (`requests.get`, `httpx.get`, `urllib.request.urlopen`) inside agent tool "
            "functions that accept arbitrary URLs without blocking private IP ranges (127.0.0.1, 169.254.169.254)."
        ),
        remediation=(
            "Validate parsed URLs against a domain allowlist and block RFC1918 / link-local cloud metadata IP addresses."
        ),
        cwe="CWE-918",
        owasp_llm="LLM06:2025 Excessive Agency",
    ),
    Rule(
        rule_id="ASA-014",
        title="Unsafe Deserialization (`pickle` / `yaml.load`) in Agent Workflow",
        severity=Severity.HIGH,
        category=Category.TOOL_EXECUTION,
        description=(
            "Detects `pickle.loads()` or unsafe `yaml.load()` without `SafeLoader` in agent state or checkpoint loaders."
        ),
        remediation=(
            "Use `json.loads()` or `yaml.safe_load()` when deserializing agent state, tool outputs, or configurations."
        ),
        cwe="CWE-502",
        owasp_llm="LLM05:2025 Improper Output Handling",
    ),
    Rule(
        rule_id="ASA-015",
        title="Hardcoded API Key in Agent Source Code",
        severity=Severity.CRITICAL,
        category=Category.SECRET_EXPOSURE,
        description=(
            "Detects hardcoded OpenAI (`sk-proj-...`), Anthropic (`sk-ant-...`), GitHub (`ghp_...`), or Slack tokens "
            "committed directly in agent source files."
        ),
        remediation=(
            "Revoke the leaked key immediately and load credentials from environment variables via `os.environ`."
        ),
        cwe="CWE-798",
        owasp_llm="LLM02:2025 Sensitive Information Disclosure",
    ),
]

RULES_BY_ID: Dict[str, Rule] = {rule.rule_id: rule for rule in RULES_CATALOG}


def get_rule(rule_id: str) -> Optional[Rule]:
    return RULES_BY_ID.get(rule_id.upper())
