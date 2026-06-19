from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from agent_sec_audit.models import Finding
from agent_sec_audit.rules import RULES_BY_ID

SECRET_VALUE_REGEX = re.compile(
    r"(sk-(?:proj-|ant-|live-)?[A-Za-z0-9_\-]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{25,}|"
    r"github_pat_[A-Za-z0-9_]{25,}|"
    r"xox[baprs]-[A-Za-z0-9\-]{15,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z\-_]{35})"
)

SENSITIVE_KEY_NAMES = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|auth|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)

SAFE_PLACEHOLDER_REGEX = re.compile(
    r"^(\$\{[^}]+\}|\$[A-Z0-9_]+|<[^>]+>|your[_-].*|xxx+|todo|changeme|none|null|env\..*)$",
    re.IGNORECASE,
)

ROOT_OR_SENSITIVE_PATHS = {
    "/",
    "c:\\",
    "c:/",
    "~",
    "~/",
    "/root",
    "/etc",
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
}

SHELL_INTERPRETERS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


def _find_line_number(lines: List[str], needle: str, default: int = 1) -> int:
    if not needle:
        return default
    for idx, line in enumerate(lines, start=1):
        if needle in line:
            return idx
    return default


def _make_finding(
    rule_id: str,
    file_path: str,
    lines: List[str],
    needle: str,
    message: str,
) -> Finding:
    rule = RULES_BY_ID[rule_id]
    line_no = _find_line_number(lines, needle)
    snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else needle
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_no,
        column=1,
        snippet=snippet[:200],
        message=message,
        remediation=rule.remediation,
        cwe=rule.cwe,
        owasp_llm=rule.owasp_llm,
    )


def _has_pinned_version(pkg_arg: str) -> bool:
    """
    Checks whether an npm or PyPI package specifier includes a pinned version.
    Examples:
      '@modelcontextprotocol/server-filesystem' -> False
      '@modelcontextprotocol/server-filesystem@0.6.2' -> True
      'mcp-server-git==0.6.0' -> True
      'some-pkg@latest' -> False
    """
    cleaned = pkg_arg.strip()
    if cleaned.startswith("-") or cleaned.startswith("/") or cleaned.startswith("."):
        return True
    if "==" in cleaned or ">=" in cleaned:
        return True
    if cleaned.startswith("@"):
        # Scoped npm package: @scope/pkg or @scope/pkg@1.2.3
        rest = cleaned[1:]
        if "@" not in rest:
            return False
        _, version = rest.rsplit("@", 1)
        return bool(version) and version.lower() not in ("latest", "next", "main")
    if "@" in cleaned:
        _, version = cleaned.rsplit("@", 1)
        return bool(version) and version.lower() not in ("latest", "next", "main")
    return False


def scan_mcp_config_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = raw_text.splitlines()
    file_str = str(path)

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, dict):
        return findings

    servers: Dict[str, Any] = {}
    if isinstance(data.get("mcpServers"), dict):
        servers.update(data["mcpServers"])
    if isinstance(data.get("servers"), dict):
        servers.update(data["servers"])
    if isinstance(data.get("context_servers"), dict):
        servers.update(data["context_servers"])

    for server_name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue

        # 1. Check hardcoded secrets in env block (ASA-001)
        env_block = cfg.get("env")
        if isinstance(env_block, dict):
            for env_key, env_val in env_block.items():
                if not isinstance(env_val, str) or not env_val.strip():
                    continue
                val_stripped = env_val.strip()
                if SAFE_PLACEHOLDER_REGEX.match(val_stripped):
                    continue
                if SECRET_VALUE_REGEX.search(val_stripped) or (
                    SENSITIVE_KEY_NAMES.search(str(env_key)) and len(val_stripped) >= 12
                ):
                    findings.append(
                        _make_finding(
                            "ASA-001",
                            file_str,
                            lines,
                            str(env_key),
                            f"MCP server '{server_name}' defines hardcoded secret in env variable '{env_key}'.",
                        )
                    )

        # 2. Check command and args
        command = str(cfg.get("command", "")).strip()
        raw_args = cfg.get("args", [])
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []

        cmd_base = Path(command).name.lower() if command else ""

        # ASA-004: Arbitrary shell interpreter exposed in MCP server
        if cmd_base in SHELL_INTERPRETERS:
            joined_args = " ".join(args)
            if any(flag in args for flag in ("-c", "/c", "-Command", "-EncodedCommand", "-enc")) or (
                "curl " in joined_args or "wget " in joined_args or "|" in joined_args
            ):
                findings.append(
                    _make_finding(
                        "ASA-004",
                        file_str,
                        lines,
                        command,
                        f"MCP server '{server_name}' executes a raw shell interpreter ('{command} {' '.join(args[:3])}').",
                    )
                )

        # ASA-002: Unpinned auto-install package in npx / uvx / pipx
        if cmd_base in ("npx", "npx.cmd", "uvx", "pipx"):
            # Look for the package argument
            non_flag_args = [a for a in args if not a.startswith("-")]
            if non_flag_args:
                pkg_spec = non_flag_args[0]
                if not _has_pinned_version(pkg_spec):
                    findings.append(
                        _make_finding(
                            "ASA-002",
                            file_str,
                            lines,
                            pkg_spec,
                            f"MCP server '{server_name}' runs unpinned package '{pkg_spec}' via '{cmd_base}'.",
                        )
                    )

        # ASA-003: Unrestricted root or sensitive filesystem path mounted
        for arg in args:
            norm_arg = arg.strip().lower().rstrip(" ")
            if norm_arg in ROOT_OR_SENSITIVE_PATHS or any(
                seg in norm_arg for seg in ("/.ssh", "\\.ssh", "/.aws", "\\.aws", "/etc/passwd", "/etc/shadow")
            ):
                findings.append(
                    _make_finding(
                        "ASA-003",
                        file_str,
                        lines,
                        arg,
                        f"MCP server '{server_name}' grants access to unrestricted or sensitive host path '{arg}'.",
                    )
                )

        # 3. Check remote URL transport (ASA-005)
        for url_key in ("url", "serverUrl", "endpoint"):
            url_val = cfg.get(url_key)
            if isinstance(url_val, str) and url_val.lower().startswith("http://"):
                lower_url = url_val.lower()
                if not any(
                    local_host in lower_url
                    for local_host in ("http://localhost", "http://127.0.0.1", "http://[::1]")
                ):
                    findings.append(
                        _make_finding(
                            "ASA-005",
                            file_str,
                            lines,
                            url_val,
                            f"MCP server '{server_name}' connects to remote endpoint over plaintext HTTP ('{url_val}').",
                        )
                    )

    return findings
