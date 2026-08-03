from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable, List, Optional, Set

from agent_sec_audit.models import Finding, ScanResult
from agent_sec_audit.scanners.code_scanner import scan_python_code_file
from agent_sec_audit.scanners.markdown_scanner import scan_markdown_or_instruction_file
from agent_sec_audit.scanners.mcp_scanner import scan_mcp_config_file

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".egg-info",
}

MCP_CONFIG_FILENAMES: Set[str] = {
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
    "roo_mcp_settings.json",
}

INSTRUCTION_FILENAMES: Set[str] = {
    "agents.md",
    "skill.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
}

CODE_EXTENSIONS: Set[str] = {".py", ".ts", ".js", ".mjs"}


def _is_mcp_json_file(path: Path) -> bool:
    name_lower = path.name.lower()
    if name_lower in MCP_CONFIG_FILENAMES:
        return True
    if path.suffix.lower() == ".json" and "mcp" in name_lower:
        return True
    return False


def _is_instruction_or_markdown_file(path: Path) -> bool:
    name_lower = path.name.lower()
    if name_lower in INSTRUCTION_FILENAMES:
        return True
    if path.suffix.lower() in (".md", ".mdc", ".prompt"):
        return True
    return False


def iter_target_files(root: Path, extra_ignore_dirs: Optional[Iterable[str]] = None) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    ignored = set(DEFAULT_IGNORED_DIRS)
    if extra_ignore_dirs:
        ignored.update(extra_ignore_dirs)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in ignored and not d.endswith(".egg-info")
        ]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if (
                _is_mcp_json_file(fpath)
                or _is_instruction_or_markdown_file(fpath)
                or fpath.suffix.lower() in CODE_EXTENSIONS
            ):
                yield fpath


def scan_path(
    target: Path,
    disabled_rules: Optional[Set[str]] = None,
    extra_ignore_dirs: Optional[Iterable[str]] = None,
) -> ScanResult:
    start_time = time.perf_counter()
    disabled = {r.upper() for r in (disabled_rules or set())}
    findings: List[Finding] = []
    files_scanned = 0

    for file_path in iter_target_files(target, extra_ignore_dirs=extra_ignore_dirs):
        files_scanned += 1
        file_findings: List[Finding] = []

        if _is_mcp_json_file(file_path):
            file_findings.extend(scan_mcp_config_file(file_path))
        elif _is_instruction_or_markdown_file(file_path):
            file_findings.extend(scan_markdown_or_instruction_file(file_path))
        elif file_path.suffix.lower() in CODE_EXTENSIONS:
            file_findings.extend(scan_python_code_file(file_path))

        for f in file_findings:
            if f.rule_id.upper() not in disabled:
                findings.append(f)

    # Sort findings by severity (CRITICAL -> LOW), then file path and line number
    findings.sort(key=lambda x: (-x.severity.rank, x.file_path, x.line_number))
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return ScanResult(
        target_path=str(target),
        files_scanned=files_scanned,
        findings=findings,
        duration_ms=round(elapsed_ms, 2),
    )
