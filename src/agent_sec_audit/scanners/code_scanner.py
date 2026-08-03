from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Optional

from agent_sec_audit.models import Finding
from agent_sec_audit.rules import RULES_BY_ID
from agent_sec_audit.scanners.mcp_scanner import SECRET_VALUE_REGEX

SUBPROCESS_FUNCS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
}

OS_SHELL_FUNCS = {"os.system", "os.popen"}

EVAL_EXEC_FUNCS = {"eval", "exec"}

HTTP_CLIENT_FUNCS = {
    "requests.get",
    "requests.post",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "urllib.request.urlopen",
}

UNSAFE_DESERIALIZE_FUNCS = {
    "pickle.loads",
    "pickle.load",
    "cPickle.loads",
    "dill.loads",
}


def _build_finding(
    rule_id: str,
    file_path: str,
    line_no: int,
    col: int,
    lines: List[str],
    message: str,
) -> Finding:
    rule = RULES_BY_ID[rule_id]
    snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else ""
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_no,
        column=col,
        snippet=snippet[:200],
        message=message,
        remediation=rule.remediation,
        cwe=rule.cwe,
        owasp_llm=rule.owasp_llm,
    )


def _resolve_call_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    return None


class _PythonAgentCodeVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: List[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []
        self._current_func_source: str = ""

    def _is_ignored(self, lineno: int) -> bool:
        if 1 <= lineno <= len(self.lines):
            return "asa-ignore" in self.lines[lineno - 1]
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_like(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_like(node)

    def _visit_function_like(self, node: ast.AST) -> None:
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1)
        prev_source = self._current_func_source
        self._current_func_source = "\n".join(self.lines[start:end])
        self.generic_visit(node)
        self._current_func_source = prev_source

    def visit_Call(self, node: ast.Call) -> None:
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        if self._is_ignored(lineno):
            self.generic_visit(node)
            return

        call_name = _resolve_call_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        # ASA-011: subprocess(..., shell=True) or os.system / os.popen
        if call_name in OS_SHELL_FUNCS:
            self.findings.append(
                _build_finding(
                    "ASA-011",
                    self.file_path,
                    lineno,
                    col,
                    self.lines,
                    f"Unsafe shell command execution via '{call_name}()' in agent code.",
                )
            )
        elif call_name in SUBPROCESS_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        _build_finding(
                            "ASA-011",
                            self.file_path,
                            lineno,
                            col,
                            self.lines,
                            f"Subprocess call '{call_name}(..., shell=True)' enables command injection.",
                        )
                    )

        # ASA-012: eval() or exec()
        if call_name in EVAL_EXEC_FUNCS:
            self.findings.append(
                _build_finding(
                    "ASA-012",
                    self.file_path,
                    lineno,
                    col,
                    self.lines,
                    f"Dynamic code execution via '{call_name}()' without sandbox isolation.",
                )
            )

        # ASA-013: Unvalidated SSRF in HTTP client call inside function accepting non-constant URL
        if call_name in HTTP_CLIENT_FUNCS and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                func_src = self._current_func_source.lower()
                has_validation = any(
                    guard in func_src
                    for guard in ("allowlist", "whitelist", "urlparse", "ipaddress", "is_private", "allowed_domains")
                )
                if not has_validation:
                    self.findings.append(
                        _build_finding(
                            "ASA-013",
                            self.file_path,
                            lineno,
                            col,
                            self.lines,
                            f"HTTP call '{call_name}()' uses dynamic URL without apparent domain/IP validation.",
                        )
                    )

        # ASA-014: Unsafe deserialization (pickle.loads or yaml.load without SafeLoader)
        if call_name in UNSAFE_DESERIALIZE_FUNCS:
            self.findings.append(
                _build_finding(
                    "ASA-014",
                    self.file_path,
                    lineno,
                    col,
                    self.lines,
                    f"Unsafe deserialization via '{call_name}()' allows arbitrary code execution.",
                )
            )
        elif call_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader"
                and isinstance(kw.value, (ast.Name, ast.Attribute))
                and "SafeLoader" in ast.unparse(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                self.findings.append(
                    _build_finding(
                        "ASA-014",
                        self.file_path,
                        lineno,
                        col,
                        self.lines,
                        "Call to 'yaml.load()' without 'Loader=yaml.SafeLoader'.",
                    )
                )

        self.generic_visit(node)


def scan_python_code_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = raw_text.splitlines()
    file_str = str(path)

    # 1. Regex check for hardcoded API keys (ASA-015)
    for idx, line in enumerate(lines, start=1):
        if "asa-ignore" in line:
            continue
        m_secret = SECRET_VALUE_REGEX.search(line)
        if m_secret:
            token_preview = m_secret.group(0)[:10] + "..."
            findings.append(
                _build_finding(
                    "ASA-015",
                    file_str,
                    idx,
                    m_secret.start() + 1,
                    lines,
                    f"Hardcoded API key or secret token detected ({token_preview}).",
                )
            )

    # 2. AST analysis for Python files
    if path.suffix.lower() == ".py":
        try:
            tree = ast.parse(raw_text, filename=file_str)
            visitor = _PythonAgentCodeVisitor(file_str, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass
    elif path.suffix.lower() in (".ts", ".js", ".mjs"):
        # Lightweight static checks for JS/TS tool definitions
        js_eval_re = re.compile(r"\b(eval|Function)\s*\(")
        js_exec_re = re.compile(r"\b(exec|execSync)\s*\(")
        for idx, line in enumerate(lines, start=1):
            if "asa-ignore" in line:
                continue
            if js_eval_re.search(line):
                findings.append(
                    _build_finding(
                        "ASA-012",
                        file_str,
                        idx,
                        1,
                        lines,
                        "Dynamic code evaluation ('eval' / 'new Function') in JS/TS agent tool.",
                    )
                )
            if js_exec_re.search(line):
                findings.append(
                    _build_finding(
                        "ASA-011",
                        file_str,
                        idx,
                        1,
                        lines,
                        "Shell execution ('child_process.exec' / 'execSync') in JS/TS agent tool.",
                    )
                )

    return findings
