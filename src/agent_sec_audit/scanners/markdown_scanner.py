from __future__ import annotations

import re
from pathlib import Path
from typing import List

from agent_sec_audit.models import Finding
from agent_sec_audit.rules import RULES_BY_ID

# Unicode Bidi overrides and Zero-Width characters used for invisible prompt injection
BIDI_AND_ZW_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

HTML_COMMENT_REGEX = re.compile(r"<!--(.*?)-->", re.DOTALL)

COVERT_OVERRIDE_PATTERNS = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|above)|"
    r"system\s+override|"
    r"do\s+not\s+(?:mention|tell|inform)\s+(?:the\s+)?user|"
    r"important\s+new\s+instructions|"
    r"you\s+are\s+now\s+in\s+developer\s+mode)",
    re.IGNORECASE,
)

SANDBOX_BYPASS_PATTERNS = re.compile(
    r"(--dangerously-bypass-approvals-and-sandbox|"
    r"--dangerously-skip-permissions|"
    r"CODEX_UNSAFE_ALLOW_NO_SANDBOX|"
    r"git\s+commit\s+[^\n]*--no-verify|"
    r"chmod\s+-x\s+\.git/hooks|"
    r"rm\s+-rf?\s+\.git/hooks)",
    re.IGNORECASE,
)

EXFIL_IMAGE_OR_WEBHOOK_REGEX = re.compile(
    r"(!\[[^\]]*\]\(https?://[^)\s]+\?(?:[^)\s]*=)*(?:\$\{?[A-Za-z0-9_]+|\b(?:env|secret|token|key|whoami|hostname)\b)[^)]*\)|"
    r"\b(?:curl|wget)\b[^\n]*(?:\$\{?[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|ENV)[A-Za-z0-9_]*\}?|`cat\s+[^`]+`))",
    re.IGNORECASE,
)

SENSITIVE_CREDENTIAL_PATHS_REGEX = re.compile(
    r"(~/\.ssh/id_(?:rsa|ed25519|ecdsa)|"
    r"~/\.aws/credentials|"
    r"~/\.npmrc|"
    r"~/\.pypirc|"
    r"~/\.netrc|"
    r"/etc/shadow)",
    re.IGNORECASE,
)


def _create_finding(
    rule_id: str,
    file_path: str,
    line_number: int,
    column: int,
    snippet: str,
    message: str,
) -> Finding:
    rule = RULES_BY_ID[rule_id]
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_number,
        column=column,
        snippet=snippet.strip()[:200],
        message=message,
        remediation=rule.remediation,
        cwe=rule.cwe,
        owasp_llm=rule.owasp_llm,
    )


def scan_markdown_or_instruction_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    file_str = str(path)
    lines = raw_text.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        if "asa-ignore" in line:
            continue

        # 1. ASA-006: Check for Unicode Tag characters (U+E0000..U+E007F) or Bidi/Zero-Width smuggling
        tag_chars = [ch for ch in line if 0xE0000 <= ord(ch) <= 0xE007F]
        if tag_chars:
            decoded_smuggled = "".join(chr(ord(c) - 0xE0000) for c in tag_chars if 0xE0020 <= ord(c) <= 0xE007E)
            findings.append(
                _create_finding(
                    "ASA-006",
                    file_str,
                    line_idx,
                    1,
                    repr(line[:80]),
                    f"Detected {len(tag_chars)} invisible Unicode Tag characters smuggling text: '{decoded_smuggled[:60]}'.",
                )
            )
        else:
            for col_idx, ch in enumerate(line, start=1):
                if ch in BIDI_AND_ZW_CHARS:
                    char_name = BIDI_AND_ZW_CHARS[ch]
                    findings.append(
                        _create_finding(
                            "ASA-006",
                            file_str,
                            line_idx,
                            col_idx,
                            repr(line[:100]),
                            f"Detected invisible control character U+{ord(ch):04X} ({char_name}) in agent instruction file.",
                        )
                    )
                    break

        # 2. ASA-008: Sandbox & permission bypass directives
        m_bypass = SANDBOX_BYPASS_PATTERNS.search(line)
        if m_bypass:
            findings.append(
                _create_finding(
                    "ASA-008",
                    file_str,
                    line_idx,
                    m_bypass.start() + 1,
                    line,
                    f"Directive instructs agent to bypass safety sandbox or verification hooks ('{m_bypass.group(0)}').",
                )
            )

        # 3. ASA-009: Markdown image / webhook exfiltration vector
        m_exfil = EXFIL_IMAGE_OR_WEBHOOK_REGEX.search(line)
        if m_exfil:
            findings.append(
                _create_finding(
                    "ASA-009",
                    file_str,
                    line_idx,
                    m_exfil.start() + 1,
                    line,
                    "Suspicious external exfiltration pattern detected in agent instructions.",
                )
            )

        # 4. ASA-010: Sensitive credential file access
        m_cred = SENSITIVE_CREDENTIAL_PATHS_REGEX.search(line)
        if m_cred:
            findings.append(
                _create_finding(
                    "ASA-010",
                    file_str,
                    line_idx,
                    m_cred.start() + 1,
                    line,
                    f"Instruction references sensitive host credential store '{m_cred.group(0)}'.",
                )
            )

    # 5. ASA-007: Covert prompt injection inside HTML comments (can span multiple lines)
    for match in HTML_COMMENT_REGEX.finditer(raw_text):
        comment_body = match.group(1)
        m_override = COVERT_OVERRIDE_PATTERNS.search(comment_body)
        if m_override:
            start_pos = match.start()
            line_no = raw_text.count("\n", 0, start_pos) + 1
            snippet = match.group(0).replace("\n", " ")
            findings.append(
                _create_finding(
                    "ASA-007",
                    file_str,
                    line_no,
                    1,
                    snippet,
                    f"HTML comment contains covert prompt injection override ('{m_override.group(0)}').",
                )
            )

    return findings
