from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return ranks[self]

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


class Category(str, Enum):
    MCP_CONFIG = "MCP Configuration"
    PROMPT_INJECTION = "Prompt Injection & Instruction Hijacking"
    SANDBOX_EVASION = "Sandbox & Permission Bypass"
    TOOL_EXECUTION = "Unsafe Tool Execution"
    SECRET_EXPOSURE = "Credential & Secret Exposure"
    EXFILTRATION = "Data Exfiltration Vector"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    cwe: str
    owasp_llm: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    column: int
    snippet: str
    message: str
    remediation: str
    cwe: str = "CWE-20"
    owasp_llm: str = "LLM01:2025 Prompt Injection"
    llm_verdict: Optional[str] = None
    llm_explanation: Optional[str] = None
    llm_suggested_patch: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data


@dataclass
class ScanResult:
    target_path: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    duration_ms: float = 0.0

    def filter_by_min_severity(self, min_severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity.rank >= min_severity.rank]

    def count_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def has_failures(self, fail_on: Severity) -> bool:
        return any(f.severity.rank >= fail_on.rank for f in self.findings)
