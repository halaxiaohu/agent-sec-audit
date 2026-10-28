from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

from agent_sec_audit.models import Finding

SYSTEM_PROMPT = """You are a senior AI Security Engineer auditing findings from `agent-sec-audit`.
Given a static security finding from an AI Coding Agent file (MCP config, AGENTS.md/SKILL.md, or tool code),
evaluate whether the finding is a genuine security risk (`TRUE_POSITIVE`) or benign (`FALSE_POSITIVE`).
Respond strictly in JSON object format with keys:
- "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE"
- "explanation": concise 1-2 sentence contextual risk analysis
- "suggested_patch": concrete one-line or short snippet fix
"""


def audit_findings_with_openai(
    findings: List[Finding],
    api_key: Optional[str] = None,
    model: str = "gpt-4o-mini",
    base_url: str = "https://api.openai.com/v1",
    max_findings: int = 10,
) -> None:
    """
    Enriches up to `max_findings` Finding objects in-place with OpenAI semantic security analysis.
    """
    resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_key:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is required when running with --llm-audit."
        )

    endpoint = f"{base_url.rstrip('/')}/chat/completions"
    parsed_url = urllib.parse.urlparse(endpoint)
    if parsed_url.scheme not in ("https", "http") or not parsed_url.netloc:
        raise ValueError(f"Invalid OpenAI base URL: {base_url}")

    for finding in findings[:max_findings]:
        user_payload = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "category": finding.category.value,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "snippet": finding.snippet,
            "static_message": finding.message,
        }

        body = {
            "model": model,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
        }

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {resolved_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                content = resp_data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                finding.llm_verdict = str(parsed.get("verdict", "TRUE_POSITIVE"))
                finding.llm_explanation = str(parsed.get("explanation", ""))
                finding.llm_suggested_patch = str(parsed.get("suggested_patch", ""))
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError) as exc:
            finding.llm_verdict = "ERROR"
            finding.llm_explanation = f"OpenAI semantic audit request failed: {exc}"
