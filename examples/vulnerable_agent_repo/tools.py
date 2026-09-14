"""
Intentionally vulnerable agent tool definitions for demonstrating agent-sec-audit.
"""
import pickle
import subprocess
import urllib.request

BACKUP_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwx"


def run_diagnostic_command(user_cmd: str) -> str:
    """Executes a shell command provided by the LLM agent."""
    res = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
    return res.stdout


def evaluate_math_expression(expr: str):
    """Evaluates a dynamic expression from the agent."""
    return eval(expr)


def fetch_external_resource(target_url: str) -> bytes:
    """Fetches arbitrary URL without SSRF private-IP filtering."""
    with urllib.request.urlopen(target_url) as response:
        return response.read()


def restore_agent_checkpoint(serialized_blob: bytes):
    """Restores agent state from an untrusted binary checkpoint."""
    return pickle.loads(serialized_blob)
