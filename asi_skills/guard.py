"""Policy engine for the ASI Code PreToolUse guard.

The guard runs as an ASI Code hook *before* a tool executes, so the model
cannot talk its way past it the way it can ignore a prompt-only skill.
Every rule is deterministic and returns a reason the agent can read.

Decisions:
- ``deny``: the call is blocked.
- ``allow``: the call proceeds (other ASI permission checks still apply).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import PurePath


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule: str
    reason: str

    def to_hook_json(self) -> str:
        return json.dumps({"allow": self.allow, "reason": f"[asi-skills:{self.rule}] {self.reason}"})


ALLOW = Decision(True, "ok", "guard policy passed")

# Shell commands that destroy data or rewrite history in ways that are hard
# to undo. Matched case-insensitively against the whole command text.
DESTRUCTIVE_SHELL = [
    ("recursive-force-delete", r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b"),
    ("recursive-force-delete", r"\bremove-item\b(?=.*-recurse)(?=.*-force)"),
    ("recursive-force-delete", r"\b(rd|rmdir)\s+/s\b"),
    ("recursive-force-delete", r"\bdel\s+(/[a-z]\s+)*/s\b"),
    ("disk-format", r"\b(format|format-volume|clear-disk|diskpart|mkfs(\.\w+)?)\b"),
    ("git-history-rewrite", r"\bgit\s+reset\s+--hard\b"),
    ("git-history-rewrite", r"\bgit\s+push\b.*(\s--force\b|\s-f\b|\s--force-with-lease\b)"),
    ("git-history-rewrite", r"\bgit\s+clean\s+-[a-z]*f"),
    ("git-history-rewrite", r"\bgit\s+(filter-branch|filter-repo)\b"),
    ("system-shutdown", r"\b(shutdown|stop-computer|restart-computer)\b"),
]

# Files whose contents are credentials. Writing or editing them is denied;
# so is reading them, because tool output is sent to the model provider.
SECRET_FILE_NAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "credentials", "id_rsa", "id_ed25519",
    "id_ecdsa", "id_dsa",
}
SECRET_FILE_SUFFIXES = (".pem", ".key", ".pfx", ".p12")
SECRET_DIR_NAMES = {".ssh", ".aws", ".gnupg"}
# `.env.example` and friends are templates, not secrets.
SECRET_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# Secret-looking literals in content the agent writes to disk.
SECRET_CONTENT = [
    ("private-key-block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("api-key-literal", r"\bsk-(ant-)?[A-Za-z0-9_-]{24,}\b"),
]

WRITE_TOOLS = {"write_file", "edit_file"}
READ_TOOLS = {"read_file"}


def _is_secret_path(path: str) -> bool:
    if not path:
        return False
    parts = [p.lower() for p in PurePath(path.replace("\\", "/")).parts]
    if not parts:
        return False
    name = parts[-1]
    if name.endswith(SECRET_TEMPLATE_SUFFIXES):
        return False
    if any(p in SECRET_DIR_NAMES for p in parts[:-1]):
        return True
    if name in SECRET_FILE_NAMES or name.startswith(".env."):
        return True
    return name.endswith(SECRET_FILE_SUFFIXES)


def extract_path(tool: str, args: str) -> str:
    """Return the target path from either argument shape ASI Code sends.

    Native tool calls arrive in legacy text form (``path <<<CONTENT ...``);
    manual ``/toolcall`` lines may pass raw JSON (``{"path": ...}``).
    """
    text = args.strip()
    if text.startswith("{"):
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if isinstance(value, dict):
            return str(value.get("path") or value.get("file_path") or "")
    first = text.split("<<<", 1)[0].strip()
    if first.startswith('"'):
        end = first.find('"', 1)
        return first[1:end] if end > 0 else first[1:]
    return first.split()[0] if first.split() else ""


def _write_content(args: str) -> str:
    text = args.strip()
    if text.startswith("{"):
        try:
            value = json.loads(text)
            if isinstance(value, dict):
                return str(value.get("content") or "") + str(value.get("new_text") or "")
        except ValueError:
            pass
    return text


def _outside_workspace(path: str, workspace: str | None) -> bool:
    if not path or not workspace:
        return False
    root = os.path.normcase(os.path.realpath(workspace))
    target = path if os.path.isabs(path) else os.path.join(workspace, path)
    target = os.path.normcase(os.path.realpath(target))
    return os.path.commonpath([root, target]) != root


def evaluate(tool: str, args: str, workspace: str | None = None) -> Decision:
    tool = (tool or "").strip()
    args = args or ""

    if tool == "bash":
        lower = args.lower()
        for rule, pattern in DESTRUCTIVE_SHELL:
            if re.search(pattern, lower):
                return Decision(False, rule, "destructive or history-rewriting shell command; ask the user to run it themselves")
        if re.search(r"(^|[\\/\s\"'])(\.ssh|\.aws|\.gnupg)([\\/\s\"']|$)", lower) or re.search(r"(^|[\\/\s\"'])\.env([\s\"']|$)", lower):
            return Decision(False, "secret-access", "shell command touches a credential location")
        return ALLOW

    if tool in WRITE_TOOLS or tool in READ_TOOLS:
        path = extract_path(tool, args)
        if _is_secret_path(path):
            verb = "read" if tool in READ_TOOLS else "modify"
            return Decision(False, "secret-file", f"refusing to {verb} credential file `{path}`")
        if tool in WRITE_TOOLS and _outside_workspace(path, workspace):
            return Decision(False, "outside-workspace", f"`{path}` is outside the workspace")
        if tool in WRITE_TOOLS:
            content = _write_content(args)
            for rule, pattern in SECRET_CONTENT:
                if re.search(pattern, content):
                    return Decision(False, rule, "content looks like a real credential; use a placeholder or environment variable")
    return ALLOW
