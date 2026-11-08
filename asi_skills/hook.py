"""ASI Code hook entry point: ``python -m asi_skills.hook``.

Reads the JSON payload ASI Code puts in ``ASI_HOOK_INPUT_JSON`` and prints
one JSON decision line. Any internal error denies the call (fail closed),
so a broken guard can never silently disable protection.
"""

from __future__ import annotations

import json
import os
import sys

if __package__ in (None, ""):
    # Run as a file path (how `asi skills install` registers it): make the
    # repository root importable so no PYTHONPATH setup is needed.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asi_skills.guard import Decision, evaluate


def decide(environ: dict[str, str]) -> Decision:
    raw = environ.get("ASI_HOOK_INPUT_JSON")
    if raw:
        payload = json.loads(raw)
        tool = str(payload.get("tool") or "")
        args = str(payload.get("args") or "")
    else:
        tool = environ.get("ASI_HOOK_TOOL", "")
        args = environ.get("ASI_HOOK_ARGS", "")
    workspace = environ.get("ASI_SKILLS_WORKSPACE") or os.getcwd()
    return evaluate(tool, args, workspace)


def main() -> int:
    try:
        decision = decide(dict(os.environ))
    except Exception as exc:  # fail closed
        decision = Decision(False, "guard-error", f"guard failed: {exc}")
    sys.stdout.write(decision.to_hook_json() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
