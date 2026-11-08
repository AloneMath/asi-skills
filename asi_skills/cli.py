"""Command line: ``python -m asi_skills <command>``.

Commands:
  install --out <hooks.json>   Write an ASI Code hook config that runs the guard.
  eval [--json]                Score the guard on labeled, never-executed cases.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from asi_skills.eval_cases import CASES
from asi_skills.guard import evaluate


def hook_config(python: str) -> dict:
    # ASI Code runs hook scripts through PowerShell on Windows and `sh -lc`
    # elsewhere. PowerShell needs the call operator to run a quoted path.
    launcher = f'& "{python}"' if os.name == "nt" else f'"{python}"'
    return {
        "handlers": [
            {
                "event": "PreToolUse",
                "script": f"{launcher} -m asi_skills.hook",
                "json_protocol": True,
                "timeout_secs": 10,
                "failure_policy": "fail-closed",
            }
        ]
    }


def cmd_install(out: Path) -> int:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(hook_config(sys.executable), indent=2), encoding="utf-8")
    pkg_root = Path(__file__).resolve().parent.parent
    print(f"wrote {out}")
    print("Enable it for ASI Code (PowerShell):")
    print("  $env:ASI_HOOKS_ENABLED = '1'")
    print(f"  $env:ASI_HOOK_CONFIG_PATH = '{out.resolve()}'")
    print(f"  $env:PYTHONPATH = '{pkg_root}'")
    return 0


def run_eval(workspace: str) -> dict:
    rows = []
    for case in CASES:
        d = evaluate(case["tool"], case["args"], workspace)
        got = "allow" if d.allow else "deny"
        rows.append({"id": case["id"], "expect": case["expect"], "got": got, "rule": d.rule, "pass": got == case["expect"]})
    risky = [r for r in rows if r["expect"] == "deny"]
    benign = [r for r in rows if r["expect"] == "allow"]
    return {
        "cases": len(rows),
        "risky_blocked": sum(r["got"] == "deny" for r in risky),
        "risky_total": len(risky),
        "benign_false_positives": sum(r["got"] == "deny" for r in benign),
        "benign_total": len(benign),
        "rows": rows,
    }


def cmd_eval(as_json: bool) -> int:
    report = run_eval(str(Path.cwd()))
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        for r in report["rows"]:
            mark = "PASS" if r["pass"] else "FAIL"
            print(f"{mark}  {r['id']:<20} expect={r['expect']:<5} got={r['got']:<5} rule={r['rule']}")
        print(
            f"\nrisky blocked: {report['risky_blocked']}/{report['risky_total']}  "
            f"benign false positives: {report['benign_false_positives']}/{report['benign_total']}"
        )
    return 0 if all(r["pass"] for r in report["rows"]) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asi_skills")
    sub = parser.add_subparsers(dest="command", required=True)
    p_install = sub.add_parser("install")
    p_install.add_argument("--out", type=Path, default=Path(".asi/asi_skills_hooks.json"))
    p_eval = sub.add_parser("eval")
    p_eval.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "install":
        return cmd_install(args.out)
    return cmd_eval(args.json)


if __name__ == "__main__":
    raise SystemExit(main())
