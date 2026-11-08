# asi-skills

Verifiable safety and workflow skills for [ASI Code](https://github.com/AloneMath/asi-code).

ASI Code's most important development directions are **safety, superintelligence, and continuous learning**, with safety first. This repository starts with safety.

## Why a hook, not a prompt

A markdown skill is only instructions; a model can ignore it. The guard in this repository runs as an ASI Code **PreToolUse hook**: ASI Code calls it before every tool executes and blocks the call when the guard says no. The model cannot talk its way past it. If the guard itself crashes or times out, the call is denied (fail closed).

## What the guard blocks

| Rule | Examples |
|---|---|
| `recursive-force-delete` | `rm -rf`, `Remove-Item -Recurse -Force`, `rd /s` |
| `git-history-rewrite` | `git reset --hard`, `git push --force`, `git clean -f` |
| `disk-format`, `system-shutdown` | disk formatting and shutdown commands |
| `secret-file` | reading or writing `.env`, `.env.*`, `*.pem`, `*.key`, files under `.ssh` / `.aws` / `.gnupg` (`.env.example` stays allowed) |
| `secret-access` | shell commands that touch those credential locations |
| `api-key-literal`, `private-key-block`, ... | writing content that looks like a real credential |
| `outside-workspace` | writes outside the project (defense in depth; ASI Code also checks this) |

Reading secret files is blocked too, because tool output is sent to the model provider.

## Install

Requires Python 3.10+ and no third-party packages.

```powershell
asi skills install D:\Code\asi-skills
asi skills status
```

`install` first runs the guard against a known-bad call (reading `.env`) and a known-good call (`cargo test`). Only if both behave correctly does it register the guard in `~/.asi/hooks.json`, which ASI Code loads in every new session without any environment variables. A guard that cannot start would deny every tool call, so an unverified install is refused. Remove it with `asi skills uninstall`.

Use `--python <path>` if `python` on PATH is not the interpreter you want.

ASI Code also has built-in credential file protection that works without this guard; the guard adds shell-command rules and secret-content checks on top.

Manual setup (older ASI Code without `asi skills`):

```powershell
python -m asi_skills install --out D:\Code\asi-skills\.asi\hooks.json
# then set the variables it prints
```

Start ASI Code in the same shell. A blocked call looks like:

```text
Permission denied: hook PreToolUse denied: [asi-skills:secret-file] refusing to read credential file `.env`
```

## Measure it

```powershell
python -m asi_skills eval          # table + summary
python -m asi_skills eval --json   # machine-readable
python -m unittest -v              # unit tests
```

`eval` scores the guard on labeled tool calls. The cases are only passed to the policy function and are never executed. It reports how many risky calls are blocked and how many ordinary development calls are wrongly blocked (false positives). Current result: 13/13 risky blocked, 0/11 false positives.

## Limits

- Pattern rules catch common, explicit forms. A determined adversary can obfuscate a shell command; use ASI Code's `ASI_SANDBOX=docker` backend for enforced isolation. The guard and the sandbox are layers, not substitutes.
- The evaluation set is small. Extend `asi_skills/eval_cases.py` whenever a rule changes, with both risky and benign cases.

## Roadmap

1. Verifier skills: each skill ships a program that decides pass/fail for its task.
2. Feed guard decisions and verifier verdicts into ASI Code trajectory records.
3. Directory-style skills (`<name>/SKILL.md` + scripts) and `asi skills install` in ASI Code.
