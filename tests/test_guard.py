import json
import os
import tempfile
import unittest

from asi_skills.cli import hook_config, run_eval
from asi_skills.guard import evaluate, extract_path
from asi_skills.hook import decide


class GuardTests(unittest.TestCase):
    def test_all_labeled_cases(self):
        report = run_eval(tempfile.gettempdir())
        failed = [r for r in report["rows"] if not r["pass"]]
        self.assertEqual(failed, [])

    def test_extract_path_handles_both_arg_shapes(self):
        self.assertEqual(extract_path("write_file", "a/b.py <<<CONTENT\nx\n<<<END"), "a/b.py")
        self.assertEqual(extract_path("write_file", '"my dir/b.py" "x"'), "my dir/b.py")
        self.assertEqual(extract_path("edit_file", '{"path": "c.py", "old_text": "a"}'), "c.py")

    def test_deny_reason_is_actionable(self):
        d = evaluate("bash", "git reset --hard", None)
        self.assertFalse(d.allow)
        self.assertIn("ask the user", d.reason)

    def test_outside_workspace_check_needs_workspace(self):
        with tempfile.TemporaryDirectory() as ws:
            inside = evaluate("write_file", "sub/x.txt <<<CONTENT\nx\n<<<END", ws)
            outside = evaluate("write_file", os.path.join(os.path.dirname(ws), "x.txt") + " <<<CONTENT\nx\n<<<END", ws)
            self.assertTrue(inside.allow)
            self.assertFalse(outside.allow)


class HookTests(unittest.TestCase):
    def test_hook_reads_json_payload(self):
        env = {"ASI_HOOK_INPUT_JSON": json.dumps({"tool": "bash", "args": "rm -rf build"})}
        self.assertFalse(decide(env).allow)

    def test_hook_falls_back_to_plain_env(self):
        env = {"ASI_HOOK_TOOL": "bash", "ASI_HOOK_ARGS": "cargo test"}
        self.assertTrue(decide(env).allow)

    def test_hook_output_matches_asi_protocol(self):
        out = json.loads(evaluate("read_file", ".env").to_hook_json())
        self.assertEqual(set(out), {"allow", "reason"})
        self.assertFalse(out["allow"])

    def test_hook_runs_as_plain_script_path(self):
        # `asi skills install` registers `python <repo>/asi_skills/hook.py`.
        import subprocess
        import sys
        from pathlib import Path

        script = Path(__file__).resolve().parent.parent / "asi_skills" / "hook.py"
        env = {**os.environ, "ASI_HOOK_INPUT_JSON": json.dumps({"tool": "read_file", "args": ".env"})}
        env.pop("PYTHONPATH", None)
        out = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True, cwd=tempfile.gettempdir())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(json.loads(out.stdout)["allow"])

    def test_install_config_is_runnable_by_asi_shell(self):
        # ASI runs hooks via PowerShell on Windows: a quoted exe path must use
        # the call operator or every hook invocation fails (and fails closed).
        script = hook_config(r"C:\Program Files\Python\python.exe")["handlers"][0]["script"]
        if os.name == "nt":
            self.assertTrue(script.startswith('& "'), script)
        self.assertTrue(script.endswith("-m asi_skills.hook"), script)


if __name__ == "__main__":
    unittest.main()
