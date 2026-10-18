"""Committed P2 browser gate (defect 6): runs tests/browser_gate.mjs headless.

Builds a fixture page with a form bubble (focus_target=act-a.submit) and
a long text bubble (missing focus_target, exercises the invoker fallback),
then drives it through real Chrome over CDP with zero JS dependencies.
Skips when node or the hermes chrome build is unavailable.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from p2rich.bubble import RichBubble
from p2rich.sandbox import build_page

BUDGET = {"revision": "r1", "max_inline_height_px": 200,
          "max_inline_width_px": 300, "max_inline_actions": 2,
          "allow_inline_focus_capture": False}

NODE_CANDIDATES = [
    shutil.which("node"),
    "/root/.hermes/tools/node-26.7.0-linux-x64/bin/node",
]
CHROME_CANDIDATES = [
    os.environ.get("HERMES_CHROME"),
    "/root/.hermes/tools/chromium-1208/chrome-linux64/chrome",
]


def _first_existing(cands):
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


NODE = _first_existing(NODE_CANDIDATES)
CHROME = _first_existing(CHROME_CANDIDATES)
MJS = os.path.join(os.path.dirname(__file__), "browser_gate.mjs")


@unittest.skipUnless(NODE and CHROME and os.path.exists(MJS),
                     "browser gate needs node + hermes chrome")
class T_BrowserGate(unittest.TestCase):
    def test_browser_gate(self):
        self.assertTrue(NODE and CHROME, "node + chrome required")
        with open(os.path.join(os.path.dirname(__file__), "goldens",
                               "form.json")) as f:
            form = json.load(f)
        with open(os.path.join(os.path.dirname(__file__), "goldens",
                               "text.json")) as f:
            long_text = json.load(f)
        long_text = json.loads(json.dumps(long_text))
        long_text["fragment_id"] = "f-long"
        long_text["tree"]["props"]["text"] = "LONG_SENTINEL " * 10000
        form_bubble = RichBubble(form, budget=BUDGET,
                                 focus_target="act-a.submit")
        form_bubble.set_measured({"height_px": 10, "width_px": 10,
                                  "actions": 1, "focus_capture": False})
        long_bubble = RichBubble(long_text, budget=None,
                                 focus_target="nope-missing")
        page = build_page("gate-token", "gate-context",
                          ("a.submit", "a.ok"),
                          bubbles=(form_bubble, long_bubble))
        tmpd = tempfile.mkdtemp(prefix="p2-gate-")
        page_path = os.path.join(tmpd, "gate.html")
        with open(page_path, "w") as f:
            f.write(page)
        user_dir = os.path.join(tmpd, "chrome")
        os.makedirs(user_dir, exist_ok=True)
        # Port "0": the gate asks chrome for an ephemeral debug port owned by
        # this run only, so parallel/repeated runs never share a stale
        # browser. The gate runs in its own process group so a timeout kills
        # the whole tree (node + its chrome child), never orphaning a gate
        # Chrome on a reused port.
        import signal as _signal
        proc = subprocess.Popen(
            [NODE, MJS, page_path, CHROME, user_dir, "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        try:
            out, err = proc.communicate(timeout=240)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            out, err = proc.communicate()
            rc = 124
            out = (out or "") + "\nGATE TIMEOUT after 240s (process group killed)"
        print(out)
        print(err)
        self.assertEqual(rc, 0,
                         f"browser gate failed:\n{out}\n{err}")


if __name__ == "__main__":
    unittest.main()
