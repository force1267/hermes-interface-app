"""Committed P3 drawer browser gate: real Chrome drives durable drawer ops.

Builds the verifier fixture (A,B,C,A entries with C pinned and B
needs_repair, plus seven pinned P-entries for the eight-pin case) and
runs tests/drawer_browser_gate.mjs headless: rename with input,
duplicate auto-numbering through the Add UI, pin/unpin reorder,
two-step confirm/cancel delete, repair, injected Add failure with
operable retry, reload persistence, and no id reuse after delete.
Skips when node or the hermes chrome build is unavailable.
"""
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from p3drawer.drawer import Drawer
from p2rich.sandbox import build_page

NODE_CANDIDATES = [
    shutil.which("node"),
    "/root/.hermes/tools/node-26.7.0-linux-x64/bin/node",
]
CHROME_CANDIDATES = [
    os.environ.get("HERMES_CHROME"),
    "/root/.hermes/tools/chromium-1208/chrome-linux64/chrome",
]
MJS = os.path.join(os.path.dirname(__file__), "drawer_browser_gate.mjs")


def _first_existing(cands):
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


NODE = _first_existing(NODE_CANDIDATES)
CHROME = _first_existing(CHROME_CANDIDATES)


def _text_tree(msg="hello"):
    return {"component": "Text", "props": {"text": msg}, "children": []}


@unittest.skipUnless(NODE and CHROME and os.path.exists(MJS),
                     "drawer browser gate needs node + hermes chrome")
class T_DrawerBrowserGate(unittest.TestCase):
    def test_drawer_browser_gate(self):
        self.assertTrue(NODE, "node required")
        self.assertTrue(CHROME, "chrome required")
        node, chrome = str(NODE), str(CHROME)
        c = sqlite3.connect(":memory:")
        d = Drawer(c)
        ids = [d.create_page(n, _text_tree(n))["drawer_entry"]
               for n in ("A", "B", "C", "A")]
        d.pin(ids[2])
        for i in range(7):
            d.pin(d.create_page(f"Pin {i}",
                                _text_tree(f"p{i}"))["drawer_entry"])
        c.execute("UPDATE drawer SET status='needs_repair' WHERE page_id=?",
                  (ids[1],))
        c.commit()
        page = build_page(drawer=d.list_drawer())
        tmpd = tempfile.mkdtemp(prefix="p3-drawer-gate-")
        page_path = os.path.join(tmpd, "drawer.html")
        with open(page_path, "w") as f:
            f.write(page)
        user_dir = os.path.join(tmpd, "chrome")
        os.makedirs(user_dir, exist_ok=True)
        import signal as _signal
        proc = subprocess.Popen(
            [node, MJS, page_path, chrome, user_dir, "0"],
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
                         f"drawer browser gate failed:\n{out}\n{err}")


if __name__ == "__main__":
    unittest.main()
