"""P3 Add flow + drawer rules (t_eda36025): one test per rule.

Each test fails against a wrong implementation (raw code admitted, silent
drop, fixed pin cap, unconfirmed delete, missing orphan marking).
"""
import json
import sqlite3
import unittest

from p0contract import store
from p3drawer.drawer import Drawer


def memdrawer():
    c = sqlite3.connect(":memory:")
    return c, Drawer(c)


def text_tree(msg="hi"):
    return {"component": "Text", "props": {"text": msg}, "children": []}


class T_AddCreate(unittest.TestCase):
    def test_create_allowlisted_ok(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hello"))
        self.assertEqual(r["status"], "ok")
        self.assertIsNotNone(r["drawer_entry"])
        self.assertEqual(c.execute("SELECT COUNT(*) FROM drawer").fetchone()[0], 1)

    def test_create_raw_code_denied_no_orphan(self):
        # R04 + F02: raw code anywhere -> chat text + retry, no drawer row.
        bad_trees = [
            {"component": "html", "props": {"html": "<b>x</b>"}, "children": []},
            {"component": "Text",
             "props": {"text": "x", "onClick": "evil()"}, "children": []},
            {"component": "Text",
             "props": {"text": "x", "src": "http://evil/x.js"}, "children": []},
            {"component": "Media",
             "props": {"asset_id": "https://evil/x.png", "alt": "x",
                       "media_type": "image"}, "children": []},
        ]
        for t in bad_trees:
            c, d = memdrawer()
            r = d.create_page("Bad", t)
            self.assertEqual(r["status"], "chat-text-retry", msg=t)
            self.assertTrue(r["retry"])
            self.assertIsNone(r["drawer_entry"])
            self.assertIsNone(
                c.execute("SELECT * FROM drawer").fetchone(), msg=t)

    def test_create_wrong_kind_denied(self):
        # Button is not in the text kind subset (same allowlist as P2).
        c, d = memdrawer()
        tree = {"component": "Button",
                "props": {"label": "go", "action_id": "a", "intent": "assigned"},
                "children": []}
        r = d.create_page("Btn", tree, kind="text")
        self.assertEqual(r["status"], "chat-text-retry")
        self.assertIsNone(c.execute("SELECT * FROM drawer").fetchone())

    def test_add_failure_leaves_no_orphan_entry(self):
        c, d = memdrawer()
        before = c.execute("SELECT COUNT(*) FROM drawer").fetchone()[0]
        d.create_page("Bad", {"component": "nope", "props": {}, "children": []})
        after = c.execute("SELECT COUNT(*) FROM drawer").fetchone()[0]
        self.assertEqual(before, after)


class T_DrawerOps(unittest.TestCase):
    def test_rename(self):
        _, d = memdrawer()
        r = d.create_page("Notes", text_tree())
        out = d.rename(r["drawer_entry"], "Journal")
        self.assertEqual(out["name"], "Journal")
        self.assertEqual(d._get(r["drawer_entry"])["name"], "Journal")

    def test_delete_needs_explicit_confirm(self):
        _, d = memdrawer()
        r = d.create_page("Tmp", text_tree())
        pid = r["drawer_entry"]
        kept = d.delete(pid)  # no confirm
        self.assertEqual(kept["status"], "confirm-required")
        self.assertFalse(kept["deleted"])
        d._get(pid)  # still there
        done = d.delete(pid, confirm=True)
        self.assertTrue(done["deleted"])
        with self.assertRaises(Exception):
            d._get(pid)

    def test_duplicate_names_auto_numbered(self):
        _, d = memdrawer()
        a = d.create_page("Notes", text_tree("a"))
        b = d.create_page("Notes", text_tree("b"))
        self.assertEqual(a["name"], "Notes")
        self.assertEqual(b["name"], "Notes 2")
        # rename onto a taken name numbers too
        e = d.create_page("Other", text_tree("c"))
        self.assertEqual(d.rename(e["drawer_entry"], "Notes")["name"], "Notes 3")

    def test_order_pinned_first_then_creation_add_last(self):
        _, d = memdrawer()
        a = d.create_page("A", text_tree("a"))["drawer_entry"]
        b = d.create_page("B", text_tree("b"))["drawer_entry"]
        cc = d.create_page("C", text_tree("c"))["drawer_entry"]
        d.pin(cc)
        got = d.list_drawer()
        self.assertEqual([e["page_id"] for e in got["entries"]], [cc, a, b])
        self.assertEqual(got["add"], {"affordance": "add-page"})
        # unpin restores pure creation order
        d.unpin(cc)
        self.assertEqual([e["page_id"] for e in d.list_drawer()["entries"]],
                         [a, b, cc])

    def test_no_fixed_pin_cap(self):
        # The plan's starter "pin-4" is superseded: >4 pins must all stick.
        _, d = memdrawer()
        ids = [d.create_page(f"P{i}", text_tree(str(i)))["drawer_entry"]
               for i in range(6)]
        for pid in ids:
            self.assertTrue(d.pin(pid)["pinned"])
        got = d.list_drawer()["entries"]
        self.assertEqual(len(got), 6)
        self.assertTrue(all(e["pinned"] for e in got))


class T_OrphanRepair(unittest.TestCase):
    def _evict_page(self, d, c, fragment_id):
        ver = {"major": 1, "minor": 0}
        c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status)"
                  " VALUES(?,?,?,?,?)",
                  (fragment_id, json.dumps(ver), "h", "rev1", "cached"))
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        dec = {"decision_id": "ev1", "agent_id": "ag", "api_id": "api1",
               "at": "2026-07-01", "action": "evict",
               "target": {"type": "fragment", "fragment_id": fragment_id,
                          "version": ver},
               "expected_revision": "rev1", "registry_revision": "r1",
               "signal_snapshot_id": "s1", "reason": "cleanup",
               "parameters": {"affected_pins": [], "allow_orphan": True,
                              "replacement_version": None},
               "approval_ref": None}
        return store.submit_decision(c, dec, {"actor_api": "api1"},
                                     evidence_snapshots=["s1"])

    def test_evict_marks_needs_repair_not_removed(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hi"))
        out = self._evict_page(d, c, r["fragment_id"])
        self.assertEqual(out["status"], "applied")
        entry = d._get(r["drawer_entry"])
        self.assertEqual(entry["status"], "needs_repair")
        listed = d.list_drawer()["entries"][0]
        self.assertTrue(listed["needs_repair"])
        self.assertEqual(listed["actions"], ["repair", "delete"])

    def test_repair_offer_confirm_flow(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hi"))
        pid = r["drawer_entry"]
        self._evict_page(d, c, r["fragment_id"])
        offer = d.repair_offer(pid)
        self.assertTrue(offer["repair_needed"])
        self.assertIn("repair", offer["options"])
        self.assertIn("delete", offer["options"])
        # unconfirmed repair does nothing
        ask = d.repair(pid, confirm=False)
        self.assertEqual(ask["status"], "confirm-required")
        self.assertEqual(d._get(pid)["status"], "needs_repair")
        # confirmed repair with a compatible replacement restores ok
        done = d.repair(
            pid, new_tree=text_tree("regenerated"), confirm=True)
        self.assertTrue(done["repaired"])
        self.assertEqual(d._get(pid)["status"], "ok")

    def test_repair_invalid_replacement_rejected(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hi"))
        pid = r["drawer_entry"]
        self._evict_page(d, c, r["fragment_id"])
        bad = d.repair(
            pid,
            new_tree={"component": "script", "props": {"src": "x"},
                      "children": []},
            confirm=True)
        self.assertEqual(bad["status"], "rejected")
        self.assertFalse(bad["repaired"])
        self.assertEqual(d._get(pid)["status"], "needs_repair")

    def test_repair_unavailable_says_so_offers_delete(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hi"))
        pid = r["drawer_entry"]
        self._evict_page(d, c, r["fragment_id"])
        c.execute("DELETE FROM page_source WHERE page_id=?", (pid,))
        c.commit()
        offer = d.repair_offer(pid)
        self.assertFalse(offer["replacement_available"])
        self.assertEqual(offer["options"], ["delete"])
        out = d.repair(pid, confirm=True)
        self.assertEqual(out["status"], "unavailable")
        # delete remains available through the i-flow
        self.assertTrue(d.delete(pid, confirm=True)["deleted"])


class T_RestartIds(unittest.TestCase):
    def test_second_instance_does_not_restart_ids(self):
        c, d = memdrawer()
        first = d.create_page("first", text_tree("a"))
        second = Drawer(c).create_page("second", text_tree("b"))
        self.assertEqual(first["status"], "ok")
        self.assertEqual(second["status"], "ok")
        self.assertEqual(first["drawer_entry"], "pg-1")
        self.assertEqual(second["drawer_entry"], "pg-2")

    def test_ids_keep_advancing_across_instances(self):
        c, d = memdrawer()
        for i in range(3):
            d.create_page(f"P{i}", text_tree(str(i)))
        nxt = Drawer(c).create_page("next", text_tree("n"))
        self.assertEqual(nxt["drawer_entry"], "pg-4")
        self.assertEqual(c.execute("SELECT COUNT(*) FROM drawer").fetchone()[0], 4)


class T_MidWriteRecovery(unittest.TestCase):
    def test_mid_write_storage_failure_returns_retry_no_orphan(self):
        c, d = memdrawer()
        c.execute("CREATE TRIGGER fail_meta BEFORE INSERT ON drawer_meta"
                  " BEGIN SELECT RAISE(ABORT, 'injected mid-write failure'); END")
        r = d.create_page("failure", text_tree("x"))
        self.assertEqual(r["status"], "chat-text-retry")
        self.assertTrue(r["retry"])
        self.assertIsNone(r["drawer_entry"])
        for t in ("drawer", "drawer_meta", "page_source"):
            self.assertEqual(
                c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0], 0, msg=t)
        # Chat stays usable: after the failure clears, Add works again.
        c.execute("DROP TRIGGER fail_meta")
        ok = d.create_page("after", text_tree("y"))
        self.assertEqual(ok["status"], "ok")
        self.assertEqual(len(d.list_drawer()["entries"]), 1)


class T_RepairPublishes(unittest.TestCase):
    def _evicted(self):
        c, d = memdrawer()
        r = d.create_page("Notes", text_tree("hi"))
        pid, fid = r["drawer_entry"], r["fragment_id"]
        ver = {"major": 1, "minor": 0}
        c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status)"
                  " VALUES(?,?,?,?,?)",
                  (fid, json.dumps(ver), "h", "rev1", "cached"))
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        store.submit_decision(c, {
            "decision_id": "ev1", "agent_id": "ag", "api_id": "api1",
            "at": "2026-07-01", "action": "evict",
            "target": {"type": "fragment", "fragment_id": fid, "version": ver},
            "expected_revision": "rev1", "registry_revision": "r1",
            "signal_snapshot_id": "s1", "reason": "cleanup",
            "parameters": {"affected_pins": [], "allow_orphan": True,
                           "replacement_version": None},
            "approval_ref": None}, {"actor_api": "api1"},
            evidence_snapshots=["s1"])
        return c, d, pid, fid

    def test_repair_changed_bytes_mints_new_version_and_resolves(self):
        c, d, pid, fid = self._evicted()
        done = d.repair(pid, new_tree=text_tree("changed bytes"), confirm=True)
        self.assertTrue(done["repaired"])
        self.assertEqual(done["status"], "ok")
        frag = json.loads(c.execute(
            "SELECT fragment FROM page_source WHERE page_id=?",
            (pid,)).fetchone()[0])
        self.assertEqual(frag["tree"], text_tree("changed bytes"))
        self.assertEqual(frag["fragment_id"], fid)
        self.assertEqual(frag["version"], {"major": 1, "minor": 1})
        rows = {tuple(r) for r in c.execute(
            "SELECT version, status FROM cache WHERE fragment_id=?", (fid,))}
        self.assertIn((json.dumps({"major": 1, "minor": 0}, sort_keys=True),
                       "tombstone"), rows)
        self.assertIn((json.dumps({"major": 1, "minor": 1}, sort_keys=True),
                       "cached"), rows)
        self.assertEqual(d._get(pid)["status"], "ok")
        self.assertEqual(d._get(pid)["fragment_version"],
                         {"major": 1, "minor": 1})
        resolved = d.resolve_page(pid)
        self.assertEqual(resolved["status"], "ok")
        self.assertEqual(resolved["fragment"], frag)

    def test_repair_revalidate_keeps_identity(self):
        c, d, pid, fid = self._evicted()
        before = c.execute(
            "SELECT fragment FROM page_source WHERE page_id=?",
            (pid,)).fetchone()[0]
        done = d.repair(pid, confirm=True)
        self.assertTrue(done["repaired"])
        after = c.execute(
            "SELECT fragment FROM page_source WHERE page_id=?",
            (pid,)).fetchone()[0]
        self.assertEqual(json.loads(after)["version"], {"major": 1, "minor": 0})
        self.assertEqual(before, after)
        self.assertEqual(d.resolve_page(pid)["status"], "ok")


class T_InvalidSourceOffer(unittest.TestCase):
    def test_invalid_retained_source_offers_delete_only(self):
        c, d = memdrawer()
        pid = d.create_page("bad-src", text_tree("hi"))["drawer_entry"]
        c.execute("UPDATE drawer SET status='needs_repair'")
        c.execute("UPDATE page_source SET fragment=?",
                  (json.dumps({"invalid": True}),))
        c.commit()
        offer = d.repair_offer(pid)
        self.assertTrue(offer["repair_needed"])
        self.assertFalse(offer["replacement_available"])
        self.assertEqual(offer["options"], ["delete"])
        out = d.repair(pid, confirm=True)
        self.assertEqual(out["status"], "unavailable")
        self.assertFalse(out["repaired"])

    def test_resolve_page_reflects_source_health(self):
        c, d = memdrawer()
        pid = d.create_page("ok", text_tree("hi"))["drawer_entry"]
        good = d.resolve_page(pid)
        self.assertEqual(good["status"], "ok")
        self.assertEqual(good["fragment"]["tree"], text_tree("hi"))
        c.execute("DELETE FROM page_source WHERE page_id=?", (pid,))
        c.commit()
        self.assertEqual(d.resolve_page(pid)["status"], "unavailable")
        with self.assertRaises(Exception):
            d.resolve_page("pg-missing")


class T_DrawerShell(unittest.TestCase):
    def test_default_shell_carries_p3_markers(self):
        from p2rich.sandbox import build_page
        html = build_page()
        for marker in ("add-page", "needs_repair", "rename", "drawer"):
            self.assertIn(marker, html)

    def test_shell_renders_listing_order_and_orphan(self):
        from p2rich.sandbox import build_page
        c, d = memdrawer()
        ids = [d.create_page(n, text_tree(n))["drawer_entry"]
               for n in ("A", "B", "C")]
        d.pin(ids[2])
        c.execute("UPDATE drawer SET status='needs_repair' WHERE page_id=?",
                  (ids[1],))
        c.commit()
        html = build_page(drawer=d.list_drawer())
        pos = [html.index(">C</span>"), html.index(">A</span>"),
               html.index(">B</span>"), html.index("add-page")]
        self.assertEqual(pos, sorted(pos))
        self.assertIn("needs_repair", html)
        self.assertIn(ids[1], html)
        self.assertIn("rename", html)


class T_IdDurability(unittest.TestCase):
    """Published ids are never recycled (stale refs must not alias)."""

    def test_deleted_id_not_reused_after_restart(self):
        import tempfile, os
        path = os.path.join(tempfile.mkdtemp(prefix="p3-ids-"), "d.sqlite")
        c = sqlite3.connect(path)
        d = Drawer(c)
        first = d.create_page("first", text_tree("a"))["drawer_entry"]
        c.close()
        c = sqlite3.connect(path)
        d = Drawer(c)
        second = d.create_page("second", text_tree("b"))["drawer_entry"]
        self.assertEqual((first, second), ("pg-1", "pg-2"))
        self.assertEqual(d.delete(second, confirm=True)["deleted"], True)
        third = d.create_page("third", text_tree("c"))["drawer_entry"]
        self.assertNotEqual(third, second)
        self.assertEqual(third, "pg-3")
        c.close()
        c = sqlite3.connect(path)
        d = Drawer(c)
        fourth = d.create_page("fourth", text_tree("d"))["drawer_entry"]
        self.assertEqual(fourth, "pg-4")
        c.close()

    def test_parallel_instances_never_collide_or_reuse(self):
        import tempfile, os, threading
        path = os.path.join(tempfile.mkdtemp(prefix="p3-par-"), "d.sqlite")
        c = sqlite3.connect(path, timeout=30)
        Drawer(c).create_page("seed", text_tree("s"))
        c.close()
        made, errors = [], []
        def worker(n):
            try:
                cc = sqlite3.connect(path, timeout=30)
                dd = Drawer(cc)
                r = dd.create_page(f"W{n}", text_tree(f"w{n}"))
                made.append(r["drawer_entry"])
                cc.close()
            except Exception as e:  # pragma: no cover - must not happen
                errors.append(repr(e))
        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(set(made)), 8)
        c = sqlite3.connect(path)
        ids = sorted(r[0] for r in
                     c.execute("SELECT page_id FROM drawer"))
        self.assertEqual(len(ids), 9)
        nxt = Drawer(c).create_page("after", text_tree("z"))["drawer_entry"]
        self.assertNotIn(nxt, ids)
        c.close()

    def test_mid_write_failure_keeps_high_water_mark(self):
        c, d = memdrawer()
        d.create_page("a", text_tree("a"))
        c.execute("CREATE TRIGGER fail_meta BEFORE INSERT ON drawer_meta"
                  " BEGIN SELECT RAISE(ABORT, 'injected mid-write failure'); END")
        r = d.create_page("failure", text_tree("x"))
        self.assertEqual(r["status"], "chat-text-retry")
        c.execute("DROP TRIGGER fail_meta")
        ok = d.create_page("after", text_tree("y"))
        self.assertEqual(ok["status"], "ok")
        self.assertEqual(ok["drawer_entry"], "pg-2")


class T_OpBoundary(unittest.TestCase):
    """handle_op routes every shell action and reports real outcomes."""

    def test_all_named_ops_route(self):
        from p3drawer import handle_op, DRAWER_OPS
        self.assertEqual(set(DRAWER_OPS),
                         {"add", "rename", "pin", "unpin", "delete",
                          "repair", "repair_offer", "resolve", "list"})
        c, d = memdrawer()
        r = handle_op(d, {"op": "add", "name": "N", "tree": text_tree("x")})
        self.assertEqual(r["status"], "ok")
        pid = r["drawer_entry"]
        self.assertEqual(handle_op(d, {"op": "pin", "page_id": pid})["pinned"],
                         True)
        self.assertEqual(handle_op(d, {"op": "unpin", "page_id": pid})["pinned"],
                         False)
        self.assertEqual(handle_op(d, {"op": "rename", "page_id": pid,
                                       "new_name": "M"})["name"], "M")
        self.assertEqual(handle_op(d, {"op": "list"})["add"],
                         {"affordance": "add-page"})
        self.assertEqual(handle_op(d, {"op": "resolve",
                                       "page_id": pid})["status"], "ok")
        kept = handle_op(d, {"op": "delete", "page_id": pid})
        self.assertEqual(kept["status"], "confirm-required")
        d._get(pid)  # still there without confirm
        done = handle_op(d, {"op": "delete", "page_id": pid,
                             "confirm": True})
        self.assertTrue(done["deleted"])

    def test_unknown_op_raises_no_success_claim(self):
        from p3drawer import handle_op
        from p3drawer.drawer import DrawerError
        c, d = memdrawer()
        with self.assertRaises(DrawerError):
            handle_op(d, {"op": "launch-missiles"})
        self.assertEqual(c.execute("SELECT COUNT(*) FROM drawer")
                         .fetchone()[0], 0)

    def test_add_failure_through_boundary_leaves_no_orphan(self):
        from p3drawer import handle_op
        c, d = memdrawer()
        c.execute("CREATE TRIGGER fail_meta BEFORE INSERT ON drawer_meta"
                  " BEGIN SELECT RAISE(ABORT, 'injected mid-write failure'); END")
        r = handle_op(d, {"op": "add", "name": "failure",
                          "tree": text_tree("x")})
        self.assertEqual(r["status"], "chat-text-retry")
        self.assertTrue(r["retry"])
        self.assertIsNone(r["drawer_entry"])
        for t in ("drawer", "drawer_meta", "page_source"):
            self.assertEqual(
                c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0], 0,
                msg=t)


if __name__ == "__main__":
    unittest.main()
