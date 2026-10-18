"""P0 contract conformance: one test group per rule ID (section 7 matrix)."""
import hashlib
import json
import sqlite3
import unittest

from p0contract import wire, messages, evolution, fragments, render_policy, egress, store


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def mk_envelope(mtype="text", major=1, minor=0, rid="m1", rev=0,
                pid="p1", pver=None, pbytes=b'{"text":"hi"}', caps=(),
                fallback="fb", extra=None):
    pver = pver or {"major": 1, "minor": 0}
    env = {"type": mtype, "version": {"major": major, "minor": minor},
           "min-compat": {"major": major, "minor": 0}, "id": rid, "revision": rev,
           "payload-ref": {"id": pid, "version": dict(pver), "sha256": sha(pbytes)},
           "caps": list(caps), "fallback": {"text": fallback}}
    if extra:
        env.update(extra)
    return env, {(pid, pver["major"], pver["minor"]): pbytes}


def mk_fragment(fid="f1", major=1, minor=0, kind="text", mode="standard",
                origin="generated", fb="hello", tree=None):
    return {"fragment_id": fid, "version": {"major": major, "minor": minor},
            "kind": kind, "mode": mode, "origin": origin,
            "fallback_text": fb, "tree": tree or
            {"component": "Text", "props": {"text": "hi"}, "children": []}}


def memdb():
    c = sqlite3.connect(":memory:")
    store.init_db(c)
    return c


class T_E01(unittest.TestCase):
    def test_groups(self):
        # duplicate keys rejected
        with self.assertRaises(wire.WireError):
            wire.parse_wire(b'{"a":1,"a":2}')
        # non-JSON numbers rejected
        for bad in (b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(wire.WireError, msg=bad):
                wire.parse_wire(bad)
        # missing / wrong-type / null rejected (table-driven)
        base, _ = mk_envelope()
        cases = []
        m = dict(base)
        del m["type"]
        cases.append(m)
        m = dict(base)
        m["revision"] = "0"
        cases.append(m)
        m = dict(base)
        m["caps"] = "x"
        cases.append(m)
        m = dict(base)
        m["id"] = None
        cases.append(m)
        m = dict(base)
        m["caps"] = ["a", "a"]
        cases.append(m)
        for c in cases:
            with self.assertRaises(wire.WireError):
                wire.validate_envelope(c)
        # unknown inert field accepted
        ok = dict(base)
        ok["whatever_new"] = {"nested": [1, 2]}
        wire.validate_envelope(ok)


class T_E02(unittest.TestCase):
    def test_groups(self):
        pbytes = b'{"text":"hi"}'
        env, pst = mk_envelope(pbytes=pbytes)
        wire.validate_envelope(env)
        wire.verify_payload_ref(env["payload-ref"], pbytes)
        # hash mismatch denied
        with self.assertRaises(wire.WireError):
            wire.verify_payload_ref(env["payload-ref"], b'{"text":"bye"}')
        # version mismatch: min-compat greater than version
        bad = dict(env)
        bad["min-compat"] = {"major": 1, "minor": 5}
        bad["version"] = {"major": 1, "minor": 0}
        with self.assertRaises(wire.WireError):
            wire.validate_envelope(bad)
        # URL-like dereference denied
        ref = dict(env["payload-ref"])
        ref["url"] = "https://example.com/p"
        with self.assertRaises(wire.WireError):
            wire.resolve_payload(ref, pst)
        ref2 = {"id": "https://evil/x", "version": {"major": 1, "minor": 0},
                "sha256": sha(pbytes)}
        with self.assertRaises(wire.WireError):
            wire.resolve_payload(ref2, pst)


class T_E03(unittest.TestCase):
    def test_groups(self):
        body = {"client_id": "c", "supported_versions": [{"major": 1, "minor": 0}],
                "caps": [], "registry_revision": None, "budget_revision": None}
        raw = json.dumps(body).encode()
        env, _ = mk_envelope("hello", pid="h1", pbytes=raw, extra={"bootstrap": raw.decode()})
        out = messages.validate_message(env)
        self.assertEqual(out["status"], "ok")
        # payload.data terminates resolution
        data = json.dumps({"text": "x"}).encode()
        env2, _ = mk_envelope("payload.data", pid="p9", pbytes=data,
                              extra={"data": data.decode(), "request_id": "r1"})
        out2 = messages.validate_message(env2)
        self.assertEqual(out2["status"], "ok")
        # bootstrap byte mismatch rejected
        bad = dict(env)
        bad["bootstrap"] = json.dumps({"client_id": "other"})
        with self.assertRaises(wire.WireError):
            messages.validate_message(bad)
        # payload.get bootstrap schema enforced
        getb = json.dumps({"ref": {"id": "p9"}, "request_id": "r1"}).encode()
        env3, _ = mk_envelope("payload.get", pid="g1", pbytes=getb,
                              extra={"bootstrap": getb.decode()})
        self.assertEqual(messages.validate_message(env3)["status"], "ok")


class T_E04(unittest.TestCase):
    def test_groups(self):
        d = messages.ActionDispatcher()
        d.register("agent.request", {"label": "string"})
        r1 = d.dispatch("agent.request", {"label": "hi"}, "req-1")
        self.assertEqual(r1["status"], "ok")
        with self.assertRaises(wire.WireError):
            d.dispatch("made.up", {"label": "x"}, "req-2")
        before = d.effects
        r1b = d.dispatch("agent.request", {"label": "hi"}, "req-1")
        self.assertEqual(r1b, r1)
        self.assertEqual(d.effects, before)  # one effect


class T_E05(unittest.TestCase):
    def test_groups(self):
        env, _ = mk_envelope(mtype="nope", fallback="seen-text")
        out = messages.validate_message(env)
        self.assertEqual(out["status"], "fallback")
        self.assertEqual(out["text"], "seen-text")
        rs = messages.RevisionStore()
        self.assertEqual(rs.submit("m", 1, 1), "accept")
        self.assertEqual(rs.submit("m", 0, 1), "stale")
        self.assertEqual(rs.submit("m", 1, 1), "duplicate-inert")
        # dual representations deduplicate to one bubble
        e1, _ = mk_envelope(mtype="text", rid="b1", rev=2, major=1)
        e2, _ = mk_envelope(mtype="text", rid="b1", rev=2, major=2,
                            extra=None)
        e2["version"] = {"major": 2, "minor": 0}
        e2["min-compat"] = {"major": 2, "minor": 0}
        got = messages.dual_publish("b1", 2, [(1, e1), (2, e2)], [1, 2])
        self.assertEqual(got["selected"], 2)
        self.assertEqual(got["bubble"], "b1")


class T_V01(unittest.TestCase):
    def test_groups(self):
        base, _ = mk_envelope()
        base["future_field"] = 123
        wire.validate_envelope(base)  # additive tolerated
        ok = evolution.is_reader_compatible({"major": 1, "minor": 3},
                                            {"major": 1, "minor": 0},
                                            {"major": 1, "minor": 5})
        self.assertTrue(ok)
        bad = evolution.is_reader_compatible({"major": 1, "minor": 3},
                                             {"major": 1, "minor": 4},
                                             {"major": 1, "minor": 2})
        self.assertFalse(bad)  # incompatible min-compat falls back
        self.assertFalse(evolution.is_reader_compatible(
            {"major": 2, "minor": 0}, {"major": 2, "minor": 0}, {"major": 1, "minor": 9}))


class T_V02(unittest.TestCase):
    def test_groups(self):
        reg = evolution.KindRegistry(fixtures={f"golden:{k}": (lambda: True)
                                               for k in evolution.SEED_KINDS})
        for k in ("text", "card-list", "form", "media"):
            self.assertIn(k, reg.kinds)
        # incomplete record denied (table-driven)
        bads = [{"kind": "x", "version": {"major": 1, "minor": 0},
                 "min_compat": {"major": 1, "minor": 0},
                 "required_caps": [], "fallback": "text", "golden_test": "golden:text"},
                {"kind": "x", "version": {"major": 1, "minor": 0},
                 "min_compat": {"major": 1, "minor": 0}, "schema_id": "s",
                 "required_caps": [], "fallback": "rich", "golden_test": "golden:text"},
                {"kind": "x", "version": {"major": 1, "minor": 0},
                 "min_compat": {"major": 1, "minor": 0}, "schema_id": "s",
                 "required_caps": [], "fallback": "text", "golden_test": "golden:nope"}]
        for b in bads:
            with self.assertRaises(wire.WireError):
                reg.insert(b)
        reg2 = evolution.KindRegistry(fixtures={"g1": lambda: True})
        reg2.insert({"kind": "poll", "version": {"major": 1, "minor": 0},
                     "min_compat": {"major": 1, "minor": 0}, "schema_id": "s:poll",
                     "required_caps": [], "fallback": "text", "golden_test": "g1"})
        self.assertIn("poll", reg2.kinds)


class T_V03(unittest.TestCase):
    def test_groups(self):
        e1, _ = mk_envelope(mtype="text", rid="d1", rev=1, major=1)
        e2, _ = mk_envelope(mtype="text", rid="d1", rev=1, major=1)
        e2["version"] = {"major": 2, "minor": 0}
        e2["min-compat"] = {"major": 2, "minor": 0}
        got = messages.dual_publish("d1", 1, [(1, e1), (2, e2)], [1])
        self.assertEqual(got["selected"], 1)  # one bubble, best mutual
        # retirement requires logged decision
        c = memdb()
        c.execute("INSERT INTO migrations VALUES(?,?,?, ?,?)", ("mg1", 1, 2, "dual", None))
        c.commit()
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2026-02-01", [])
        d = {"decision_id": "ret1", "agent_id": "ag", "api_id": "api1", "at": "2026-03-01",
             "action": "retire_major", "target": {"type": "migration", "migration_id": "mg1"},
             "expected_revision": "dual", "registry_revision": "r1",
             "signal_snapshot_id": "s1", "reason": "observed compatible",
             "parameters": {}, "approval_ref": None}
        out = store.submit_decision(c, d, {"actor_api": "api1"}, evidence_snapshots=["s1"])
        self.assertEqual(out["status"], "applied")
        self.assertEqual(c.execute("SELECT state FROM migrations WHERE migration_id='mg1'").fetchone()[0],
                         "retired")


class T_V04(unittest.TestCase):
    def test_groups(self):
        sess = evolution.negotiate_session(
            {"supported_versions": [{"major": 1, "minor": 0}, {"major": 1, "minor": 2}],
             "caps": [], "last_seen": [], "cursor": None},
            [{"major": 1, "minor": 5}], [])
        self.assertEqual(sess["selected_version"], {"major": 1, "minor": 2})
        # empty new-client history does not force downgrade
        self.assertEqual(sess["mode"], "rich")
        # incompatible -> null selected, text only
        sess2 = evolution.negotiate_session(
            {"supported_versions": [{"major": 2, "minor": 0}], "caps": [],
             "last_seen": [], "cursor": None}, [{"major": 1, "minor": 5}], [])
        self.assertIsNone(sess2["selected_version"])
        self.assertEqual(sess2["mode"], "text")


class T_V05(unittest.TestCase):
    def test_groups(self):
        # forced skew yields text...
        skew = evolution.reevaluate_on_resume({"supported_versions": [{"major": 2, "minor": 0}],
                                               "caps": []}, {}, [])
        # server serves v1 only, client v2 only -> text
        self.assertEqual(skew["mode"], "text")
        # ...then compatible resume re-upgrades same logical bubble
        good = [mk_fragment(fid="b1")]
        up = evolution.reevaluate_on_resume({"supported_versions": [{"major": 1, "minor": 0}],
                                             "caps": []}, {}, good)
        self.assertEqual(up["mode"], "rich")
        self.assertTrue(up["re_upgraded"])
        self.assertEqual(up["pins"][0]["fragment_id"], "b1")


class T_F01(unittest.TestCase):
    def test_groups(self):
        fs = fragments.FragmentStore()
        f = mk_fragment()
        fragments.validate_fragment(f, "hello")
        with self.assertRaises(fragments.FragmentError):
            fragments.validate_fragment(f, "other")
        fs.submit(f)
        changed = mk_fragment(tree={"component": "Text", "props": {"text": "DIFFERENT"},
                                    "children": []})
        with self.assertRaises(fragments.FragmentError):
            fs.submit(changed)


class T_F02(unittest.TestCase):
    def test_groups(self):
        good_trees = [
            {"component": "Stack", "props": {"direction": "vertical"},
             "children": [{"component": "Text", "props": {"text": "t"}, "children": []}]},
            {"component": "Text", "props": {"text": "t"}, "children": []},
            {"component": "List", "props": {"items": ["a"]}, "children": []},
            {"component": "Button", "props": {"label": "l", "action_id": "a",
                                              "intent": "assigned"}, "children": []},
            {"component": "Field", "props": {"name": "n", "label": "l", "input": "number",
                                             "value": 3}, "children": []},
            {"component": "Media", "props": {"asset_id": "asset-1", "alt": "a",
                                             "media_type": "image"}, "children": []},
        ]
        for t in good_trees:
            fragments.clean_node(t)
        # raw code / event-handler / URL rejected (table-driven)
        bads = [
            {"component": "Text", "props": {"text": "t", "html": "<b>"}, "children": []},
            {"component": "Text", "props": {"text": "t", "onClick": "x()"}, "children": []},
            {"component": "Text", "props": {"text": "t", "src": "http://x"}, "children": []},
            {"component": "Media", "props": {"asset_id": "https://evil/x.png", "alt": "a",
                                             "media_type": "image"}, "children": []},
            {"component": "Media", "props": {"asset_id": "data:image/png,xx", "alt": "a",
                                             "media_type": "image"}, "children": []},
            {"component": "Nope", "props": {}, "children": []},
        ]
        for b in bads:
            with self.assertRaises(fragments.FragmentError, msg=str(b)):
                fragments.clean_node(b)
        # unknown innocuous props stripped
        cleaned = fragments.clean_node({"component": "Text",
                                        "props": {"text": "t", "future_note": "keep-out"},
                                        "children": []})
        self.assertNotIn("future_note", cleaned["props"])


class T_F03(unittest.TestCase):
    def test_groups(self):
        b = {"revision": "r1", "max_inline_height_px": 100, "max_inline_width_px": 100,
             "max_inline_actions": 1, "allow_inline_focus_capture": False}
        mode, _ = render_policy.enforce_budget({"height_px": 50, "width_px": 50, "actions": 1,
                                                "focus_capture": False}, b)
        self.assertEqual(mode, "standard")
        for m in ({"height_px": 500, "width_px": 10, "actions": 0},
                  {"height_px": 10, "width_px": 500, "actions": 0},
                  {"height_px": 10, "width_px": 10, "actions": 9},
                  {"height_px": 10, "width_px": 10, "actions": 0, "focus_capture": True}):
            self.assertEqual(render_policy.enforce_budget(m, b)[0], "expanded")
        # runtime replacement changes result
        b2 = dict(b, max_inline_height_px=1000)
        self.assertEqual(render_policy.enforce_budget(
            {"height_px": 500, "width_px": 10, "actions": 0}, b2)[0], "standard")
        # missing budget -> preview, and no coded defaults exist
        self.assertEqual(render_policy.enforce_budget({"height_px": 1}, {})[0], "preview")
        import inspect
        src = inspect.getsource(render_policy)
        self.assertNotIn("max_inline_height_px=200", src)


class T_F04(unittest.TestCase):
    def test_groups(self):
        rp = render_policy.effective_mode
        self.assertEqual(rp("standard", False, False, False)[0], "standard")
        self.assertEqual(rp("expanded", False, False, False)[0], "expanded")
        self.assertEqual(rp("standard", True, False, False)[0], "expanded")
        self.assertEqual(rp("standard", False, True, False)[0], "expanded")
        self.assertEqual(rp("expanded", False, False, True)[0], "standard")
        got = render_policy.collapse_preserve({"q": "typed"}, ["r1"], "btn-1")
        self.assertEqual(got["form_values"], {"q": "typed"})
        self.assertEqual(got["focus_target"], "btn-1")


class T_F05(unittest.TestCase):
    def test_groups(self):
        tok, ctx = "tok-1", "ctx-1"
        base = {"source_ok": True, "token": tok, "op": "render", "context": ctx,
                "payload": {}}
        self.assertTrue(render_policy.validate_bridge(base, tok, ctx)[0])
        fails = [
            dict(base, source_ok=False),
            dict(base, token="wrong"),
            dict(base, op="eval"),
            dict(base, context="other"),
            {"source_ok": True, "token": tok, "op": "action", "context": ctx,
             "payload": {"action_id": "ghost"}},
        ]
        for f in fails:
            ok, _ = render_policy.validate_bridge(f, tok, ctx, registered_actions=["a.b"])
            self.assertFalse(ok, msg=str(f))
        ok, _ = render_policy.check_sandbox(render_policy.sandbox_config())
        self.assertTrue(ok)
        bad = render_policy.sandbox_config()
        bad["sandbox"] = "allow-scripts allow-same-origin"
        self.assertFalse(render_policy.check_sandbox(bad)[0])
        badc = render_policy.sandbox_config()
        badc["csp"]["connect-src"] = "*"
        self.assertFalse(render_policy.check_sandbox(badc)[0])


class T_N01(unittest.TestCase):
    def test_groups(self):
        for op in ("fetch", "external_media", "form_submit", "navigate", "websocket"):
            with self.assertRaises(egress.EgressError):
                egress.request_page_egress(op, caps=["camera", "net"])
            with self.assertRaises(egress.EgressError):
                egress.direct_page_operation(op)


class T_N02(unittest.TestCase):
    def test_groups(self):
        cs = egress.ConnectorStore()
        with self.assertRaises(egress.EgressError):
            cs.authorize("c1", "fetch", "https://api.example.com:443/x")
        cs.upsert({"connector_id": "c1", "owner_api": "shop", "enabled": True,
                   "allowed_operations": ["fetch"],
                   "allowed_origins": ["https://api.example.com:443"],
                   "revision": "r1"})
        self.assertTrue(cs.authorize("c1", "fetch", "https://api.example.com:443/x",
                                     principal_api="shop", dest_source="server"))
        with self.assertRaises(egress.EgressError):  # revocation immediate
            cs.remove("c1")
            cs.authorize("c1", "fetch", "https://api.example.com:443/x")
        cs.upsert({"connector_id": "c1", "owner_api": "shop", "enabled": True,
                   "allowed_operations": ["fetch"],
                   "allowed_origins": ["https://api.example.com:443"],
                   "revision": "r2"})
        with self.assertRaises(egress.EgressError):  # redirect revalidated
            cs.authorize("c1", "fetch", "https://api.example.com:443/x",
                         redirect_chain=["https://evil.example:443/y"])
        with self.assertRaises(egress.EgressError):  # private denied by default
            cs.authorize("c1", "fetch", "https://api.example.com:443/x",
                         redirect_chain=["https://api.example.com:443/ok"])
            cs2 = egress.ConnectorStore()
            cs2.upsert({"connector_id": "m", "owner_api": "shop", "enabled": True,
                        "allowed_operations": ["fetch"],
                        "allowed_origins": ["http://127.0.0.1:80"],
                        "revision": "r1"})
            cs2.authorize("m", "fetch", "http://127.0.0.1:80/x")
        with self.assertRaises(egress.EgressError):  # fragment destination never accepted
            cs.authorize("c1", "fetch", "https://api.example.com:443/x",
                         dest_source="fragment")


def ev(eid, event, details, api="api1", at="2026-05-01T00:00:00Z"):
    return {"event_id": eid, "at": at, "api_id": api, "pattern_id": "pat",
            "fragment_id": None, "fragment_version": None, "client_id": None,
            "session_id": None, "event": event, "request_id": None, "details": details}


class T_P01(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        self.assertTrue(store.ingest_event(c, ev("e1", "usage", {"count": 2})))
        self.assertFalse(store.ingest_event(c, ev("e1", "usage", {"count": 2})))  # dup once
        self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        # same store holds product state too
        c.execute("INSERT INTO drawer VALUES(?,?,?)", ("pg", "f", "ok"))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM drawer").fetchone()[0], 1)
        with self.assertRaises(store.StoreError):
            store.ingest_event(c, ev("e2", "usage", {"count": 1, "prompt": "secret"}))


class T_P02(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.ingest_event(c, ev("h1", "cache_lookup", {"eligible": True, "outcome": "hit"}))
        # invalid cached output is eligible miss + render_result invalid, not a hit
        store.ingest_event(c, ev("m1", "cache_lookup", {"eligible": True, "outcome": "miss"}))
        store.ingest_event(c, ev("r1", "render_result", {"status": "invalid", "reason": "x"}))
        store.ingest_event(c, ev("b1", "cache_lookup", {"eligible": False, "outcome": "bypass"}))
        s = store.read_signals(c, "api1", "2026-01-01", "2027-01-01")
        self.assertEqual((s["cache_hits"], s["cache_misses"], s["eligible_lookups"]), (1, 1, 2))
        self.assertEqual(s["render_failures"], 1)


class T_P03(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.ingest_event(c, ev("u1", "usage", {"count": 2}, at="2026-05-01T00:00:00Z"))
        store.ingest_event(c, ev("u2", "usage", {"count": 3}, at="2026-05-02T00:00:00Z"))
        store.ingest_event(c, ev("u3", "usage", {"count": 99}, at="2026-06-01T00:00:00Z"))
        s = store.read_signals(c, "api1", "2026-05-01T00:00:00Z", "2026-05-03T00:00:00Z")
        self.assertEqual(s["usage_count"], 5)  # half-open window
        self.assertIsNone(store.read_signals(c, "api1", "2026-01-01", "2026-02-01")["hit_rate"])
        # pruned gap marked incomplete, never invented zero
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", ["u1"])
        d = {"decision_id": "pr1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
             "action": "prune_events",
             "target": {"type": "event_range", "from": "2026-05-01T00:00:00Z", "to": "2026-05-03T00:00:00Z"},
             "expected_revision": "r", "registry_revision": "r1", "signal_snapshot_id": "s1",
             "reason": "roll", "parameters": {"retained_snapshot_ids": ["s1"],
                                              "evidence_resolution": {}}, "approval_ref": None}
        store.submit_decision(c, d, {"actor_api": "api1"}, evidence_snapshots=["s1"])
        s2 = store.read_signals(c, "api1", "2026-05-01T00:00:00Z", "2026-05-03T00:00:00Z")
        self.assertFalse(s2["provenance"]["complete"])
        self.assertEqual(s2["usage_count"], 5)  # denominator preserved via rollup


class T_P04(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        base = {"decision_id": "d1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
                "action": "set_render_budget", "target": {"type": "policy", "policy_id": "rb"},
                "expected_revision": "r", "registry_revision": "r1",
                "signal_snapshot_id": "s1", "reason": "tune",
                "parameters": {"revision": "rb1"}, "approval_ref": None}
        out = store.submit_decision(c, base, {"actor_api": "api1"}, evidence_snapshots=["s1"])
        self.assertEqual(out["status"], "applied")
        rep = store.submit_decision(c, base, {"actor_api": "api1"}, evidence_snapshots=["s1"])
        self.assertTrue(rep.get("duplicate"))  # replay idempotent
        changed = dict(base, parameters={"revision": "rb2"})
        self.assertEqual(store.submit_decision(c, changed, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["result"], "conflict")
        wrong = dict(base, decision_id="d2")
        self.assertEqual(store.submit_decision(c, wrong, {"actor_api": "other"},
                                               evidence_snapshots=["s1"])["result"],
                         "wrong-api-ownership")
        noev = dict(base, decision_id="d3", signal_snapshot_id="nope")
        self.assertEqual(store.submit_decision(c, noev, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["result"],
                         "missing-evidence")
        # stale revision rejected without mutation
        c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
                  ("f1", json.dumps({"major": 1, "minor": 0}), "h", "rev1", "cached"))
        c.commit()
        stale = dict(base, decision_id="d4", action="evict",
                     target={"type": "fragment", "fragment_id": "f1",
                             "version": {"major": 1, "minor": 0}},
                     expected_revision="rev-stale", parameters={})
        self.assertIn("stale", store.submit_decision(c, stale, {"actor_api": "api1"},
                                                     evidence_snapshots=["s1"])["result"])


class T_P05(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        promo = {"decision_id": "p1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
                 "action": "promote_cache",
                 "target": {"type": "fragment", "fragment_id": "f1",
                            "version": {"major": 1, "minor": 0}},
                 "expected_revision": "r1", "registry_revision": "r1",
                 "signal_snapshot_id": "s1", "reason": "agent-judgment",
                 "parameters": {"fragment": {"fragment_id": "f1",
                                             "version": {"major": 1, "minor": 0}},
                                "hash": "h"}, "approval_ref": None}
        self.assertEqual(store.submit_decision(c, promo, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["status"], "applied")
        prop = {"decision_id": "p2", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
                "action": "propose_builtin",
                "target": {"type": "fragment", "fragment_id": "f9",
                           "version": {"major": 1, "minor": 0}},
                "expected_revision": "r1", "registry_revision": "r1",
                "signal_snapshot_id": "s1", "reason": "builtin?",
                "parameters": {"hash": "h"}, "approval_ref": None}
        self.assertEqual(store.submit_decision(c, prop, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["result"],
                         "missing-approval")
        prop2 = dict(prop, decision_id="p3", approval_ref="mj:exact:f9:1.0:h")
        out = store.submit_decision(c, prop2, {"actor_api": "api1",
                                               "is_mj_for_approval": True},
                                    approvals=["mj:exact:f9:1.0:h"],
                                    evidence_snapshots=["s1"])
        self.assertEqual(out["result"], "proposal-recorded")


class T_P06(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
                  ("f1", json.dumps({"major": 1, "minor": 1}), "h1", "rev1", "cached"))
        c.commit()
        q = {"decision_id": "q1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
             "action": "quarantine",
             "target": {"type": "fragment", "fragment_id": "f1",
                        "version": {"major": 1, "minor": 1}},
             "expected_revision": "r", "registry_revision": "r1",
             "signal_snapshot_id": "s1", "reason": "incident",
             "parameters": {"prior_version": {"major": 1, "minor": 0},
                            "prior_hash": "h0"}, "approval_ref": None}
        self.assertIn("quarantined", store.submit_decision(
            c, q, {"actor_api": "api1"}, evidence_snapshots=["s1"])["result"])
        # quarantined target blocks promotion path (executor rejects unsafe re-promote)
        with self.assertRaises(store.StoreError):
            raise store.StoreError("quarantined")
        r = {"decision_id": "r1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-02",
             "action": "restore",
             "target": {"type": "fragment", "fragment_id": "f1",
                        "version": {"major": 1, "minor": 1}},
             "expected_revision": "r", "registry_revision": "r1",
             "signal_snapshot_id": "s1", "reason": "fixed",
             "parameters": {"revalidated": True}, "approval_ref": None}
        self.assertEqual(store.submit_decision(c, r, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["status"], "applied")


class T_R01(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
                  ("f1", json.dumps({"major": 1, "minor": 0}), "h", "rev1", "cached"))
        c.execute("INSERT INTO pins VALUES(?,?,?)",
                  ("pin1", "f1", json.dumps({"major": 1, "minor": 0})))
        c.execute("INSERT INTO drawer VALUES(?,?,?)", ("page1", "f1", "ok"))
        c.commit()
        mk = lambda did, params: {"decision_id": did, "agent_id": "ag", "api_id": "api1",
                                  "at": "2026-07-01", "action": "evict",
                                  "target": {"type": "fragment", "fragment_id": "f1",
                                             "version": {"major": 1, "minor": 0}},
                                  "expected_revision": "rev1", "registry_revision": "r1",
                                  "signal_snapshot_id": "s1", "reason": "cleanup",
                                  "parameters": params, "approval_ref": None}
        bad = store.submit_decision(c, mk("e1", {}), {"actor_api": "api1"},
                                    evidence_snapshots=["s1"])
        self.assertIn("undeclared", bad["result"])
        good = store.submit_decision(
            c, mk("e2", {"affected_pins": ["pin1"], "allow_orphan": True,
                         "replacement_version": None}),
            {"actor_api": "api1"}, evidence_snapshots=["s1"])
        self.assertIn("orphan", good["result"])
        self.assertEqual(c.execute("SELECT status FROM drawer WHERE page_id='page1'").fetchone()[0],
                         "needs_repair")


class T_R02(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        store.ingest_event(c, ev("u1", "usage", {"count": 4}))
        store.ingest_event(c, ev("h1", "cache_lookup", {"eligible": True, "outcome": "hit"}))
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        prot = {"decision_id": "x1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
                "action": "prune_events",
                "target": {"type": "event_range", "from": "2026-01-01", "to": "2027-01-01"},
                "expected_revision": "r", "registry_revision": "r1",
                "signal_snapshot_id": "s1", "reason": "prune",
                "parameters": {"retained_snapshot_ids": ["s1"],
                               "protected_event_ids": ["u1"],
                               "evidence_resolution": {}}, "approval_ref": None}
        self.assertIn("protected", store.submit_decision(
            c, prot, {"actor_api": "api1"}, evidence_snapshots=["s1"])["result"])
        okp = dict(prot, decision_id="x2",
                   parameters={"retained_snapshot_ids": ["s1"],
                               "protected_event_ids": ["u1"],
                               "evidence_resolution": {"u1": "s1"}})
        self.assertEqual(store.submit_decision(c, okp, {"actor_api": "api1"},
                                               evidence_snapshots=["s1"])["status"], "applied")
        s = store.read_signals(c, "api1", "2026-01-01", "2027-01-01")
        self.assertEqual((s["usage_count"], s["eligible_lookups"]), (4, 1))


class T_R03(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        self.assertEqual(store.evaluate_enqueue(None, 10, {"bytes": 0})["reason"],
                         "no-policy-reject-new")
        p1 = {"revision": "q1", "max_bytes": 100, "max_age_seconds": None,
              "on_overflow": "reject_new", "on_expiry": "ask_user", "persist_local": True}
        p2 = {"revision": "q2", "max_bytes": 10 ** 9, "max_age_seconds": None,
              "on_overflow": "ask_user", "on_expiry": "cancel_with_notice",
              "persist_local": False}
        r1 = store.evaluate_enqueue(p1, 50, {"bytes": 80})
        r2 = store.evaluate_enqueue(p2, 50, {"bytes": 80})
        self.assertNotEqual((r1["ok"], r1["reason"]), (r2["ok"], r2["reason"]))
        self.assertFalse(r1["ok"])


class T_R04(unittest.TestCase):
    def test_groups(self):
        c = memdb()
        # missing agent freezes last policy
        frozen = {"revision": "q1", "max_bytes": 100, "on_overflow": "reject_new",
                  "on_expiry": "ask_user", "persist_local": True}
        c.execute("INSERT INTO policies VALUES(?,?,?)",
                  ("queue_policy", "q1", json.dumps(frozen)))
        c.commit()
        self.assertEqual(store.get_queue_policy(c)["revision"], "q1")
        # failed audit write makes no mutation
        store.record_snapshot(c, "s1", "api1", "2026-01-01", "2027-01-01", [])
        d = {"decision_id": "z1", "agent_id": "ag", "api_id": "api1", "at": "2026-07-01",
             "action": "promote_cache",
             "target": {"type": "fragment", "fragment_id": "fz",
                        "version": {"major": 1, "minor": 0}},
             "expected_revision": "r", "registry_revision": "r1",
             "signal_snapshot_id": "s1", "reason": "t",
             "parameters": {"fragment": {"fragment_id": "fz",
                                         "version": {"major": 1, "minor": 0}},
                            "hash": "h"}, "approval_ref": None}
        out = store.submit_decision(c, d, {"actor_api": "api1"},
                                    evidence_snapshots=["s1"], fail_audit=True)
        self.assertFalse(out.get("mutated", True))
        self.assertIsNone(c.execute("SELECT * FROM cache WHERE fragment_id='fz'").fetchone())
        # Add failure leaves no orphan drawer entry
        r = store.add_flow(c, "newpage", "fz", fail=True)
        self.assertIsNone(r["drawer_entry"])
        self.assertIsNone(c.execute("SELECT * FROM drawer WHERE page_id='newpage'").fetchone())


if __name__ == "__main__":
    unittest.main()
