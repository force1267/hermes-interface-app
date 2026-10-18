"""P4 ops loop: unaided promote / quarantine / evict over the one P0 store.

Drives the loop through real signals with the agent's policy supplied at
runtime. Proves "unaided" by running with no manual step between lanes, and
proves "no hard-coded threshold" by rerunning the same signals with a
stricter runtime policy and watching promotion stop.
"""
import json
import sqlite3
import unittest

from p0contract import store
from p4ops import PolicyError, decision_log, run_cycle, status_view

V10 = {"major": 1, "minor": 0}
V11 = {"major": 1, "minor": 1}
FROM = "2026-01-01"
TO = "2026-02-01"
AT = "2026-02-02"

BASE_POLICY = {
    "promotion_min_uses": 5,
    "promotion_max_render_failures": 0,
    "quarantine_flag_threshold": 1,
    "quarantine_min_hit_rate": 0.5,
    "evict_max_uses": 1,
    "evict_max_hit_rate": 0.5,
    "allow_orphan": True,
    "fragments": {
        "f_new": {"version": dict(V10), "hash": "hnew", "revision": "revN"},
        "f_bad": {"version": dict(V11), "hash": "h1", "revision": "revB",
                  "prior_version": dict(V10), "prior_hash": "h0"},
        "f_cold": {"version": dict(V10), "hash": "hc", "revision": "revC"},
    },
}


def memdb():
    c = sqlite3.connect(":memory:")
    store.init_db(c)
    return c


def seed(c):
    c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
              ("f_hot", json.dumps(V10), "hh", "revA", "cached"))
    c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
              ("f_bad", json.dumps(V11), "h1", "revB", "cached"))
    c.execute("INSERT INTO cache(fragment_id,version,hash,revision,status) VALUES(?,?,?,?,?)",
              ("f_cold", json.dumps(V10), "hc", "revC", "cached"))
    c.execute("INSERT INTO pins VALUES(?,?,?)", ("pin1", "f_cold", json.dumps(V10)))
    c.execute("INSERT INTO drawer VALUES(?,?,?)", ("page1", "f_cold", "ok"))
    c.commit()
    evs = [
        ("u1", "usage", "p_new", "f_new", {"count": 3}),
        ("u2", "usage", "p_new", "f_new", {"count": 4}),
        ("u3", "usage", "p_hot", "f_hot", {"count": 2}),
        ("g1", "user_flag", "p_bad", "f_bad", {"reason": "mj: bad answer"}),
        ("g2", "user_flag", "p_bad", "f_bad", {"reason": "mj: again"}),
    ]
    for eid, event, pattern, fid, details in evs:
        store.ingest_event(c, {"event_id": eid, "at": "2026-01-10",
                               "api_id": "api1", "pattern_id": pattern,
                               "fragment_id": fid, "event": event,
                               "details": details})
    for i in range(4):
        store.ingest_event(c, {"event_id": "hn%d" % i, "at": "2026-01-10",
                               "api_id": "api1", "pattern_id": "p_new",
                               "fragment_id": "f_new", "event": "cache_lookup",
                               "details": {"eligible": True, "outcome": "hit"}})
    store.ingest_event(c, {"event_id": "hn4", "at": "2026-01-10",
                           "api_id": "api1", "pattern_id": "p_new",
                           "fragment_id": "f_new", "event": "cache_lookup",
                           "details": {"eligible": True, "outcome": "miss"}})
    store.ingest_event(c, {"event_id": "hb0", "at": "2026-01-10",
                           "api_id": "api1", "pattern_id": "p_bad",
                           "fragment_id": "f_bad", "event": "cache_lookup",
                           "details": {"eligible": True, "outcome": "hit"}})
    for i in range(1, 5):
        store.ingest_event(c, {"event_id": "hb%d" % i, "at": "2026-01-10",
                               "api_id": "api1", "pattern_id": "p_bad",
                               "fragment_id": "f_bad", "event": "cache_lookup",
                               "details": {"eligible": True, "outcome": "miss"}})
    store.ingest_event(c, {"event_id": "r1", "at": "2026-01-10",
                           "api_id": "api1", "pattern_id": "p_bad",
                           "fragment_id": "f_bad", "event": "render_result",
                           "details": {"status": "invalid", "reason": "schema"}})


def policy(**over):
    p = dict(BASE_POLICY)
    p.update(over)
    return p


class T_P4Loop(unittest.TestCase):
    def test_promote_quarantine_evict_unaided(self):
        c = memdb()
        seed(c)
        tables_before = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        # One call, no manual step between lanes: promote + quarantine + evict.
        res = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                        policy=policy(), from_ts=FROM, to_ts=TO, at=AT)
        acts = [(o["action"], o["fragment_id"], o["status"]) for o in res["outcomes"]]
        self.assertIn(("promote_cache", "f_new", "applied"), acts)
        self.assertIn(("quarantine", "f_bad", "applied"), acts)
        self.assertIn(("evict", "f_cold", "applied"), acts)
        # f_hot is healthy and already serving: no decision, still cached.
        self.assertFalse([o for o in res["outcomes"] if o["fragment_id"] == "f_hot"])
        self.assertEqual(c.execute("SELECT status FROM cache WHERE fragment_id='f_hot'").fetchone()[0],
                         "cached")
        # Promote landed; quarantine pinned the prior version (P06).
        self.assertEqual(c.execute("SELECT status FROM cache WHERE fragment_id='f_new'").fetchone()[0],
                         "cached")
        self.assertEqual(c.execute("SELECT status FROM cache WHERE fragment_id='f_bad' "
                                   "AND version=?", (json.dumps(V11),)).fetchone()[0],
                         "quarantined")
        self.assertEqual(c.execute("SELECT status FROM cache WHERE fragment_id='f_bad' "
                                   "AND version=?", (json.dumps(V10),)).fetchone()[0],
                         "cached")
        # Evict left a visible tombstone + needs_repair, never a silent drop (R01).
        self.assertEqual(c.execute("SELECT status FROM cache WHERE fragment_id='f_cold'").fetchone()[0],
                         "tombstone")
        self.assertEqual(c.execute("SELECT status FROM drawer WHERE page_id='page1'").fetchone()[0],
                         "needs_repair")
        # Every decision logged with reason + the signal values behind it.
        log = decision_log(c, "api1")
        self.assertEqual(len(log), 3)
        by_action = {d["action"]: d for d in log}
        self.assertIn("usage 7 >= policy min 5", by_action["promote_cache"]["reason"])
        self.assertEqual(by_action["promote_cache"]["parameters"]["signals"]["usage_count"], 7)
        self.assertEqual(by_action["promote_cache"]["parameters"]["policy"]["promotion_min_uses"], 5)
        self.assertIn("user_flags 2 >= policy threshold 1", by_action["quarantine"]["reason"])
        self.assertIn("hit_rate 0.200 < policy floor 0.500", by_action["quarantine"]["reason"])
        self.assertIn("pin1", by_action["evict"]["reason"])
        self.assertEqual(by_action["evict"]["parameters"]["affected_pins"], ["pin1"])
        self.assertTrue(by_action["evict"]["parameters"]["allow_orphan"])
        # One store only: the loop created no tables of its own.
        tables_after = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertEqual(tables_before, tables_after)
        # Observability: signals + audit readable in one view.
        view = status_view(c, api_id="api1", from_ts=FROM, to_ts=TO)
        self.assertIn("f_new", view["text"])
        self.assertIn("promote_cache", view["text"])
        self.assertIn("quarantine", view["text"])
        self.assertIn("evict", view["text"])

    def test_rerun_is_idempotent_duplicates(self):
        c = memdb()
        seed(c)
        first = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                          policy=policy(), from_ts=FROM, to_ts=TO, at=AT)
        self.assertEqual(len(first["outcomes"]), 3)
        second = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                           policy=policy(), from_ts=FROM, to_ts=TO, at=AT)
        # Flags attach to the fragment, so round two also quarantines the
        # pinned prior; afterwards the loop is at a fixpoint.
        new_in_second = [o for o in second["outcomes"] if not o["duplicate"]]
        self.assertEqual([(o["action"], o["fragment_id"]) for o in new_in_second],
                         [("quarantine", "f_bad")])
        cache_after_second = c.execute("SELECT * FROM cache ORDER BY fragment_id, version").fetchall()
        n_decisions = len(decision_log(c, "api1"))
        third = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                          policy=policy(), from_ts=FROM, to_ts=TO, at=AT)
        # Same window + same policy replays the same decision ids: dedup, no double mutation.
        self.assertEqual(len(decision_log(c, "api1")), n_decisions)
        self.assertTrue(all(o["duplicate"] for o in third["outcomes"]))
        self.assertEqual(c.execute("SELECT * FROM cache ORDER BY fragment_id, version").fetchall(),
                         cache_after_second)

    def test_thresholds_come_from_policy_at_runtime(self):
        # Same signals, stricter agent policy: promotion stops. No literal in code decides.
        c = memdb()
        seed(c)
        res = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                        policy=policy(promotion_min_uses=100,
                                      quarantine_flag_threshold=99,
                                      quarantine_min_hit_rate=0.0,
                                      evict_max_uses=-1),
                        from_ts=FROM, to_ts=TO, at=AT)
        self.assertFalse([o for o in res["outcomes"] if o["action"] == "promote_cache"])
        self.assertFalse([o for o in res["outcomes"] if o["action"] == "quarantine"])
        self.assertFalse([o for o in res["outcomes"] if o["action"] == "evict"])
        self.assertIsNone(c.execute("SELECT * FROM cache WHERE fragment_id='f_new'").fetchone())
        # Missing policy key disables the judgment instead of defaulting it.
        with self.assertRaises(PolicyError):
            run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                      policy={k: v for k, v in policy().items() if k != "evict_max_uses"},
                      from_ts=FROM, to_ts=TO, at=AT)

    def test_prune_same_store_preserves_signals(self):
        c = memdb()
        seed(c)
        res = run_cycle(c, api_id="api1", agent_id="ag", actor_api="api1",
                        policy=policy(prune_from=FROM, prune_to=TO),
                        from_ts=FROM, to_ts=TO, at=AT)
        self.assertEqual(res["prune"]["status"], "applied")
        # Raw events rolled into one aggregate in the SAME store; denominator intact (R02).
        s = store.read_signals(c, "api1", FROM, TO)
        self.assertEqual((s["usage_count"], s["eligible_lookups"]), (9, 10))
        self.assertFalse(s["provenance"]["complete"])
        self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM aggregates").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
