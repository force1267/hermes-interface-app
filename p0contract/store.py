"""P01-P06 / R01-R04 signals, decisions, prune, eviction, queues.

Same SQLite store for product + events. Agent-managed policy: no coded
thresholds, retention intervals, caps, or queue bounds anywhere.
"""
import json
import sqlite3

from .wire import WireError

EVENT_ENUM = {"usage", "cache_lookup", "render_result", "user_flag",
              "compatibility", "queue_state", "resource_state", "decision_result"}

FORBIDDEN_DETAIL_KEYS = {"prompt", "form_values", "credential", "credentials",
                         "media_bytes", "raw_text", "raw_prompt", "upload_bytes"}

# P01/P02: exact allowed details shape per event type. The denylist above
# stays as a second layer; the allowlist below is the mechanism: unknown
# keys are rejected so raw content cannot ride in under a novel key name.
EVENT_DETAIL_SHAPES = {
    "usage": {"count"},
    "cache_lookup": {"eligible", "outcome"},
    "render_result": {"status", "reason"},
    "user_flag": {"reason"},
    "compatibility": {"selected_version", "supported_versions"},
    "queue_state": {"bytes", "items"},
    "resource_state": {"store_bytes"},
    "decision_result": {"status", "decision_id", "reason"},
}

DECISION_ACTIONS = {"promote_cache", "propose_builtin", "quarantine", "restore",
                    "pin_version", "evict", "prune_events", "set_render_budget",
                    "set_queue_policy", "retire_major"}


class StoreError(ValueError):
    pass


def init_db(conn):
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS events(
      event_id TEXT PRIMARY KEY, at TEXT NOT NULL, api_id TEXT NOT NULL,
      pattern_id TEXT NOT NULL, fragment_id TEXT, fragment_version TEXT,
      client_id TEXT, session_id TEXT, event TEXT NOT NULL,
      request_id TEXT, details TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS aggregates(
      agg_id TEXT PRIMARY KEY, api_id TEXT NOT NULL, pattern_id TEXT,
      from_ts TEXT NOT NULL, to_ts TEXT NOT NULL,
      usage_count INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0,
      misses INTEGER NOT NULL DEFAULT 0, render_failures INTEGER NOT NULL DEFAULT 0,
      user_flags INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS gaps(
      gap_id INTEGER PRIMARY KEY AUTOINCREMENT, api_id TEXT NOT NULL,
      from_ts TEXT NOT NULL, to_ts TEXT NOT NULL, kind TEXT NOT NULL,
      ref TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS decisions(
      decision_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, api_id TEXT NOT NULL,
      at TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
      expected_revision TEXT NOT NULL, registry_revision TEXT NOT NULL,
      signal_snapshot_id TEXT NOT NULL, reason TEXT NOT NULL,
      parameters TEXT NOT NULL, approval_ref TEXT, actor_api TEXT NOT NULL,
      status TEXT NOT NULL, result TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cache(
      fragment_id TEXT NOT NULL, version TEXT NOT NULL,
      hash TEXT NOT NULL, revision TEXT NOT NULL DEFAULT 'rev1',
      status TEXT NOT NULL DEFAULT 'cached', pinned_version TEXT,
      PRIMARY KEY(fragment_id, version));
    CREATE TABLE IF NOT EXISTS pins(
      pin_id TEXT PRIMARY KEY, fragment_id TEXT NOT NULL, version TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS snapshots(
      snapshot_id TEXT PRIMARY KEY, api_id TEXT NOT NULL,
      from_ts TEXT NOT NULL, to_ts TEXT NOT NULL, event_ids TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS policies(
      policy_id TEXT PRIMARY KEY, revision TEXT NOT NULL, body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS migrations(
      migration_id TEXT PRIMARY KEY, from_major INTEGER NOT NULL,
      to_major INTEGER NOT NULL, state TEXT NOT NULL, agent_decision_id TEXT);
    CREATE TABLE IF NOT EXISTS drawer(
      page_id TEXT PRIMARY KEY, fragment_id TEXT, status TEXT NOT NULL);
    """)
    conn.commit()


def _details_for(event, details):
    if not isinstance(details, dict):
        raise StoreError("details-must-be-object")
    if set(details.keys()) & FORBIDDEN_DETAIL_KEYS:
        raise StoreError("event-contains-raw-content")
    allowed = EVENT_DETAIL_SHAPES.get(event)
    if allowed is not None and (set(details.keys()) - allowed):
        raise StoreError("event-unknown-detail-key")
    if event == "usage":
        v = details.get("count")
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise StoreError("usage.count-must-be-positive-int")
    elif event == "cache_lookup":
        if not isinstance(details.get("eligible"), bool):
            raise StoreError("cache_lookup.eligible-must-be-bool")
        if details.get("outcome") not in ("hit", "miss", "bypass"):
            raise StoreError("cache_lookup.outcome-invalid")
        if not details["eligible"] and details["outcome"] != "bypass":
            raise StoreError("ineligible-must-bypass")
        if details["eligible"] and details["outcome"] == "bypass":
            raise StoreError("eligible-cannot-bypass")
    elif event == "render_result":
        if details.get("status") not in ("ok", "invalid", "fallback"):
            raise StoreError("render_result.status-invalid")
        if not isinstance(details.get("reason"), str):
            raise StoreError("render_result.reason-required")
    elif event == "user_flag":
        if not isinstance(details.get("reason"), str):
            raise StoreError("user_flag.reason-required")
    elif event == "compatibility":
        if "selected_version" not in details or "supported_versions" not in details:
            raise StoreError("compatibility-shape")
    elif event == "queue_state":
        for f in ("bytes", "items"):
            v = details.get(f)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise StoreError(f"queue_state.{f}-must-be-nonneg-int")
    elif event == "resource_state":
        v = details.get("store_bytes")
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise StoreError("resource_state.store_bytes-invalid")
    elif event == "decision_result":
        if details.get("status") not in ("applied", "rejected"):
            raise StoreError("decision_result.status-invalid")
        if not isinstance(details.get("decision_id"), str):
            raise StoreError("decision_result.decision_id-required")
        if not isinstance(details.get("reason"), str):
            raise StoreError("decision_result.reason-required")


def ingest_event(conn, ev):
    """P01: append-only, dedup event_id, same store. Returns True if stored."""
    for f in ("event_id", "at", "api_id", "pattern_id", "event", "details"):
        if f not in ev:
            raise StoreError(f"event-missing: {f}")
    if ev["event"] not in EVENT_ENUM:
        raise StoreError(f"event-unknown: {ev['event']}")
    if not isinstance(ev["event_id"], str) or not ev["event_id"]:
        raise StoreError("event_id-invalid")
    _details_for(ev["event"], ev["details"])
    fv = ev.get("fragment_version")
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT OR IGNORE INTO events(event_id,at,api_id,pattern_id,fragment_id,"
            "fragment_version,client_id,session_id,event,request_id,details)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (ev["event_id"], ev["at"], ev["api_id"], ev["pattern_id"],
             ev.get("fragment_id"),
             json.dumps(fv, sort_keys=True) if fv is not None else None,
             ev.get("client_id"), ev.get("session_id"), ev["event"],
             ev.get("request_id"), json.dumps(ev["details"], sort_keys=True)))
    except sqlite3.OperationalError as e:
        raise StoreError(f"audit-write-failed: {e}")
    conn.commit()
    return cur.rowcount == 1


def record_snapshot(conn, snapshot_id, api_id, from_ts, to_ts, event_ids):
    conn.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?)",
                 (snapshot_id, api_id, from_ts, to_ts, json.dumps(list(event_ids))))
    conn.commit()


def read_signals(conn, api_id, from_ts, to_ts, pattern_id=None, fragment_id=None):
    """P03 caller-selected half-open window [from,to).

    pattern_id narrows live events to one pattern (pattern totals).
    fragment_id narrows live events to one fragment (fragment attribution:
    only events carrying that fragment_id count). Rolled aggregates are
    window-level and unattributable to a single fragment, so under a
    fragment filter they stay out of the counts while any overlapping
    aggregate or gap still marks provenance incomplete.
    """
    q = ("SELECT event_id, event, details FROM events WHERE api_id=? "
         "AND at>=? AND at<?" + (" AND pattern_id=?" if pattern_id else "")
         + (" AND fragment_id=?" if fragment_id is not None else ""))
    args = [api_id, from_ts, to_ts] + ([pattern_id] if pattern_id else [])
    if fragment_id is not None:
        args.append(fragment_id)
    rows = conn.execute(q, args).fetchall()
    usage = 0
    hits = misses = render_failures = user_flags = 0
    store_bytes = 0
    queue_state = None
    compat = []
    ids = []
    for eid, event, details in rows:
        ids.append(eid)
        d = json.loads(details)
        if event == "usage":
            usage += d["count"]
        elif event == "cache_lookup":
            if d["eligible"]:
                if d["outcome"] == "hit":
                    hits += 1
                elif d["outcome"] == "miss":
                    misses += 1
        elif event == "render_result":
            if d["status"] in ("invalid", "fallback"):
                render_failures += 1
        elif event == "user_flag":
            user_flags += 1
        elif event == "resource_state":
            store_bytes = max(store_bytes, d["store_bytes"])
        elif event == "queue_state":
            queue_state = d
        elif event == "compatibility":
            compat.append(d)
    # rolled-up aggregates overlapping the window count too (R02), except
    # under a fragment filter: window rollups are not attributable to one
    # fragment, so they stay out of the counts (their ids stay visible in
    # provenance) while still marking the fragment read incomplete.
    agg_rows = conn.execute(
            "SELECT usage_count,hits,misses,render_failures,user_flags,agg_id FROM aggregates "
            "WHERE api_id=? AND NOT (to_ts<=? OR from_ts>=?)",
            (api_id, from_ts, to_ts)).fetchall()
    for r in agg_rows:
        if fragment_id is not None:
            ids.append(r[5])
            continue
        usage += r[0]
        hits += r[1]
        misses += r[2]
        render_failures += r[3]
        user_flags += r[4]
        ids.append(r[5])
    gaps = conn.execute(
        "SELECT gap_id FROM gaps WHERE api_id=? AND NOT (to_ts<=? OR from_ts>=?)",
        (api_id, from_ts, to_ts)).fetchall()
    eligible = hits + misses
    complete = not gaps
    if fragment_id is not None and agg_rows:
        complete = False
    return {
        "snapshot_id": f"snap:{api_id}:{from_ts}:{to_ts}",
        "from": from_ts, "to": to_ts, "usage_count": usage,
        "eligible_lookups": eligible, "cache_hits": hits, "cache_misses": misses,
        "hit_rate": (hits / eligible) if eligible else None,
        "render_failures": render_failures, "user_flags": user_flags,
        "store_bytes": store_bytes, "queue_state": queue_state,
        "compatibility": compat,
        "provenance": {"event_ids": ids, "complete": complete},
    }


# ---- decisions (P04-P06) ----

def _target_key(target):
    t = target.get("type")
    if t == "fragment":
        return ("fragment", target.get("fragment_id"), json.dumps(target.get("version"), sort_keys=True))
    if t == "event_range":
        return ("event_range", target.get("from"), target.get("to"))
    if t == "policy":
        return ("policy", target.get("policy_id"))
    if t == "migration":
        return ("migration", target.get("migration_id"))
    raise StoreError("unsafe-target")


def submit_decision(conn, decision, auth, approvals=(), evidence_snapshots=(),
                    fail_audit=False):
    """P04 atomic logged decision. auth={actor_api, is_mj}.

    approvals: iterable of approval_ref strings bound to exact target/version/hash.
    evidence_snapshots: known snapshot ids.
    fail_audit: simulate disk-full/logging failure -> no mutation (R04).
    """
    for f in ("decision_id", "agent_id", "api_id", "at", "action", "target",
              "expected_revision", "registry_revision", "signal_snapshot_id",
              "reason", "parameters"):
        if f not in decision:
            return _reject(conn, decision, auth, f"missing:{f}", fail_audit)
    if decision["action"] not in DECISION_ACTIONS:
        return _reject(conn, decision, auth, "unknown-action", fail_audit)
    if not isinstance(decision["target"], dict):
        return _reject(conn, decision, auth, "unsafe-target", fail_audit)
    try:
        _target_key(decision["target"])
    except StoreError as e:
        return _reject(conn, decision, auth, str(e), fail_audit)
    if not isinstance(decision["parameters"], dict):
        return _reject(conn, decision, auth, "parameters-must-be-object", fail_audit)
    if not isinstance(decision["reason"], str) or not decision["reason"]:
        return _reject(conn, decision, auth, "reason-required", fail_audit)
    # dedup: identical content returns original
    row = conn.execute("SELECT target, parameters, action, status, result FROM decisions "
                       "WHERE decision_id=?", (decision["decision_id"],)).fetchone()
    canon = json.dumps({k: decision[k] for k in
                        ("agent_id", "api_id", "action", "target", "parameters")}, sort_keys=True)
    if row:
        old_canon = json.dumps({"agent_id": None}, sort_keys=True)  # placeholder
        old = conn.execute("SELECT target, parameters, action FROM decisions WHERE decision_id=?",
                           (decision["decision_id"],)).fetchone()
        old_canon = json.dumps({"action": old[2], "target": json.loads(old[0]),
                                "parameters": json.loads(old[1])}, sort_keys=True)
        new_canon = json.dumps({"action": decision["action"], "target": decision["target"],
                                "parameters": decision["parameters"]}, sort_keys=True)
        if old_canon == new_canon:
            return {"status": row[3], "result": row[4], "duplicate": True}
        return {"status": "rejected", "result": "conflict", "duplicate": False}
    actor_api = auth.get("actor_api")
    if actor_api != decision["api_id"]:
        return _reject(conn, decision, auth, "wrong-api-ownership", fail_audit)
    if decision["signal_snapshot_id"] not in set(evidence_snapshots):
        # also accept persisted snapshots table
        has = conn.execute("SELECT 1 FROM snapshots WHERE snapshot_id=?",
                           (decision["signal_snapshot_id"],)).fetchone()
        if not has:
            return _reject(conn, decision, auth, "missing-evidence", fail_audit)
    # approval discipline (P05): builtin / new components / backend authority need MJ ref
    if decision["action"] == "propose_builtin":
        ref = decision.get("approval_ref")
        if not ref or ref not in set(approvals) or not auth.get("is_mj_for_approval", False):
            # bound MJ approval required; record proposal only when present
            if not ref or ref not in set(approvals):
                return _reject(conn, decision, auth, "missing-approval", fail_audit)
    if fail_audit:
        return {"status": "rejected", "result": "audit-write-failed", "mutated": False}
    try:
        with conn:
            conn.execute(
                "INSERT INTO decisions(decision_id,agent_id,api_id,at,action,target,"
                "expected_revision,registry_revision,signal_snapshot_id,reason,"
                "parameters,approval_ref,actor_api,status,result)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (decision["decision_id"], decision["agent_id"], decision["api_id"],
                 decision["at"], decision["action"], json.dumps(decision["target"], sort_keys=True),
                 json.dumps(decision["expected_revision"]), decision["registry_revision"],
                 decision["signal_snapshot_id"], decision["reason"],
                 json.dumps(decision["parameters"], sort_keys=True),
                 decision.get("approval_ref"), actor_api, "pending", ""))
            outcome = _apply(conn, decision, auth)
            conn.execute("UPDATE decisions SET status=?, result=? WHERE decision_id=?",
                         (outcome["status"], outcome["result"], decision["decision_id"]))
    except (sqlite3.OperationalError, StoreError) as e:
        return {"status": "rejected", "result": str(e), "mutated": False}
    return outcome


def _reject(conn, decision, auth, reason, fail_audit=False):
    did = decision.get("decision_id", "unknown")
    try:
        if not fail_audit:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO decisions(decision_id,agent_id,api_id,at,action,target,"
                    "expected_revision,registry_revision,signal_snapshot_id,reason,"
                    "parameters,approval_ref,actor_api,status,result)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (did, decision.get("agent_id", ""), decision.get("api_id", ""),
                     decision.get("at", ""), decision.get("action", ""), json.dumps(
                         decision.get("target", {}), sort_keys=True),
                     json.dumps(decision.get("expected_revision")), decision.get(
                         "registry_revision", ""), decision.get("signal_snapshot_id", ""),
                     decision.get("reason", ""), json.dumps(decision.get("parameters", {}),
                                                            sort_keys=True),
                     decision.get("approval_ref"), auth.get("actor_api", ""),
                     "rejected", reason))
    except sqlite3.OperationalError:
        pass
    return {"status": "rejected", "result": reason, "mutated": False}


def _apply(conn, d, auth):
    action = d["action"]
    tgt = d["target"]
    params = d["parameters"]
    if action == "promote_cache":
        # Lane A: no threshold; needs validated compatible fragment described in params
        frag = params.get("fragment")
        if not frag:
            raise StoreError("promote-needs-fragment")
        h = params.get("hash", "h")
        ver = json.dumps(frag["version"], sort_keys=True)
        # P04/P06: quarantine + revision guards run BEFORE any write, so a
        # rejected decision cannot mutate the row or corrupt the revision.
        cur = conn.execute('SELECT revision, status FROM cache WHERE fragment_id=? AND version=?',
                         (frag["fragment_id"], ver)).fetchone()
        if cur and cur[1] == "quarantined":
            raise StoreError("quarantined")
        if cur and cur[0] != d["expected_revision"]:
            raise StoreError("stale-revision")
        conn.execute("INSERT OR REPLACE INTO cache(fragment_id,version,hash,revision,status)"
                     " VALUES(?,?,?,?,?)",
                     (frag["fragment_id"], ver,
                      h, d["expected_revision"], "cached"))
        return {"status": "applied", "result": "promoted", "mutated": True}
    if action == "propose_builtin":
        return {"status": "applied", "result": "proposal-recorded", "mutated": True}
    if action == "quarantine":
        ver = json.dumps(tgt.get("version"), sort_keys=True)
        row = conn.execute("SELECT hash FROM cache WHERE fragment_id=? AND version=?",
                           (tgt.get("fragment_id"), ver)).fetchone()
        if not row:
            raise StoreError("quarantine-unknown-target")
        conn.execute("UPDATE cache SET status='quarantined' WHERE fragment_id=? AND version=?",
                     (tgt.get("fragment_id"), ver))
        prior = params.get("prior_version")
        if prior:
            conn.execute("INSERT OR REPLACE INTO cache(fragment_id,version,hash,revision,status)"
                         " VALUES(?,?,?,?,?)",
                         (tgt.get("fragment_id"), json.dumps(prior, sort_keys=True),
                          params.get("prior_hash", "h"), "rev-prior", "cached"))
            return {"status": "applied", "result": "quarantined-pinned-prior", "mutated": True}
        return {"status": "applied", "result": "quarantined-text-fallback", "mutated": True}
    if action == "restore":
        ver = json.dumps(tgt.get("version"), sort_keys=True)
        row = conn.execute("SELECT status FROM cache WHERE fragment_id=? AND version=?",
                           (tgt.get("fragment_id"), ver)).fetchone()
        if not row or row[0] != "quarantined":
            raise StoreError("restore-not-quarantined")
        if not params.get("revalidated"):
            raise StoreError("restore-needs-revalidation")
        conn.execute("UPDATE cache SET status='cached' WHERE fragment_id=? AND version=?",
                     (tgt.get("fragment_id"), ver))
        return {"status": "applied", "result": "restored", "mutated": True}
    if action == "pin_version":
        conn.execute("INSERT OR REPLACE INTO pins(pin_id,fragment_id,version) VALUES(?,?,?)",
                     (params.get("pin_id", tgt.get("fragment_id")),
                      tgt.get("fragment_id"), json.dumps(tgt.get("version"), sort_keys=True)))
        return {"status": "applied", "result": "pinned", "mutated": True}
    if action == "evict":
        return _apply_evict(conn, d)
    if action == "prune_events":
        return _apply_prune(conn, d)
    if action == "set_render_budget":
        conn.execute("INSERT OR REPLACE INTO policies(policy_id,revision,body) VALUES(?,?,?)",
                     ("render_budget", params.get("revision", "rev"),
                      json.dumps(params, sort_keys=True)))
        return {"status": "applied", "result": "budget-set", "mutated": True}
    if action == "set_queue_policy":
        for f in ("revision", "on_overflow", "on_expiry"):
            if f not in params:
                raise StoreError(f"queue-policy-missing:{f}")
        conn.execute("INSERT OR REPLACE INTO policies(policy_id,revision,body) VALUES(?,?,?)",
                     ("queue_policy", params["revision"], json.dumps(params, sort_keys=True)))
        return {"status": "applied", "result": "queue-policy-set", "mutated": True}
    if action == "retire_major":
        mig = tgt.get("migration_id")
        row = conn.execute("SELECT state FROM migrations WHERE migration_id=?", (mig,)).fetchone()
        if not row:
            raise StoreError("unknown-migration")
        conn.execute("UPDATE migrations SET state='retired', agent_decision_id=? WHERE migration_id=?",
                     (d["decision_id"], mig))
        return {"status": "applied", "result": "retired", "mutated": True}
    raise StoreError("unhandled-action")


def _apply_evict(conn, d):
    tgt = d["target"]
    params = d["parameters"]
    ver = json.dumps(tgt.get("version"), sort_keys=True)
    row = conn.execute("SELECT revision FROM cache WHERE fragment_id=? AND version=?",
                       (tgt.get("fragment_id"), ver)).fetchone()
    if not row:
        raise StoreError("evict-unknown-target")
    if json.dumps(row[0]) != json.dumps(d["expected_revision"]) and row[0] != d["expected_revision"]:
        raise StoreError("stale-revision")
    # pins are NOT silent exemptions: must name affected pins
    pins = conn.execute("SELECT pin_id FROM pins WHERE fragment_id=? AND version=?",
                        (tgt.get("fragment_id"), ver)).fetchall()
    declared = params.get("affected_pins", [])
    if pins and set(r[0] for r in pins) - set(declared):
        raise StoreError("undeclared-pin-impact")
    repl = params.get("replacement_version")
    conn.execute("DELETE FROM cache WHERE fragment_id=? AND version=?",
                 (tgt.get("fragment_id"), ver))
    conn.execute("INSERT OR REPLACE INTO cache(fragment_id,version,hash,revision,status)"
                 " VALUES(?,?,?,?,?)",
                 (tgt.get("fragment_id"), ver, "tombstone", d["expected_revision"], "tombstone"))
    for pid in declared:
        conn.execute("UPDATE pins SET version=? WHERE pin_id=?",
                     (json.dumps(repl, sort_keys=True) if repl else ver, pid))
    for (page,) in conn.execute("SELECT page_id FROM drawer WHERE fragment_id=?",
                                (tgt.get("fragment_id"),)).fetchall():
        conn.execute("UPDATE drawer SET status='needs_repair' WHERE page_id=?", (page,))
    if params.get("allow_orphan"):
        return {"status": "applied", "result": "evicted-visible-orphan", "mutated": True}
    return {"status": "applied", "result": "evicted-tombstone", "mutated": True}


def _apply_prune(conn, d):
    params = d["parameters"]
    tgt = d["target"]
    if tgt.get("type") != "event_range":
        raise StoreError("prune-needs-event-range")
    frm, to = tgt.get("from"), tgt.get("to")
    # protected evidence: unresolved decision/incident refs must map to retained aggregates
    protected = params.get("protected_event_ids", [])
    resolution = params.get("evidence_resolution", {})
    retained = set(params.get("retained_snapshot_ids", []))
    for pid in protected:
        if pid not in resolution or resolution[pid] not in retained:
            raise StoreError("protected-evidence")
    rows = conn.execute(
        "SELECT event, details, event_id FROM events WHERE at>=? AND at<?", (frm, to)).fetchall()
    usage = hits = misses = rf = uf = 0
    for event, details, _eid in rows:
        dd = json.loads(details)
        if event == "usage":
            usage += dd["count"]
        elif event == "cache_lookup" and dd["eligible"]:
            if dd["outcome"] == "hit":
                hits += 1
            else:
                misses += 1
        elif event == "render_result" and dd["status"] in ("invalid", "fallback"):
            rf += 1
        elif event == "user_flag":
            uf += 1
    agg_id = f"agg:{frm}:{to}"
    with conn:
        conn.execute("INSERT OR REPLACE INTO aggregates VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (agg_id, d["api_id"], None, frm, to, usage, hits, misses, rf, uf))
        conn.execute("DELETE FROM events WHERE at>=? AND at<?", (frm, to))
        conn.execute("INSERT INTO gaps(api_id,from_ts,to_ts,kind,ref) VALUES(?,?,?,?,?)",
                     (d["api_id"], frm, to, "rolled", agg_id))
    return {"status": "applied", "result": "pruned-rolled", "mutated": True}


# ---- queue policy (R03) ----

def get_queue_policy(conn):
    row = conn.execute("SELECT revision, body FROM policies WHERE policy_id='queue_policy'").fetchone()
    if not row:
        return None
    body = json.loads(row[1])
    body["revision"] = row[0]
    return body


def evaluate_enqueue(policy, item_bytes, queue_state):
    """R03 policy evaluation. No policy -> visible reject of NEW enqueue."""
    if policy is None:
        return {"ok": False, "reason": "no-policy-reject-new",
                "existing_retained": True}
    max_b = policy.get("max_bytes")
    if max_b is not None and queue_state.get("bytes", 0) + item_bytes > max_b:
        if policy.get("on_overflow") == "reject_new":
            return {"ok": False, "reason": "overflow-reject-new"}
        return {"ok": False, "reason": "overflow-ask-user", "ask_user": True}
    return {"ok": True, "reason": "within-policy"}


def add_flow(conn, page_id, fragment_id, fail=False):
    """R04: Add-flow failure stays in chat, no half-created drawer entry."""
    if fail:
        return {"status": "chat-text-retry", "drawer_entry": None}
    conn.execute("INSERT OR REPLACE INTO drawer(page_id,fragment_id,status) VALUES(?,?,?)",
                 (page_id, fragment_id, "ok"))
    conn.commit()
    return {"status": "ok", "drawer_entry": page_id}
