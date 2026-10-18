"""P4 ops loop: agent-driven promote / quarantine / evict over the P0 store.

Reads the usage/hit-rate signals the P0 policy interface already exposes
(store.read_signals), issues promote/quarantine/evict/prune decisions through
the P0 policy API (store.submit_decision), and logs each decision with its
reason and the signal values behind it.

No numeric policy lives in this module. Every threshold, retention bound and
allow_orphan flag arrives in ``policy`` at runtime (agent-supplied data);
missing keys disable that lane instead of falling back to a coded constant.
The values actually used are persisted inside each decision's parameters, so
the audit trail proves which runtime numbers produced the outcome.

Fragment attribution: each fragment's signals count only live events
carrying its own fragment_id -- pattern and window totals are never copied
across fragments. Rolled aggregates are window-level and unattributable,
so after a prune fragments without live events read as unknown (never as
known zero): absence-based lanes (evict, hit-rate collapse) stand down,
while presence-based lanes (promote on live usage, quarantine on live
flags) still act on real fragment-specific evidence.

One SQLite store only: this module creates no tables of its own and writes
only through p0contract.store into the tables store.init_db creates.
"""
import json

from p0contract import store


class PolicyError(ValueError):
    pass


# Lanes this loop drives. Anything absent from policy is skipped, never
# defaulted: a missing key means the agent expressed no judgment for it.
_REQUIRED_POLICY_KEYS = (
    "promotion_min_uses",
    "promotion_max_render_failures",
    "quarantine_flag_threshold",
    "quarantine_min_hit_rate",  # None disables the hit-rate trigger
    "evict_max_uses",
    "evict_max_hit_rate",  # None evicts on disuse alone
    "allow_orphan",  # bool, passed straight into evict parameters
    "fragments",  # {fragment_id: {version, hash, revision, ...}} agent catalog
)


def _check_policy(policy):
    if not isinstance(policy, dict):
        raise PolicyError("policy-must-be-object")
    missing = [k for k in _REQUIRED_POLICY_KEYS if k not in policy]
    if missing:
        raise PolicyError("policy-missing: %s" % ",".join(sorted(missing)))
    if not isinstance(policy["fragments"], dict):
        raise PolicyError("policy.fragments-must-be-object")
    if not isinstance(policy["allow_orphan"], bool):
        raise PolicyError("policy.allow_orphan-must-be-bool")
    return policy


def _ver_key(version):
    return json.dumps(version, sort_keys=True)


def _window_event_ids(conn, api_id, from_ts, to_ts):
    rows = conn.execute(
        "SELECT event_id FROM events WHERE api_id=? AND at>=? AND at<?",
        (api_id, from_ts, to_ts)).fetchall()
    return [r[0] for r in rows]


def _pattern_fragment_map(conn, api_id, from_ts, to_ts):
    """{pattern_id: set(fragment_id)} for events in the window."""
    rows = conn.execute(
        "SELECT DISTINCT pattern_id, fragment_id FROM events "
        "WHERE api_id=? AND at>=? AND at<? AND fragment_id IS NOT NULL",
        (api_id, from_ts, to_ts)).fetchall()
    mapping = {}
    for pattern_id, fragment_id in rows:
        mapping.setdefault(pattern_id, set()).add(fragment_id)
    return mapping


def _fragment_member_patterns(conn, api_id, from_ts, to_ts):
    """{fragment_id: sorted [pattern_id]} for window events carrying both."""
    mapping = _pattern_fragment_map(conn, api_id, from_ts, to_ts)
    out = {}
    for pattern_id, members in mapping.items():
        for fid in members:
            out.setdefault(fid, []).append(pattern_id)
    return {fid: sorted(pats) for fid, pats in out.items()}


def _fragment_versions(conn, api_id, from_ts, to_ts, fragment_id):
    """Distinct fragment_version values behind a fragment's live events.

    None means version-unattributed evidence: it counts toward the
    cataloged version under decision, and the audit says so openly.
    """
    rows = conn.execute(
        "SELECT DISTINCT fragment_version FROM events "
        "WHERE api_id=? AND at>=? AND at<? AND fragment_id=?",
        (api_id, from_ts, to_ts, fragment_id)).fetchall()
    ordered = sorted({r[0] for r in rows}, key=repr)
    return [None if raw is None else json.loads(raw) for raw in ordered]


def _has_rolled_history(conn, api_id, from_ts, to_ts):
    """True when pruned rollups or gaps overlap the window.

    Rolled counts carry no fragment attribution, so True means fragments
    without live events read as unknown -- never as known zero -- and
    absence-based lanes (evict, hit-rate collapse) stand down.
    """
    agg = conn.execute(
        "SELECT agg_id FROM aggregates "
        "WHERE api_id=? AND NOT (to_ts<=? OR from_ts>=?)",
        (api_id, from_ts, to_ts)).fetchone()
    if agg is not None:
        return True
    gap = conn.execute(
        "SELECT gap_id FROM gaps "
        "WHERE api_id=? AND NOT (to_ts<=? OR from_ts>=?)",
        (api_id, from_ts, to_ts)).fetchone()
    return gap is not None


def _fragment_signals(conn, api_id, from_ts, to_ts):
    """Per-fragment signals from fragment-filtered P0 reads.

    Each fragment's counts come only from live events carrying its own
    fragment_id: whole-pattern and whole-window totals are never copied
    across fragments, so fragments sharing one pattern keep their own
    attribution. Rolled aggregates are window-level and unattributable,
    so the P0 fragment read excludes them from the counts and reports
    provenance incomplete. ``versions`` names the distinct
    fragment_version values behind the counts (None = unattributed).
    """
    member_patterns = _fragment_member_patterns(conn, api_id, from_ts, to_ts)
    live = conn.execute(
        "SELECT DISTINCT fragment_id FROM events "
        "WHERE api_id=? AND at>=? AND at<? AND fragment_id IS NOT NULL",
        (api_id, from_ts, to_ts)).fetchall()
    frags = {}
    for (fid,) in live:
        sig = store.read_signals(
            conn, api_id, from_ts, to_ts, fragment_id=fid)
        frags[fid] = {
            "pattern_ids": member_patterns.get(fid, []),
            "versions": _fragment_versions(conn, api_id, from_ts, to_ts, fid),
            "usage_count": sig["usage_count"],
            "eligible_lookups": sig["eligible_lookups"],
            "cache_hits": sig["cache_hits"],
            "cache_misses": sig["cache_misses"],
            "hit_rate": sig["hit_rate"],
            "render_failures": sig["render_failures"],
            "user_flags": sig["user_flags"],
            "complete": sig["provenance"]["complete"],
            "store_bytes": sig["store_bytes"],
            "queue_state": sig["queue_state"]}
    return frags


def _cache_rows(conn):
    rows = conn.execute(
        "SELECT fragment_id, version, hash, revision, status FROM cache").fetchall()
    out = {}
    for fid, ver, h, rev, status in rows:
        out[(fid, ver)] = {"hash": h, "revision": rev, "status": status,
                           "version": json.loads(ver)}
    return out


def _decision_base(policy_frag, *, decision_id, agent_id, api_id, at,
                   action, fragment_id, version, expected_revision,
                   registry_revision, snapshot_id, reason, parameters):
    return {
        "decision_id": decision_id, "agent_id": agent_id, "api_id": api_id,
        "at": at, "action": action,
        "target": {"type": "fragment", "fragment_id": fragment_id,
                   "version": version},
        "expected_revision": expected_revision,
        "registry_revision": registry_revision,
        "signal_snapshot_id": snapshot_id, "reason": reason,
        "parameters": parameters, "approval_ref": None,
    }


def run_cycle(conn, *, api_id, agent_id, actor_api, policy,
              from_ts, to_ts, at, registry_revision="r1"):
    """Run one unaided ops cycle over [from_ts, to_ts).

    No human step inside: signals in, decisions out, every decision logged
    with reason + signal values. Returns {"snapshot_id", "outcomes"} where
    each outcome names the lane taken (or "keep") and the store result.
    Idempotent: rerunning the same window with the same policy replays the
    same decision ids, which the store dedups without double mutation.
    """
    _check_policy(policy)
    catalog = policy["fragments"]
    snapshot_id = "p4:%s:%s:%s" % (api_id, from_ts, to_ts)
    store.record_snapshot(conn, snapshot_id, api_id, from_ts, to_ts,
                          _window_event_ids(conn, api_id, from_ts, to_ts))
    evidence = [snapshot_id]
    auth = {"actor_api": actor_api}
    frags = _fragment_signals(conn, api_id, from_ts, to_ts)
    rolled = _has_rolled_history(conn, api_id, from_ts, to_ts)
    cache = _cache_rows(conn)
    cached_ids = {fid for (fid, _ver) in cache}
    outcomes = []

    def submit(decision):
        out = store.submit_decision(conn, decision, auth, evidence_snapshots=evidence)
        outcomes.append({"decision_id": decision["decision_id"],
                         "action": decision["action"],
                         "fragment_id": decision["target"]["fragment_id"],
                         "status": out.get("status"),
                         "result": out.get("result"),
                         "duplicate": bool(out.get("duplicate")),
                         "mutated": out.get("mutated", True)})
        return out

    # Lane 1: promote hot ephemeral fragments (Lane A, no MJ approval).
    # Presence-based: live fragment-specific usage promotes even when older
    # history was rolled (the evidence is real); unknown history with no
    # live events is not a promote case.
    for fid in sorted(set(frags) | set(catalog)):
        sig = frags.get(fid)
        if sig is None:
            if rolled:
                continue
            sig = {"pattern_ids": [], "versions": [], "usage_count": 0,
                   "eligible_lookups": 0, "cache_hits": 0,
                   "cache_misses": 0, "hit_rate": None,
                   "render_failures": 0, "user_flags": 0,
                   "complete": True, "store_bytes": 0,
                   "queue_state": None}
        spec = catalog.get(fid)
        if spec is None:
            continue  # agent named no candidate identity: no judgment, no promote
        ver = spec["version"]
        row = cache.get((fid, _ver_key(ver)))
        if row is not None and row["status"] in ("cached", "quarantined"):
            continue  # already serving or deliberately held: not a promote case
        if (sig["usage_count"] >= policy["promotion_min_uses"]
                and sig["render_failures"] <= policy["promotion_max_render_failures"]
                and sig["user_flags"] == 0):
            promotable = dict(sig, pattern_ids=list(sig["pattern_ids"]),
                              versions=list(sig["versions"]))
            reason = ("promote: usage %(u)d >= policy min %(t)d, "
                      "render_failures %(rf)d <= policy max %(m)d, "
                      "user_flags 0, patterns %(p)s" % {
                          "u": sig["usage_count"],
                          "t": policy["promotion_min_uses"],
                          "rf": sig["render_failures"],
                          "m": policy["promotion_max_render_failures"],
                          "p": ",".join(sig["pattern_ids"]) or "none"})
            submit(_decision_base(
                spec, decision_id="%s:promote:%s" % (snapshot_id, fid),
                agent_id=agent_id, api_id=api_id, at=at,
                action="promote_cache", fragment_id=fid, version=ver,
                expected_revision=(row["revision"] if row else spec.get("revision", "rev1")),
                registry_revision=registry_revision, snapshot_id=snapshot_id,
                reason=reason,
                parameters={"fragment": {"fragment_id": fid, "version": ver},
                            "hash": spec["hash"],
                            "signals": promotable,
                            "policy": {"promotion_min_uses": policy["promotion_min_uses"],
                                       "promotion_max_render_failures":
                                       policy["promotion_max_render_failures"]}}))

    # Lane 2: quarantine on MJ/user flag or hit-rate collapse. Flags are
    # presence-based (a live flag is real fragment-specific evidence);
    # hit-rate collapse is absence-sensitive, so it needs complete history.
    cache = _cache_rows(conn)  # refresh after promotions
    for fid in sorted(cached_ids & set(frags)):
        sig = frags[fid]
        for entry in [k for k in cache if k[0] == fid]:
            _fid, verkey = entry
            row = cache[entry]
            if row["status"] != "cached":
                continue
            version = row["version"]
            collapse = (sig["complete"]
                        and policy["quarantine_min_hit_rate"] is not None
                        and sig["hit_rate"] is not None
                        and sig["hit_rate"] < policy["quarantine_min_hit_rate"])
            flagged = sig["user_flags"] >= policy["quarantine_flag_threshold"]
            if not (collapse or flagged):
                continue
            why = []
            if flagged:
                why.append("user_flags %d >= policy threshold %d"
                           % (sig["user_flags"], policy["quarantine_flag_threshold"]))
            if collapse:
                why.append("hit_rate %.3f < policy floor %.3f"
                           % (sig["hit_rate"], policy["quarantine_min_hit_rate"]))
            spec = catalog.get(fid, {})
            params = {"signals": dict(sig, pattern_ids=list(sig["pattern_ids"]),
                                      versions=list(sig["versions"])),
                      "policy": {"quarantine_flag_threshold":
                                 policy["quarantine_flag_threshold"],
                                 "quarantine_min_hit_rate":
                                 policy["quarantine_min_hit_rate"]}}
            if spec.get("prior_version") is not None:
                params["prior_version"] = spec["prior_version"]
                params["prior_hash"] = spec.get("prior_hash", "h")
            submit(_decision_base(
                spec, decision_id="%s:quarantine:%s:%s" % (snapshot_id, fid, verkey),
                agent_id=agent_id, api_id=api_id, at=at,
                action="quarantine", fragment_id=fid, version=version,
                expected_revision=row["revision"],
                registry_revision=registry_revision, snapshot_id=snapshot_id,
                reason="quarantine: %s" % "; ".join(why), parameters=params))

    # Lane 3: evict cold cached fragments; R01 declared impacts only.
    # Disuse is absence-based: it needs complete history. Fragments with
    # partial history, or none with rolled history behind them, are
    # unknown -- never known zero -- so the lane stands down.
    cache = _cache_rows(conn)  # refresh after quarantines
    for (fid, verkey), row in sorted(cache.items()):
        if row["status"] != "cached":
            continue
        sig = frags.get(fid)
        if sig is None:
            if rolled:
                continue
            sig = {"pattern_ids": [], "versions": [], "usage_count": 0, "eligible_lookups": 0,
                   "cache_hits": 0, "cache_misses": 0, "hit_rate": None,
                   "render_failures": 0, "user_flags": 0, "complete": True,
                   "store_bytes": 0, "queue_state": None,
                   "note": "no-events-in-window"}
        elif not sig["complete"]:
            continue
        if sig["user_flags"] != 0:
            continue  # flagged items quarantine, never silently evict
        rate_ok = (policy["evict_max_hit_rate"] is None
                   or sig["hit_rate"] is None
                   or sig["hit_rate"] <= policy["evict_max_hit_rate"])
        if not (sig["usage_count"] <= policy["evict_max_uses"] and rate_ok):
            continue
        pins = [r[0] for r in conn.execute(
            "SELECT pin_id FROM pins WHERE fragment_id=? AND version=?",
            (fid, verkey)).fetchall()]
        spec = catalog.get(fid, {})
        rate_txt = ("any" if policy["evict_max_hit_rate"] is None
                    else "<= policy %.3f" % policy["evict_max_hit_rate"])
        params = {"affected_pins": pins,
                  "allow_orphan": policy["allow_orphan"],
                  "replacement_version": spec.get("replacement_version"),
                  "signals": dict(sig, pattern_ids=list(sig["pattern_ids"]),
                                  versions=list(sig.get("versions", []))),
                  "policy": {"evict_max_uses": policy["evict_max_uses"],
                             "evict_max_hit_rate": policy["evict_max_hit_rate"]}}
        submit(_decision_base(
            spec, decision_id="%s:evict:%s:%s" % (snapshot_id, fid, verkey),
            agent_id=agent_id, api_id=api_id, at=at,
            action="evict", fragment_id=fid, version=row["version"],
            expected_revision=row["revision"],
            registry_revision=registry_revision, snapshot_id=snapshot_id,
            reason=("evict: usage %(u)d <= policy max %(t)d, hit_rate %(h)s "
                    "%(rt)s, pins %(pins)s, allow_orphan %(ao)s" % {
                        "u": sig["usage_count"], "t": policy["evict_max_uses"],
                        "h": ("%.3f" % sig["hit_rate"]
                              if sig["hit_rate"] is not None else "null"),
                        "rt": rate_txt, "pins": pins or "none",
                        "ao": policy["allow_orphan"]}),
            parameters=params))

    # Lane 4: prune the same store under the same agent retention judgment.
    prune = None
    if "prune_from" in policy or "prune_to" in policy:
        if "prune_from" not in policy or "prune_to" not in policy:
            raise PolicyError("policy.prune needs both prune_from and prune_to")
        frm, to = policy["prune_from"], policy["prune_to"]
        prot = [r[0] for r in conn.execute(
            "SELECT event_id FROM events WHERE api_id=? AND at>=? AND at<? "
            "AND event IN ('user_flag','decision_result')",
            (api_id, frm, to)).fetchall()]
        resolution = {pid: snapshot_id for pid in prot}
        window_before = store.read_signals(conn, api_id, frm, to)
        decision = {
            "decision_id": "%s:prune" % snapshot_id, "agent_id": agent_id,
            "api_id": api_id, "at": at, "action": "prune_events",
            "target": {"type": "event_range", "from": frm, "to": to},
            "expected_revision": "r", "registry_revision": registry_revision,
            "signal_snapshot_id": snapshot_id,
            "reason": ("prune: agent retention window [%s,%s), %d raw events, "
                       "%d protected mapped to retained %s"
                       % (frm, to,
                          len(_window_event_ids(conn, api_id, frm, to)),
                          len(prot), snapshot_id)),
            "parameters": {"retained_snapshot_ids": [snapshot_id],
                           "protected_event_ids": prot,
                           "evidence_resolution": resolution,
                           "signals": {
                               "usage_count": window_before["usage_count"],
                               "eligible_lookups":
                               window_before["eligible_lookups"],
                               "cache_hits": window_before["cache_hits"],
                               "cache_misses": window_before["cache_misses"],
                               "render_failures":
                               window_before["render_failures"],
                               "user_flags": window_before["user_flags"],
                               "provenance": window_before["provenance"]},
                           "policy": {"prune_from": frm, "prune_to": to}},
            "approval_ref": None}
        out = store.submit_decision(conn, decision, auth, evidence_snapshots=evidence)
        prune = {"decision_id": decision["decision_id"],
                 "status": out.get("status"), "result": out.get("result")}
        outcomes.append(dict(prune, action="prune_events", fragment_id="",
                             duplicate=bool(out.get("duplicate")),
                             mutated=out.get("mutated", True)))
    return {"snapshot_id": snapshot_id, "outcomes": outcomes, "prune": prune}


def decision_log(conn, api_id=None):
    """Every logged decision with reason + signal values (newest last)."""
    q = ("SELECT decision_id, agent_id, api_id, at, action, target, "
         "expected_revision, registry_revision, signal_snapshot_id, reason, "
         "parameters, approval_ref, actor_api, status, result FROM decisions")
    args = []
    if api_id is not None:
        q += " WHERE api_id=?"
        args.append(api_id)
    q += " ORDER BY rowid"
    rows = conn.execute(q, args).fetchall()
    out = []
    for (did, agent, api, at, action, target, exp, reg, snap, reason,
         params, approval, actor, status, result) in rows:
        out.append({"decision_id": did, "agent_id": agent, "api_id": api,
                    "at": at, "action": action,
                    "target": json.loads(target), "expected_revision": exp,
                    "registry_revision": reg, "signal_snapshot_id": snap,
                    "reason": reason, "parameters": json.loads(params),
                    "approval_ref": approval, "actor_api": actor,
                    "status": status, "result": result})
    return out


def status_view(conn, *, api_id, from_ts, to_ts):
    """MJ-readable observability: live signals + the decision audit trail.

    Fragments without live events in a window with rolled history show
    the retained window rollup marked attribution-unknown -- with the
    incomplete flag -- instead of a bare no-events note, so retained
    activity never reads as known zero.
    """
    frags = _fragment_signals(conn, api_id, from_ts, to_ts)
    cache = _cache_rows(conn)
    rolled = _has_rolled_history(conn, api_id, from_ts, to_ts)
    window = store.read_signals(conn, api_id, from_ts, to_ts)
    rollup_unknown = {"note": "history-rolled-attribution-unknown",
                      "complete": False,
                      "window_usage_count": window["usage_count"],
                      "window_cache_hits": window["cache_hits"],
                      "window_cache_misses": window["cache_misses"],
                      "window_render_failures": window["render_failures"],
                      "window_user_flags": window["user_flags"],
                      "window_complete": window["provenance"]["complete"]}
    signals = []
    for fid in sorted(set(frags) | {f for (f, _v) in cache}):
        sig = frags.get(fid)
        states = ["%s=%s" % (v, r["status"])
                  for (f, v), r in cache.items() if f == fid]
        if sig is None and rolled:
            shown = dict(rollup_unknown)
        else:
            shown = (dict(sig, pattern_ids=list(sig["pattern_ids"]),
                          versions=list(sig["versions"]))
                     if sig else {"note": "no-events-in-window"})
        signals.append({"fragment_id": fid,
                        "signals": shown,
                        "cache": states or ["not-cached"]})
    lines = ["signals [%s,%s) api=%s" % (from_ts, to_ts, api_id)]
    if rolled:
        lines.append("  window-rollup attribution-unknown incomplete "
                     "usage=%(u)d hits=%(h)d misses=%(m)d flags=%(f)d" % {
                         "u": window["usage_count"],
                         "h": window["cache_hits"],
                         "m": window["cache_misses"],
                         "f": window["user_flags"]})
    for s in signals:
        lines.append("  %s cache=%s signals=%s"
                     % (s["fragment_id"], ",".join(s["cache"]), s["signals"]))
    lines.append("decisions:")
    for d in decision_log(conn, api_id):
        lines.append("  %s %s -> %s (%s) reason=%s" % (
            d["decision_id"], d["action"], d["status"], d["result"], d["reason"]))
    return {"signals": signals, "decisions": decision_log(conn, api_id),
            "text": "\n".join(lines)}
