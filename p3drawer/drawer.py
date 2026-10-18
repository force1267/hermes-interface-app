"""P3 Add flow + drawer rules (spec R01/R04, F01 immutable identity).

Backed by the shared P0 SQLite store (same tables P0/R01/R04 tests use)
plus one P3 meta table. No fixed pin cap anywhere: the pinned section is
an unordered-by-policy subset of stored pages, and pin() never refuses
on count.

i-flow surface (all explicit, all confirmed where destructive):
  create_page / pin / unpin / rename / delete(confirm) /
  repair_offer / repair(confirm) / list_drawer / resolve_page

Identity rules:
  Page ids (pg-N) are allocated from committed DB state, never from a
  per-instance counter, so restarts and parallel Drawer instances cannot
  collide. Repair with changed bytes mints a new version (F01: changed
  bytes require a new version/identity), publishes it atomically, keeps
  the old tombstone row, and proves the result via resolve_page -- the
  authoritative page resolver over the retained page_source payload.
"""
import json
import sqlite3

from p0contract import fragments, store
from p0contract.fragments import FragmentError, fragment_identity_hash
from p2rich.renderer import check_kind


class DrawerError(ValueError):
    pass


def ensure_tables(conn):
    store.init_db(conn)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS drawer_meta("
        " page_id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " pinned INTEGER NOT NULL DEFAULT 0,"
        " created_seq INTEGER NOT NULL, fragment_version TEXT NOT NULL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS page_source("
        " page_id TEXT PRIMARY KEY, fragment TEXT NOT NULL)")
    conn.commit()


def _ver_str(version):
    return json.dumps(version, sort_keys=True)


def _chat_retry(text):
    return {"status": "chat-text-retry", "text": text,
            "retry": True, "drawer_entry": None}


class Drawer:
    """Add-flow pages + drawer ordering/pins/repair over a sqlite conn."""

    def __init__(self, conn):
        self.conn = conn
        ensure_tables(conn)

    # -- helpers --
    def _next_seq(self):
        row = self.conn.execute("SELECT MAX(created_seq) FROM drawer_meta").fetchone()
        return (row[0] or 0) + 1

    def _alloc_page_id(self):
        """Collision-safe id from committed state (restart/instance safe)."""
        best = 0
        for table, col in (("drawer", "page_id"),
                           ("page_source", "page_id")):
            try:
                rows = self.conn.execute(
                    f"SELECT {col} FROM {table}").fetchall()
            except sqlite3.Error:
                continue
            for (pid,) in rows:
                if isinstance(pid, str) and pid.startswith("pg-"):
                    try:
                        best = max(best, int(pid[3:]))
                    except ValueError:
                        continue
        return f"pg-{best + 1}"

    def _names(self):
        return {r[0] for r in self.conn.execute("SELECT name FROM drawer_meta")}

    def _unique_name(self, base):
        taken = self._names()
        if base not in taken:
            return base
        n = 2
        while f"{base} {n}" in taken:
            n += 1
        return f"{base} {n}"

    def _get(self, page_id):
        row = self.conn.execute(
            "SELECT d.page_id, d.fragment_id, d.status, m.name, m.pinned,"
            " m.created_seq, m.fragment_version"
            " FROM drawer d LEFT JOIN drawer_meta m ON m.page_id=d.page_id"
            " WHERE d.page_id=?", (page_id,)).fetchone()
        if not row:
            raise DrawerError(f"unknown-page: {page_id}")
        return {"page_id": row[0], "fragment_id": row[1], "status": row[2],
                "name": row[3], "pinned": bool(row[4]),
                "created_seq": row[5],
                "fragment_version": json.loads(row[6]) if row[6] else None}

    def _stored_fragment(self, page_id):
        """Retained page_source payload, validated. Returns (frag, error).

        error is None on success; 'pruned' when no source row exists; else
        the validation exception. A stored payload that no longer
        validates is NOT a compatible replacement.
        """
        row = self.conn.execute("SELECT fragment FROM page_source WHERE page_id=?",
                                (page_id,)).fetchone()
        if row is None:
            return None, "pruned"
        try:
            frag = json.loads(row[0])
            fragments.validate_fragment(frag)
            check_kind(frag["tree"], frag["kind"])
        except (FragmentError, KeyError, TypeError,
                AttributeError, ValueError) as e:
            return None, e
        return frag, None

    def resolve_page(self, page_id):
        """Authoritative page resolver: retained source, validated.

        A repaired page must resolve here; anything that does not resolve
        is not a published replacement.
        """
        self._get(page_id)  # unknown page still raises
        frag, err = self._stored_fragment(page_id)
        if err is not None or frag is None:
            if err == "pruned":
                text = ("No compatible replacement is available."
                        " You can delete the entry.")
            else:
                text = (f"Stored content no longer validates ({err});"
                        " no compatible replacement is available."
                        " You can delete the entry.")
            return {"status": "unavailable", "page_id": page_id,
                    "text": text, "options": ["delete"]}
        return {"status": "ok", "page_id": page_id, "fragment": frag}

    # -- Add flow (R04) --
    def create_page(self, name, tree, kind="text", fallback_text=None):
        """Validate against the P2 allowlist, then insert. On ANY
        validation failure the user stays in chat with text + retry and
        no drawer row exists (R04). Storage failures mid-write roll back
        atomically and also return chat-text-retry (usable chat)."""
        try:
            kind = kind or "text"
            probe = {"fragment_id": "pg-probe",
                     "version": {"major": 1, "minor": 0},
                     "kind": kind, "mode": "standard", "origin": "generated",
                     "fallback_text": fallback_text or f"{name or 'page'} page",
                     "tree": tree}
            fragments.validate_fragment(probe)
            check_kind(tree, kind)
        except (FragmentError, KeyError, TypeError, AttributeError) as e:
            return _chat_retry(
                f"Couldn't add that page ({e}). Nothing was added.")
        final_name = self._unique_name(name or "Untitled")
        attempts = 0
        while True:
            attempts += 1
            page_id = self._alloc_page_id()
            frag = dict(probe, fragment_id=page_id)
            try:
                with self.conn:
                    self.conn.execute(
                        "INSERT INTO drawer(page_id,fragment_id,status) VALUES(?,?,?)",
                        (page_id, frag["fragment_id"], "ok"))
                    self.conn.execute(
                        "INSERT INTO drawer_meta(page_id,name,pinned,created_seq,"
                        "fragment_version) VALUES(?,?,?,?,?)",
                        (page_id, final_name, 0, self._next_seq(),
                         _ver_str(frag["version"])))
                    self.conn.execute(
                        "INSERT INTO page_source(page_id,fragment) VALUES(?,?)",
                        (page_id, json.dumps(frag, sort_keys=True)))
            except sqlite3.IntegrityError as e:
                if "UNIQUE constraint failed" in str(e) and attempts < 10:
                    continue  # id raced; allocate afresh from committed state
                return _chat_retry(
                    f"Couldn't add that page ({e}). Nothing was added."
                    " Please retry.")
            except sqlite3.Error as e:
                return _chat_retry(
                    f"Couldn't add that page ({e}). Nothing was added."
                    " Please retry.")
            break
        return {"status": "ok", "drawer_entry": page_id,
                "name": final_name, "fragment_id": frag["fragment_id"]}

    # -- drawer listing: pinned first, then unpinned in creation order,
    #    Add affordance last --
    def list_drawer(self):
        rows = self.conn.execute(
            "SELECT d.page_id, d.fragment_id, d.status, m.name, m.pinned,"
            " m.created_seq FROM drawer d"
            " LEFT JOIN drawer_meta m ON m.page_id=d.page_id"
            " ORDER BY m.created_seq").fetchall()
        entries = [{"page_id": r[0], "fragment_id": r[1], "status": r[2],
                    "name": r[3], "pinned": bool(r[4]),
                    "needs_repair": r[2] == "needs_repair",
                    "actions": (["repair", "delete"] if r[2] == "needs_repair"
                                else ["pin" if not r[4] else "unpin",
                                      "rename", "delete"])}
                   for r in rows]
        pinned = [e for e in entries if e["pinned"]]
        unpinned = [e for e in entries if not e["pinned"]]
        return {"entries": pinned + unpinned, "add": {"affordance": "add-page"}}

    # -- i-flow ops --
    def pin(self, page_id):
        """Pin via the i-flow. No cap: never refuses on count."""
        self._get(page_id)
        with self.conn:
            self.conn.execute("UPDATE drawer_meta SET pinned=1 WHERE page_id=?",
                              (page_id,))
        return {"status": "ok", "page_id": page_id, "pinned": True}

    def unpin(self, page_id):
        self._get(page_id)
        with self.conn:
            self.conn.execute("UPDATE drawer_meta SET pinned=0 WHERE page_id=?",
                              (page_id,))
        return {"status": "ok", "page_id": page_id, "pinned": False}

    def rename(self, page_id, new_name):
        entry = self._get(page_id)
        taken = self._names() - {entry["name"]}
        final = new_name
        if final in taken:
            n = 2
            while f"{final} {n}" in taken:
                n += 1
            final = f"{final} {n}"
        with self.conn:
            self.conn.execute("UPDATE drawer_meta SET name=? WHERE page_id=?",
                              (final, page_id))
        return {"status": "ok", "page_id": page_id, "name": final}

    def delete(self, page_id, confirm=False):
        """Delete requires explicit confirm=True, else the entry is kept
        and the caller gets the confirm prompt."""
        self._get(page_id)  # unknown page still raises
        if not confirm:
            return {"status": "confirm-required", "page_id": page_id,
                    "prompt": "Delete this page? Confirm to delete.",
                    "deleted": False}
        with self.conn:
            self.conn.execute("DELETE FROM drawer WHERE page_id=?", (page_id,))
            self.conn.execute("DELETE FROM drawer_meta WHERE page_id=?",
                              (page_id,))
            self.conn.execute("DELETE FROM page_source WHERE page_id=?",
                              (page_id,))
        return {"status": "ok", "page_id": page_id, "deleted": True}

    # -- repair (R01): evicted/pruned fragments surface as needs_repair --
    def _no_replacement(self, page_id, err):
        if err == "pruned":
            text = ("The original content is gone and no compatible"
                    " replacement is available. You can delete the entry.")
        else:
            text = (f"Stored content no longer validates ({err});"
                    " no compatible replacement is available."
                    " You can delete the entry.")
        return text

    def repair_offer(self, page_id):
        entry = self._get(page_id)
        if entry["status"] != "needs_repair":
            return {"status": "ok", "page_id": page_id,
                    "repair_needed": False, "options": []}
        _frag, err = self._stored_fragment(page_id)
        if err is not None:
            # Source pruned or invalid: no compatible replacement on hand.
            # Say so, offer delete, never promise reproducibility.
            return {"status": "ok", "page_id": page_id, "repair_needed": True,
                    "replacement_available": False,
                    "text": self._no_replacement(page_id, err),
                    "options": ["delete"]}
        return {"status": "ok", "page_id": page_id, "repair_needed": True,
                "replacement_available": True,
                "text": "A compatible replacement can be regenerated."
                        " Confirm to repair, or delete the entry.",
                "options": ["repair", "delete"]}

    def repair(self, page_id, new_tree=None, confirm=False):
        """Regenerate with user confirmation. new_tree=None revalidates the
        stored source; a supplied tree must pass the allowlist + kind.

        Changed bytes mint a new version (F01): the replacement is written
        to page_source, drawer/meta/cache references move atomically, the
        old tombstone row is retained, and the result is proven by
        resolving it through resolve_page.
        """
        entry = self._get(page_id)
        if entry["status"] != "needs_repair":
            return {"status": "ok", "page_id": page_id,
                    "repaired": False, "reason": "no-repair-needed"}
        if not confirm:
            return {"status": "confirm-required", "page_id": page_id,
                    "prompt": "Repair this page with a compatible replacement?"
                              " Confirm to proceed.",
                    "repaired": False}
        stored, err = self._stored_fragment(page_id)
        if err is not None or stored is None:
            return {"status": "unavailable", "page_id": page_id,
                    "repaired": False,
                    "text": self._no_replacement(page_id, err),
                    "options": ["delete"]}
        if new_tree is not None:
            try:
                candidate = dict(stored, tree=new_tree)
                fragments.validate_fragment(candidate)
                check_kind(new_tree, stored["kind"])
            except (FragmentError, KeyError, TypeError, AttributeError) as e:
                return {"status": "rejected", "page_id": page_id,
                        "repaired": False,
                        "reason": f"replacement-invalid: {e}"}
            if _payload_equal(candidate, stored):
                frag = stored
            else:
                new_version = {"major": stored["version"]["major"],
                               "minor": stored["version"]["minor"] + 1}
                frag = dict(candidate, version=new_version)
        else:
            frag = stored
        old_ver = _ver_str(stored["version"])
        row = self.conn.execute(
            "SELECT revision FROM cache WHERE fragment_id=? AND version=?",
            (stored["fragment_id"], old_ver)).fetchone()
        revision = row[0] if row else "r1"
        new_ver = _ver_str(frag["version"])
        with self.conn:
            self.conn.execute("UPDATE drawer SET status='ok' WHERE page_id=?",
                              (page_id,))
            self.conn.execute("INSERT OR REPLACE INTO page_source(page_id,fragment)"
                              " VALUES(?,?)",
                              (page_id, json.dumps(frag, sort_keys=True)))
            self.conn.execute("UPDATE drawer_meta SET fragment_version=? WHERE page_id=?",
                              (new_ver, page_id))
            if new_ver != old_ver:
                # Publish the replacement under its new identity; the old
                # tombstone row is retained, never rewritten.
                self.conn.execute("INSERT INTO cache(fragment_id,version,hash,revision,status)"
                                  " VALUES(?,?,?,?,?)",
                                  (frag["fragment_id"], new_ver,
                                   fragment_identity_hash(frag),
                                   revision, "cached"))
            self.conn.execute("UPDATE drawer SET fragment_id=? WHERE page_id=?",
                              (frag["fragment_id"], page_id))
        resolved = self.resolve_page(page_id)
        if resolved["status"] != "ok":
            return {"status": "unavailable", "page_id": page_id,
                    "repaired": False,
                    "text": self._no_replacement(page_id, "unresolvable"),
                    "options": ["delete"]}
        return {"status": "ok", "page_id": page_id, "repaired": True} | {
            "fragment_id": frag["fragment_id"], "version": frag["version"]}


def _payload_equal(a, b):
    """Same immutable payload ignoring the version stamp."""
    keys = ("fragment_id", "kind", "mode", "origin", "tree")
    return all(a.get(k) == b.get(k) for k in keys)
