"""ChatSurface: the P1 client chat state machine (E02/E05, V05 + composer)."""
import json

from p0contract import wire
from p0contract.messages import RevisionStore

# P1 renders text envelopes only. Fragment/action trees, rich chrome,
# sandbox and Add-flow pages are later phases (F03/F04 boundary), so any
# non-text type lands as a visible fallback bubble per E05.
RICH_TYPES = {"text"}


def composer_mode(draft):
    """Send control when text is present, voice control when empty.

    P1 wires the text/send path only; voice capture is a later phase,
    so the voice control is displayed but not actionable.
    """
    has_text = bool(draft and draft.strip())
    return {"control": "send" if has_text else "voice",
            "send_enabled": has_text,
            "voice_visible": not has_text}


class ChatSurface:
    def __init__(self, client_id, supported_caps=()):
        self.client_id = client_id
        self.supported_caps = list(supported_caps)
        self._rev = RevisionStore()
        self._seen = set()   # exact (id, revision, major) replays
        self._bubbles = []   # one logical bubble per id, first-seen order
        self._by_id = {}
        self.notices = []    # E01 protocol errors (id may be unavailable)
        self.mode = None     # "rich" | "text" | None (no session yet)
        self.reason = ""
        self.upgrade_available = False
        self.pins = []

    # -- session (V04/V05) --
    @property
    def degraded(self):
        return self.mode == "text"

    @property
    def banner(self):
        """Static degrade notice with the session reason, or None."""
        if self.degraded:
            return f"Text-only mode: {self.reason}"
        return None

    def on_session(self, body):
        """Apply a session response. Re-evaluates every time (no sticky
        flag); bubbles are never touched here, so re-upgrade is lossless."""
        body = dict(body or {})
        mode = body.get("mode")
        if mode not in ("rich", "text"):
            self.notices.append(
                {"render": "protocol-error",
                 "text": f"protocol error: bad session mode: {mode!r}",
                 "reason": "session-mode-missing", "id": None})
            mode, reason = "text", "bad-session-mode"
        else:
            reason = body.get("reason", "")
        self.mode = mode
        self.reason = reason
        self.upgrade_available = bool(body.get("upgrade_available", False))
        self.pins = list(body.get("pins", []))
        return {"mode": self.mode, "reason": self.reason,
                "banner": self.banner}

    # -- ingest (E02/E05) --
    def ingest(self, env, payload_bytes=None):
        """Fold one envelope into the bubble list. Returns the bubble (or
        a protocol-error notice). Never silently drops a logical message."""
        try:
            norm = wire.validate_envelope(env)
        except wire.WireError as e:
            notice = {"render": "protocol-error",
                      "text": f"protocol error: {e}",
                      "reason": str(e), "id": None}
            self.notices.append(notice)
            return notice
        msg_id = norm["id"]
        revision = norm["revision"]
        major = norm["version"]["major"]
        key = (msg_id, revision, major)
        if key in self._seen:
            return self._by_id[msg_id]  # duplicate-inert: no double
        verdict = self._rev.submit(msg_id, revision, major)
        if verdict == "stale":
            cur = self._by_id.get(msg_id)
            if cur is not None:
                # Bad update retains the previous good representation (E05).
                cur["warning"] = (f"stale-revision:{revision}"
                                  f"-kept-{cur['revision']}")
                return cur
            return self._store_fallback(norm, "stale-revision:%d" % revision)
        self._seen.add(key)
        if (msg_id in self._by_id
                and self._by_id[msg_id]["revision"] == revision):
            # Dual-major second representation: one logical bubble (E05).
            return self._by_id[msg_id]
        text, render, reason = self._resolve(norm, payload_bytes)
        existing = self._by_id.get(msg_id)
        if existing is not None:
            if render == "fallback" and existing.get("render") == "text" \
                    and reason in ("missing-payload", "hash-mismatch",
                                   "payload-bad-json",
                                   "payload-validation:bad-text"):
                # E05 corrupt update: keep previous good representation
                # with a warning; do not commit the bad update.
                existing["warning"] = (f"bad-update-kept-{revision}:"
                                       f"{reason}")
                return existing
            # Newer revision replaces in place; position kept, warning out.
            existing.update({"revision": revision, "major": major,
                             "text": text, "render": render,
                             "reason": reason})
            existing.pop("warning", None)
            return existing
        bubble = {"id": msg_id, "revision": revision, "major": major,
                  "text": text, "render": render, "reason": reason}
        self._bubbles.append(bubble)
        self._by_id[msg_id] = bubble
        return bubble

    def _resolve(self, norm, payload_bytes):
        """Returns (text, render, reason). render is 'text' or 'fallback'."""
        fb_text = norm["fallback"]["text"]
        if norm["type"] not in RICH_TYPES:
            return fb_text, "fallback", \
                "unsupported-type:%s" % norm["type"]
        missing = [c for c in norm["caps"] if c not in self.supported_caps]
        if missing:
            return fb_text, "fallback", \
                "unsupported-caps:%s" % ",".join(missing)
        if payload_bytes is None:
            return fb_text, "fallback", "missing-payload"
        try:
            wire.verify_payload_ref(
                {"sha256": norm["payload_ref"]["sha256"]}, payload_bytes)
        except wire.WireError:
            return fb_text, "fallback", "hash-mismatch"
        try:
            body = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return fb_text, "fallback", "payload-bad-json"
        if not isinstance(body, dict) or not isinstance(body.get("text"),
                                                       str):
            return fb_text, "fallback", "payload-validation:bad-text"
        return body["text"], "text", None

    def _store_fallback(self, norm, reason):
        bubble = {"id": norm["id"], "revision": norm["revision"],
                  "major": norm["version"]["major"],
                  "text": norm["fallback"]["text"],
                  "render": "fallback", "reason": reason}
        if norm["id"] not in self._by_id:
            self._bubbles.append(bubble)
            self._by_id[norm["id"]] = bubble
        return self._by_id[norm["id"]]

    def ingest_sent(self, msg_id, text, revision=0, major=1):
        """Record an outgoing acked message as a bubble (transport feeds
        the surface through this after send_text acks). Same dedup."""
        key = (msg_id, revision, major)
        if key in self._seen:
            return self._by_id[msg_id]
        verdict = self._rev.submit(msg_id, revision, major)
        if verdict == "stale":
            # E05: a stale outgoing revision cannot replace newer text.
            cur = self._by_id.get(msg_id)
            if cur is not None:
                cur["warning"] = (f"stale-revision:{revision}"
                                  f"-kept-{cur['revision']}")
                return cur
            bubble = {"id": msg_id, "revision": revision, "major": major,
                      "text": text, "render": "text", "reason": None,
                      "warning": f"stale-revision:{revision}-no-good"}
            self._bubbles.append(bubble)
            self._by_id[msg_id] = bubble
            return bubble
        if verdict == "duplicate-inert":
            return self._by_id[msg_id]
        self._seen.add(key)
        existing = self._by_id.get(msg_id)
        if existing is not None and existing["revision"] == revision:
            return existing  # dual-major: one bubble
        if existing is not None:
            existing.update({"revision": revision, "major": major,
                             "text": text, "render": "text", "reason": None})
            existing.pop("warning", None)
            return existing
        bubble = {"id": msg_id, "revision": revision, "major": major,
                  "text": text, "render": "text", "reason": None}
        self._bubbles.append(bubble)
        self._by_id[msg_id] = bubble
        return bubble

    def sync_from_transport(self, client):
        """Pull session + acked outgoing bubbles from a live P1 Client."""
        if getattr(client, "session", None):
            self.on_session(client.session)
        for b in getattr(client, "bubbles", []):
            self.ingest_sent(b["id"], b["text"],
                             revision=b.get("revision", 0),
                             major=b.get("major", 1))
        return self.rendered_bubbles()

    # -- views --
    def last_seen(self):
        """Resume history for the next hello/resume (V04)."""
        return [{"id": b["id"], "revision": b["revision"],
                 "fragment_id": None, "fragment_version": None}
                for b in self._bubbles]

    def rendered_bubbles(self):
        """Final display list. Degraded mode shows every bubble as static
        text (banner carries the session reason); fallback bubbles always
        carry their own static reason indicator. Re-upgrade flips styles
        back without touching bubble contents (V05)."""
        out = []
        for b in self._bubbles:
            if b["render"] == "fallback":
                style, reason = "static", b["reason"]
            elif self.degraded:
                style, reason = "static", None
            else:
                style, reason = "rich", None
            row = {"id": b["id"], "revision": b["revision"],
                   "text": b["text"], "style": style, "reason": reason}
            if "warning" in b:
                row["warning"] = b["warning"]
            out.append(row)
        return out
