"""P1 chat-surface tests, driven by a scripted transport (no sockets).

Gate scenario (T_ChatScripted): a resume carrying last_seen, an
out-of-order message, a duplicated message, a forced degrade to text,
then a re-upgrade -- the final rendered bubble list must match exactly
(no loss, no duplication). The rest pins E05 fallback indicators,
composer behavior, V05 banner/re-upgrade, and one live check that the
real P1 transport feeds the surface.
"""
import json
import unittest

from p0contract import evolution
from p1chat import ChatSurface, composer_mode
from p1transport import Client, Provider, Relay, protocol

V10 = {"major": 1, "minor": 0}
V20 = {"major": 2, "minor": 0}

RICH = {"selected_version": dict(V10), "registry_revision": "r1",
        "mode": "rich", "reason": "negotiated",
        "upgrade_available": False, "pins": []}
DEGRADED = {"selected_version": None, "registry_revision": "r1",
            "mode": "text", "reason": "incompatible-major",
            "upgrade_available": True, "pins": []}


def text_env(msg_id, text, revision=0, caps=()):
    payload = json.dumps({"text": text}, sort_keys=True).encode("utf-8")
    env = protocol.mk_text_envelope(msg_id, revision, payload, caps=caps,
                                    fallback=text[:80] or "text")
    return env, payload


class T_ChatScripted(unittest.TestCase):
    """The P1 gate: resume + out-of-order + duplicate + degrade +
    re-upgrade over a scripted transport, exact final list."""

    def test_scripted_transport_no_loss_no_double(self):
        surf = ChatSurface("dev-chat")
        surf.on_session(dict(RICH))
        env, pay = text_env("m1", "hello")
        surf.ingest(env, pay)
        env, pay = text_env("m2", "world")
        surf.ingest(env, pay)

        # resume carrying last_seen: re-negotiate from the surface history
        seen = surf.last_seen()
        self.assertEqual([(e["id"], e["revision"]) for e in seen],
                         [("m1", 0), ("m2", 0)])
        hello = {"supported_versions": [dict(V10)], "caps": [],
                 "last_seen": seen}
        sess = evolution.negotiate_session(hello, [dict(V10)], [], "r1")
        surf.on_session(sess)
        self.assertEqual(surf.mode, "rich")
        self.assertEqual(len(surf.rendered_bubbles()), 2)

        # out-of-order arrival: m4 before m3 -- neither may be lost
        env, pay = text_env("m4", "fourth")
        surf.ingest(env, pay)
        env, pay = text_env("m3", "third")
        surf.ingest(env, pay)
        # duplicated delivery of m3 -- must not double
        env, pay = text_env("m3", "third")
        surf.ingest(env, pay)
        # corrupt payload on m5: hash matches bytes, content is not a
        # text payload -- fallback with a visible reason, not a drop
        bad = b"[not-a-text-envelope"
        bad_env = protocol.mk_text_envelope(
            "m5", 0, bad, fallback="m5-fallback")
        surf.ingest(bad_env, bad)
        mid = surf.rendered_bubbles()
        self.assertEqual([b["id"] for b in mid],
                         ["m1", "m2", "m4", "m3", "m5"])
        m5 = [b for b in mid if b["id"] == "m5"][0]
        self.assertEqual(m5["style"], "static")
        self.assertTrue(m5["reason"])  # visible reason indicator

        pre_degrade = surf.rendered_bubbles()

        # forced degrade to text: static + session reason, nothing lost
        surf.on_session(dict(DEGRADED))
        self.assertTrue(surf.degraded)
        self.assertIn("incompatible-major", surf.banner or "")
        deg = surf.rendered_bubbles()
        self.assertEqual([(b["id"], b["text"]) for b in deg],
                         [(b["id"], b["text"]) for b in pre_degrade])
        self.assertTrue(all(b["style"] == "static" for b in deg))

        # re-upgrade on a compatible resume: same bubbles, no regen/dupe
        surf.on_session(dict(RICH))
        self.assertFalse(surf.degraded)
        self.assertIsNone(surf.banner)
        final = surf.rendered_bubbles()
        self.assertEqual(
            [(b["id"], b["revision"], b["text"], b["style"]) for b in final],
            [("m1", 0, "hello", "rich"),
             ("m2", 0, "world", "rich"),
             ("m4", 0, "fourth", "rich"),
             ("m3", 0, "third", "rich"),
             ("m5", 0, "m5-fallback", "static")])
        # the fallback keeps its reason indicator after the round-trip
        self.assertTrue(final[-1]["reason"])


class T_ChatFallback(unittest.TestCase):
    def test_unsupported_type_is_fallback_not_drop(self):
        surf = ChatSurface("d")
        surf.on_session(dict(RICH))
        env, pay = text_env("x1", "hello")
        env = dict(env, type="fragment")
        b = surf.ingest(env, pay)
        self.assertEqual(b["render"], "fallback")
        self.assertIn("unsupported-type", b["reason"])
        self.assertEqual(surf.rendered_bubbles()[0]["text"], "hello")

    def test_missing_payload_hash_mismatch_bad_text(self):
        surf = ChatSurface("d")
        surf.on_session(dict(RICH))
        env, pay = text_env("a", "A")
        self.assertEqual(surf.ingest(env, None)["reason"],
                         "missing-payload")
        env2, pay2 = text_env("b", "B")
        env2 = dict(env2)
        env2["payload-ref"] = dict(env2["payload-ref"], sha256="0" * 64)
        self.assertEqual(surf.ingest(env2, pay2)["reason"],
                         "hash-mismatch")
        raw = json.dumps({"nope": 1}, sort_keys=True).encode("utf-8")
        env3 = protocol.mk_text_envelope("c", 0, raw, fallback="c-fb")
        self.assertEqual(surf.ingest(env3, raw)["reason"],
                         "payload-validation:bad-text")
        rows = surf.rendered_bubbles()
        self.assertEqual(len(rows), 3)  # nothing silently dropped
        self.assertTrue(all(r["style"] == "static" and r["reason"]
                            for r in rows))

    def test_stale_revision_keeps_good_rep_with_warning(self):
        surf = ChatSurface("d")
        surf.on_session(dict(RICH))
        env, pay = text_env("k", "v1", revision=1)
        surf.ingest(env, pay)
        env0, pay0 = text_env("k", "v0-older", revision=0)
        kept = surf.ingest(env0, pay0)
        self.assertEqual(kept["text"], "v1")
        self.assertIn("stale-revision", kept["warning"])
        self.assertEqual(len(surf.rendered_bubbles()), 1)

    def test_malformed_envelope_is_protocol_notice(self):
        surf = ChatSurface("d")
        surf.on_session(dict(RICH))
        note = surf.ingest({"type": "text"}, None)
        self.assertEqual(note["render"], "protocol-error")
        self.assertEqual(surf.rendered_bubbles(), [])
        self.assertEqual(len(surf.notices), 1)

    def test_newer_revision_replaces_in_place(self):
        surf = ChatSurface("d")
        surf.on_session(dict(RICH))
        env, pay = text_env("r", "one", revision=0)
        surf.ingest(env, pay)
        env, pay = text_env("r", "two", revision=1)
        surf.ingest(env, pay)
        rows = surf.rendered_bubbles()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["text"], "two")


class T_ChatComposer(unittest.TestCase):
    def test_send_when_text_voice_when_empty(self):
        send = composer_mode("hello")
        self.assertEqual(send["control"], "send")
        self.assertTrue(send["send_enabled"])
        self.assertFalse(send["voice_visible"])
        voice = composer_mode("")
        self.assertEqual(voice["control"], "voice")
        self.assertFalse(voice["send_enabled"])
        self.assertTrue(voice["voice_visible"])
        # whitespace-only is not sendable text
        blank = composer_mode("   ")
        self.assertFalse(blank["send_enabled"])
        self.assertEqual(blank["control"], "voice")


class T_ChatDegrade(unittest.TestCase):
    def test_no_sticky_flag_across_negotiations(self):
        surf = ChatSurface("d")
        surf.on_session(dict(DEGRADED))
        self.assertTrue(surf.degraded)
        surf.on_session(dict(RICH))
        self.assertFalse(surf.degraded)
        surf.on_session(dict(DEGRADED))
        self.assertTrue(surf.degraded)
        # each session body alone decides; bubbles never touched
        env, pay = text_env("z", "zee")
        surf.ingest(env, pay)
        n = len(surf.rendered_bubbles())
        surf.on_session(dict(RICH))
        surf.on_session(dict(DEGRADED))
        self.assertEqual(len(surf.rendered_bubbles()), n)


class T_ChatLiveTransport(unittest.TestCase):
    """The real P1 transport feeds the surface: live provider + relay."""

    def test_live_client_feeds_surface(self):
        p = Provider()
        pport = p.start()
        relay = Relay("127.0.0.1", pport)
        rport = relay.start()
        try:
            c = Client("dev-live", supported_versions=[dict(V10)])
            c.connect("127.0.0.1", rport)
            c.send_text("live one", msg_id="l1")
            c.send_text("live two", msg_id="l2")
            surf = ChatSurface("dev-live")
            rows = surf.sync_from_transport(c)
            self.assertFalse(surf.degraded)
            self.assertEqual([(r["id"], r["text"]) for r in rows],
                             [("l1", "live one"), ("l2", "live two")])
            c.close()
        finally:
            relay.kill()
            p.stop()


if __name__ == "__main__":
    unittest.main()
