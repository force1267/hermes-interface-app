"""P1 transport + resume/re-pin tests. All live TCP; fault injection kills
a real relay socket mid-conversation. Fails if a bubble is lost or doubled.
"""
import threading
import time
import unittest

from p1transport import Client, ConnectionLost, Provider, Relay
from p1transport import protocol

V10 = {"major": 1, "minor": 0}
V12 = {"major": 1, "minor": 2}
V15 = {"major": 1, "minor": 5}
V20 = {"major": 2, "minor": 0}


def live_provider(**kw):
    p = Provider(**kw)
    port = p.start()
    return p, port


def live_chain(**kw):
    """Provider + relay in front. Returns (provider, relay, host, relay_port)."""
    p, pport = live_provider(**kw)
    r = Relay("127.0.0.1", pport)
    rport = r.start()
    return p, r, "127.0.0.1", rport


class T_P1_Handshake(unittest.TestCase):
    def test_v04_highest_common_version_live(self):
        p, r, host, port = live_chain(server_versions=[V15])
        try:
            c = Client("dev-h1", supported_versions=[V10, V12], caps=[])
            sess = c.connect(host, port)
            self.assertEqual(sess["selected_version"], V12)
            self.assertEqual(sess["mode"], "rich")
            self.assertEqual(sess["registry_revision"], "r1")
            for f in ("reason", "upgrade_available", "pins"):
                self.assertIn(f, sess)
            # new client, empty history: not a downgrade
            self.assertEqual(sess["pins"], [])
            c.close()
            # incompatible major -> null version, text only
            c2 = Client("dev-h2", supported_versions=[V20], caps=[])
            sess2 = c2.connect(host, port)
            self.assertIsNone(sess2["selected_version"])
            self.assertEqual(sess2["mode"], "text")
            c2.close()
        finally:
            r.kill()
            p.stop()

    def test_v04_missing_caps_live(self):
        p, r, host, port = live_chain(server_caps=["hi-res"])
        try:
            c = Client("dev-h3", supported_versions=[V10], caps=[])
            sess = c.connect(host, port)
            self.assertIsNone(sess["selected_version"])
            self.assertEqual(sess["mode"], "text")
            self.assertIn("missing-caps", sess["reason"])
            c.close()
        finally:
            r.kill()
            p.stop()


class T_P1_Resume(unittest.TestCase):
    def test_v05_skew_then_reupgrade_without_regen(self):
        p, r, host, port = live_chain()
        try:
            c = Client("dev-r1", supported_versions=[V10], caps=[])
            c.connect(host, port)
            c.send_text("hello one", msg_id="b1")
            regen_after_first = p.regen_count
            self.assertEqual(regen_after_first, 1)
            c.close()
            # skewed resume (v2-only): static text, no pins served usefully
            c.supported_versions = [V20]
            sess = c.connect(host, port, resume=True)
            self.assertEqual(sess["mode"], "text")
            self.assertIsNone(sess["selected_version"])
            c.close()
            # compatible resume: re-upgrades same logical bubble, no regen
            c.supported_versions = [V10]
            sess2 = c.connect(host, port, resume=True)
            self.assertEqual(sess2["mode"], "rich")
            ids = [pin["id"] for pin in sess2["pins"]]
            self.assertIn("b1", ids)
            self.assertEqual(p.regen_count, regen_after_first)
            c.close()
        finally:
            r.kill()
            p.stop()

    def test_v05_no_sticky_downgrade(self):
        p, r, host, port = live_chain(server_caps=["hi-res"])
        try:
            c = Client("dev-r2", supported_versions=[V10], caps=[])
            sess = c.connect(host, port)
            self.assertEqual(sess["mode"], "text")  # missing caps
            c.close()
            c.caps = ["hi-res"]  # next compatible resume re-upgrades
            sess2 = c.connect(host, port, resume=True)
            self.assertEqual(sess2["mode"], "rich")
            self.assertIsNotNone(sess2["selected_version"])
            c.close()
        finally:
            r.kill()
            p.stop()


class T_P1_Dedup(unittest.TestCase):
    def test_e04_replayed_action_single_effect(self):
        p, r, host, port = live_chain()
        try:
            c = Client("dev-d1", supported_versions=[V10], caps=[])
            c.connect(host, port)
            t1 = c.send_action("echo", {"text": "hi"}, msg_id="a1")
            effects = p.dispatcher.effects
            self.assertEqual(effects, 1)
            # replay the identical action bytes (same id+revision,
            # same request_id) over a fresh resume; backend dedups.
            c.close()
            c2 = Client("dev-d1", supported_versions=[V10], caps=[])
            c2.connect(host, port, resume=True)
            import json as _json
            payload = _json.dumps({"action_id": "echo",
                                   "request_id": "dev-d1:1",
                                   "context_id": "dev-d1",
                                   "values": {"text": "hi"}}, sort_keys=True)
            env = protocol.mk_action_envelope(
                "a1", 0, payload.encode("utf-8"))
            c2._send_and_ack(env, payload, bubble_text="action:echo")
            self.assertEqual(p.dispatcher.effects, effects)
            # one logical bubble for a1, not two
            ids = [b["id"] for b in c2.bubbles]
            self.assertEqual(ids.count("a1"), 1)
            c2.close()
            _ = t1
        finally:
            r.kill()
            p.stop()

    def test_e02_e05_duplicate_revision_inert(self):
        p, r, host, port = live_chain()
        try:
            c = Client("dev-d2", supported_versions=[V10], caps=[])
            c.connect(host, port)
            c.send_text("same", msg_id="m1", revision=0)
            n = len(p.acked_list())
            c.send_text("same", msg_id="m1", revision=0)  # exact replay
            self.assertEqual(len(p.acked_list()), n)  # no double
            self.assertEqual(c.bubble_ids().count(("m1", 0)), 1)
            c.close()
        finally:
            r.kill()
            p.stop()


class T_P1_Relay(unittest.TestCase):
    def test_relay_is_forward_only(self):
        import pathlib
        import socket as _socket
        src = pathlib.Path(__file__).resolve().parent.parent / "p1transport" \
            / "relay.py"
        text = src.read_text()
        # no product imports: only stdlib socket/threading
        imports = [l.strip() for l in text.splitlines()
                   if l.startswith("import ") or l.startswith("from ")]
        self.assertTrue(imports)
        for line in imports:
            self.assertNotIn("p0contract", line)
            self.assertTrue(line.split()[1].split(".")[0] in
                            ("socket", "threading"),
                            msg=line)
        r = Relay("127.0.0.1", 9)
        self.assertFalse(hasattr(r, "registry"))
        self.assertFalse(hasattr(r, "policy"))
        # behavioral: opaque bytes pass through unchanged (no parsing).
        # dumb echo server stands in for the provider.
        echo = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        echo.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        echo.bind(("127.0.0.1", 0))
        echo.listen(1)
        eport = echo.getsockname()[1]
        blob = bytes(range(256)) * 64

        def serve_once():
            conn, _ = echo.accept()
            with conn:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    conn.sendall(chunk)

        import threading as _t
        _t.Thread(target=serve_once, daemon=True).start()
        rel = Relay("127.0.0.1", eport)
        rport = rel.start()
        try:
            s = _socket.create_connection(("127.0.0.1", rport), timeout=5)
            s.settimeout(5)
            s.sendall(blob)
            got = b""
            while len(got) < len(blob):
                part = s.recv(65536)
                if not part:
                    break
                got += part
            s.close()
            self.assertEqual(got, blob)
        finally:
            rel.kill()
            echo.close()


class T_P1_FaultInjection(unittest.TestCase):
    def test_relay_kill_reconnect_no_loss_no_double(self):
        p, r, host, port = live_chain()
        c = Client("dev-f1", supported_versions=[V10], caps=[])
        try:
            c.connect(host, port)
            for i in range(3):
                c.send_text(f"pre-kill {i}", msg_id=f"pre-{i}")
            # sender thread keeps talking while the relay dies for real
            stop = threading.Event()

            def sender():
                i = 0
                while not stop.is_set():
                    try:
                        c.send_text(f"mid {i}", msg_id=f"mid-{i}")
                    except ConnectionLost:
                        time.sleep(0.02)
                        continue
                    except (OSError, ValueError):
                        time.sleep(0.02)
                        continue
                    i += 1

            t = threading.Thread(target=sender, daemon=True)
            t.start()
            time.sleep(0.3)
            r.kill()  # real socket kill mid-conversation
            stop.set()
            t.join(timeout=10)
            c.close()
            # reconnect through a fresh relay to the same provider
            r2 = Relay("127.0.0.1", p.port)
            port2 = r2.start()
            try:
                sess = c.reconnect(host, port2)
                self.assertEqual(sess["mode"], "rich")
                # drain anything still queued, then compare exactly
                client_ids = c.bubble_ids()
                server_ids = p.acked_list()
                self.assertEqual(client_ids, server_ids)
                self.assertEqual(len(client_ids), len(set(client_ids)))
                # sensitivity: the comparison must catch loss and doubling
                self.assertNotEqual(client_ids[:-1], server_ids)
                self.assertNotEqual(client_ids + [client_ids[0]],
                                    server_ids)
            finally:
                r2.kill()
            c.close()
        finally:
            p.stop()


if __name__ == "__main__":
    unittest.main()
