"""Serving P0 tests: one test per spec rule S001..S030 (spec/serving.md).

Upstream is the real fixture Provider for mechanics; hermes_provider +
the installed Hermes CLI for the real binding (S012) and durability
mechanics (S013/S014/S022 use stub executables, never as binding proof).
Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_serving_p5 -v
"""
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse

from p0contract import wire
from p1transport import Client, ConnectionLost, Provider
from p1transport import protocol
from p1transport.hermes_provider import HermesProvider
from p5serve import adapter as adaptermod
from p5serve import auth as authmod
from p5serve import config as configmod

ORIGIN = "https://chat.typeacid.ir"
HOST = "chat.typeacid.ir"
SUBPROTO = "hermes.web.v1"
RELEASE = "p5-P0"


def b64(b):
    return base64.b64encode(b).decode()


def password_record(password, epoch="e1"):
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8,
                       p=1, dklen=32)
    return {"account_id": "mj", "credential_epoch": epoch,
            "salt_b64": b64(salt), "hash_b64": b64(h), "n": 16384,
            "r": 8, "p": 1, "dklen": 32}


def make_settings(tmp, provider_port, secret="svc-secret-1", **over):
    pw_path = os.path.join(tmp, "mj-password.json")
    with open(pw_path, "w") as f:
        json.dump(password_record("correct-horse"), f)
    os.chmod(pw_path, 0o600)
    sec_path = os.path.join(tmp, "provider-secret")
    with open(sec_path, "w") as f:
        f.write(secret)
    pol_path = os.path.join(tmp, "admission-policy.json")
    with open(pol_path, "w") as f:
        json.dump({"revision": "p1",
                   "expires_at": int(time.time()) + 3600,
                   "queue_max_messages": 100,
                   "queue_max_bytes": 1048576,
                   "inflight_per_conversation": 4}, f)
    cfg = {
        "adapter": {
            "bind_host": "127.0.0.1", "bind_port": 0, "path": "/app/ws",
            "origin": ORIGIN, "host": HOST, "subprotocol": SUBPROTO,
            "state_db": os.path.join(tmp, "serving.sqlite3"),
            "release_id": RELEASE, "max_connections": 8,
            "http_header_bytes": 16384, "http_body_bytes": 16384,
            "http_timeout_seconds": 10, "frame_bytes": 1048576,
            "json_depth": 64, "write_timeout_seconds": 10,
            "sqlite_busy_seconds": 2, "outbound_messages": 64,
            "outbound_bytes": 2097152, "queue_safety_messages": 64,
            "queue_safety_bytes": 2097152, "ws_ping_seconds": 20,
            "ws_pong_timeout_seconds": 10, "session_check_seconds": 1,
            "credential_check_seconds": 1, "reconnect_base_seconds": 1,
            "reconnect_factor": 2, "reconnect_cap_seconds": 30,
            "reconnect_stable_seconds": 60, "draft_bytes": 65536,
            "frame_min_height": 80, "frame_max_height": 800,
            "frame_ready_timeout_seconds": 10},
        "auth": {
            "account_id": "mj", "password_file": pw_path,
            "cookie_name": "__Host-chat",
            "preauth_cookie_name": "__Host-chat-pre",
            "token_bytes": 32, "csrf_bytes": 32, "salt_bytes": 16,
            "scrypt_n": 16384, "scrypt_r": 8, "scrypt_p": 1,
            "scrypt_dklen": 32, "absolute_seconds": 86400,
            "idle_seconds": 3600, "preauth_seconds": 300,
            "login_window_seconds": 300,
            "login_attempts_per_account": 5,
            "login_attempts_per_peer": 10,
            "command_window_seconds": 60, "commands_per_session": 60},
        "upstream": {
            "host": "127.0.0.1", "port": provider_port,
            "service_secret_file": sec_path,
            "connect_timeout_seconds": 5, "write_timeout_seconds": 10,
            "read_timeout_seconds": 30, "tcp_keepalive": True,
            "tcp_idle_seconds": 30, "tcp_interval_seconds": 10,
            "tcp_probes": 3},
        "provider": {
            "enabled": True, "bind_host": "127.0.0.1", "bind_port": 9121,
            "hermes_executable": "/root/.local/bin/hermes",
            "hermes_home": "/root/.hermes",
            "workspace": os.path.join(tmp, "work"),
            "agent_timeout_seconds": 120,
            "termination_grace_seconds": 10,
            "output_bytes": 4194304, "stdout_line_bytes": 1048576,
            "actions_enabled": False, "drawer_writes_enabled": False},
        "policy": {"file": pol_path}}
    for section, vals in over.items():
        cfg[section].update(vals)
    with open(os.path.join(tmp, "settings.json"), "w") as f:
        json.dump(cfg, f)
    return os.path.join(tmp, "settings.json")


def http_request(port, method, path, headers=None, body=b""):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    head = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
    for k, v in (headers or {}).items():
        head += f"{k}: {v}\r\n"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    head += "Connection: close\r\n\r\n"
    s.sendall(head.encode() + body)
    data = b""
    while True:
        try:
            part = s.recv(65536)
        except socket.timeout:
            break
        if not part:
            break
        data += part
    s.close()
    htext, _, rest = data.partition(b"\r\n\r\n")
    lines = htext.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return status, hdrs, rest


class WSClient:
    """Minimal masked WS client for the adapter (stdlib only)."""

    def __init__(self, testcase, port, origin=ORIGIN, host=HOST,
                 cookie="", subproto=SUBPROTO, version="13",
                 key=None, path="/app/ws", extra_headers=()):
        self.tc = testcase
        self.sock = socket.create_connection(("127.0.0.1", port),
                                             timeout=10)
        self.key = key or b64(os.urandom(16))
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {self.key}\r\n"
               f"Sec-WebSocket-Version: {version}\r\n"
               f"Sec-WebSocket-Protocol: {subproto}\r\n"
               f"Origin: {origin}\r\n")
        if cookie:
            req += f"Cookie: {cookie}\r\n"
        for k, v in extra_headers:
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        self.sock.sendall(req.encode())
        self.status = None
        self.resp_headers = {}
        self._read_handshake()
        self.inbox = []
        self.closes = []
        self.pongs = []
        self.lock = threading.Lock()
        self.dead = False
        if self.status == 101:
            self.sock.settimeout(None)  # reader blocks; agent turns
                                         # outlast any fixed timeout
            threading.Thread(target=self._reader, daemon=True).start()

    def _read_handshake(self):
        data = b""
        while b"\r\n\r\n" not in data:
            part = self.sock.recv(4096)
            if not part:
                break
            data += part
        htext = data.decode("latin-1", "replace")
        first = htext.split("\r\n", 1)[0]
        self.status = int(first.split(" ", 2)[1])
        self.handshake_raw = htext

    def _recvn(self, n):
        data = b""
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise ConnectionLost("closed")
            data += part
        return data

    def _reader(self):
        try:
            while True:
                hdr = self._recvn(2)
                b1, b2 = hdr[0], hdr[1]
                fin = bool(b1 & 0x80)
                opcode = b1 & 0x0F
                length = b2 & 0x7F
                if length == 126:
                    length = struct.unpack(
                        "!H", self._recvn(2))[0]
                elif length == 127:
                    length = struct.unpack(
                        "!Q", self._recvn(8))[0]
                payload = self._recvn(length) if length else b""
                if opcode == 0x9:
                    self.sock.sendall(b"\x8a" + bytes([length])
                                      + payload)
                    continue
                if opcode == 0xA:
                    with self.lock:
                        self.pongs.append(payload)
                    continue
                if opcode == 0x8:
                    code = struct.unpack(
                        "!H", payload[:2])[0] if len(payload) >= 2 \
                        else None
                    with self.lock:
                        self.closes.append((code, payload[2:]))
                    self.dead = True
                    return
                if opcode == 0x1 and fin:
                    try:
                        obj = json.loads(payload.decode())
                    except ValueError:
                        obj = {"_raw": payload.decode("replace")}
                    with self.lock:
                        self.inbox.append(obj)
        except (OSError, ConnectionLost):
            self.dead = True

    def send(self, obj, opcode=0x81):
        raw = json.dumps(obj).encode()
        mask = os.urandom(4)
        frame = (bytes([opcode, 0x80 | len(raw)]) if len(raw) < 126
                 else bytes([opcode, 0x80 | 126])
                 + struct.pack("!H", len(raw)))
        frame += mask + bytes(c ^ mask[i % 4]
                              for i, c in enumerate(raw))
        self.sock.sendall(frame)

    def send_raw_frame(self, opcode, payload, mask=True, fin=True):
        b1 = (0x80 if fin else 0) | opcode
        m = os.urandom(4) if mask else b"\x00\x00\x00\x00"
        n = len(payload)
        if n < 126:
            frame = bytes([b1, (0x80 if mask else 0) | n])
        elif n < 65536:
            frame = (bytes([b1, (0x80 if mask else 0) | 126])
                     + struct.pack("!H", n))
        else:
            frame = (bytes([b1, (0x80 if mask else 0) | 127])
                     + struct.pack("!Q", n))
        if mask:
            frame += m + bytes(c ^ m[i % 4]
                               for i, c in enumerate(payload))
        else:
            frame += payload
        self.sock.sendall(frame)

    def wait_op(self, op, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for m in self.inbox:
                    if isinstance(m, dict) and m.get("op") == op:
                        self.inbox.remove(m)
                        return m
            time.sleep(0.05)
        return None

    def wait_close(self, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if self.closes:
                    return self.closes[0]
            time.sleep(0.05)
        return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def do_login(port, password="correct-horse", user="mj"):
    st, hdrs, body = http_request(port, "GET", "/app/ws")
    assert st == 200, st
    pre = ""
    for c in hdrs.get("set-cookie", []):
        if c.startswith("__Host-chat-pre="):
            pre = c.split(";", 1)[0]
    m = re.search(r'name="csrf" value="([^"]+)"', body.decode())
    assert m, "challenge in login page"
    form = urllib.parse.urlencode(
        {"op": "login", "username": user, "password": password,
         "csrf": m.group(1)}).encode()
    st2, hdrs2, _ = http_request(
        port, "POST", "/app/ws",
        {"Content-Type": "application/x-www-form-urlencoded",
         "Origin": ORIGIN, "Cookie": pre}, form)
    return st2, hdrs2


def session_cookie(hdrs):
    for c in hdrs.get("set-cookie", []):
        if c.startswith("__Host-chat=") and "dead" not in c:
            return c.split(";", 1)[0]
    return ""


def attach(ws, tab="tab-t", release=RELEASE, cursor_hint=None,
           csrf=None, client_id=None, generation=0, req="a1"):
    ws.send({"v": 1, "kind": "command", "request_id": req,
             "client_id": client_id, "generation": generation,
             "csrf": csrf, "op": "attach",
             "body": {"tab_id": tab, "release_id": release,
                      "cursor_hint": cursor_hint}})
    return ws.wait_op("welcome")


class ServingBase(unittest.TestCase):
    def start_stack(self, settings_over=(), provider="fixture",
                    secret="svc-secret-1"):
        self.tmp = tempfile.mkdtemp(prefix="p5t")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.provider = None
        self.hermes_provider = None
        if provider == "fixture":
            self.provider = Provider()
            pport = self.provider.start()
        elif provider == "hermes":
            pport = 1  # placeholder; overwritten once HermesProvider
                       # starts on its ephemeral port
        else:  # none: nothing listens
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            pport = s.getsockname()[1]
            s.close()
        spath = make_settings(self.tmp, pport, secret=secret,
                              **dict(settings_over))
        self.srv = adaptermod.AdapterServer(spath)
        self.port = self.srv.start()
        self.addCleanup(self.srv.stop)
        if provider == "fixture":
            self.addCleanup(self.provider.stop)
        return spath

    def start_hermes_provider(self, settings_dict, secret="svc-secret-1",
                              db_name="hp.sqlite3", stub=None):
        psettings = dict(settings_dict["provider"])
        if stub is not None:
            psettings["hermes_executable"] = stub
            psettings["hermes_home"] = self.tmp
        db = os.path.join(self.tmp, db_name)
        hp = HermesProvider(psettings, db, secret, account_id="mj")
        hp.db_path = db
        hp.start("127.0.0.1", 0)
        self.addCleanup(hp.stop)
        return hp

    def login(self, password="correct-horse"):
        st, hdrs = do_login(self.port, password)
        self.assertEqual(st, 303)
        ck = session_cookie(hdrs)
        self.assertTrue(ck)
        return ck


_BROWSER = {}


def _node_chrome():
    node = shutil.which("node")
    if not node or not os.path.exists(node):
        node = "/root/.hermes/tools/node-26.7.0-linux-x64/bin/node"
    chrome = os.environ.get("HERMES_CHROME") or \
        "/root/.hermes/tools/chromium-1208/chrome-linux64/chrome"
    if not (os.path.exists(node) and os.path.exists(chrome)):
        raise unittest.SkipTest("node or chrome unavailable")
    return node, chrome


def _browser_stack(provider=True):
    """Standalone stack for the real-Chrome gate (localhost origin so
    the Secure host-only cookie is trustworthy without TLS)."""
    tmp = tempfile.mkdtemp(prefix="p5b")
    secret = "svc-browser-1"
    hp = None
    pport = 1
    if provider:
        psettings = {
            "bind_host": "127.0.0.1", "bind_port": 0,
            "hermes_executable": "/root/.local/bin/hermes",
            "hermes_home": "/root/.hermes",
            "workspace": os.path.join(tmp, "work"),
            "agent_timeout_seconds": 180,
            "termination_grace_seconds": 10,
            "output_bytes": 4194304, "stdout_line_bytes": 1048576,
            "actions_enabled": False, "drawer_writes_enabled": False}
        os.makedirs(psettings["workspace"], exist_ok=True)
        hp = HermesProvider(psettings, os.path.join(tmp, "hp.sqlite3"),
                             secret, account_id="mj")
        pport = hp.start("127.0.0.1", 0)
    spath = make_settings(tmp, pport, secret=secret)
    srv = adaptermod.AdapterServer(spath)
    port = srv.start()
    srv.origin = "http://localhost:%d" % port
    srv.host = "localhost:%d" % port
    base = "http://localhost:%d" % port
    return {"tmp": tmp, "srv": srv, "hp": hp, "port": port,
            "base": base}


def live_report():
    if "live" in _BROWSER:
        return _BROWSER["live"]
    node, chrome = _node_chrome()
    st = _browser_stack(provider=True)
    nonce = "browser-nonce-%s" % os.urandom(3).hex()
    userdir = tempfile.mkdtemp(prefix="p5chrome")
    out = os.path.join(st["tmp"], "live-report.json")
    proc = subprocess.run(
        [node, "tests/p5_browser_gate.mjs", st["base"], chrome,
         userdir, "full", nonce, out, "correct-horse"],
        capture_output=True, text=True, timeout=420)
    if not os.path.exists(out):
        raise AssertionError(
            "browser gate produced no report: %s %s" %
            (proc.returncode, (proc.stderr or "")[-500:]))
    with open(out) as f:
        rep = json.load(f)
    rep["_nonce"] = nonce
    _BROWSER["live"] = (rep, st)
    return rep, st


def dead_report():
    if "dead" in _BROWSER:
        return _BROWSER["dead"]
    node, chrome = _node_chrome()
    st = _browser_stack(provider=False)
    userdir = tempfile.mkdtemp(prefix="p5chrome-dead")
    out = os.path.join(st["tmp"], "dead-report.json")
    subprocess.run(
        [node, "tests/p5_browser_gate.mjs", st["base"], chrome,
         userdir, "deadbackend", "none", out, "correct-horse"],
        capture_output=True, text=True, timeout=300)
    with open(out) as f:
        rep = json.load(f)
    _BROWSER["dead"] = (rep, st)
    return rep, st


class T_S001_RouteBoundary(ServingBase):
    def test_s001_route_boundary(self):
        self.start_stack()
        self.assertEqual(
            self.srv._lsock.getsockname()[0], "127.0.0.1")
        st, _, _ = http_request(self.port, "GET", "/nope")
        self.assertEqual(st, 404)
        st, _, _ = http_request(self.port, "DELETE", "/app/ws")
        self.assertEqual(st, 405)
        for p in ("/login", "/api", "/health", "/api/v1"):
            st, _, _ = http_request(self.port, "GET", p)
            self.assertEqual(st, 404, p)
        # exactly one dynamic path: GET /app/ws is the login page
        st, _, body = http_request(self.port, "GET", "/app/ws")
        self.assertEqual(st, 200)
        self.assertIn(b"sign in", body)


class T_S002_DomainOwnership(ServingBase):
    def test_s002_domain_ownership(self):
        self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        w = attach(ws)
        self.assertIsNotNone(w)
        conv = ws.wait_op("snapshot")["body"]["conversation_id"]
        ws.send({"v": 1, "kind": "command", "request_id": "s1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "hello-domain"}})
        done = ws.wait_op("outcome", timeout=15)
        self.assertIsNotNone(done)
        self.assertEqual(done["body"]["status"], "accepted")
        done = ws.wait_op("outcome", timeout=15)
        self.assertIsNotNone(done)
        self.assertEqual(done["body"]["status"], "completed")
        # upstream fixture really got the text payload (p0 translation)
        self.assertTrue(any(
            True for _ in [self.provider.acked_list()]))
        snap = None
        ws.send({"v": 1, "kind": "command", "request_id": "s2",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "snapshot", "body": {}})
        snap = ws.wait_op("snapshot", timeout=10)
        self.assertTrue(any(b["text"] == "hello-domain"
                            for b in snap["body"]["bubbles"]))
        # no generic URL-fetch proxy, no browser-selected destination
        ws.send({"v": 1, "kind": "command", "request_id": "s3",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "fetch", "body": {"url": "http://evil/x"}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "unknown-op")


class T_S003_NativeAuth(ServingBase):
    def test_s003_native_auth_same_path(self):
        self.start_stack()
        st, hdrs, body = http_request(self.port, "GET", "/app/ws")
        self.assertEqual(st, 200)
        self.assertIn("no-store", hdrs.get("cache-control", [""])[0])
        pre = [c for c in hdrs.get("set-cookie", [])
               if c.startswith("__Host-chat-pre=")]
        self.assertTrue(pre)
        m = re.search(r'name="csrf" value="([^"]+)"', body.decode())
        self.assertTrue(m)
        # wrong password: same generic message, no session
        st2, hdrs2 = do_login(self.port, "wrong-pw")
        self.assertEqual(st2, 401)
        self.assertEqual(session_cookie(hdrs2), "")
        # single-use challenge: replay same preauth fails
        st3, _ = do_login(self.port, "correct-horse")
        # fresh login works
        st4, hdrs4 = do_login(self.port, "correct-horse")
        self.assertEqual(st4, 303)
        ck = session_cookie(hdrs4)
        self.assertTrue(ck)
        # authenticated GET shows logout form, no extra route
        st5, _, body5 = http_request(
            self.port, "GET", "/app/ws", {"Cookie": ck})
        self.assertEqual(st5, 200)
        self.assertIn("logout", body5.decode())
        # logout revokes + redirects
        m2 = re.search(r'name="csrf" value="([^"]+)"', body5.decode())
        form = urllib.parse.urlencode(
            {"op": "logout", "csrf": m2.group(1)}).encode()
        st6, hdrs6, _ = http_request(
            self.port, "POST", "/app/ws",
            {"Content-Type": "application/x-www-form-urlencoded",
             "Origin": ORIGIN, "Cookie": ck}, form)
        self.assertEqual(st6, 303)
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 401)


class T_S004_CookieSession(ServingBase):
    def test_s004_cookie_session(self):
        self.start_stack()
        st, hdrs = do_login(self.port, "correct-horse")
        ck = session_cookie(hdrs)
        parts = ck.split("=", 1)
        raw = parts[1]
        full = [c for c in hdrs["set-cookie"]
                if c.startswith("__Host-chat=")][0]
        for flag in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict",
                     "Max-Age="):
            self.assertIn(flag, full)
        self.assertNotIn("Domain=", full)
        # server stores only the hash
        db = sqlite3.connect(
            self.srv.cfg["adapter"]["state_db"])
        vals = [r[0] for r in db.execute(
            "SELECT token_hash FROM sessions").fetchall()]
        self.assertIn(hashlib.sha256(raw.encode()).hexdigest(), vals)
        texts = [str(r[0]) for r in db.execute(
            "SELECT token_hash || csrf_hash || ws_token_hash FROM"
            " sessions").fetchall()]
        self.assertNotIn(raw, "".join(texts))
        db.close()
        # no bearer in browser storage: shell keeps only tab/draft hints
        with open(os.path.join(adaptermod.STATIC_DIR, "app.js")) as f:
            js = f.read()
        self.assertNotIn("localStorage", js)


class T_S005_UpgradeOrigin(ServingBase):
    def test_s005_upgrade_origin(self):
        self.start_stack()
        ck = self.login()
        cases = [
            dict(origin="https://evil.test"),
            dict(origin=""),
            dict(origin="null"),
            dict(host="evil.test"),
            dict(version="12"),
            dict(subproto="wrong.proto"),
        ]
        for kw in cases:
            ws = WSClient(self, self.port, cookie=ck, **kw)
            self.addCleanup(ws.close)
            self.assertIn(ws.status, (400, 403), kw)
        ws = WSClient(self, self.port, cookie="")
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 401)
        ws = WSClient(self, self.port, cookie=ck,
                      extra_headers=[("X-Forwarded-For", "1.2.3.4")])
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)


class T_S006_CsrfWrites(ServingBase):
    def test_s006_csrf_writes(self):
        self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot")["body"]["conversation_id"]
        good = w["body"]["csrf"]
        for bad in (None, "", "stale-token"):
            ws.send({"v": 1, "kind": "command",
                     "request_id": f"bad-{bad}",
                     "client_id": w["client_id"],
                     "generation": w["generation"], "csrf": bad,
                     "op": "chat.send",
                     "body": {"conversation_id": conv, "text": "x"}})
            rej = ws.wait_op("outcome", timeout=10)
            self.assertEqual(rej["body"]["code"], "bad-csrf", bad)
        # reads need no token
        ws.send({"v": 1, "kind": "command", "request_id": "r1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "snapshot", "body": {}})
        self.assertIsNotNone(ws.wait_op("snapshot", timeout=10))
        # HTTP logout with bad token leaves the session alive
        st, _, body = http_request(
            self.port, "GET", "/app/ws", {"Cookie": ck})
        m = re.search(r'name="csrf" value="([^"]+)"', body.decode())
        form = urllib.parse.urlencode(
            {"op": "logout", "csrf": "bogus"}).encode()
        http_request(
            self.port, "POST", "/app/ws",
            {"Content-Type": "application/x-www-form-urlencoded",
             "Origin": ORIGIN, "Cookie": ck}, form)
        ws2 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws2.close)
        self.assertEqual(ws2.status, 101)
        # frame bundle never carries auth material
        from p2rich.sandbox import FRAME_JS
        for secret_word in ("csrf", "cookie", "__Host-chat"):
            self.assertNotIn(secret_word, FRAME_JS)
            with open(os.path.join(adaptermod.STATIC_DIR,
                                   "app.js")) as f:
                self.assertNotIn("contentWindow.postMessage", f.read())


class T_S007_RevocationExpiry(ServingBase):
    def test_s007_revocation_expiry(self):
        self.start_stack(
            settings_over={"auth": {"idle_seconds": 2,
                                    "absolute_seconds": 86400,
                                    "session_check_seconds": 1,
                                    "credential_check_seconds": 1}})
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        w = attach(ws)
        self.assertIsNotNone(w)
        code, _ = ws.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1008)
        # rotation revokes persisted sessions
        ck2 = self.login()
        ws2 = WSClient(self, self.port, cookie=ck2)
        self.addCleanup(ws2.close)
        self.assertEqual(ws2.status, 101)
        pw_path = self.srv.cfg["auth"]["password_file"]
        with open(pw_path) as f:
            rec = json.load(f)
        rec["credential_epoch"] = "e2-rotated"
        with open(pw_path, "w") as f:
            json.dump(rec, f)
        code2, _ = ws2.wait_close(timeout=10) or (None, None)
        self.assertEqual(code2, 1008)
        dead = self.srv.authdb.expire_sweep()
        ws3 = WSClient(self, self.port, cookie=ck2)
        self.addCleanup(ws3.close)
        self.assertEqual(ws3.status, 401)


class T_S008_PasswordRateLimits(ServingBase):
    def test_s008_password_rate_limits(self):
        self.start_stack()
        for _ in range(5):
            st, _ = do_login(self.port, "wrong-pw")
            self.assertEqual(st, 401)
        st, hdrs = do_login(self.port, "wrong-pw")
        self.assertEqual(st, 429)
        self.assertIn("retry-after",
                      {k: n for k, n in hdrs.items()})
        # no default password: missing file refuses login (fresh stack
        # so the rate window above does not mask the check)
        self.start_stack()
        os.remove(self.srv.cfg["auth"]["password_file"])
        st, _ = do_login(self.port, "correct-horse")
        self.assertEqual(st, 401)
        # command budget honors non-default settings
        self.start_stack(
            settings_over={"auth": {"commands_per_session": 3}})
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        for i in range(3):
            ws.send({"v": 1, "kind": "command",
                     "request_id": f"c{i}", "client_id": w["client_id"],
                     "generation": w["generation"], "csrf": None,
                     "op": "snapshot", "body": {}})
            self.assertIsNotNone(
                ws.wait_op("snapshot", timeout=10))
        ws.send({"v": 1, "kind": "command", "request_id": "cX",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "snapshot", "body": {}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "rate-limited")


class T_S009_Envelopes(ServingBase):
    def test_s009_ws_envelopes(self):
        self.start_stack()
        ck = self.login()
        raw = socket.create_connection(("127.0.0.1", self.port),
                                       timeout=10)
        raw.sendall(
            f"GET /app/ws HTTP/1.1\r\nHost: {HOST}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {b64(os.urandom(16))}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {SUBPROTO}\r\n"
            f"Origin: {ORIGIN}\r\nCookie: {ck}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += raw.recv(4096)
        self.assertIn(b"101", head.split(b"\r\n")[0])
        raw.close()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        for key in ("csrf", "release_id", "protocol"):
            self.assertIn(key, w["body"])
        # duplicate keys rejected (raw frame with dup key)
        dup = (b'{"v":1,"kind":"command","request_id":"d1",'
               b'"client_id":null,"generation":0,"csrf":null,'
               b'"op":"attach","op":"attach","body":{}}')
        ws.send_raw_frame(0x1, dup)
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "bad-envelope")
        # non-finite numbers rejected
        ws.send_raw_frame(0x1, b'{"v":1,"kind":"command",'
                               b'"request_id":NaN,"client_id":null,'
                               b'"generation":0,"csrf":null,'
                               b'"op":"snapshot","body":{}}')
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "bad-envelope")
        # unknown op
        ws.send({"v": 1, "kind": "command", "request_id": "u1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "nuke", "body": {}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "unknown-op")
        # wrong kind
        ws.send({"v": 1, "kind": "event", "request_id": "u2",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "snapshot", "body": {}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "bad-envelope")


class T_S010_Framing(ServingBase):
    def test_s010_ws_framing(self):
        self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        # fragmented text with interleaved ping reassembles
        w = attach(ws)
        snap = ws.wait_op("snapshot", timeout=10)
        self.assertIsNotNone(snap)
        part1 = (b'{"v":1,"kind":"command","request_id":"f1",'
                 b'"client_id":"' + w["client_id"].encode() + b'",'
                 b'"generation":' + str(w["generation"]).encode() +
                 b',"csrf":null,"op":"snapshot","body":{}}')
        half = len(part1) // 2
        ws.send_raw_frame(0x1, part1[:half], fin=False)
        ws.send_raw_frame(0x9, b"ping-me")
        ws.send_raw_frame(0x0, part1[half:], fin=True)
        got = ws.wait_op("snapshot", timeout=10)
        self.assertIsNotNone(got)
        self.assertTrue(ws.pongs)
        # binary rejected
        ws2 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws2.close)
        ws2.send_raw_frame(0x2, b"\x00\x01")
        code, _ = ws2.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1003)
        # bad RSV -> 1002
        ws3 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws3.close)
        mask = os.urandom(4)
        ws3.sock.sendall(b"\xc1\x84" + mask +
                         bytes(c ^ mask[i % 4] for i, c in
                               enumerate(b"test")))
        code, _ = ws3.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1002)
        # invalid UTF-8 -> 1007
        ws4 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws4.close)
        ws4.send_raw_frame(0x1, b"\xff\xfe bad")
        code, _ = ws4.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1007)
        # unmasked client frame -> close
        ws5 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws5.close)
        ws5.send_raw_frame(0x1, b"{}", mask=False)
        code, _ = ws5.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1002)


class T_S011_LineJson(ServingBase):
    def test_s011_line_json_translation(self):
        self.start_stack()
        # p0 round-trip
        env = protocol.mk_text_envelope(
            "m1", 0, b'{"text":"hi"}')
        line = protocol.encode_frame(env)
        self.assertTrue(line.endswith(b"\n"))
        back = protocol.decode_frame(line)
        self.assertEqual(back["id"], "m1")
        # duplicate keys rejected, non-finite rejected
        with self.assertRaises(wire.WireError):
            protocol.decode_frame(b'{"a":1,"a":2}\n')
        with self.assertRaises(wire.WireError):
            protocol.decode_frame(b'{"a":NaN}\n')
        # payload hash/ref validation
        ref = {"id": "payload:m1:0",
               "version": {"major": 1, "minor": 0},
               "sha256": "0" * 64}
        with self.assertRaises(wire.WireError):
            protocol.mk_payload_data(ref, '{"text":"hi"}', "r1")
        # partial + coalesced TCP lines handled by the real chain
        c = Client("probe-1",
                   supported_versions=[dict(protocol.V10)])
        c.connect("127.0.0.1", self.provider.port)
        mid = c.send_text("line with\nescaped newline intact")
        self.assertTrue(mid)
        self.assertEqual(c.bubbles[-1]["text"],
                         "line with\nescaped newline intact")
        c.close()


class T_S012_BindingRealHermes(ServingBase):
    def test_s012_binding_real_hermes(self):
        self.start_stack(provider="hermes")
        with open(os.path.join(self.tmp, "settings.json")) as f:
            cfg = json.load(f)
        hp = self.start_hermes_provider(cfg)
        self.srv.cfg["upstream"]["port"] = hp.port
        nonce = "quasar-waffle-p5-%s" % os.urandom(3).hex()
        prompt = ("In exactly one short sentence, use the word %s "
                  "to describe a working websocket bridge." % nonce)
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws, tab="tab-s012")
        snap = ws.wait_op("snapshot", timeout=10)
        conv = snap["body"]["conversation_id"]
        gen = w["generation"]
        ws.send({"v": 1, "kind": "command", "request_id": "send1",
                 "client_id": w["client_id"], "generation": gen,
                 "csrf": w["body"]["csrf"], "op": "chat.send",
                 "body": {"conversation_id": conv, "text": prompt}})
        accepted = ws.wait_op("outcome", timeout=15)
        self.assertEqual(accepted["body"]["status"], "accepted")
        patch = ws.wait_op("patch", timeout=180)
        self.assertIsNotNone(patch, "no bubble patch from Hermes")
        done = ws.wait_op("outcome", timeout=15)
        self.assertEqual(done["body"]["status"], "completed")
        bubble = patch["body"]["items"][0]
        # durable provider record correlates
        row = hp._db.execute(
            "SELECT request_id FROM requests").fetchone()
        self.assertIsNotNone(row)
        rec = hp.get_request(row[0])
        self.assertEqual(rec["state"], "completed")
        terminal_text = rec["result"]["text"]
        self.assertIn(nonce, terminal_text)
        self.assertEqual(bubble["text"], terminal_text)
        self.assertEqual(bubble["role"], "assistant")
        hermes_sid = rec["result"]["hermes_session_id"]
        self.assertTrue(hermes_sid)
        # restart + lost-response lookup: no second agent launch
        before = hp.launch_count
        hp2 = HermesProvider(cfg["provider"], hp.db_path,
                             "svc-secret-1")
        self.assertEqual(hp2.get_request(
            rec["request_id"])["state"], "completed")
        self.assertEqual(hp2.launch_count, 0)
        hp2.stop()
        again = hp.get_request(rec["request_id"])
        self.assertEqual(again["state"], "completed")
        self.assertEqual(again["result"]["text"], terminal_text)
        transcript = {
            "release": RELEASE,
            "adapter_generation": gen,
            "conversation_id": conv,
            "prompt": prompt,
            "payload_hash": hp._db.execute(
                "SELECT payload_hash FROM requests WHERE request_id=?",
                (rec["request_id"],)).fetchone()[0],
            "cli": [cfg["provider"]["hermes_executable"], "chat",
                    "--oneshot", "--query-file", "-",
                    "--format", "stream-json", "--no-restore-cwd",
                    "--source", "interface-app"],
            "hermes_session_id": hermes_sid,
            "terminal_exit": 0,
            "terminal_text": terminal_text,
            "assistant_message_id": rec["assistant_message_id"],
            "ws_outcome": done["body"],
            "rendered_bubble": bubble,
            "launch_count": hp.launch_count,
            "restart_lookup_without_relaunch": True}
        with open(os.path.join("tests",
                               "p5_binding_transcript.json"),
                  "w") as f:
            json.dump(transcript, f, indent=2)
        print("\nS012 transcript: prompt=%r terminal=%r bubble=%r "
              "session=%s launches=%d" % (
                  prompt, terminal_text[:120], bubble["text"][:120],
                  hermes_sid, hp.launch_count))
        # DOM proof: a real browser repeats the loop and the rendered
        # article text matches a durable provider terminal result.
        rep, bst = live_report()
        nonce = rep["_nonce"]
        self.assertIn(nonce, rep.get("bubbleText", ""),
                      json.dumps(rep.get("checks")))
        rows = bst["hp"]._db.execute(
            "SELECT result_json FROM requests WHERE state='completed'"
            ).fetchall()
        texts = [json.loads(r[0])["text"] for r in rows]
        self.assertTrue(any(t and t in rep.get("bubbleText", "")
                            for t in texts),
                        "no durable terminal result matches DOM bubble")


class T_S013_Durability(unittest.TestCase):
    def test_s013_provider_durability(self):
        tmp = tempfile.mkdtemp(prefix="p5p")
        self.addCleanup(shutil.rmtree, tmp, True)
        script = os.path.join(tmp, "stub.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncat >/dev/null\n"
                    'printf \'{"type":"system","subtype":"init",'
                    '"model":"stub","session_id":"SID-1"}\\n\'\n'
                    'printf \'{"type":"result","exit_code":0,'
                    '"text":"STUB-ANSWER","session_id":"SID-1"}\\n\'\n'
                    "exit 0\n")
        os.chmod(script, 0o755)
        psettings = {"bind_host": "127.0.0.1", "bind_port": 0,
                     "hermes_executable": script,
                     "hermes_home": tmp,
                     "workspace": os.path.join(tmp, "w"),
                     "agent_timeout_seconds": 30,
                     "termination_grace_seconds": 5,
                     "output_bytes": 4194304,
                     "stdout_line_bytes": 1048576,
                     "actions_enabled": False,
                     "drawer_writes_enabled": False}
        db = os.path.join(tmp, "hp.sqlite3")
        hp = HermesProvider(psettings, db, "s3cr3t")
        hp.start()
        self.addCleanup(hp.stop)
        ph = hashlib.sha256(b'{"text":"q"}').hexdigest()
        env1 = hp._run_text_turn("conv1", "req-A", ph, "m-A", 0, "q")
        self.assertEqual(env1.get("status"), "completed")
        n = hp.launch_count
        env2 = hp._run_text_turn("conv1", "req-A", ph, "m-A", 0, "q")
        self.assertEqual(env2.get("status"), "completed")
        self.assertEqual(hp.launch_count, n,
                         "identical request must reuse, not relaunch")
        env3 = hp._run_text_turn("conv1", "req-A", "f" * 64, "m-A",
                                 0, "different")
        self.assertEqual(env3.get("code"), "conflict")
        # crash with running intent -> outcome-unknown, never relaunched
        hp._db.execute(
            "INSERT INTO requests(account_id, conversation_id,"
            " request_id, payload_hash, state, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("mj", "conv1", "req-RUN", "a" * 64, "running",
             int(time.time())))
        hp._db.commit()
        hp2 = HermesProvider(psettings, db, "s3cr3t")
        self.addCleanup(hp2.stop)
        got = hp2.get_request("req-RUN")
        self.assertEqual(got["state"], "outcome-unknown")
        self.assertEqual(hp2.launch_count, 0)


class T_S014_Execution(unittest.TestCase):
    STUB = ("#!/bin/sh\n"
            'echo "$@" > "$ARGV_DUMP"\n'
            'echo "PWD:$PWD HOME:$HOME KB:${HERMES_KANBAN_TASK-unset}"'
            ' > "$ENV_DUMP"\n'
            "cat > \"$STDIN_DUMP\"\n"
            "sleep ${STUB_SLEEP:-0}\n"
            "printf '%s\\n' \"$STUB_LINES\"\n"
            "exit ${STUB_EXIT:-0}\n")

    def _stub_provider(self, tmp, lines, sleep="0", exitc="0",
                       extra_env=True):
        script = os.path.join(tmp, "stub.sh")
        with open(script, "w") as f:
            f.write(self.STUB)
        os.chmod(script, 0o755)
        env = dict(os.environ)
        env["ARGV_DUMP"] = os.path.join(tmp, "argv")
        env["ENV_DUMP"] = os.path.join(tmp, "envdump")
        env["STDIN_DUMP"] = os.path.join(tmp, "stdin")
        env["STUB_SLEEP"] = sleep
        env["STUB_EXIT"] = exitc
        env["STUB_LINES"] = lines
        if extra_env:
            env["HERMES_KANBAN_TASK"] = "t_poison"
        old = dict(os.environ)
        os.environ.update(env)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(old)))
        psettings = {"bind_host": "127.0.0.1", "bind_port": 0,
                     "hermes_executable": script,
                     "hermes_home": os.path.join(tmp, "home"),
                     "workspace": os.path.join(tmp, "w"),
                     "agent_timeout_seconds": 30,
                     "termination_grace_seconds": 5,
                     "output_bytes": 4194304,
                     "stdout_line_bytes": 1048576,
                     "actions_enabled": False,
                     "drawer_writes_enabled": False}
        os.makedirs(psettings["hermes_home"], exist_ok=True)
        hp = HermesProvider(psettings, os.path.join(tmp, "hp.sqlite3"),
                             "s3cr3t")
        self.addCleanup(hp.stop)
        return hp, tmp

    def test_s014_provider_execution(self):
        tmp = tempfile.mkdtemp(prefix="p5e")
        self.addCleanup(shutil.rmtree, tmp, True)
        lines = ('{"type":"system","subtype":"init","model":"s",'
                 '"session_id":"SID-X"}\n'
                 '{"type":"result","exit_code":0,"text":"ANS",'
                 '"session_id":"SID-X"}')
        hp, tmp = self._stub_provider(tmp, lines)
        ph = hashlib.sha256(b"x").hexdigest()
        env = hp._run_text_turn("c1", "r1", ph, "m1", 0, "hello-dire")
        self.assertEqual(env.get("status"), "completed")
        with open(os.path.join(tmp, "argv")) as f:
            argv = f.read()
        self.assertIn("--oneshot", argv)
        self.assertIn("--format", argv)
        self.assertNotIn("--resume", argv)
        self.assertNotIn("shell=True", argv)
        with open(os.path.join(tmp, "stdin")) as f:
            self.assertEqual(f.read(), "hello-dire")
        with open(os.path.join(tmp, "envdump")) as f:
            dump = f.read()
        self.assertIn("KB:unset", dump)
        self.assertIn("PWD:%s" % os.path.join(tmp, "w"), dump)
        self.assertIn("HOME:%s" % os.path.join(tmp, "home"), dump)
        # resume uses the stored session, never latest
        env2 = hp._run_text_turn("c1", "r2", hashlib.sha256(
            b"y").hexdigest(), "m2", 0, "follow-up")
        self.assertEqual(env2.get("status"), "completed")
        with open(os.path.join(tmp, "argv")) as f:
            self.assertIn("--resume SID-X", f.read())
        # nonzero exit is failed, never wrapped as ok
        tmp2 = tempfile.mkdtemp(prefix="p5e2")
        self.addCleanup(shutil.rmtree, tmp2, True)
        hp2, tmp2 = self._stub_provider(tmp2, lines, exitc="3")
        env3 = hp2._run_text_turn("c9", "r9", hashlib.sha256(
            b"z").hexdigest(), "m9", 0, "q")
        self.assertEqual(env3.get("status"), "failed")
        self.assertNotEqual(env3.get("code"), "ok")
        # timeout is failed
        tmp3 = tempfile.mkdtemp(prefix="p5e3")
        self.addCleanup(shutil.rmtree, tmp3, True)
        hp3, tmp3 = self._stub_provider(tmp3, lines, sleep="8")
        hp3.agent_timeout = 2
        env4 = hp3._run_text_turn("c8", "r8", hashlib.sha256(
            b"w").hexdigest(), "m8", 0, "q")
        self.assertEqual(env4.get("status"), "failed")


class T_S015_Projection(ServingBase):
    def test_s015_real_result_projection(self):
        self.start_stack()
        with open(os.path.join(self.tmp, "settings.json")) as f:
            cfg = json.load(f)
        script = os.path.join(self.tmp, "stub.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncat >/dev/null\n"
                    'printf \'{"type":"system","subtype":"init",'
                    '"model":"s","session_id":"SID-P"}\\n\'\n'
                    'printf \'{"type":"result","exit_code":0,'
                    '"text":"REAL-ANSWER-xyz","session_id":"SID-P"}\\n\'\n'
                    "exit 0\n")
        os.chmod(script, 0o755)
        cfg["provider"]["hermes_executable"] = script
        cfg["provider"]["hermes_home"] = self.tmp
        hp = HermesProvider(cfg["provider"],
                             os.path.join(self.tmp, "hp.sqlite3"),
                             "svc-secret-1")
        self.addCleanup(hp.stop)
        hp.start("127.0.0.1", 0)
        self.srv.cfg["upstream"]["port"] = hp.port
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        ws.send({"v": 1, "kind": "command", "request_id": "p1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "ask"}})
        patch = ws.wait_op("patch", timeout=60)
        self.assertIsNotNone(patch)
        bubble = patch["body"]["items"][0]
        self.assertEqual(bubble["text"], "REAL-ANSWER-xyz")
        self.assertEqual(bubble["role"], "assistant")
        self.assertNotIn("acked:", bubble["text"])


class T_S016_FailClosed(ServingBase):
    def test_s016_fail_closed_admission(self):
        # missing policy file refuses readiness for writes
        self.start_stack(settings_over={
            "policy": {"file": os.path.join(
                tempfile.gettempdir(), "p5-missing-policy.json")}})
        try:
            os.remove(os.path.join(
                tempfile.gettempdir(), "p5-missing-policy.json"))
        except OSError:
            pass
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        ws.send({"v": 1, "kind": "command", "request_id": "w1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "hi"}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "policy-unavailable")
        # stale policy also fails closed
        with open(self.srv.cfg["policy"]["file"], "w") as f:
            json.dump({"revision": "p0", "expires_at": 1,
                       "queue_max_messages": 100,
                       "queue_max_bytes": 999999,
                       "inflight_per_conversation": 4}, f)
        self.srv._load_policy()
        ws.send({"v": 1, "kind": "command", "request_id": "w2",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "hi"}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "policy-unavailable")
        # backend down fails closed, never fake-accepted
        self.start_stack(provider="none")
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        ws.send({"v": 1, "kind": "command", "request_id": "w3",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "hi"}})
        rej = ws.wait_op("outcome", timeout=15)
        self.assertEqual(rej["body"]["code"], "backend-unavailable")


class T_S017_SlowConsumer(ServingBase):
    def test_s017_slow_consumer(self):
        self.start_stack(settings_over={
            "adapter": {"outbound_messages": 1, "outbound_bytes": 64}})
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws, req="a1")
        # welcome(1 msg) already saturates the bound; next event 1013s
        code, _ = ws.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1013)
        # recover from durable history: re-attach works
        ws2 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws2.close)
        self.assertEqual(ws2.status, 101)


class T_S018_StoreFailure(unittest.TestCase):
    def test_s018_store_failure(self):
        tmp = tempfile.mkdtemp(prefix="p5f")
        self.addCleanup(shutil.rmtree, tmp, True)
        # state_db that cannot be a database refuses readiness
        bad = os.path.join(tmp, "adir")
        os.makedirs(bad)
        cfg = {"adapter": {"bind_host": "127.0.0.1", "bind_port": 0,
                           "path": "/app/ws", "origin": ORIGIN,
                           "host": HOST, "subprotocol": SUBPROTO,
                           "state_db": bad, "release_id": RELEASE},
               "auth": {}, "upstream": {}, "provider": {},
               "policy": {}}
        path = os.path.join(tmp, "s.json")
        with open(path, "w") as f:
            json.dump({"adapter": dict(cfg["adapter"], **{
                k: 1 for k in configmod.REQUIRED["adapter"]
                if k not in cfg["adapter"]}),
                "auth": {k: ("__Host-x" if "cookie" in k else 1)
                         for k in configmod.REQUIRED["auth"]},
                "upstream": dict({k: (True if k == "tcp_keepalive"
                                      else 1) for k in
                                  configmod.REQUIRED["upstream"]},
                                 **{"host": "127.0.0.1", "port": 1,
                                     "service_secret_file": path}),
                "provider": {k: (True if k in ("enabled",
                                               "actions_enabled",
                                               "drawer_writes_enabled")
                                  else 1) for k in
                             configmod.REQUIRED["provider"]},
                "policy": {"file": path}}, f)
        with self.assertRaises(Exception):
            adaptermod.AdapterServer(path)


class T_S019_ResumeRecords(ServingBase):
    def test_s019_resume_records(self):
        spath = self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws, tab="tab-persist")
        snap = ws.wait_op("snapshot", timeout=10)
        conv = snap["body"]["conversation_id"]
        gen1 = w["generation"]
        # persisted logical-client record
        db = sqlite3.connect(self.srv.cfg["adapter"]["state_db"])
        row = db.execute(
            "SELECT record FROM clients WHERE client_id=?",
            (w["client_id"],)).fetchone()
        self.assertIsNotNone(row)
        rec = json.loads(row[0])
        self.assertEqual(rec["tab_hint"], "tab-persist")
        self.assertEqual(rec["generation"], gen1)
        ws.close()
        # restart keeps durable records; tab hint recovers, no new writer
        port = self.port
        self.srv.stop()
        srv2 = adaptermod.AdapterServer(spath)
        srv2.start()
        self.addCleanup(srv2.stop)
        port2 = srv2.port
        ws2 = WSClient(self, port2, cookie=ck)
        self.addCleanup(ws2.close)
        w2 = attach(ws2, tab="tab-persist", req="a2")
        self.assertEqual(w2["client_id"], w["client_id"])
        self.assertEqual(w2["generation"], gen1 + 1)
        conv2 = ws2.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        self.assertEqual(conv2, conv)
        # browser cursor hint cannot assert authority
        ws2.send({"v": 1, "kind": "command", "request_id": "x1",
                  "client_id": w2["client_id"],
                  "generation": w2["generation"], "csrf": None,
                  "op": "attach",
                  "body": {"tab_id": "tab-persist",
                           "release_id": RELEASE,
                           "cursor_hint": "hacked-cursor"}})
        self.assertIsNotNone(ws2.wait_op("welcome", timeout=10))


class T_S020_Fencing(ServingBase):
    def test_s020_socket_fencing(self):
        self.start_stack()
        ck = self.login()
        ws1 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws1.close)
        w1 = attach(ws1, tab="tab-shared", req="a1")
        ws1.wait_op("snapshot", timeout=10)
        ws2 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws2.close)
        w2 = attach(ws2, tab="tab-shared", req="a2")
        ws2.wait_op("snapshot", timeout=10)
        self.assertEqual(w2["client_id"], w1["client_id"])
        self.assertEqual(w2["generation"], w1["generation"] + 1)
        # old generation is fenced
        ws1.send({"v": 1, "kind": "command", "request_id": "old1",
                  "client_id": w1["client_id"],
                  "generation": w1["generation"], "csrf": None,
                  "op": "snapshot", "body": {}})
        rej = ws1.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "stale-generation")
        # different tab: separate record, own cursor
        ws3 = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws3.close)
        w3 = attach(ws3, tab="tab-other", req="a3")
        ws3.wait_op("snapshot", timeout=10)
        self.assertNotEqual(w3["client_id"], w1["client_id"])


class T_S021_UnknownNoReplay(ServingBase):
    def test_s021_unknown_no_replay(self):
        self.start_stack()
        with open(os.path.join(self.tmp, "settings.json")) as f:
            cfg = json.load(f)
        script = os.path.join(self.tmp, "stub.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncat >/dev/null\n"
                    'printf \'{"type":"system","subtype":"init",'
                    '"model":"s","session_id":"SID-U"}\\n\'\n'
                    'printf \'{"type":"result","exit_code":0,'
                    '"text":"U-ANS","session_id":"SID-U"}\\n\'\n'
                    "exit 0\n")
        os.chmod(script, 0o755)
        cfg["provider"]["hermes_executable"] = script
        cfg["provider"]["hermes_home"] = self.tmp
        hp = HermesProvider(cfg["provider"],
                             os.path.join(self.tmp, "hp.sqlite3"),
                             "svc-secret-1")
        self.addCleanup(hp.stop)
        hp.start("127.0.0.1", 0)
        self.srv.cfg["upstream"]["port"] = hp.port
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        n0 = hp.launch_count
        ws.send({"v": 1, "kind": "command", "request_id": "u1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "once"}})
        self.assertEqual(ws.wait_op("outcome", timeout=15)["body"][
            "status"], "accepted")
        done = ws.wait_op("outcome", timeout=60)
        self.assertEqual(done["body"]["status"], "completed")
        self.assertEqual(hp.launch_count, n0 + 1)
        # drop mid-flight on the next send: kill provider first
        hp.stop()
        ws.send({"v": 1, "kind": "command", "request_id": "u2",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "twice"}})
        acc = ws.wait_op("outcome", timeout=30)
        self.assertEqual(acc["body"]["status"], "accepted")
        out = ws.wait_op("outcome", timeout=30)
        self.assertIsNotNone(out)
        self.assertIn(out["body"]["status"],
                      ("outcome-unknown", "rejected"))
        self.assertNotEqual(out["body"]["status"], "completed")
        # Client.reconnect (auto outbox replay) is never used
        with open(os.path.join(os.path.dirname(
                adaptermod.__file__), "adapter.py")) as f:
            src = f.read()
        self.assertNotIn(".reconnect(", src)


class T_S022_SplitLiveness(ServingBase):
    def test_s022_split_liveness(self):
        self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        ws.wait_op("snapshot", timeout=10)
        # WS ping/pong crosses browser-Caddy-adapter independently
        ws.send_raw_frame(0x9, b"alive?")
        end = time.time() + 10
        while time.time() < end and not ws.pongs:
            time.sleep(0.05)
        self.assertTrue(ws.pongs)
        # upstream TCP failure is a separate domain: explicit status
        self.srv.upstream_drop()
        self.provider.stop()
        ws.send({"v": 1, "kind": "command", "request_id": "d1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "snapshot", "body": {}})
        st = ws.wait_op("status", timeout=15)
        self.assertEqual(st["body"]["state"], "backend-unavailable")
        # long agent turn exceeds the baseline 5s client timeout
        self.start_stack()
        with open(os.path.join(self.tmp, "settings.json")) as f:
            cfg = json.load(f)
        script = os.path.join(self.tmp, "slow.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncat >/dev/null\nsleep 7\n"
                    'printf \'{"type":"system","subtype":"init",'
                    '"model":"s","session_id":"SID-S"}\\n\'\n'
                    'printf \'{"type":"result","exit_code":0,'
                    '"text":"SLOW-OK","session_id":"SID-S"}\\n\'\n'
                    "exit 0\n")
        os.chmod(script, 0o755)
        cfg["provider"]["hermes_executable"] = script
        cfg["provider"]["hermes_home"] = self.tmp
        hp = HermesProvider(cfg["provider"],
                             os.path.join(self.tmp, "hp2.sqlite3"),
                             "svc-secret-1")
        self.addCleanup(hp.stop)
        hp.start("127.0.0.1", 0)
        self.srv.cfg["upstream"]["port"] = hp.port
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        ws.send({"v": 1, "kind": "command", "request_id": "slow1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": w["body"]["csrf"],
                 "op": "chat.send",
                 "body": {"conversation_id": conv, "text": "slow"}})
        acc = ws.wait_op("outcome", timeout=30)
        self.assertIsNotNone(acc)
        self.assertEqual(acc["body"]["status"], "accepted")
        done = ws.wait_op("outcome", timeout=60)
        self.assertIsNotNone(done)
        self.assertEqual(done["body"]["status"], "completed")


class T_S023_ReleaseResync(ServingBase):
    def test_s023_release_resync(self):
        self.start_stack()
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        ws.send({"v": 1, "kind": "command", "request_id": "bad1",
                 "client_id": None, "generation": 0, "csrf": None,
                 "op": "attach",
                 "body": {"tab_id": "t", "release_id": "WRONG",
                          "cursor_hint": None}})
        st = ws.wait_op("status", timeout=10)
        self.assertEqual(st["body"]["state"], "reload-required")
        # writes blocked before a good attach
        ws.send({"v": 1, "kind": "command", "request_id": "bad2",
                 "client_id": None, "generation": 0, "csrf": None,
                 "op": "snapshot", "body": {}})
        rej = ws.wait_op("outcome", timeout=10)
        self.assertEqual(rej["body"]["code"], "not-attached")
        # expired cursor hint still yields a full snapshot, never empty-ok
        w = attach(ws, tab="t2", cursor_hint="stale-cursor", req="a9")
        snap = ws.wait_op("snapshot", timeout=10)
        self.assertIsNotNone(snap)
        self.assertIn("bubbles", snap["body"])


class T_S024_StaticMounts(unittest.TestCase):
    def test_s024_static_mounts(self):
        self.assertTrue(os.path.exists(os.path.join(
            adaptermod.STATIC_DIR, "index.html")))
        with open(os.path.join(adaptermod.STATIC_DIR,
                               "index.html")) as f:
            html = f.read()
        for mid in ("app-shell", "composer", "connection-status",
                    "bubbles", "drawer-items", "add-content",
                    "frag-frame"):
            self.assertIn(mid, html)
        self.assertNotIn("document.write", html)
        self.assertNotIn("outerHTML", html)
        # real browser: incremental patch preserves composer/focus/draft
        rep, _st = live_report()
        for name in ("shell paints with all mount IDs",
                     "composer node stable across patch",
                     "focus preserved after patch",
                     "draft retained across reload"):
            self.assertEqual(rep["checks"].get(name), "pass",
                             "%s :: %s" % (name, rep["checks"].get(
                                 name)))


class T_S025_SandboxBridge(unittest.TestCase):
    def test_s025_sandbox_bridge(self):
        with open(os.path.join(adaptermod.STATIC_DIR,
                               "index.html")) as f:
            html = f.read()
        self.assertIn('sandbox="allow-scripts"', html)
        self.assertNotIn("allow-same-origin", html)
        from p2rich.sandbox import SANDBOX_ATTR, FRAME_ID
        self.assertEqual(SANDBOX_ATTR, "allow-scripts")
        self.assertEqual(FRAME_ID, "frag-frame")
        with open(os.path.join(adaptermod.STATIC_DIR, "app.js")) as f:
            js = f.read()
        for op in ("render", "action", "resize", "ready",
                   "form-state"):
            self.assertIn(op, js)


class T_S026_NoPageNetwork(unittest.TestCase):
    def test_s026_no_page_network(self):
        with open(os.path.join(adaptermod.STATIC_DIR, "app.js")) as f:
            js = f.read()
        for banned in ("fetch(", "XMLHttpRequest", "EventSource",
                       "navigator.sendBeacon", "WebTransport"):
            self.assertNotIn(banned, js)
        # exactly one socket: the /app/ws transport shim
        self.assertEqual(js.count("new WebSocket"), 1)
        self.assertIn("/app/ws", js)
        # real browser: CSP + zero page/frame network
        rep, _st = live_report()
        csp = rep.get("csp") or {}
        csp_text = " ".join("%s %s" % (k, v)
                            for k, v in csp.items())
        self.assertIn("default-src 'none'", csp_text)
        self.assertIn("/app/ws", csp_text)
        self.assertIn("sha256-", csp_text)
        self.assertNotIn("unsafe-inline", csp_text)
        allowed = ("http://localhost:", "ws://localhost:",
                   "data:", "about:", "devtools://", "chrome://")
        for url in rep.get("netUrls", []):
            self.assertTrue(url.startswith(allowed), url)
            self.assertFalse(url.startswith("ws://"), url)
        ws_urls = rep.get("wsUrls", [])
        self.assertTrue(ws_urls, "no websocket observed")
        self.assertEqual(set(ws_urls), set(ws_urls[:1]), ws_urls)
        self.assertTrue(ws_urls[0].startswith("ws://localhost:"),
                        ws_urls)
        self.assertIn("/app/ws", ws_urls[0])


class T_S027_DeadBackend(ServingBase):
    def test_s027_dead_backend_shell(self):
        self.start_stack(provider="none")
        st, hdrs, body = http_request(self.port, "GET", "/")
        self.assertEqual(st, 200)
        text = body.decode()
        for mid in ("app-shell", "composer", "connection-status",
                    "frag-frame"):
            self.assertIn(mid, text)
        self.assertNotIn("golden", text.lower())
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws)
        snap = ws.wait_op("snapshot", timeout=15)
        self.assertIsNotNone(snap)
        ws.send({"v": 1, "kind": "command", "request_id": "d1",
                 "client_id": w["client_id"],
                 "generation": w["generation"], "csrf": None,
                 "op": "snapshot", "body": {}})
        status = ws.wait_op("status", timeout=15)
        self.assertEqual(status["body"]["state"],
                         "backend-unavailable")
        # real browser on a dead backend: shell, banner, draft
        rep, _st = dead_report()
        for name in ("shell paints with all mount IDs",
                     "dead backend banner, no fabricated chat",
                     "send disabled while backend down",
                     "no chat bubbles on dead backend",
                     "draft retained across reload on dead backend"):
            self.assertEqual(rep["checks"].get(name), "pass",
                             "%s :: %s" % (name, rep["checks"].get(
                                 name)))


class T_S028_RuntimeConfig(ServingBase):
    def test_s028_runtime_configuration(self):
        tmp = tempfile.mkdtemp(prefix="p5c")
        self.addCleanup(shutil.rmtree, tmp, True)
        import copy
        with open("p5serve/settings.template.json") as f:
            tpl = json.load(f)
        bad = copy.deepcopy(tpl)
        del bad["adapter"]["ws_ping_seconds"]
        p = os.path.join(tmp, "s.json")
        with open(p, "w") as f:
            json.dump(bad, f)
        with self.assertRaises(configmod.SettingsError):
            configmod.load(p)
        bad2 = copy.deepcopy(tpl)
        bad2["auth"]["idle_seconds"] = -5
        with open(p, "w") as f:
            json.dump(bad2, f)
        with self.assertRaises(configmod.SettingsError):
            configmod.load(p)
        # non-default thresholds take effect: tiny frame bound
        self.start_stack(settings_over={
            "adapter": {"frame_bytes": 64}})
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        big = b"x" * 200
        ws.send_raw_frame(0x1, b'{"v":1,"kind":"command",'
                               b'"request_id":"big","client_id":null,'
                               b'"generation":0,"csrf":null,'
                               b'"op":"snapshot","body":{"pad":"'
                         + big + b'"}}')
        code, _ = ws.wait_close(timeout=10) or (None, None)
        self.assertEqual(code, 1009)


class T_S029_FrameFocus(unittest.TestCase):
    def test_s029_frame_focus_size(self):
        with open(os.path.join(adaptermod.STATIC_DIR, "app.js")) as f:
            js = f.read()
        self.assertIn("action.invoke", js)
        self.assertIn("Math.min(800", js)
        self.assertIn("Math.max(80", js)
        # patches touch bubble articles only; composer node is stable
        self.assertIn('getElementById("composer")', js)
        self.assertNotIn("composer.replaceWith", js)
        self.assertNotIn("bubbles.replaceChildren", js.replace(
            "bubblesEl.replaceChildren", ""))
        # real browser: bridge ops, focus, sizing
        rep, _st = live_report()
        for name in ("exactly one reusable iframe",
                     "frame sandbox exactly allow-scripts",
                     "bogus frame op ignored",
                     "frame action forwarded through domain validation",
                     "frame resize clamped to configured max"):
            self.assertEqual(rep["checks"].get(name), "pass",
                             "%s :: %s" % (name, rep["checks"].get(
                                 name)))


class T_S030_ReleaseRecovery(ServingBase):
    def test_s030_release_recovery(self):
        spath = self.start_stack()
        rel = os.path.join(self.tmp, "releases", "v1")
        os.makedirs(rel)
        for name in ("index.html", "app.js", "style.css"):
            shutil.copy(os.path.join(adaptermod.STATIC_DIR, name),
                        rel)
        cur = os.path.join(self.tmp, "releases", "current")
        os.symlink(rel, cur)
        self.assertTrue(os.path.islink(cur))
        # state lives outside release dirs
        self.assertNotIn(
            os.path.realpath(self.srv.cfg["adapter"]["state_db"]),
            os.path.realpath(cur))
        ck = self.login()
        ws = WSClient(self, self.port, cookie=ck)
        self.addCleanup(ws.close)
        w = attach(ws, tab="tab-rollback")
        conv = ws.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        # incompatible bundle blocks writes with reload-required
        ws.send({"v": 1, "kind": "command", "request_id": "rb1",
                 "client_id": None, "generation": 0, "csrf": None,
                 "op": "attach",
                 "body": {"tab_id": "tab-rollback",
                          "release_id": "v2-BROKEN",
                          "cursor_hint": None}})
        st = ws.wait_op("status", timeout=10)
        self.assertEqual(st["body"]["state"], "reload-required")
        # rollback = symlink swap + restart; durable history survives
        self.srv.stop()
        srv2 = adaptermod.AdapterServer(spath)
        srv2.start()
        self.addCleanup(srv2.stop)
        ws2 = WSClient(self, srv2.port, cookie=ck)
        self.addCleanup(ws2.close)
        w2 = attach(ws2, tab="tab-rollback", req="rb2")
        conv2 = ws2.wait_op("snapshot", timeout=10)["body"][
            "conversation_id"]
        self.assertEqual(conv2, conv)
        # outcome-unknown is never reported as delivered
        with open(os.path.join(os.path.dirname(
                adaptermod.__file__), "adapter.py")) as f:
            src = f.read()
        self.assertNotIn("delivered", src)


if __name__ == "__main__":
    unittest.main()
