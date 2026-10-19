"""P5 serving adapter: stdlib-only loopback web bridge (spec S001-S030).

Browser -> Caddy TLS -> 127.0.0.1:9120 /app/ws -> p1transport Client
-> HermesProvider (127.0.0.1:9121) -> real Hermes CLI.

Exactly one dynamic path: /app/ws. GET without Upgrade serves the
native login/challenge page; POST handles op=login/op=logout forms;
GET with RFC6455 Upgrade opens the WS after exact-Origin + session
checks. No /api, /login, /logout, /health, /asset-fetch routes.
Local/test convenience: GET / serves the static shell so the real
browser gate can run without Caddy; in production Caddy serves static
and routes ONLY /app/ws here.

Python stays authoritative: p1chat state, p2rich render + sandbox
policy, p3drawer allowlist run server-side; the browser is a thin
transport shim. Client.reconnect is NEVER used (it auto-replays the
outbox); resume is Client.connect(resume=True) plus durable outcome
lookup by request_id. Interrupted sends are outcome-unknown, never
auto-resent.

All tunables come from the settings file (R4); no numeric policy
constants live in code. Structural RFC bounds (control frame sizes,
close codes) are protocol invariants, not policy.
"""
import base64
import hashlib
import json
import os
import secrets as _secrets
import socket
import sqlite3 as _sqlite3
import struct
import threading
import time

from p0contract import messages, wire
from p0contract import render_policy as render_policy_mod
from p1transport import Client, ConnectionLost
from p1transport import protocol
from p2rich.renderer import PREVIEW_MAX_TEXT_CHARS
from p3drawer import drawer as drawer_mod
from p3drawer import ops as drawer_ops

from . import auth as authmod
from . import config as configmod


class StoreError(Exception):
    """Durable-store failure: callers must fail closed, never proceed."""

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUBPROTOCOL = "hermes.web.v1"

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

ALLOWED_OPS = ("attach", "snapshot", "chat.send", "action.invoke",
               "drawer.read", "drawer.op", "view.set", "receipt",
               "logout")
WRITE_OPS = ("chat.send", "action.invoke", "drawer.op", "view.set",
             "logout")
READ_OPS = ("attach", "snapshot", "drawer.read", "receipt")
REQUIRED_WS_KEYS = ("v", "kind", "request_id", "client_id",
                    "generation", "csrf", "op", "body")


def release_id():
    try:
        with open(os.path.join(STATIC_DIR, "release.json")) as f:
            return json.load(f).get("release_id", "dev")
    except OSError:
        return "dev"


class AdapterServer:
    def __init__(self, settings_path):
        self.cfg = configmod.load(settings_path)
        a = self.cfg["adapter"]
        self.bind = (a["bind_host"], a["bind_port"])
        self.origin = a["origin"]
        self.host = a["host"]
        self.path = a["path"]
        self.authdb = authmod.AuthStore(self.cfg)
        self._drawer_db = self._open_db()
        drawer_mod.ensure_tables(self._drawer_db)
        self.drawer = drawer_mod.Drawer(self._drawer_db)
        self.policy = {"revision": None, "expires_at": 0,
                       "queue_max_messages": None,
                       "queue_max_bytes": None,
                       "inflight_per_conversation": None}
        self._load_policy()
        self.sockets = {}   # token_hash -> [WSConn]
        self.sockets_lock = threading.Lock()
        self.up = None      # upstream Client or None
        self.up_lock = threading.Lock()
        self.up_cursor = None
        self.up_last_seen = []
        self.inflight = {}  # (conversation_id) -> count
        self.pending = {}   # request_id -> {state, payload_hash,...}
        self.clients = {}   # client_id -> record (persisted)
        self._lsock = None
        self._closed = False
        self._serve = None
        self.release = self.cfg["adapter"]["release_id"]
        self._load_clients()
        self.asset_hashes = {}
        for name in ("app.js", "style.css"):
            try:
                with open(os.path.join(STATIC_DIR, name), "rb") as f:
                    self.asset_hashes[name] = base64.b64encode(
                        hashlib.sha256(f.read()).digest()).decode()
            except OSError:
                self.asset_hashes[name] = ""
        self.shell_doc = self._build_shell()
        threading.Thread(target=self._expiry_loop, daemon=True).start()

    def _open_db(self):
        """Service-owned handle on the state db honoring sqlite_busy_seconds."""
        db = _sqlite3.connect(self.cfg["adapter"]["state_db"],
                              check_same_thread=False, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        try:
            ms = int(self.cfg["adapter"]["sqlite_busy_seconds"]) * 1000
            db.execute("PRAGMA busy_timeout=%d" % ms)
        except (ValueError, _sqlite3.Error):
            pass
        return db

    def client_policy(self):
        """Runtime knobs the browser must obey (R4); no JS-owned literals."""
        a = self.cfg["adapter"]
        return {
            "draft_bytes": a["draft_bytes"],
            "reconnect_base_seconds": a["reconnect_base_seconds"],
            "reconnect_factor": a["reconnect_factor"],
            "reconnect_cap_seconds": a["reconnect_cap_seconds"],
            "reconnect_stable_seconds": a["reconnect_stable_seconds"],
            "frame_min_height": a["frame_min_height"],
            "frame_max_height": a["frame_max_height"],
            "frame_ready_timeout_seconds": a[
                "frame_ready_timeout_seconds"],
            "outbound_messages": a["outbound_messages"],
            "outbound_bytes": a["outbound_bytes"],
        }

    def _build_shell(self):
        """Assemble the served document: release-owned chrome with the
        transport shim and styles inlined so the pinned-hash CSP covers
        them. The release marker lives in a meta tag, never inside a
        hashed block, so per-release substitution cannot break a pin."""
        with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
            doc = f.read()
        with open(os.path.join(STATIC_DIR, "app.js"), "rb") as f:
            app_js = f.read()
        with open(os.path.join(STATIC_DIR, "style.css"), "rb") as f:
            css = f.read()
        assert hashlib.sha256(app_js).digest() == base64.b64decode(
            self.asset_hashes["app.js"])
        assert hashlib.sha256(css).digest() == base64.b64decode(
            self.asset_hashes["style.css"])
        doc = doc.replace(b"/*__APP_JS__*/", app_js)
        doc = doc.replace(b"/*__STYLE_CSS__*/", css)
        doc = doc.replace(b"__RELEASE_ID__", self.release.encode())
        from p2rich.sandbox import serving_frame_srcdoc as _frame_doc
        frame_json = json.dumps(_frame_doc()).replace(
            "</script", "<\\/script").replace("<", "\\u003c").encode()
        doc = doc.replace(b"__FRAME_DOC_JSON__", frame_json)
        return doc

    # -- lifecycle --
    def start(self):
        if self.bind[0] != "127.0.0.1":
            raise RuntimeError("adapter binds loopback only")
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(self.bind)
        self._lsock.listen(self.cfg["adapter"]["max_connections"])
        self._serve = self._lsock
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self._lsock.getsockname()[1]

    @property
    def port(self):
        return self._lsock.getsockname()[1]

    def stop(self):
        self._closed = True
        try:
            self._lsock.close()
        except OSError:
            pass
        with self.sockets_lock:
            conns = [c for lst in self.sockets.values() for c in lst]
        for c in conns:
            try:
                c.close(1001, "server-shutdown")
            except OSError:
                pass

    def _accept_loop(self):
        while not self._closed:
            try:
                conn, peer = self._lsock.accept()
            except OSError:
                return
            if peer[0] != "127.0.0.1":
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._handle_http, args=(conn,),
                             daemon=True).start()

    # -- HTTP --
    def _handle_http(self, conn):
        try:
            rfile = conn.makefile("rb")
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = rfile.read(1)
                if not chunk:
                    conn.close()
                    return
                head += chunk
                if len(head) > self.cfg["adapter"]["http_header_bytes"]:
                    conn.sendall(b"HTTP/1.1 431 Too Large\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                    conn.close()
                    return
            try:
                htext = head.decode("latin-1")
            except UnicodeDecodeError:
                conn.close()
                return
            lines = htext.split("\r\n")
            method, target, _ver = lines[0].split(" ", 2)
            headers = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            body = b""
            if method == "POST":
                try:
                    n = int(headers.get("content-length", "0"))
                except ValueError:
                    n = 0
                if n > self.cfg["adapter"]["http_body_bytes"]:
                    self._http(conn, 413, "too large", {})
                    return
                while len(body) < n:
                    part = rfile.read(n - len(body))
                    if not part:
                        break
                    body += part
            if target == "/" and method == "GET" and \
                    self._is_ws_upgrade(headers):
                self._handle_ws(conn, rfile, method, target, headers)
            elif target == "/" and method == "GET":
                self._serve_static(conn, "index.html", "text/html")
            elif target.startswith("/static/") and method == "GET":
                name = target[len("/static/"):]
                if "/" in name or name.startswith("."):
                    self._http(conn, 404, "not found", {})
                else:
                    ctype = "application/javascript" \
                        if name.endswith(".js") else \
                        "text/css" if name.endswith(".css") else \
                        "application/octet-stream"
                    self._serve_static(conn, name, ctype)
            elif target == "/favicon.ico" and method == "GET":
                self._http(conn, 204, "", {})
            elif target == self.path:
                if self._is_ws_upgrade(headers):
                    self._handle_ws(conn, rfile, method, target,
                                    headers)
                elif method == "GET":
                    self._http_auth_page(conn, headers)
                elif method == "POST":
                    self._http_auth_post(conn, headers, body)
                else:
                    self._http(conn, 405, "method not allowed", {})
            else:
                self._http(conn, 404, "not found", {})
        except (OSError, ValueError):
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _is_ws_upgrade(headers):
        return headers.get("upgrade", "").lower() == "websocket" and \
            "upgrade" in headers.get("connection", "").lower()

    def _http(self, conn, code, text, extra_headers, ctype="text/plain",
              extra_cookies=()):
        reason = {200: "OK", 303: "See Other", 400: "Bad Request",
                  401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                  405: "Method Not Allowed", 413: "Too Large",
                  429: "Too Many Requests"}.get(code, "OK")
        lines = [f"HTTP/1.1 {code} {reason}",
                 "Cache-Control: no-store",
                 f"Content-Type: {ctype}",
                 f"Content-Length: {len(text.encode())}"]
        for k, v in extra_headers.items():
            lines += [f"{k}: {v}"]
        for ck in extra_cookies:
            lines += [f"Set-Cookie: {ck}"]
        lines += ["Connection: close", "", ""]
        conn.sendall("\r\n".join(lines).encode() + text.encode())
        conn.close()

    def _serve_static(self, conn, name, ctype):
        if name == "index.html":
            data = self.shell_doc
        else:
            try:
                with open(os.path.join(STATIC_DIR, name), "rb") as f:
                    data = f.read()
            except OSError:
                self._http(conn, 404, "not found", {})
                return
        reason = "HTTP/1.1 200 OK"
        head = (reason + "\r\nCache-Control: no-store\r\nContent-Type: "
                + ctype + f"\r\nContent-Length: {len(data)}\r\n"
                + self._csp_header() + "\r\nConnection: close\r\n\r\n")
        conn.sendall(head.encode() + data)
        conn.close()

    def _csp_header(self):
        import hashlib as _hl
        from p2rich.sandbox import serving_frame_js as _serving_js
        frame_raw = _hl.sha256(_serving_js().encode()).digest()
        frame_b64 = base64.b64encode(frame_raw).decode()
        pins = " ".join(
            "'sha256-" + h + "'" for h in
            [frame_b64] + list(self.asset_hashes.values())
            if h)
        if self.origin.startswith("https:"):
            connect = "wss://" + self.host + self.path
        else:
            connect = self.origin.replace("http://", "ws://",
                                          1) + self.path
        return ("Content-Security-Policy: default-src 'none'; "
                "connect-src " + connect + "; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; "
                "frame-src 'self'; frame-ancestors 'none'; script-src " +
                pins + "; style-src " + pins)

    # -- native auth on the same path --
    def _http_auth_page(self, conn, headers):
        authed, _sess = self._session_of(headers)
        if authed:
            csrf = self.authdb.new_form_token(
                headers.get("cookie", ""))
            page = ("<html><body><p>signed in</p>"
                    '<form method="POST" action="/app/ws">'
                    '<input type="hidden" name="op" value="logout">'
                    '<input type="hidden" name="csrf" value="'
                    + csrf + '">'
                    "</form></body></html>")
            self._http(conn, 200, page, {}, ctype="text/html")
            return
        pre, challenge = self.authdb.new_preauth()
        cookie = (f"{self.cfg['auth']['preauth_cookie_name']}={pre}; "
                  "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="
                  + str(self.cfg["auth"]["preauth_seconds"]))
        page = ("<html><body><h1>sign in</h1>"
                '<form method="POST" action="/app/ws">'
                '<input type="hidden" name="op" value="login">'
                '<input type="text" name="username" autocomplete="username">'
                '<input type="password" name="password" '
                'autocomplete="current-password">'
                '<input type="hidden" name="csrf" value="' + challenge
                + '"><button>sign in</button></form></body></html>')
        self._http(conn, 200, page, {}, ctype="text/html",
                   extra_cookies=(cookie,))

    def _http_auth_post(self, conn, headers, body):
        try:
            fields = dict(p.split("=", 1) for p in
                          body.decode().split("&") if "=" in p)
        except UnicodeDecodeError:
            fields = {}
        import urllib.parse as _u
        fields = {k: _u.unquote_plus(v) for k, v in fields.items()}
        op = fields.get("op", "")
        origin = headers.get("origin", "")
        if origin != self.origin:
            self._http(conn, 403, "bad origin", {})
            return
        if op == "login":
            ok, cookies, err = self.authdb.login(
                fields.get("username", ""), fields.get("password", ""),
                headers.get("cookie", ""), fields.get("csrf", ""),
                peer="loopback")
            if not ok:
                if err == "rate-limited":
                    self._http(conn, 429, "too many attempts",
                               {"Retry-After": str(self.cfg["adapter"][
                                   "retry_after_seconds"])})
                else:
                    self._http(conn, 401, "bad credentials", {})
                return
            self._http(conn, 303, "", {"Location": "/"},
                       extra_cookies=tuple(cookies))
        elif op == "logout":
            cookie = self.authdb.logout(headers.get("cookie", ""),
                                        fields.get("csrf", ""))
            self._close_session_sockets(headers.get("cookie", ""))
            self._http(conn, 303, "", {"Location": "/"},
                       extra_cookies=(cookie,))
        else:
            self._http(conn, 400, "bad op", {})

    def _session_of(self, headers):
        return self.authdb.check_session(headers.get("cookie", ""))

    def _close_session_sockets(self, cookie_header):
        th = authmod.token_hash_of(cookie_header,
                                   self.cfg["auth"]["cookie_name"])
        if not th:
            return
        with self.sockets_lock:
            conns = self.sockets.pop(th, [])
        for c in conns:
            try:
                c.close(1008, "logged-out")
            except OSError:
                pass

    def broadcast_client(self, rec_id, op, body, request_id=None):
        """Deliver to every live socket holding this logical client.

        Lets a completion land on the post-reload generation, not just
        the socket that sent the command. Each socket keeps its own
        event numbering; closed sockets are skipped, never resurrected.
        """
        with self.sockets_lock:
            conns = [c for lst in self.sockets.values() for c in lst
                     if c.client_id == rec_id and not c.closed]
        sent = False
        for c in conns:
            try:
                if c.send_event(op, body, request_id):
                    sent = True
            except Exception:
                pass
        return sent

    # -- websocket --
    def _handle_ws(self, conn, rfile, method, target, headers):
        a = self.cfg["adapter"]
        origin = headers.get("origin", "")
        host = headers.get("host", "")
        if target != self.path:
            self._http(conn, 404, "not found", {})
            return
        if origin != self.origin:
            self._http(conn, 403, "bad origin", {})
            return
        if host != self.host:
            self._http(conn, 403, "bad host", {})
            return
        if headers.get("sec-websocket-version", "") != "13":
            self._http(conn, 400, "bad version", {})
            return
        key = headers.get("sec-websocket-key", "")
        try:
            if len(base64.b64decode(key)) != 16:
                raise ValueError
        except Exception:
            self._http(conn, 400, "bad key", {})
            return
        proto = headers.get("sec-websocket-protocol", "")
        if SUBPROTOCOL not in [p.strip() for p in proto.split(",")]:
            self._http(conn, 400, "bad subprotocol", {})
            return
        authed, sess = self._session_of(headers)
        if not authed:
            self._http(conn, 401, "unauthorized", {})
            return
        accept = base64.b64encode(hashlib.sha1(
            (key + WS_GUID).encode()).digest()).decode()
        resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept
                + "\r\nSec-WebSocket-Protocol: " + SUBPROTOCOL
                + "\r\nCache-Control: no-store\r\n\r\n")
        try:
            conn.sendall(resp.encode())
        except OSError:
            return
        wsc = WSConn(conn, rfile, self, sess, origin)
        th = sess["token_hash"]
        with self.sockets_lock:
            self.sockets.setdefault(th, []).append(wsc)
        try:
            wsc.run()
        finally:
            with self.sockets_lock:
                lst = self.sockets.get(th, [])
                if wsc in lst:
                    lst.remove(wsc)

    # -- upstream --
    def upstream(self):
        with self.up_lock:
            if self.up is not None:
                return self.up
            u = self.cfg["upstream"]
            c = Client("adapter-" + os.path.basename(
                self.cfg["adapter"]["state_db"]),
                supported_versions=[dict(protocol.V10)], caps=[])
            extra = None
            try:
                with open(u["service_secret_file"]) as f:
                    secret = f.read().strip()
                if secret:
                    extra = {"service_auth": secret}
            except OSError:
                extra = None
            c.connect(u["host"], u["port"], resume=True, extra=extra)
            try:
                c._sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_KEEPALIVE,
                    1 if u["tcp_keepalive"] else 0)
                if u["tcp_keepalive"]:
                    for name, val in (
                            ("TCP_KEEPIDLE", u["tcp_idle_seconds"]),
                            ("TCP_KEEPINTVL", u["tcp_interval_seconds"]),
                            ("TCP_KEEPCNT", u["tcp_probes"])):
                        opt = getattr(socket, name, None)
                        if opt is not None:
                            try:
                                c._sock.setsockopt(
                                    socket.IPPROTO_TCP, opt, val)
                            except OSError:
                                pass
            except (OSError, AttributeError):
                pass
            self.up = c
            return c

    def upstream_drop(self):
        with self.up_lock:
            if self.up is not None:
                try:
                    self.up.close()
                except OSError:
                    pass
                self.up = None

    def policy_ok(self):
        if not self.policy.get("revision"):
            return False, "policy-unavailable"
        if self.policy.get("expires_at", 0) <= time.time():
            return False, "policy-unavailable"
        return True, ""

    def _load_policy(self):
        try:
            with open(self.cfg["policy"]["file"]) as f:
                self.policy = json.load(f)
        except (OSError, ValueError):
            self.policy = {"revision": None, "expires_at": 0}

    def _load_clients(self):
        try:
            db = authmod.sqlite(
                self.cfg["adapter"]["state_db"],
                busy_seconds=self.cfg["adapter"]["sqlite_busy_seconds"])
            rows = db.execute("SELECT client_id, record FROM clients"
                              ).fetchall()
            for cid, rec in rows:
                self.clients[cid] = json.loads(rec)
            db.close()
        except Exception:
            pass

    def _save_client(self, cid, rec):
        self.clients[cid] = rec
        try:
            db = authmod.sqlite(
                self.cfg["adapter"]["state_db"],
                busy_seconds=self.cfg["adapter"]["sqlite_busy_seconds"])
            db.execute("INSERT OR REPLACE INTO clients(client_id,"
                       " record) VALUES(?,?)", (cid, json.dumps(rec)))
            db.commit()
            db.close()
        except Exception as e:
            raise StoreError(f"store-unavailable: {e}")

    def _expiry_loop(self):
        while not self._closed:
            period = self.cfg["adapter"]["session_check_seconds"]
            cred = self.cfg["adapter"]["credential_check_seconds"]
            delay = min(period, cred) or 1
            time.sleep(delay)
            try:
                dead = self.authdb.expire_sweep()
            except Exception:
                dead = []
            for th in dead:
                with self.sockets_lock:
                    conns = self.sockets.pop(th, [])
                for c in conns:
                    try:
                        c.close(1008, "expired")
                    except OSError:
                        pass


class WSConn:
    def __init__(self, conn, rfile, server, sess, origin):
        self.conn = conn
        self.rfile = rfile
        self.srv = server
        self.sess = sess
        self.origin = origin
        self.a = server.cfg["adapter"]
        self.client_id = None
        self.generation = 0
        self.csrf = None
        self.event_seq = 0
        self.unacked = []  # [(event_seq, bytes)] not yet receipted
        self.last_pong = time.time()
        self.ping_sent = None  # time of the last ping needing a pong
        self.closed = False
        self.wlock = threading.Lock()
        self.frag = None  # fragmented text buffer
        threading.Timer(self.a["ws_ping_seconds"],
                        self._ping_tick).start()

    # -- frame IO --
    def _recvn(self, n):
        data = b""
        while len(data) < n:
            part = self.rfile.read(n - len(data))
            if not part:
                raise ConnectionLost("peer closed")
            data += part
        return data

    def send_text(self, obj):
        if self.closed:
            return False
        payload = json.dumps(obj, sort_keys=True).encode("utf-8")
        if len(payload) > self.a["frame_bytes"]:
            return False
        # Outstanding (unreceipted) backpressure: a healthy reader that
        # receipts stays alive indefinitely; a silent consumer is fenced
        # with 1013 and recovers from durable history via explicit resync.
        pending = sum(size for _, size in self.unacked)
        if len(self.unacked) + 1 > self.a["outbound_messages"] or \
                pending + len(payload) > self.a["outbound_bytes"]:
            self.close(1013, "backpressure")
            return False
        frame = b"\x81" + _encode_len(len(payload)) + payload
        with self.wlock:
            try:
                self.conn.sendall(frame)
            except OSError:
                return False
        self.unacked.append((self.event_seq, len(payload)))
        return True

    def send_event(self, op, body, request_id=None):
        self.event_seq += 1
        return self.send_text(
            {"v": 1, "kind": "event", "request_id": request_id,
             "client_id": self.client_id, "generation": self.generation,
             "event_seq": self.event_seq, "op": op, "body": body})

    def close(self, code, reason):
        if self.closed:
            return
        self.closed = True
        payload = struct.pack("!H", code) + reason.encode()[:123]
        try:
            self.conn.sendall(b"\x88" + _encode_len(len(payload))
                              + payload)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass

    def _ping_tick(self):
        if self.closed:
            return
        now = time.time()
        if self.ping_sent is not None and \
                self.last_pong < self.ping_sent and \
                now - self.ping_sent > \
                self.a["ws_pong_timeout_seconds"]:
            self.close(1008, "pong-timeout")
            return
        with self.wlock:
            try:
                self.conn.sendall(b"\x89\x00")
            except OSError:
                return
        self.ping_sent = now
        threading.Timer(self.a["ws_ping_seconds"],
                        self._ping_tick).start()

    def run(self):
        try:
            while not self.closed:
                opcode, payload = self._read_frame()
                if opcode == 0x8:
                    # RFC6455 close echo: answer the peer's close so
                    # its onclose (and our reconnect) fires promptly.
                    with self.wlock:
                        try:
                            self.conn.sendall(
                                b"\x88" + _encode_len(len(payload))
                                + payload)
                        except OSError:
                            pass
                    self.closed = True
                    try:
                        self.conn.close()
                    except OSError:
                        pass
                    return
                if opcode == 0x9:
                    with self.wlock:
                        try:
                            self.conn.sendall(b"\x8a" + _encode_len(
                                len(payload)) + payload)
                        except OSError:
                            return
                    continue
                if opcode == 0xA:
                    self.last_pong = time.time()
                    continue
                if opcode == 0x2:
                    self.close(1003, "binary-not-supported")
                    return
                if opcode == 0x1:
                    self._on_text(payload)
                else:
                    self.close(1003, "bad-opcode")
                    return
        except (ConnectionLost, OSError):
            self.closed = True
        except ValueError as e:
            code = 1002
            if "frame-too-large" in str(e):
                code = 1009
            elif "bad-utf8" in str(e):
                code = 1007
            try:
                self.close(code, "protocol-error")
            except OSError:
                pass
            self.closed = True

    def _read_raw_frame(self):
        """One raw frame: (fin, opcode, payload). Control validation
        included; ping/pong/close handled by the caller."""
        hdr = self._recvn(2)
        b1, b2 = hdr[0], hdr[1]
        fin = bool(b1 & 0x80)
        if b1 & 0x70:
            raise ValueError("rsv-no-compression")
        opcode = b1 & 0x0F
        if not (b2 & 0x80):
            raise ValueError("client-must-mask")
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recvn(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recvn(8))[0]
        if opcode in (0x8, 0x9, 0xA):
            if not fin:
                raise ValueError("fragmented-control")
            if length > 125:
                raise ValueError("control-too-large")
        elif length > self.a["frame_bytes"]:
            raise ValueError("frame-too-large")
        mask = self._recvn(4)
        payload = self._recvn(length) if length else b""
        payload = bytes(c ^ mask[i % 4]
                        for i, c in enumerate(payload))
        return fin, opcode, payload

    def _read_frame(self):
        """Next complete data unit: (opcode, payload). Fragmented text
        is reassembled (bounded); ping/pong answered inline; close
        returned as (0x8, payload) for run() to handle."""
        frag = None
        frag_op = None
        while True:
            fin, opcode, payload = self._read_raw_frame()
            if opcode == 0x9:
                with self.wlock:
                    try:
                        self.conn.sendall(b"\x8a" + _encode_len(
                            len(payload)) + payload)
                    except OSError:
                        raise ConnectionLost("peer closed")
                continue
            if opcode == 0xA:
                self.last_pong = time.time()
                continue
            if opcode == 0x8:
                if payload:
                    if len(payload) < 2:
                        raise ValueError("bad-close-payload")
                    try:
                        payload[2:].decode("utf-8")
                    except UnicodeDecodeError:
                        raise ValueError("bad-close-utf8")
                return 0x8, payload
            if opcode == 0x2:
                return 0x2, payload
            if opcode == 0x1:
                if frag is not None:
                    raise ValueError("interleaved-data-frame")
                if fin:
                    self._check_utf8(payload)
                    return 0x1, payload
                frag, frag_op = payload, 0x1
                continue
            if opcode == 0x0:
                if frag is None:
                    raise ValueError("orphan-continuation")
                frag += payload
                if len(frag) > self.a["frame_bytes"]:
                    raise ValueError("frame-too-large")
                if fin:
                    self._check_utf8(frag)
                    return frag_op, frag
                continue
            raise ValueError("bad-opcode")

    @staticmethod
    def _check_utf8(payload):
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("bad-utf8")

    def _on_text(self, payload):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            self.close(1007, "bad-utf8")
            return
        try:
            msg = json.loads(text, object_pairs_hook=_no_dupes,
                             parse_constant=_no_const)
        except ValueError:
            self._outcome(None, "rejected", "bad-envelope", None)
            return
        if not isinstance(msg, dict):
            self._outcome(None, "rejected", "bad-envelope", None)
            return
        if any(k not in msg for k in REQUIRED_WS_KEYS):
            self._outcome(msg.get("request_id"), "rejected",
                          "bad-envelope", None)
            return
        if not isinstance(msg["request_id"], str) or \
                not msg["request_id"]:
            self._outcome(None, "rejected", "bad-envelope", None)
            return
        if msg.get("v") != 1 or msg.get("kind") != "command":
            self._outcome(msg["request_id"], "rejected",
                          "bad-envelope", None)
            return
        if msg.get("op") not in ALLOWED_OPS or \
                not isinstance(msg.get("body"), dict):
            self._outcome(msg["request_id"], "rejected",
                          "unknown-op", None)
            return
        if not isinstance(msg.get("generation"), int) or \
                isinstance(msg.get("generation"), bool):
            self._outcome(msg["request_id"], "rejected",
                          "bad-generation", None)
            return
        try:
            ok, sess = self.srv.authdb.check_session_by_hash(
                self.sess["token_hash"])
        except Exception:
            self.close(1011, "store-unavailable")
            return
        if not ok:
            self.close(1008, "expired")
            return
        if msg["op"] == "attach":
            self._do_attach(msg)
            return
        if self.client_id is None:
            self._outcome(msg["request_id"], "rejected",
                          "not-attached", None)
            return
        rec = self.srv.clients.get(self.client_id)
        if rec is None or msg.get("client_id") != self.client_id or \
                msg["generation"] != rec.get("generation"):
            self._outcome(msg["request_id"], "rejected",
                          "stale-generation", None)
            return
        if msg["op"] in WRITE_OPS and \
                not self.srv.authdb.check_ws_token(
                    self.sess["token_hash"], msg.get("csrf")):
            self._outcome(msg["request_id"], "rejected",
                          "bad-csrf", None)
            return
        if not self.srv.authdb.check_command_budget(
                self.sess["token_hash"]):
            self._outcome(msg.get("request_id"), "rejected",
                          "rate-limited", None)
            return
        handler = {"snapshot": self._do_snapshot,
                   "chat.send": self._do_send,
                   "action.invoke": self._do_action,
                   "drawer.read": self._do_drawer_read,
                   "drawer.op": self._do_drawer_op,
                   "view.set": self._do_view,
                   "receipt": self._do_receipt,
                   "logout": self._do_logout}[msg["op"]]
        handler(msg)

    # -- ops --
    def _outcome(self, request_id, status, code, message_id,
                 cursor=None):
        body = {"status": status, "code": code,
                "message_id": message_id, "cursor": cursor}
        self.event_seq += 1
        self.send_text(
            {"v": 1, "kind": "event", "request_id": request_id,
             "client_id": self.client_id, "generation": self.generation,
             "event_seq": self.event_seq, "op": "outcome", "body": body})

    def _do_attach(self, msg):
        a = self.srv.authdb
        body = msg["body"]
        try:
            ok, sess = a.check_session_by_hash(self.sess["token_hash"])
        except Exception:
            self.close(1011, "store-unavailable")
            return
        if not ok:
            self.close(1008, "expired")
            return
        tab_hint = body.get("tab_id") if isinstance(
            body.get("tab_id"), str) else None
        cursor_hint = body.get("cursor_hint")
        if cursor_hint is not None and \
                not isinstance(cursor_hint, str):
            self._outcome(msg["request_id"], "rejected",
                          "bad-cursor-hint", None)
            return
        if body.get("release_id") != self.srv.release:
            self.send_event("status",
                            {"state": "reload-required",
                             "detail": "release mismatch; reload"},
                            msg["request_id"])
            return
        rec = None
        rec_id = None
        if tab_hint:
            for cid, r in self.srv.clients.items():
                if r.get("tab_hint") == tab_hint and \
                        r.get("account_id") == sess["account_id"]:
                    rec = dict(r)
                    rec_id = cid
                    break
        if rec is None:
            import secrets as _s
            rec_id = "c-" + _s.token_hex(8)
            rec = {"account_id": sess["account_id"],
                   "tab_hint": tab_hint,
                   "conversation_id": "conv-" + rec_id,
                   "generation": 0, "upstream_cursor": None,
                   "projection_receipt_seq": 0,
                   "last_seen": [], "pins": [],
                   "registry_revision": None,
                   "budget_revision": None, "updated_at": int(time.time())}
        rec["generation"] = int(rec.get("generation", 0)) + 1
        rec["updated_at"] = int(time.time())
        rec["frame_token"] = _secrets.token_hex(16)
        rec["frame_context"] = "ctx-%s-%d" % (rec_id,
                                              rec["generation"])
        try:
            self.srv._save_client(rec_id, rec)
        except StoreError:
            self.close(1011, "store-unavailable")
            return
        self.client_id = rec_id
        self.generation = rec["generation"]
        try:
            self.csrf = a.rotate_ws_token(sess["token_hash"])
        except Exception:
            self.close(1011, "store-unavailable")
            return
        self.send_event("welcome",
                        {"csrf": self.csrf,
                         "release_id": self.srv.release,
                         "protocol": SUBPROTOCOL, "state": "resuming",
                         "client_policy": self.srv.client_policy(),
                         "frame_token": rec["frame_token"],
                         "frame_context": rec["frame_context"],
                         "registered_actions": []},
                        msg["request_id"])
        try:
            self._push_snapshot(msg["request_id"], resync=True)
        except StoreError:
            self.close(1011, "store-unavailable")

    def _drawer_projection(self):
        """Real drawer read: entries + honest Add framing from backend state."""
        try:
            res = drawer_ops.handle_op(self.srv.drawer, {"op": "list"})
        except Exception:
            return {"items": [],
                    "add": {"affordance": "add-page", "enabled": False}}
        entries = res.get("entries", []) if isinstance(res, dict) else []
        items = [{"id": e.get("page_id"), "label": e.get("name"),
                  "pinned": bool(e.get("pinned")),
                  "state": e.get("status")}
                 for e in entries if isinstance(e, dict)]
        add = dict(res.get("add", {})) if isinstance(res, dict) else {}
        add["enabled"] = bool(
            self.srv.cfg["provider"]["drawer_writes_enabled"])
        if not add["enabled"]:
            add["detail"] = "not enabled yet"
        return {"items": items, "add": add}

    def _push_snapshot(self, request_id, resync=False):
        bubbles, conv, alive = self._domain_snapshot()
        drawer = self._drawer_projection()
        self.send_event("snapshot",
                        {"conversation_id": conv,
                         "revision": len(bubbles),
                         "cursor": self.srv.up_cursor,
                         "bubbles": bubbles, "drawer": drawer,
                         "pending": [p for p in
                                     self.srv.pending.values() if
                                     p.get("client_id")
                                     == self.client_id]},
                        request_id)
        if not alive:
            # Verified cached history only, explicitly marked stale.
            self.send_event("status",
                            {"state": "backend-unavailable",
                             "detail": "backend unreachable"},
                            request_id)

    def _known_bubble_ids(self):
        rec = self.srv.clients.get(self.client_id, {})
        ids = {b.get("id") for b in rec.get("assistant", [])
               if isinstance(b, dict) and b.get("id")}
        for b in self.srv.up_last_seen:
            if isinstance(b, dict) and b.get("id"):
                ids.add(b["id"])
        return ids

    def _domain_snapshot(self):
        conv = (self.srv.clients.get(self.client_id, {})
                .get("conversation_id", "conv-none"))
        rec = self.srv.clients.get(self.client_id, {})
        modes = rec.get("view_modes", {}) if isinstance(
            rec.get("view_modes"), dict) else {}
        try:
            up = self.srv.upstream()
            sess = up.session or {}
            bubbles = [{"id": b["id"], "revision": b["revision"],
                        "major": b["major"], "text": b["text"],
                        "preview_html": None, "frame_payload": None,
                        "role": "user",
                        "mode": modes.get(b["id"], "standard")}
                       for b in up.bubbles]
            alive = True
        except (ConnectionLost, OSError, ValueError):
            self.srv.upstream_drop()
            alive = False
            bubbles = []
        assist = []
        for b in rec.get("assistant", []):
            b = dict(b)
            b["mode"] = modes.get(b.get("id"), b.get("mode",
                                                     "standard"))
            assist.append(b)
        bubbles = bubbles + assist
        return bubbles, conv, alive

    def _do_snapshot(self, msg):
        try:
            self.srv.upstream()
        except (ConnectionLost, OSError, ValueError):
            self.srv.upstream_drop()
            self.send_event("status",
                            {"state": "backend-unavailable",
                             "detail": "backend unreachable"},
                            msg["request_id"])
            return
        self._push_snapshot(msg["request_id"])

    def _admit_write(self, msg, conversation_id):
        ok, why = self.srv.policy_ok()
        if not ok:
            self._outcome(msg["request_id"], "rejected", why, None)
            return False
        try:
            self.srv.upstream()
        except (ConnectionLost, OSError, ValueError):
            self.srv.upstream_drop()
            self._outcome(msg["request_id"], "rejected",
                          "backend-unavailable", None)
            return False
        pol = self.srv.policy
        qmax = pol.get("queue_max_messages")
        if qmax is not None and len(self.srv.pending) >= qmax:
            self._outcome(msg["request_id"], "rejected", "busy", None)
            return False
        smax = self.a["queue_safety_messages"]
        if len(self.srv.pending) >= smax:
            self._outcome(msg["request_id"], "rejected", "busy", None)
            return False
        if sum(len(json.dumps(p)) for p in
               self.srv.pending.values()) >= self.a[
                "queue_safety_bytes"]:
            self._outcome(msg["request_id"], "rejected", "busy", None)
            return False
        infl = self.srv.inflight.get(conversation_id, 0)
        imax = pol.get("inflight_per_conversation")
        if imax is not None and infl >= imax:
            self._outcome(msg["request_id"], "rejected", "busy", None)
            return False
        return True

    def _do_send(self, msg):
        import secrets as _s
        body = msg["body"]
        text = body.get("text")
        cid = body.get("conversation_id")
        if not isinstance(text, str) or not text.strip() or \
                len(text.encode()) > self.a["frame_bytes"] or \
                not isinstance(cid, str) or not cid:
            self._outcome(msg["request_id"], "rejected",
                          "bad-payload", None)
            return
        own = self.srv.clients.get(self.client_id, {})
        if cid != own.get("conversation_id"):
            self._outcome(msg["request_id"], "rejected",
                          "not-owned", None)
            return
        if not self._admit_write(msg, cid):
            return
        request_id = "r-" + _s.token_hex(8)
        payload_hash = hashlib.sha256(json.dumps(
            {"text": text, "conversation_id": cid,
             "request_id": request_id},
            sort_keys=True).encode()).hexdigest()
        self.srv.pending[request_id] = {
            "state": "accepted", "client_id": self.client_id,
            "payload_hash": payload_hash}
        self._outcome(msg["request_id"], "accepted", "admitted",
                      None)
        self.srv.inflight[cid] = self.srv.inflight.get(cid, 0) + 1
        try:
            threading.Thread(
                target=self._exec_send,
                args=(msg["request_id"], request_id, cid, text),
                daemon=True).start()
        except RuntimeError:
            self.srv.inflight[cid] -= 1
            self._outcome(msg["request_id"], "failed",
                          "backend-unavailable", None)

    def _exec_send(self, ws_req, request_id, cid, text):
        try:
            up = self.srv.upstream()
            payload = json.dumps(
                {"text": text, "conversation_id": cid,
                 "request_id": request_id}, sort_keys=True)
            env = protocol.mk_text_envelope(
                "ws-" + request_id, 0, payload.encode("utf-8"))
            reply = self._upstream_roundtrip(up, env, payload)
            try:
                self._record_upstream_state(up)
            except Exception:
                self._finish(ws_req, request_id, cid,
                             "outcome-unknown", "unknown", None)
                return
            term_text = self._result_text(reply)
            if term_text is None:
                self._finish(ws_req, request_id, cid,
                             "outcome-unknown", "unknown", None)
                return
            try:
                up._add_bubble(env["id"], 0,
                               env["version"]["major"], text)
            except (AttributeError, KeyError):
                pass
            if isinstance(reply, dict) and reply.get("cursor"):
                try:
                    up.cursor = reply["cursor"]
                except AttributeError:
                    pass
            try:
                self._render_and_patch(ws_req, request_id, cid, text,
                                       term_text)
            except StoreError:
                self._finish(ws_req, request_id, cid,
                             "outcome-unknown", "unknown", None)
        except (ConnectionLost, OSError, ValueError):
            self.srv.upstream_drop()
            self._finish(ws_req, request_id, cid, "outcome-unknown",
                         "unknown", None)
        finally:
            self.srv.inflight[cid] = max(
                0, self.srv.inflight.get(cid, 1) - 1)

    def _upstream_roundtrip(self, up, env, payload):
        u = self.srv.cfg["upstream"]
        sock = up._sock
        sock.settimeout(u["write_timeout_seconds"])
        sock.sendall(protocol.encode_frame(env))
        line = up._rfile.readline()
        if not line:
            raise ConnectionLost("upstream closed")
        get = protocol.decode_frame(line.encode("utf-8"))
        if get.get("type") != "payload.get":
            raise ValueError("expected payload.get")
        res = messages.validate_message(get)
        if res["status"] != "ok":
            raise ValueError("payload.get-invalid")
        data = protocol.mk_payload_data(
            res["body"]["ref"], payload,
            res["body"]["request_id"])
        sock.settimeout(u["read_timeout_seconds"])
        sock.sendall(protocol.encode_frame(data))
        line2 = up._rfile.readline()
        if not line2:
            raise ConnectionLost("upstream closed")
        return protocol.decode_frame(line2.encode("utf-8"))

    @staticmethod
    def _result_text(reply):
        if reply.get("type") != "result":
            return None
        try:
            res = wire.validate_envelope(reply)
        except wire.WireError:
            return None
        body_text = None
        if "bootstrap" in reply:
            try:
                body_text = json.loads(reply["bootstrap"]) \
                    .get("text")
            except ValueError:
                body_text = None
        status = reply.get("status", "completed")
        if status in ("failed",) or reply.get("code") == "conflict":
            return None
        if status == "outcome-unknown":
            return None
        return body_text

    def _record_upstream_state(self, up):
        try:
            self.srv.up_cursor = up.cursor
            self.srv.up_last_seen = [
                {"id": b["id"], "revision": b["revision"],
                 "fragment_id": None, "fragment_version": None}
                for b in up.bubbles]
            rec = self.srv.clients.get(self.client_id, {})
            rec["upstream_cursor"] = up.cursor
            rec["last_seen"] = self.srv.up_last_seen
            self.srv._save_client(self.client_id, rec)
        except AttributeError:
            pass

    def _render_and_patch(self, ws_req, request_id, cid, text,
                           term_text):
        from p2rich.renderer import (render_preview_html,
                                     fallback_bubble_html)
        frag = {"kind": "text", "origin": "generated",
                "fragment_id": "f-" + request_id,
                "fallback_text": term_text[:PREVIEW_MAX_TEXT_CHARS],
                "tree": {"component": "Text", "props": {"text": term_text},
                         "children": []},
                "version": {"major": 1, "minor": 0}}
        try:
            preview = render_preview_html(frag)
        except Exception:
            preview = fallback_bubble_html(term_text, "render-failed")
        rec = self.srv.clients.get(self.client_id, {})
        assist = rec.get("assistant", [])
        modes = rec.get("view_modes", {}) if isinstance(
            rec.get("view_modes"), dict) else {}
        bubble = {"id": "m-" + request_id + "-a",
                  "revision": len(assist) + 1,
                  "major": 1, "text": term_text,
                  "preview_html": preview,
                  "frame_payload": {
                      "fragment_id": frag["fragment_id"],
                      "kind": "text", "tree": frag["tree"],
                      "preview": True},
                  "role": "assistant",
                  "mode": modes.get("m-" + request_id + "-a",
                                    "standard")}
        assist.append(bubble)
        cap = self.a["outbound_messages"]
        rec["assistant"] = assist[-cap:] if cap > 0 else assist
        # Durable history BEFORE projecting completed: a store failure
        # leaves outcome-unknown, never a completed projection.
        self.srv._save_client(self.client_id, rec)
        if self.client_id is not None:
            self.srv.broadcast_client(
                self.client_id,
                "patch",
                {"region": "bubbles", "revision": 1,
                 "items": [bubble]}, ws_req)
        else:
            self.send_event("patch",
                            {"region": "bubbles", "revision": 1,
                             "items": [bubble]}, ws_req)
        self._finish(ws_req, request_id, cid, "completed", "ok",
                     bubble["id"])

    def _finish(self, ws_req, request_id, cid, status, code,
                message_id):
        pend = self.srv.pending.get(request_id)
        if pend is not None:
            pend["state"] = status
        body = {"status": status, "code": code,
                "message_id": message_id, "cursor": message_id}
        if self.client_id is None:
            self._outcome(ws_req, status, code, message_id,
                          cursor=message_id)
            return
        # Broadcast: a reload may have moved this logical client to a
        # new generation; the completion must reach the live socket.
        self.srv.broadcast_client(self.client_id, "outcome", body,
                                  ws_req)

    def _do_action(self, msg):
        body = msg["body"]
        cid = body.get("conversation_id")
        own = self.srv.clients.get(self.client_id, {})
        if not isinstance(cid, str) or not cid or \
                cid != own.get("conversation_id") or \
                not isinstance(body.get("action_id"), str) or \
                not body.get("action_id") or \
                not isinstance(body.get("values", {}), dict) or \
                not isinstance(body.get("expected_revision"), int) or \
                isinstance(body.get("expected_revision"), bool) or \
                not isinstance(body.get("confirm", False), bool):
            self._outcome(msg["request_id"], "rejected",
                          "bad-payload", None)
            return
        rec = self.srv.clients.get(self.client_id, {})
        event = {"source_ok": True, "token": body.get("frame_token"),
                 "op": "action", "context": rec.get("frame_context"),
                 "payload": {"action_id": body.get("action_id")}}
        ok, reason = render_policy_mod.validate_bridge(
            event, rec.get("frame_token"), rec.get("frame_context"), ())
        if not ok:
            if reason in ("bridge-source-denied",
                          "bridge-token-denied",
                          "bridge-context-denied"):
                code = "bad-frame-token"
            else:
                code = "unknown-action"
            self._outcome(msg["request_id"], "rejected",
                          code, None)
            return
        if not self.srv.cfg["provider"]["actions_enabled"]:
            self._outcome(msg["request_id"], "rejected",
                          "actions-disabled", None)
            return
        self._outcome(msg["request_id"], "rejected",
                      "actions-unwired", None)

    def _do_drawer_read(self, msg):
        proj = self._drawer_projection()
        self.send_event("patch",
                        {"region": "drawer-items", "revision": 0,
                         "items": proj["items"]}, msg["request_id"])
        self.send_event("patch",
                        {"region": "add-content", "revision": 0,
                         "items": [proj["add"]]}, msg["request_id"])
        self._outcome(msg["request_id"], "completed", "ok", None)

    def _do_drawer_op(self, msg):
        body = msg["body"]
        name = body.get("op")
        if name == "list":
            self._do_drawer_read(msg)
            return
        if name not in drawer_ops.DRAWER_OPS:
            self._outcome(msg["request_id"], "rejected",
                          "unknown-op", None)
            return
        if not isinstance(body.get("args", {}), dict) or \
                not isinstance(body.get("expected_revision"), int) or \
                isinstance(body.get("expected_revision"), bool):
            self._outcome(msg["request_id"], "rejected",
                          "bad-payload", None)
            return
        # Add-flow writes stay deferred per the plan: honest disabled,
        # never a pretended browser-local success.
        self._outcome(msg["request_id"], "rejected",
                      "drawer-writes-disabled", None)

    def _do_view(self, msg):
        body = msg["body"]
        if not isinstance(body.get("bubble_id"), str) or \
                body.get("mode") not in ("standard", "expanded"):
            self._outcome(msg["request_id"], "rejected",
                          "bad-payload", None)
            return
        if body["bubble_id"] not in self._known_bubble_ids():
            self._outcome(msg["request_id"], "rejected",
                          "unknown-bubble", None)
            return
        try:
            rec = self.srv.clients.get(self.client_id, {})
            modes = rec.get("view_modes")
            if not isinstance(modes, dict):
                modes = {}
            modes[body["bubble_id"]] = body["mode"]
            rec["view_modes"] = modes
            self.srv._save_client(self.client_id, rec)
        except StoreError:
            self._outcome(msg["request_id"], "rejected",
                          "store-unavailable", None)
            return
        self._outcome(msg["request_id"], "completed", "ok", None)

    def _do_receipt(self, msg):
        seq = msg["body"].get("event_seq")
        if not isinstance(seq, int) or isinstance(seq, bool) \
                or seq < 0:
            self._outcome(msg["request_id"], "rejected",
                          "bad-payload", None)
            return
        rec = self.srv.clients.get(self.client_id, {})
        rec["projection_receipt_seq"] = seq
        try:
            self.srv._save_client(self.client_id, rec)
        except StoreError:
            self._outcome(msg["request_id"], "rejected",
                          "store-unavailable", None)
            return
        # Receipted events leave the outstanding set: healthy readers
        # never trip backpressure, silent consumers still do.
        self.unacked = [(s, z) for (s, z) in self.unacked if s > seq]
        self._outcome(msg["request_id"], "completed", "ok", None)

    def _do_logout(self, msg):
        self.srv.authdb.revoke(self.sess["token_hash"])
        self.close(1008, "logged-out")


def _encode_len(n):
    if n < 126:
        return bytes([n])
    if n < 65536:
        return b"\x7e" + struct.pack("!H", n)
    return b"\x7f" + struct.pack("!Q", n)


def _no_dupes(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate-key: {k}")
        obj[k] = v
    return obj


def _no_const(v):
    raise ValueError(f"non-json-number: {v}")


def frame_bundle_js():
    from p2rich.sandbox import FRAME_JS
    return FRAME_JS.replace("__TOKEN__", "test-token") \
        .replace("__CONTEXT__", "test-context") \
        .replace("__ACTIONS__", "[]")
