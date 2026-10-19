"""P5 auth: single MJ account, opaque server-side sessions (spec S003-S008).

Cookie: __Host-chat=<opaque>; Path=/; Secure; HttpOnly; SameSite=Strict;
Max-Age from config; no Domain. Server stores only SHA-256(token).
Password hash lives OUTSIDE source control at auth.password_file
(JSON: account_id, credential_epoch, salt_b64, hash_b64, n, r, p, dklen),
mode 0600. No default password. Rotation = change epoch -> all
sessions revoked, live sockets closed by the adapter's sweep.

Pre-auth: GET /app/ws issues opaque __Host-chat-pre cookie + single-use
synchronizer challenge bound to it server-side. Login POST must present
both; success rotates the identifier and deletes the challenge.

Rate limits (config-owned, persisted SQLite windows keyed to account
and to the actual loopback peer address actually seen, never to
X-Forwarded-For which is untrusted): login attempts per account/peer,
WS commands per session.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  credential_epoch TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  csrf_hash TEXT NOT NULL,
  ws_token_hash TEXT NOT NULL,
  revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS preauth(
  token TEXT PRIMARY KEY,
  challenge_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(
  scope_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS clients(
  client_id TEXT PRIMARY KEY,
  record TEXT NOT NULL);
"""


def sqlite(db_path):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    db = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    db.commit()
    try:
        db.execute("SELECT client_id FROM clients LIMIT 1")
    except sqlite3.OperationalError:
        pass
    return db


def token_hash_of(cookie_header, name):
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            raw = part[len(name) + 1:]
            if raw:
                return hashlib.sha256(raw.encode()).hexdigest()
    return None


def _raw_of(cookie_header, name):
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return ""


class AuthStore:
    def __init__(self, cfg):
        self.cfg = cfg
        a = cfg["auth"]
        self.cookie_name = a["cookie_name"]
        self.pre_name = a["preauth_cookie_name"]
        self.db = sqlite(cfg["adapter"]["state_db"])
        self.lock = __import__("threading").Lock()

    # -- provisioning --
    def load_record(self):
        path = self.cfg["auth"]["password_file"]
        try:
            with open(path) as f:
                rec = json.load(f)
        except (OSError, ValueError):
            return None
        for k in ("account_id", "credential_epoch", "salt_b64",
                  "hash_b64", "n", "r", "p", "dklen"):
            if k not in rec:
                return None
        return rec

    def verify_password(self, password, rec):
        import base64 as _b
        try:
            salt = _b.b64decode(rec["salt_b64"])
            want = _b.b64decode(rec["hash_b64"])
            got = hashlib.scrypt(
                (password or "").encode(), salt=salt,
                n=int(rec["n"]), r=int(rec["r"]), p=int(rec["p"]),
                dklen=int(rec["dklen"]))
        except (ValueError, MemoryError):
            return False
        return hmac.compare_digest(got, want)

    # -- pre-auth challenge --
    def new_preauth(self):
        token = secrets.token_urlsafe(24)
        challenge = secrets.token_urlsafe(32)
        with self.lock:
            self._purge_preauth()
            self.db.execute(
                "INSERT INTO preauth(token, challenge_hash,"
                " created_at) VALUES(?,?,?)",
                (token, hashlib.sha256(challenge.encode())
                 .hexdigest(), int(time.time())))
            self.db.commit()
        return token, challenge

    def _purge_preauth(self):
        cutoff = int(time.time()) - self.cfg["auth"]["preauth_seconds"]
        self.db.execute("DELETE FROM preauth WHERE created_at<?",
                        (cutoff,))

    def _consume_preauth(self, cookie_header, csrf):
        token = _raw_of(cookie_header, self.pre_name)
        if not token or not csrf:
            return False
        row = self.db.execute(
            "SELECT challenge_hash, created_at FROM preauth WHERE"
            " token=?", (token,)).fetchone()
        if row is None:
            return False
        if int(time.time()) - row[1] > self.cfg["auth"][
                "preauth_seconds"]:
            self.db.execute("DELETE FROM preauth WHERE token=?",
                            (token,))
            self.db.commit()
            return False
        ok = hmac.compare_digest(
            row[0], hashlib.sha256(csrf.encode()).hexdigest())
        self.db.execute("DELETE FROM preauth WHERE token=?", (token,))
        self.db.commit()
        return ok

    # -- rate limits --
    def _limited(self, scope, window, maximum):
        now = int(time.time())
        with self.lock:
            row = self.db.execute(
                "SELECT window_start, count FROM rate_limits WHERE"
                " scope_key=?", (scope,)).fetchone()
            if row is None or now - row[0] >= window:
                self.db.execute(
                    "INSERT OR REPLACE INTO rate_limits(scope_key,"
                    " window_start, count) VALUES(?,?,1)",
                    (scope, now))
                self.db.commit()
                return False
            if row[1] >= maximum:
                return True
            self.db.execute(
                "UPDATE rate_limits SET count=count+1 WHERE scope_key=?",
                (scope,))
            self.db.commit()
            return False

    # -- login / logout --
    def login(self, username, password, cookie_header, csrf,
              peer="loopback"):
        a = self.cfg["auth"]
        acct_scope = f"login-acct:{username}"
        peer_scope = f"login-peer:{peer}"
        if self._limited(acct_scope, a["login_window_seconds"],
                         a["login_attempts_per_account"]):
            return False, "", "rate-limited"
        if self._limited(peer_scope, a["login_window_seconds"],
                         a["login_attempts_per_peer"]):
            return False, "", "rate-limited"
        if not self._consume_preauth(cookie_header, csrf):
            return False, "", "bad-challenge"
        rec = self.load_record()
        if rec is None or username != rec["account_id"] or \
                username != a["account_id"] or \
                not self.verify_password(password, rec):
            return False, "", "bad-credentials"
        token = secrets.token_urlsafe(32)
        csrf_tok = secrets.token_urlsafe(32)
        ws_tok = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.lock:
            self.db.execute(
                "INSERT INTO sessions(token_hash, account_id,"
                " credential_epoch, created_at, absolute_expires_at,"
                " idle_expires_at, last_seen_at, csrf_hash,"
                " ws_token_hash, revoked_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                (hashlib.sha256(token.encode()).hexdigest(),
                 rec["account_id"], rec["credential_epoch"], now,
                 now + a["absolute_seconds"],
                 now + a["idle_seconds"], now,
                 hashlib.sha256(csrf_tok.encode()).hexdigest(),
                 hashlib.sha256(ws_tok.encode()).hexdigest()))
            self.db.commit()
        cookie = (f"{self.cookie_name}={token}; Path=/; Secure;"
                  f" HttpOnly; SameSite=Strict; Max-Age="
                  f"{a['absolute_seconds']}")
        clear_pre = (f"{self.pre_name}=dead; Path=/; Secure; HttpOnly;"
                     " SameSite=Strict; Max-Age=0")
        return True, [cookie, clear_pre], ""

    def logout(self, cookie_header, csrf):
        th = token_hash_of(cookie_header, self.cookie_name)
        if th:
            with self.lock:
                row = self.db.execute(
                    "SELECT csrf_hash FROM sessions WHERE token_hash=?",
                    (th,)).fetchone()
                if row is not None and hmac.compare_digest(
                        row[0],
                        hashlib.sha256((csrf or "").encode())
                        .hexdigest()):
                    self.db.execute(
                        "UPDATE sessions SET revoked_at=? WHERE"
                        " token_hash=?", (int(time.time()), th))
                    self.db.commit()
        return (f"{self.cookie_name}=dead; Path=/; Secure; HttpOnly;"
                " SameSite=Strict; Max-Age=0")

    # -- session checks --
    def check_session(self, cookie_header):
        th = token_hash_of(cookie_header, self.cookie_name)
        if not th:
            return False, None
        return self.check_session_by_hash(th)

    def check_session_by_hash(self, th):
        a = self.cfg["auth"]
        row = self.db.execute(
            "SELECT account_id, credential_epoch, absolute_expires_at,"
            " idle_expires_at, last_seen_at, revoked_at FROM sessions"
            " WHERE token_hash=?", (th,)).fetchone()
        if row is None or row[5] is not None:
            return False, None
        now = int(time.time())
        if now >= min(row[2], row[3]):
            return False, None
        rec = self.load_record()
        epoch = rec["credential_epoch"] if rec else None
        if epoch is not None and row[1] != epoch:
            return False, None
        with self.lock:
            self.db.execute(
                "UPDATE sessions SET last_seen_at=?,"
                " idle_expires_at=? WHERE token_hash=?",
                (now, now + a["idle_seconds"], th))
            self.db.commit()
        return True, {"token_hash": th, "account_id": row[0]}

    def revoke(self, th):
        with self.lock:
            self.db.execute(
                "UPDATE sessions SET revoked_at=? WHERE token_hash=?",
                (int(time.time()), th))
            self.db.commit()

    def expire_sweep(self):
        now = int(time.time())
        rows = self.db.execute(
            "SELECT token_hash, account_id, credential_epoch,"
            " absolute_expires_at, idle_expires_at FROM sessions"
            " WHERE revoked_at IS NULL").fetchall()
        rec = self.load_record()
        epoch = rec["credential_epoch"] if rec else None
        dead = []
        for th, _acct, sess_epoch, abs_e, idle_e in rows:
            if now >= min(abs_e, idle_e) or \
                    (epoch is not None and sess_epoch != epoch):
                dead.append(th)
        with self.lock:
            for th in dead:
                self.db.execute(
                    "UPDATE sessions SET revoked_at=? WHERE"
                    " token_hash=?", (now, th))
            self.db.commit()
        return dead

    # -- synchronizer tokens --
    def new_form_token(self, cookie_header):
        th = token_hash_of(cookie_header, self.cookie_name)
        if not th:
            return ""
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.db.execute(
                "UPDATE sessions SET csrf_hash=? WHERE token_hash=?",
                (hashlib.sha256(tok.encode()).hexdigest(), th))
            self.db.commit()
        return tok

    def check_form_token(self, cookie_header, csrf):
        th = token_hash_of(cookie_header, self.cookie_name)
        if not th:
            return False
        row = self.db.execute(
            "SELECT csrf_hash FROM sessions WHERE token_hash=?",
            (th,)).fetchone()
        if row is None:
            return False
        return hmac.compare_digest(
            row[0], hashlib.sha256((csrf or "").encode()).hexdigest())

    def rotate_ws_token(self, th):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.db.execute(
                "UPDATE sessions SET ws_token_hash=? WHERE token_hash=?",
                (hashlib.sha256(tok.encode()).hexdigest(), th))
            self.db.commit()
        return tok

    def check_ws_token(self, th, csrf):
        row = self.db.execute(
            "SELECT ws_token_hash FROM sessions WHERE token_hash=?",
            (th,)).fetchone()
        if row is None:
            return False
        return hmac.compare_digest(
            row[0], hashlib.sha256((csrf or "").encode()).hexdigest())

    def check_command_budget(self, token_hash):
        a = self.cfg["auth"]
        scope = f"cmd:{token_hash}"
        return not self._limited(scope, a["command_window_seconds"],
                                 a["commands_per_session"])
