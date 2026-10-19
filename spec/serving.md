# Serving contract v1

Status: implementation specification, not a deployment or binding proof.
Authority: t_52b7c4a5; serving decision t_97dedb07; PM R1–R6 on t_35058d43 override meeting proposals; product v3 and MJ rulings on t_28c018e2 remain authoritative. Composer send belongs in the first usable release. This change contains specification only.

## Components and boundaries

Browser -> Caddy (TLS/static release) -> p5serve adapter (127.0.0.1:9120) -> p1transport client/protocol -> HermesProvider (proposed 127.0.0.1:9121) -> installed Hermes CLI -> configured model/tools.

One adapter process and one supervised provider worker/listener in that same service process; subprocess Hermes runs are backend work, not another public service. Use stdlib Python for serving, SQLite and subprocess integration. p1chat owns chat state/validation, p2rich owns rendering/budget/sandbox, p3drawer owns allowlisted page operations, p4ops owns promotion/eviction/queue policy. The adapter invokes these modules; it owns transport/session orchestration only. Existing harness JavaScript drawer storage is NOT the served authority. Narrow mount/dispatch injection is allowed; do not fork its policies in a new renderer.

Trade-off: durable local state and a real agent worker cost more than a framing proxy, but an acknowledgement fixture cannot deliver chat.

## Read-only binding survey

On the Iran host during this task, `ss -lntp` showed Hermes listening on :9119, Caddy :80/:443/:2019, SSH :22, resolver and Tailscale listeners. No :9120/:9121 or identifiable line-JSON Hermes provider was present. :9119 is the existing HTTP dashboard, not evidence of our line-JSON endpoint; do not redirect it or assume its private chat API is this protocol.

At baseline 06c1c216ae82eea794252dbee67d912e2f12bee7:
- p1transport/provider.py binds an ephemeral loopback port; _accept_payload returns `acked:<id>:<revision>` for text, has in-memory revision/cursor/action state, and never calls Hermes.
- client.py Client.reconnect replays its outbox automatically; that method is unsafe for interrupted agent actions under this contract.
- protocol.py supplies encode_frame/decode_frame and hello/resume/session/payload.get/payload.data/result helpers. A result status=ok from the fixture is NOT an assistant answer.
- `/root/.local/bin/hermes` delegates to `/root/.hermes/hermes-agent/.hermes/bin/hermes`. `hermes chat --help` confirms --query-file, --oneshot, --format stream-json, --resume, --no-restore-cwd and --source. Installed hermes_cli/stream_json.py emits system/init, text/tool events and terminal result with session_id, exit_code, text, tokens, duration_ms.

Conclusion: a binding MUST BE BUILT; this survey does not prove absence of every dormant service, and no real model call was made in this spec task. No placeholder endpoint qualifies for release.

## Public route and authentication sequence

Exactly one dynamic path: /app/ws (no trailing slash or query parameters). All other paths are static assets/navigation supplied by Caddy. No /api, /login, /logout, /health or asset-fetch dynamic routes.

GET /app/ws without Upgrade is a top-level navigation to the minimal login/challenge page, Cache-Control: no-store. It issues an opaque pre-auth __Host-chat-pre cookie and a hidden synchronizer CSRF challenge bound server-side to that cookie. Login is a native form POST /app/ws with application/x-www-form-urlencoded fields op=login, username=mj, password, csrf. Exact Origin is required on POST. Successful POST rotates the identifier, deletes the pre-auth challenge and returns 303 Location: / with the session cookie. Failure uses the same generic message, never echoes credentials. No application fetch/XHR is needed. Authenticated GET may show a native logout form with op=logout and fresh synchronizer token; successful logout POST revokes then redirects. These are same-path auth controls, not extra routes or page internet access.

Authenticated GET /app/ws with RFC6455 Upgrade requires exact Origin https://chat.typeacid.ir, Host chat.typeacid.ir, version 13, valid key and subprotocol hermes.web.v1. Reject missing/null/multiple/unexpected Origin before 101; do not trust forwarded identity headers. On upgrade send welcome including per-session CSRF token. Every mutation over WS includes that token; reads do not. HTTP CSRF challenges and WS tokens are not login credentials and are held only in trusted page memory/forms, never passed to the frame. Use constant-time comparisons.

Cookie: __Host-chat=<opaque random value>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age from config; no Domain. No bearer in localStorage/sessionStorage, URL, subprotocol or log. Server stores only SHA-256(token), not the raw session token. Provision an mj scrypt hash record outside Git at auth.password_file, mode 0600, service-user readable; no default password. Password record JSON: {account_id:"mj",credential_epoch:<opaque string>,salt_b64:<string>,hash_b64:<string>,n:<integer>,r:<integer>,p:<integer>,dklen:<integer>}. Parameters come from config and are checked against provisioned record. Rotation changes epoch, revokes all sessions, closes all sockets and invalidates pending admission; never accept an old in-memory hash indefinitely.

Session SQLite record: {token_hash,account_id,credential_epoch,created_at,absolute_expires_at,idle_expires_at,last_seen_at,csrf_hash,revoked_at}. Times are UTC epoch seconds. Persist CSRF verification material; generate fresh token on upgrade and invalidate older socket tokens with socket generation. Expiry is minimum idle/absolute deadline and is checked before every mutation and by a timer even on an idle socket. Revocation/expiry clears cookie on next HTTP response and closes associated sockets with 1008. Existing backend execution may already have effects; logout is not an undo.

## WS boundary: exact shapes

WS text messages contain exactly one JSON object, UTF-8, without a line terminator; escaped newlines inside strings are allowed. Reject duplicate keys, non-finite numbers, binary frames, unsupported RSV/compression and unknown required operations. Unknown additive fields may be ignored only after validation; they never become HTML attributes or destination settings. Integer fields are nonnegative integers, not booleans. Opaque IDs are server-generated and ownership checked.

Client message:

    {"v":1,"kind":"command","request_id":"<opaque>","client_id":"<assigned>","generation":<integer>,"csrf":"<token or null>","op":"<enum>","body":{...}}

Initial command is op=attach with client_id=null, generation=0, csrf=null, body={tab_id:<random browser hint>,release_id:<static release>,cursor_hint:<string or null>}. Server resolves only authenticated ownership, allocates or recovers logical client, increments durable generation and fences previous socket. welcome below assigns client_id/generation. All later commands must match them.

Allowed ops/body:
- snapshot: {} (read).
- chat.send: {conversation_id:<owned id>,text:<string>} (write).
- action.invoke: {conversation_id:<owned id>,action_id:<registered id>,values:<object>,context_id:<owned id>,expected_revision:<integer>,confirm:<boolean>} (write, confirmation checked by domain).
- drawer.read: {} (read).
- drawer.op: {op:<p3drawer op>,args:<object>,expected_revision:<integer>} (write; return feature-disabled until enabled, never browser-local success).
- view.set: {bubble_id:<owned id>,mode:<p2rich accepted mode>} (write through domain).
- receipt: {event_seq:<integer>} (persist projection cursor, not backend execution acknowledgement).
- logout: {} (write, revokes session before close).

Server message:

    {"v":1,"kind":"event","request_id":"<correlated id or null>","client_id":"<assigned or null>","generation":<integer>,"event_seq":<integer>,"op":"<enum>","body":{...}}

Server ops/body:
- welcome: {csrf:<token>,release_id:<string>,protocol:"hermes.web.v1",state:"resuming"}.
- snapshot: {conversation_id:<id>,revision:<integer>,cursor:<string or null>,bubbles:<array>,drawer:<domain projection>,pending:<array of request outcomes>}. Each bubble is {id,revision,major,role,text,preview_html,frame_payload}; preview_html/frame_payload are p2rich outputs only; missing rich representation is null, text is escaped by textContent. role is user or assistant, assigned by provider history, not browser.
- patch: {region:"bubbles"|"drawer-items"|"add-content",revision:<integer>,items:<domain projection array>}. Stable item IDs permit incremental replacement; no arbitrary selector or script field.
- status: {state:"ready"|"backend-unavailable"|"resuming"|"resync-required"|"reload-required"|"policy-unavailable",detail:<safe text>}.
- outcome: {status:"rejected"|"accepted"|"completed"|"failed"|"outcome-unknown",code:<stable string>,message_id:<id or null>,cursor:<string or null>}. accepted means durable admission, not delivered or agent success. completed requires durable real provider result.

These are a serving wrapper, NOT a replacement for p0 envelope v1. Browser sends semantic commands so Python remains authoritative. Adapter creates p0 envelopes with protocol helpers; bootstrap/session and payload exchange stay on upstream TCP. It does not forward WS wrapper bytes onto TCP. One encoded p0 envelope plus LF per upstream frame; one decoded frame per dispatch, partial reads buffered with a configured byte limit. Validate references and payload SHA-256 before execution. Escape JSON control characters; never split JSON on an embedded escaped newline. Client/protocol behavior stays compatible with existing tests. Resume uses Client.connect(resume=True) plus restored safe state, NOT Client.reconnect with uncertain outbox entries. Backend result text is consumed as assistant output only after its durable completion, not Client.bubbles (which contains submitted user text).

RFC6455: validate masking, opcodes, lengths and close payloads; support bounded fragmented text with interleaved ping/pong, reject malformed sequence with 1002, invalid UTF-8 1007, oversized aggregate 1009. Server frames unmasked; control frame bounds follow RFC, not tunable policy. Negotiate no compression. Serialize socket writes. Unsupported method gives 405; unknown path 404; auth failure 401/403 before upgrade; rate limit 429 with Retry-After; unhealthy admission does not manufacture 101 success/readiness.

## Provider surface to build

Add HermesProvider in p1transport/hermes_provider.py, preserving Provider as a test fixture. Interface: start(host,port,settings,store)->bound_address; stop(); existing v1 hello/resume/payload.get/payload.data/result on TCP. Bind loopback only. Authentication/capability between adapter and provider is an out-of-band service-owned secret supplied by settings secret-file reference, checked in hello/resume bootstrap extension `service_auth`; do not log or send it to browser. Only admitted local service clients may negotiate. Endpoint is server configured, never browser supplied.

Provider store uses SQLite outside release dirs: conversations(conversation_id,account_id,hermes_session_id,revision); requests(account_id,conversation_id,request_id,payload_hash,state,user_message_id,assistant_message_id,result_json,started_at,finished_at); history(conversation_id,event_seq,message_id,revision,major,role,text,fragment_json); pins and cursors. Unique request key and payload hash enforce duplicate rejection/reuse; same ID with different bytes is conflict. Commit pending intent before launching Hermes; commit result/history/cursor in one transaction before completed. Crash with running intent becomes outcome-unknown, never re-launch it. Serialize turns per conversation with bounded agent-owned admission, return conflict/busy rather than fork a Hermes session. Two devices see the same ordered conversation history with separate client cursors.

After payload validation for text {text:<string>}, allocate request/message IDs without colons in message IDs (baseline Provider parses get:<msg_id>:<revision>). Do not use remote command text as a shell command. subprocess.Popen uses argv (shell=False):

    /root/.local/bin/hermes chat --oneshot --query-file - --format stream-json --no-restore-cwd --source interface-app

Pass exact text through stdin then close stdin. For existing conversation append --resume and its stored Hermes session ID, never latest. Set cwd to provider.workspace. Resolve execution HOME/profile from provider.hermes_home (default main Hermes home, explicitly not the architect worker profile). Strip inherited HERMES_KANBAN_TASK, HERMES_KANBAN_WORKSPACE, board dispatch and worker identity variables so chat cannot accidentally complete a board task. Retain configured provider credentials via Hermes's normal resolution; never copy them into the adapter or browser. Do not add --yolo or silently change approval settings. Approved tool restrictions come from the existing Hermes profile; unattended approval refusal is a visible failed turn, not bypassed approval.

Parse stdout JSONL independently of our TCP envelope; only terminal type=result with exit_code=0, nonempty text and session_id plus successful process exit is a successful agent answer. Store system/init session mapping when available before a potential crash. Tool events/deltas may be logged privately or projected as clearly provisional status, never a final fabricated answer; do not forward raw tool results/secrets. Exit error, malformed/missing terminal record or timeout yields failed/outcome-unknown according to whether execution began. A terminal failure must not be wrapped in mk_result status=ok as a success. Provider can use mk_result for successful completion and additive bootstrap metadata {conversation_id,request_id,message_id,assistant_message_id,hermes_session_id,outcome}; errors use validated error envelope or explicit failed result metadata that adapter checks. Read-only history/outcome lookup uses additive hello/resume session fields `history`, `cursor`, `requests`, `conversation_id` after account ownership check. This permits recovery without re-execution and without new public routes. Bind text first; action invocation calls existing dispatcher/allowlist and can be disabled until genuinely wired, never generic arbitrary subprocess execution.

Binding evidence gate (builder, NOT fulfilled by this document): capture redacted timestamped transcript containing release and commit; browser request_id/conversation_id/text; adapter generation and p0 message/payload hash; provider durable request transitions; actual CLI argv excluding secrets; system/init session_id; terminal result exit_code/text/session_id and process exit; provider history assistant ID/cursor; WS completed plus rendered DOM bubble text/ID. Prompt must contain a fresh verifier-supplied nonce/question, not a golden response. Correlate terminal text to DOM and stored Hermes session, include exact launch/browser/test commands and actual outputs. Include provider/adapter restart and lost-response lookup demonstrating no second CLI launch for the same request. Fixtures and echo/acked strings remain useful tests but never binding proof. If real credentials/runtime/permissions prevent this, builder blocks R1; no placeholder ships.

## Recovery, admission and persistence

SQLite at state_db, WAL and transactions, service ownership and 0600 data files, lives outside code/releases. Records: logical_clients {account_id,client_id,tab_hint,conversation_id,generation,upstream_cursor,projection_receipt_seq,last_seen:[{id,revision,major}],pins:[{id,revision,fragment_id,fragment_version}],registry_revision,budget_revision,updated_at}; pending {account_id,client_id,request_id,payload_hash,state,backend_request_id,created_at,updated_at}. Persist generation and intent before I/O; commit authoritative cursor/pins/history before projecting completed. No resume secret returned to browser; client ID/tab hint confers no authority. SQLite unavailable/disk-full/schema mismatch means fail-closed writes, degraded shell and no agent execution. Reads may show only verified cached state explicitly marked stale.

Reload attaches authenticated tab hint to persisted record, fences old generation, resumes upstream, validates/re-pins with protocol helpers, hydrates snapshot and only then enables mutations. A duplicate tab hint displaces old socket rather than creating two writers. Different tabs/devices have different records; account/conversation ownership is mandatory. Browser cursor can request older visible position but cannot advance authoritative upstream cursor, inject pins or claim execution. Missing/expired cursor requires explicit full snapshot/resync; it never means an empty successful history. Incompatible release or schema produces reload-required before any write; keep draft and no silent bundle mixing.

Interrupted writes are outcome-unknown after bytes may have left; never auto-resend chat, destructive action or drawer mutation. Reconnect queries outcome/history by durable request_id. Only a known never-admitted rejected request may be submitted again by explicit user action; unknown requires reconciliation or an explicit new user action acknowledging possible effects. Draft is retained locally in sessionStorage with configured size bound, scoped to account/conversation, no credential, cleared on logout; clear sent draft only on durable accepted and retain pending text until resolved. No automatic queued offline send.

WS Ping/Pong crosses browser–Caddy–adapter only; send configured ping interval and close on missing pong deadline. Upstream TCP transport liveness uses configured SO_KEEPALIVE and supported TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT independently, plus connect/write deadlines. No mapping WS ping into chat or invented p0 heartbeat type; installed client has no standalone application heartbeat API. Long agent turns must not be killed by its baseline five-second roundtrip timeout: serving injection sets configured upstream read deadline covering agent timeout plus grace. Report WS-alive/TCP-dead as backend-unavailable, TCP-alive/WS-dead retains durable result. Reconnect uses full jitter delay uniform(0,min(cap,base*factor^attempt)), reset after configured stable interval, no send replay.

Admission requires valid session/CSRF/generation, hydrated domain state, live backend, valid payload and fresh p4ops queue policy. Agent supplies queue_max_messages/queue_max_bytes/inflight_per_conversation and policy revision/expiry in a persisted policy file. Adapter safety ceilings further bound these values; missing/stale policy rejects writes policy-unavailable, does not invent a fallback queue policy. Reject before upstream write when full (outcome rejected, code busy). Saturated outbound queue stops projection and closes 1013/resync-required; durable history is source of recovery, never unlimited buffering. Bound each frame, queue, socket count, parser, subprocess output and database wait using configuration. Do not evict history to relieve transport pressure; that is managing-agent work.

## Static shell, iframe and no-page-network contract

Static release-owned chrome: app/header/nav, composer and buttons, drawer skeleton/Add-last affordance, Add/i form frames and confirmation/error controls, login link, logout/reconnect/offline banner, bubble mode/expand/collapse controls, one iframe host and trusted transport/bridge bundles. Mount IDs: app-shell, composer, connection-status, bubbles, drawer-items, add-content, frag-frame. IDs identify fixed slots, never provider selectors. Data-owned regions: user/assistant bubble text/bounded previews, validated frame content, drawer item labels/state, allowlisted Add contents. Reuse p1chat and p2rich rendering seams, p3drawer.ops server dispatcher; disable the sandbox harness's localStorage drawer dispatcher in served mode. Snapshot updates content slots incrementally; never document.write, outerHTML of app-shell/body, replacing composer or a second JS policy renderer. Preserve focus, draft, form values and scroll anchor.

Exactly one reusable iframe sandbox="allow-scripts", srcdoc generated by p2rich; no allow-same-origin, popups, navigation or forms. Retain trusted p2rich frame bundle rather than introduce a second renderer. postMessage op allowlist and p0 render_policy validation remain authoritative; check event.source against the actual frame, per-instance random channel token, context, current fragment and registered action for effect-bearing messages. Opaque origin "null" is not authentication. Reverse messages form-state/action-click are typed bridge events and never raw backend commands. Forward actions through parent WS/domain validation; frame never receives CSRF/cookie/resume auth. Rotate frame token/context on replacement/logout, reject stale messages. Resize accepts finite numeric dimensions within config limits; clamp and scroll on excess, preserve mobile focus.

Parent CSP: default-src 'none'; connect-src wss://chat.typeacid.ir/app/ws; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; script-src and style-src only pinned release hashes (including inherited srcdoc script hash), frame-src only minimum srcdoc-compatible policy validated in the real browser gate. No unsafe-inline/eval, external font/CDN/media, service-worker or generic self connect wildcard. Static asset loading and top-level same-origin native auth navigation are shell operations, not a separate page data channel. Browser uses WS only for application data; no fetch/XHR/EventSource/beacon/WebRTC/WebTransport or additional data sockets. Frame CSP keeps connect-src/form-action/frame-src/object-src/base-uri 'none', hash-pinned trusted script only. Content cannot introduce links, URLs, inline style/scripts or resource requests; navigate-to alone is not a supported-browser security boundary. Remote assets must arrive as validated backend protocol asset bytes/IDs (initial text-only build may show fallback), never an adapter URL proxy. Browser network capture must show only release assets, auth navigations and the one WS, zero frame/remote data requests.

Backend dead: cached/static shell paints, banner says Backend unavailable, composer retains draft but send is disabled, verified cached history is explicitly stale; never golden bubbles masquerading as live chat or a blank document. p2rich invalid content shows escaped fallback. Expired auth shows sign-in state and closes socket. Status is not inferred from static status.json test counts.

## Runtime settings (normative defaults, not Python literals)

Implementation ships a settings template loaded at startup. Missing/invalid required entries prevent readiness; constraints are security invariants, not adjustable ways to disable auth. Settings changes require restart unless noted. Numeric operational defaults below are configuration entries; no duplicate hidden literals in JS/Python. Extra thresholds introduced later must be added here and tested under non-default settings. Production secrets never enter the template.

    {
      "adapter": {
        "bind_host":"127.0.0.1", "bind_port":9120,
        "path":"/app/ws", "origin":"https://chat.typeacid.ir",
        "host":"chat.typeacid.ir", "subprotocol":"hermes.web.v1",
        "state_db":"/var/lib/interface-app/serving.sqlite3",
        "release_id":"REQUIRED_RELEASE_ID",
        "max_connections":8, "http_header_bytes":16384,
        "http_body_bytes":16384, "http_timeout_seconds":10,
        "frame_bytes":1048576, "json_depth":64,
        "write_timeout_seconds":10, "sqlite_busy_seconds":2,
        "outbound_messages":64, "outbound_bytes":2097152,
        "queue_safety_messages":64, "queue_safety_bytes":2097152,
        "retry_after_seconds":60,
        "ws_ping_seconds":20, "ws_pong_timeout_seconds":10,
        "session_check_seconds":1, "credential_check_seconds":1,
        "reconnect_base_seconds":1, "reconnect_factor":2,
        "reconnect_cap_seconds":30, "reconnect_stable_seconds":60,
        "draft_bytes":65536, "frame_min_height":80,
        "frame_max_height":800, "frame_ready_timeout_seconds":10
      },
      "auth": {
        "account_id":"mj", "password_file":"/etc/interface-app/mj-password.json",
        "cookie_name":"__Host-chat", "preauth_cookie_name":"__Host-chat-pre",
        "token_bytes":32, "csrf_bytes":32, "salt_bytes":16,
        "scrypt_n":16384, "scrypt_r":8, "scrypt_p":1, "scrypt_dklen":32,
        "absolute_seconds":86400, "idle_seconds":3600,
        "preauth_seconds":300, "login_window_seconds":300,
        "login_attempts_per_account":5, "login_attempts_per_peer":10,
        "command_window_seconds":60, "commands_per_session":60
      },
      "upstream": {
        "host":"127.0.0.1", "port":9121,
        "service_secret_file":"/etc/interface-app/provider-secret",
        "connect_timeout_seconds":5, "write_timeout_seconds":10,
        "read_timeout_seconds":330, "tcp_keepalive":true,
        "tcp_idle_seconds":30, "tcp_interval_seconds":10, "tcp_probes":3
      },
      "provider": {
        "enabled":true, "bind_host":"127.0.0.1", "bind_port":9121,
        "hermes_executable":"/root/.local/bin/hermes",
        "hermes_home":"/root/.hermes", "workspace":"/var/lib/interface-app/work",
        "agent_timeout_seconds":300, "termination_grace_seconds":10,
        "output_bytes":4194304, "stdout_line_bytes":1048576,
        "actions_enabled":false, "drawer_writes_enabled":false
      },
      "policy": {"file":"/var/lib/interface-app/admission-policy.json"}
    }

Owner: service operator owns adapter/auth/upstream/provider settings and secret-file provisioning, including rate limits (persistent SQLite windows keyed to account/actual loopback proxy admission context, never attacker-supplied X-Forwarded-For; account limiter remains effective behind Caddy). p4ops managing agent owns policy.file values, revision and expires_at, crystallization/eviction and existing rich budgets, NOT the browser/adapter. Policy record shape: {revision:<string>,expires_at:<epoch>,queue_max_messages:<integer>,queue_max_bytes:<integer>,inflight_per_conversation:<integer>}; no adapter-supplied numeric defaults. Transport safety ceilings never authorize buffering when policy is missing. Existing renderer limits are read from its authoritative budget/settings; do not copy its preview literals into a new JS renderer. Retention/pruning uses p4ops, not an adapter timer. No automatic destructive schema migration. Backups and schema validation belong in the future ops runbook.

## Stable rule registry / implementation test plan

This table is the machine-readable rule section: delimiter `|`, first two columns are stable ID and exact pytest test function name; each ID appears exactly once here. Never renumber or reuse retired IDs. Each named test must execute its assertions, not merely assert a rule exists; a name may contain multiple parameterized scenarios. Unit fixtures may test mechanics; live/browser acceptance rows must run against the real integration. Builder must report any future-phase browser/ops row not yet exercised instead of claiming all serving gates pass.

| ID | Test | Normative assertion / implementation gate |
| --- | --- | --- |
| S001 | test_s001_route_boundary | Loopback bind, sole /app/ws dynamic path, unknown path/method rejected; no infrastructure edits outside later authorized ops. |
| S002 | test_s002_domain_ownership | Invoke Python p1chat/p2rich/p3drawer/p4ops seams; no served localStorage drawer authority, policy fork, generic URL proxy or browser-selected destination. |
| S003 | test_s003_native_auth_same_path | GET challenge, native POST login/logout, single-use preauth CSRF, generic failure, 303/no-store; no extra dynamic route or fetch. |
| S004 | test_s004_cookie_session | Exact cookie flags, opaque entropy, hashed durable session record, no browser-stored bearer or credential logging. |
| S005 | test_s005_upgrade_origin | Reject wrong/missing/null Origin, bad Host/key/version/subprotocol and unauthenticated upgrades before 101. |
| S006 | test_s006_csrf_writes | Every WS/HTTP mutation checks live session and synchronizer token, rejects frame/missing/stale token without effect. |
| S007 | test_s007_revocation_expiry | Idle/absolute expiry and hash-epoch rotation revoke persisted sessions and close already-live sockets within configured check interval. |
| S008 | test_s008_password_rate_limits | External 0600 scrypt provisioning, no default password, account and peer login limits and command limits persist and honor non-default settings. |
| S009 | test_s009_ws_envelopes | Exact command/event shapes, typed bodies, allowed operations, ownership, unknown op/invalid schema rejected; no wrapper leaks upstream. |
| S010 | test_s010_ws_framing | RFC6455 masking/fragmentation/interleaved control/UTF-8/size errors; no compression, bounded parsing and serialized writes. |
| S011 | test_s011_line_json_translation | p0 helper round-trip, partial/coalesced TCP lines, duplicate-key/nonfinite rejection, payload hash/ref validation and escaped newline integrity. |
| S012 | test_s012_binding_real_hermes | Live browser request through real provider CLI terminal result to matching assistant DOM bubble and persisted Hermes session; nonce and captured commands/output required. |
| S013 | test_s013_provider_durability | Durable intent/result/history transaction, identical request lookup reuses result, changed payload conflicts, running crash becomes unknown without second agent launch. |
| S014 | test_s014_provider_execution | shell=False argv/stdin, explicit resume session, worker env stripped, correct home/cwd, timeout/output bounds; errors/tool output never fabricated success or approval bypass. |
| S015 | test_s015_real_result_projection | Project actual terminal assistant text, not ack fixture or Client user-text bubble; role, IDs/cursor and failures correlated. |
| S016 | test_s016_fail_closed_admission | Missing/stale policy, full queue, unavailable backend, invalid session/state reject before send; non-default agent queue limits and safety ceilings effective. |
| S017 | test_s017_slow_consumer | Bounded outbound bytes/messages, 1013 and explicit resync, recover from durable history without eviction or unlimited buffering. |
| S018 | test_s018_store_failure | Disk-full/SQLite failure/schema mismatch prevents execution and false acknowledgement, preserves degraded static shell and stale labeling. |
| S019 | test_s019_resume_records | Persist all logical-client fields/intent/generation, reload/restart snapshot and re-pin; browser cursor/tab/pins cannot assert authority. |
| S020 | test_s020_socket_fencing | New generation fences old callbacks/receipts/actions; separate devices retain cursors and shared ordered conversation; revision conflicts explicit. |
| S021 | test_s021_unknown_no_replay | Reload/drop mid-send queries outcome by ID; no Client.reconnect auto-outbox replay, no automatic chat/destructive resend, pending text retained. |
| S022 | test_s022_split_liveness | WS ping and upstream TCP failure tested independently, long turn exceeds baseline five seconds without failure, runtime deadlines/backoff honored. |
| S023 | test_s023_release_resync | Incompatible bundle/schema blocks writes with reload-required; expired cursor gives full resync, never falsely empty history. |
| S024 | test_s024_static_mounts | Real browser incremental update preserves composer node/focus/draft/scroll and one iframe; only named dynamic slots change. |
| S025 | test_s025_sandbox_bridge | allow-scripts-only opaque frame, pinned trusted bundle, source/token/context/fragment/action/schema validation and stale-token rejection; no CSRF/auth in frame. |
| S026 | test_s026_no_page_network | Real browser CSP/network capture denies content/frame requests and navigation; only shell assets/native auth and single WS; backend assets use protocol, never URL fetch proxy. |
| S027 | test_s027_dead_backend_shell | Backend death gives visible unavailable shell, disabled send, preserved draft and labeled stale history; no blank/golden/fabricated chat. |
| S028 | test_s028_runtime_configuration | All tunables loaded/validated from settings, absent/invalid fails readiness, non-default thresholds affect behavior, p4ops policy retains ownership. |
| S029 | test_s029_frame_focus_size | Real frame action/form state round trip, bounded resize fallback and keyboard/focus preservation without another renderer. |
| S030 | test_s030_release_recovery | Later ops gate: paired static/adapter versioned symlink rollback plus service restart and reboot restore durable sessions/history; no unknown send called delivered and protected host surfaces untouched. |

Implementation order: S001–S011 security/framing; S013–S023 provider/recovery/admission with first composer; S024–S029 real browser mounting/CSP; S012 real binding evidence before any usable release; S030 only after written ops rollback procedure and separate infra authorization. Existing 111 tests remain baseline, not substitutes for these tests. No need to create another task: t_9dd03430 implements this contract and its existing downstream verification/chat/ops cards own the successive gates.

Open implementation risks, not undecided interfaces: installed Hermes process/credentials may fail under the chosen service identity; builder must prove them with S012 or block. Static hash pinning of an instance-specific p2rich srcdoc must be reconciled by release-owned bundle plus data initialization without weakening CSP; S025/S026 must verify actual browser inheritance. CLI terminal result is batch completion, not a promise of streaming token UI. No deployment, Caddy, systemd, firewall, SSH, Tailscale or Frankfurt change is authorized by this spec.
