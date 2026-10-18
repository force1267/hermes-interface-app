# Interface App contract — envelope v1

Status: P0 normative handoff. Source: approved plan v3 (t_b7071cc0), root t_28c018e2 including verifier rounds, and its [mj-rulings]. Those rulings replace all starter thresholds and per-page egress grants. This task authorizes contract work; it does not implement P1–P4.

MUST means a conformance requirement. Rule IDs are test IDs; every ID below needs a passing test in the implementation child t_badfd72c. Numeric protocol versions, JSON arities, and hashes are format constants, not resource policies. No usage threshold, retention interval, pin count, cache size, queue size, or layout budget is a compiled policy constant.

## Ownership and boundaries

Provider (Iran backend): authenticated protocol endpoint, immutable payload store, action dispatcher, version registry, SQLite product/event/decision state, and policy executor. Managing agent: runtime policy author for its owned API/plugin, not a bypass around validation or authorization. Web client: static chat/drawer/Add/i chrome, budget enforcement, trusted component renderer, and one sandboxed iframe. CLI: protocol plus text fallback. Frankfurt relay: forwarding only, no renderer, registry, policy, or product state. A second renderer, native client, Mission Control, and headless parity harness are deferred.

Registry owner is the backend maintainer (MJ approval for new built-ins or components). Registry is source-controlled provider data, not an independently mutable list in each page. Runtime registry snapshots have a revision and are distributed through hello. Policy decisions refer to that revision; mismatches are stale, not implicit grants. Dynamic pages reference immutable fragment IDs and action IDs; they cannot amend registries.

## 1. Wire and payloads

E01. Wire units are UTF-8 JSON objects. Reject duplicate JSON keys, non-JSON numbers, wrong required types, missing required fields, and null where not explicitly permitted. Strings described as IDs are nonempty opaque strings; never interpret them as filesystem paths or executable expressions. Arrays declared as sets contain unique strings. Unknown ordinary fields are ignored at every schema level, but never executed or treated as permissions.

E02. Every envelope has exactly these defined fields (additional fields allowed by E01):

| Field | Required type and meaning |
|---|---|
| type | string; registered message type |
| version | object {major: positive integer, minor: nonnegative integer}; envelope version, initially {major:1,minor:0} |
| min-compat | same version object; minimum reader version within this major, not greater than version |
| id | string; stable logical message ID across retries and dual-published representations |
| revision | nonnegative integer; replacement revision within id |
| payload-ref | object {id:string, version:version-object, sha256:string}; immutable backend payload identity/version; sha256 is lowercase 64-hex digest of exact stored UTF-8 payload bytes |
| caps | unique string array of REQUIRED capabilities, not grants |
| fallback | object {text:string}; nonempty plain text, always readable without fetching payload |

No inline executable or HTML payload exists. Payload resolution is authenticated through the same provider protocol, not a URL in payload-ref. Receiver MUST verify hash and payload version before use. Payload versions describe the referenced schema, not envelope version. Fallback is inert text (no HTML/Markdown execution).

E03. Initial message registry is: hello, resume, session, text, fragment, action, result, error, payload.get, payload.data. Each uses E02 and its registered JSON payload. Bootstrap hello/resume include an additional required `bootstrap` field containing their payload as an exact UTF-8 JSON string inline; payload-ref describes those exact string-content bytes held by the sender, so no payload fetch is required to negotiate. On bootstrap mismatch reject the session. payload.data includes `data` (the exact payload UTF-8 string) inline, matching its payload-ref; this is the terminating payload transfer, never another mandatory fetch. payload.get has required inline `bootstrap` JSON-string payload {ref:payload-ref-object,request_id:string}, checked against its own payload-ref without fetching. payload.data additionally has required top-level request_id:string; it references and carries the requested payload bytes, not a recursively wrapped payload. session/result/error also carry their small registered payload as required inline `bootstrap` JSON strings, hash-checked locally. Each response is correlated by request_id (inside result/error payloads, top-level for payload.data). Other payloads are obtained from a local validated cache or payload.get. Implementation may preload a reference in a test store; P0 requires no live transport.

E04. Payloads: text={text:string}; fragment=section 3; action={action_id:string,request_id:string,context_id:string,values:object}; result={request_id:string,status:"ok",text:string}; error={request_id:string,code:string,text:string,retryable:boolean}; session=section 2. values contains inert JSON only and is validated against the registered action input schema. Unknown actions never execute; an unassigned-button interaction uses registered `agent.request` with label/context as inert input, not an invented action. Authenticated backend dispatcher owns side effects, permission checks, and request_id deduplication. Replayed action returns the saved result, not a repeated effect.

E05. Unsupported type/kind/version/capability, missing or corrupt payload, and failed validation render fallback with a static reason indicator; never silently drop a logical message or execute the partially validated tree. E01 malformed envelopes produce a static protocol error (id may be unavailable). A bad update retains the previous good representation of the same id with a warning, else fallback. A revision cannot replace a newer revision; duplicate (id,revision,representation-major) is inert. Dual-major representations are one logical bubble, choose the highest mutually supported major.

## 2. Evolution and reconnect

V01. Within a major, changes are additive and optional with old behavior as default. No changed meaning/type, removed fields, or newly required fields. Minor versions do not excuse breaking changes. Receivers tolerate unknown ordinary fields; unknown executable semantics (type, kind, component, action, required cap) always fallback/reject rather than ignore. min-compat is checked lexicographically within a matching major; capability support remains a separate check.

V02. A new kind needs an approved registry record {kind:string,version:version-object,min_compat:version-object,schema_id:string,required_caps:string[],fallback:"text",golden_test:string}. Initial kinds are text, card-list, form, media; kind payloads all use the fragment tree below, with text restricted to Text, card-list to layout/Text/List/Button, form additionally Field, and media additionally Media. Nested layout containers are permitted in every kind. A registry insertion without schema, text fallback, and passing golden fixture is rejected. Pending kinds are text in chat and do not block Add-flow or imply a new component.

V03. Breaking changes require a new major and dual-publish: two valid representations sharing id/revision and equivalent intent, each validated against its own major. Registry migration record {migration_id,from_major,to_major,state:"dual"|"retired",agent_decision_id} controls serving. No fixed retention window or count is implied. Managing agent must explicitly authorize retirement with observed compatibility evidence; offline clients outside supported majors get static incompatibility text, not a promise of indefinite support. No migration may reinterpret old bytes under a new schema.

V04. hello payload={client_id:string,supported_versions:version-object[],caps:string[],registry_revision:string|null,budget_revision:string|null}. resume adds `last_seen` array of {id:string,revision:integer,fragment_id:string|null,fragment_version:version-object|null} and `cursor`:string|null. New clients use empty last_seen and null cursor; absence of history is not evidence of incompatibility. session payload={selected_version:version-object|null,registry_revision:string,mode:"rich"|"text",reason:string,upgrade_available:boolean,pins:array}. Each pin={id:string,revision:integer,fragment_id:string,fragment_version:version-object}. Provider selects highest common major/minor it can serve, then checks required caps and per-fragment schema. Null selected_version means static incompatibility status only; do not decode an unsupported major as v1.

V05. On every hello/resume, re-evaluate current capabilities and registry, re-pin to compatible approved last-good fragments or send static text with required version/capabilities and upgrade nudge. No sticky downgrade flag survives negotiation. Next reconnect with compatible support MUST re-upgrade without regenerating a known good fragment. A new client can receive supported current fragments without pretending its last-seen version is zero. P1 owns cursors, retention-gap resync, keepalive and fault-injection transport tests; P0 tests selection as a pure function.

## 3. Fragment and UI schema

F01. Fragment required fields: {fragment_id:string,version:version-object,kind:string,mode:"standard"|"expanded",origin:"generated"|"cached"|"builtin",fallback_text:string,tree:Node}. fallback_text is nonempty. Envelope fallback equals fallback_text. Immutable identity is (fragment_id,version,hash); changed bytes require a new version. A cached/builtin label never skips validation or confers authority.

F02. Node={component:string,props:object,children:Node[]}. Full initial component/property allowlist:

| Component | Allowed props (all required unless marked optional) | Children |
|---|---|---|
| Stack | direction:"vertical"|"horizontal" | nodes |
| Text | text:string | empty |
| List | items:string[] | empty |
| Button | label:string, action_id:string, intent:"assigned"|"generative" | empty |
| Field | name:string, label:string, input:"text"|"number"|"boolean", value:matching primitive, optional placeholder:string | empty |
| Media | asset_id:string, alt:string, media_type:"image"|"audio"|"video"|"file" | empty |

Every props object admits unknown inert fields for evolution, but the renderer receives ONLY allowlisted validated properties; never spread unknown props onto DOM. No arbitrary CSS/style, HTML, scripts, event-handler source, URLs, expressions, dynamic imports, raw SVG, executable templates, custom elements, or code-bearing component exist. These are rejected wherever a known executable field/component is supplied, including `html`, `code`, `script`, `style`, `src`, `href`, `on*` property keys (case-insensitive). Unknown innocuous fields are ignored; unknown components reject the entire tree. Media assets resolve only through authenticated backend asset IDs, never external/data URLs. Field values never interpolate into HTML or executable code.

F03. Provider declares mode. Client receives revisioned runtime `render_budget` through backend policy: {revision:string,max_inline_height_px:positive number,max_inline_width_px:positive number,max_inline_actions:nonnegative integer,allow_inline_focus_capture:boolean}. Trusted client measures dimensions/action count and input focus behavior. Exceeding any bound escalates to expanded; missing/invalid budget uses static preview with explicit Expand, never unbounded inline content. Budget settings are supplied by managing agent and may change at runtime; no starter numbers in code. Client local accessibility/viewport restrictions may tighten but never weaken the policy.

F04. Effective mode: explicit user expand wins; otherwise provider expanded or any budget overflow means expanded; otherwise standard. User Collapse always closes takeover and returns to a bounded preview when full inline rendering cannot fit. Every rich standard preview has Expand; expanded chrome has Close/Collapse. Expansion preserves form values and request IDs; mid-typing escalation must not submit or discard input. Shared chrome restores focus to invoking control on close and isolates expanded focus while open. Generated origin and generative-intent buttons have one shared visible generative treatment; cached/builtin origin is displayed truthfully. Chrome is not supplied by the tree.

F05. Sandbox contract: a single reusable iframe with sandbox="allow-scripts" and NO allow-same-origin, forms, navigation, popups, downloads, or other sandbox permissions. Only bundled trusted renderer executes; fragments are data. CSP default-src 'none'; connect-src 'none'; form-action 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'. Bundled renderer script uses a build-supplied hash; approved backend-fetched media can be passed as trusted blob handles with narrowly configured media/image blob sources, never a fragment-supplied URL. The parent owns the backend connection. postMessage bridge validates event.source, per-instance unpredictable channel token (opaque-origin frame has no trustworthy origin), exact operation schema, current context, and registered action. Only render, action, resize, ready are allowed bridge operation names; resize is clamped to effective mode budget. Parent never exposes tokens, arbitrary fetch, eval, DOM handles, or a generic RPC bridge. P0 tests policy/bridge validation; P2 must exercise actual sandbox isolation before claiming browser security.

## 4. Backend-only egress

N01. Pages have NO separate internet connection and NO per-page egress grant. Their only application traffic is the parent-mediated authenticated provider protocol. caps declares needs; it cannot authorize them. Direct fetch, external media URLs, form submission, navigation, and websocket creation by fragments are denied. The client application's own backend connection is the static shell's transport, not a generated-page permission.

N02. Backend egress is default deny. Registered action maps server-side to a configured backend connector. Authorization checks current backend connector policy, principal, API/plugin scope, operation, and destination at execution time. Unknown/revoked connector or destination is denied even if a page was previously cached. A runtime `backend_connector` policy record contains {connector_id,owner_api,enabled,allowed_operations:string[],allowed_origins:string[],revision}; disabled or missing record denies. Origins are exact parsed scheme/host/port matches; redirects and resolved addresses are revalidated, private/link-local/loopback destinations denied unless explicitly authorized by backend operator configuration. No destination or credential is accepted from a fragment. MJ approval is required for new backend external authority; cached pages never inherit a stale grant. Removing a connector policy invalidates future calls immediately. Default-deny does not prevent the provider's already configured model connection; that is an explicit backend connector too.

## 5. Signals and managing-agent decisions

P01. Provider records append-only events in the SAME SQLite store as product state; no second analytics store. Required event shape: {event_id:string,at:UTC-RFC3339-string,api_id:string,pattern_id:string,fragment_id:string|null,fragment_version:version-object|null,client_id:string|null,session_id:string|null,event:string,request_id:string|null,details:object}. Deduplicate event_id on ingestion. Event enum: usage, cache_lookup, render_result, user_flag, compatibility, queue_state, resource_state, decision_result. Log IDs/counts/statuses only, not raw prompts, form values, credentials, or uploaded media.

P02. Defined details: usage={count:positive integer}; cache_lookup={eligible:boolean,outcome:"hit"|"miss"|"bypass"}; render_result={status:"ok"|"invalid"|"fallback",reason:string}; user_flag={reason:string}; compatibility={supported_versions:array,selected_version:version-object|null,last_seen:array}; queue_state={bytes:nonnegative integer,items:nonnegative integer,oldest_at:string|null}; resource_state={store_bytes:nonnegative integer}; decision_result={decision_id:string,status:"applied"|"rejected",reason:string}. Eligible lookups have hit/miss, ineligible ones bypass. Hit means a validated compatible cache result was actually served. Invalid cached output records an eligible miss plus render_result invalid, not a hit.

P03. `read_signals({api_id,from,to,pattern_id?})` returns {snapshot_id,from,to,usage_count,eligible_lookups,cache_hits,cache_misses,hit_rate,render_failures,user_flags,store_bytes,queue_state,compatibility,provenance}. Window is caller-selected, half-open [from,to). usage_count sums deduplicated usage counts; eligible_lookups=hits+misses; hit_rate=hits/eligible_lookups, null if denominator zero. provenance contains source event IDs or immutable aggregate IDs and completeness status. Retention gaps are marked incomplete, never invented as zero. Agent judges recurrence/hit-rate trend and whether promotion, quarantine, cleanup, or limits need changing; provider never embeds a frequency cutoff or automatic statistical collapse threshold.

P04. `submit_decision` accepts required {decision_id:string,agent_id:string,api_id:string,at:string,action:string,target:object,expected_revision:string,registry_revision:string,signal_snapshot_id:string,reason:string,parameters:object,approval_ref:string|null}. action enum: promote_cache, propose_builtin, quarantine, restore, pin_version, evict, prune_events, set_render_budget, set_queue_policy, retire_major. Executor derives agent identity/scope from authentication, not agent_id alone. Each target is a typed resource: fragment {fragment_id,version}, event_range {from,to}, policy {policy_id}, or migration {migration_id}. expected_revision is current target revision, including a tombstone revision for absent cache entries. Every decision is persisted with target, evidence snapshot, expected revisions, reason, and authenticated actor BEFORE mutation. Decision and mutation/result are atomic within SQLite (external work uses a durable pending intent and idempotent completion). Duplicate decision_id with identical content returns original result; changed content conflicts. Stale revisions, wrong API ownership, missing evidence, unsafe target, or missing approval reject without mutation and produce decision_result. No decisions means no automatic promotion/eviction; continue ephemeral operation and report policy unavailable/resource pressure rather than silently deleting.

P05. Lane A: managing agent can promote validated compatible fragments to cache without MJ approval; no usage threshold auto-promotes. Lane B: propose_builtin records proposal only; activation requires a separately authenticated MJ approval_ref bound to exact target/version/hash. Same approval discipline applies to new registry components and backend authority, not per-page grants. Pending proposals do not block ephemeral/cached output. No generated code is admitted in Lane A or sent to clients; built-in implementation is reviewed trusted application code, not arbitrary agent payload execution.

P06. Quarantine decision makes target unavailable to cache/promotion, preserves incident evidence, and pins the explicitly named previous validated compatible version if available, else text. User flag and hit-rate change are signals for the agent, not numeric executor triggers. Security/schema validation rejects unsafe output immediately independent of agent availability. Restore requires an explicit logged decision and revalidation; repeated use cannot escape quarantine.

## 6. Prune, eviction, pins and queues

R01. evict targets exact fragment versions, with parameters {replacement_version:version-object|null,allow_orphan:boolean}. Pins are references, NOT unconditional exemption and NOT silently removable: decision must name affected pin/page IDs in parameters. Executor rejects undeclared impacts and active read/upload dependencies; agent must re-pin/retry or explicitly authorize a visible orphan. Atomically invalidate cache and indexes, retain tombstone identity, and mark affected drawer entries `needs_repair`; never silently remove a user-created page. Repair via i-flow attempts compatible replacement/regeneration with user confirmation; if unavailable, say so and offer delete, never promise reproducibility. UX pins are a subset of stored templates, not an extra storage tier; neither has a fixed cap.

R02. prune_events targets an explicit event range or explicit aggregate IDs, includes retained snapshot IDs and `evidence_resolution` mapping affected unresolved decisions/incidents to retained aggregates. It must preserve their referenced evidence and decision audit trail; otherwise reject. Roll up eligible counts before raw-event deletion in one transaction, preserving exact hit-rate denominator and completeness markers. Append-only means records are not overwritten in place; authorized audited pruning is allowed. Retention age/storage ceiling are agent policy, not hard-coded intervals. Prune failure leaves original evidence intact.

R03. set_queue_policy parameters={revision:string,max_bytes:nonnegative integer|null,max_age_seconds:nonnegative number|null,on_overflow:"reject_new"|"ask_user",on_expiry:"ask_user"|"cancel_with_notice",persist_local:boolean}. Null means no agent-imposed bound, not a coded default. Client reports queue_state, receives authenticated policy, and enforces it; agent controls bounds automatically. Missing policy/offline startup forbids new durable media enqueue, retains existing pending data and offers explicit retry/cancel. Never silently truncate, recompress, or drop attachments. Preserve pending status across reconnect; when persist_local=false disclose that closing client loses unsent data before accepting it. Use per-device request IDs and backend deduplication; two devices' queues are distinct, not last-writer-wins. Agent can change policy at runtime, but destructive expiration requires specified notice/confirmation behavior and a logged decision. P1 implements durable delivery; P0 tests policy evaluation and absence of fixed bounds.

R04. Agent unavailability freezes last accepted valid runtime policy, does not invent decisions. Disk-full/logging failure rejects state-changing policy actions (including promotion and eviction) because an unaudited change is forbidden; returns a static actionable error. Provider may decline new work for actual resource exhaustion, but cannot use that exception as a hidden fixed cache/prune threshold. Add-flow failure remains in chat with text/retry and no half-created drawer entry. Degraded content uses compatible validated last-good cache, else text; in-flight media has explicit pending/failure status, not disappearance.

## 7. Conformance acceptance matrix

Each ID above names one test group; use table-driven subcases for multiple requirements. The implementation is not done if only the happy path passes.

| ID | Minimum passing evidence |
|---|---|
| E01 | duplicate/missing/wrong-type/null rejected; unknown inert field accepted |
| E02 | complete envelope accepted; hash/version mismatch and URL-like dereference denied |
| E03 | bootstrap and payload.data terminate resolution; bootstrap byte mismatch rejected |
| E04 | registered action accepted; unknown action denied; duplicate request has one effect |
| E05 | unknown kind/cap/corrupt tree gives visible text; revisions and dual representation deduplicate |
| V01 | unknown additive field retains behavior; incompatible min-compat falls back |
| V02 | all seed kinds have goldens; incomplete new registry record denied |
| V03 | dual-major publishes yield one bubble; retirement requires logged decision |
| V04 | highest common version chosen; empty new-client history does not force downgrade |
| V05 | forced skew yields text then compatible resume re-upgrades same logical bubble |
| F01 | valid immutable fragment accepted; changed bytes under same identity denied |
| F02 | each component validates; raw code/event/URL rejected; unknown inert props stripped |
| F03 | supplied budget bounds enforced; runtime replacement changes result; missing budget preview |
| F04 | declaration/overflow/user override truth table; collapse preserves unsent values/focus target |
| F05 | bridge source/token/op/shape failures denied; sandbox/CSP config denies direct egress |
| N01 | requested page grant and direct network operation denied even with declared caps |
| N02 | default denied; explicitly authorized backend action succeeds; revocation/redirect denied |
| P01 | duplicate event ingests once into same store; event contains no raw content |
| P02 | invalid cache output cannot count as hit; bypass excluded from eligible count |
| P03 | selected-window counts/rate correct; empty denominator null; pruned gap incomplete |
| P04 | decision logged and atomic; replay idempotent; stale/wrong-owner decision rejected |
| P05 | agent cache promotion succeeds without threshold; builtin requires bound MJ approval |
| P06 | quarantine prevents recurrence promotion; compatible prior pin or text; explicit restore |
| R01 | undeclared pin impact denied; authorized eviction yields visible orphan/tombstone |
| R02 | protected evidence prune rejected; valid rollup/prune preserves denominator atomically |
| R03 | two supplied queue policies differ at runtime; no policy rejects new enqueue visibly |
| R04 | missing agent freezes policy; failed audit write makes no mutation; Add failure no orphan |

P0 implementer may model interfaces with in-memory payload fixtures and SQLite transactions, but MUST run real tests. Browser isolation, live relay interruption, durable queue delivery, Add UI and actual agent scheduling are later phase integration criteria, not claims earned by a validator test.

## Decisions, trade-offs, open questions

Decisions settled here: backend registry is authoritative; agent owns runtime judgments; executor owns invariants; layout/resource numbers are runtime data; all pages use backend-only egress; retirements are explicit and observable. This avoids invented thresholds, at the cost of operational dependence on a managing agent and retained decision evidence. Declarative allowlist deliberately cannot express arbitrary mini-games yet; extending trusted components costs review and goldens instead of executing generated code.

No blocking product question remains for P0. Deployment must later bind an actual authenticated managing-agent identity and approved backend connectors. P1 must select transport cursor/resync and storage implementation details; P2 must supply approved runtime budget and exercise browser security; P4 must run the real decision loop. No default numeric policy is implied while those integrations are absent.
