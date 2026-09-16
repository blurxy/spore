# APP — Application Model: Colonies, Fruitings, Media, Presence

> Every APP feature is an op in a single-writer append-only log per (author, colony), which SUBSTRATE merges into a per-colony causal DAG — so there are no write conflicts, only display-order and authority questions, and optimistic local echo is free. Permissions are Discord-shaped bitmasks resolved Matrix-style from replicated state with a three-valued ALLOW/DENY/UNVERIFIED outcome that fails open for retention and closed for authority. High-frequency signals (presence, typing, voice) never touch the substrate: they ride a separate signed, rate-limited, TTL-hopped ephemeral frame over SESSION, and degrade to aggregate digests at scale.

# SPORE APP LAYER — Colonies, Fruitings, Media, Presence

## 0. Load-bearing assumption
One append-only log per (author, colony), SSB/Hypercore style. SUBSTRATE merges them into a per-colony causal DAG. Every APP op is a block in the author's own log. Consequence: a spore is the SOLE WRITER of its own log, so there is never a write conflict — only a display-order question and an authority question. Surfaced in contractConflicts.

## 1. APP op envelope (bytes, inside a substrate block payload)
```
off  size field
0    1    ENV_VERSION = 0x01
1    1    op_type (u8)
2    2    flags (u16 LE)  bit0 ephemeral-hint, bit1 tombstoned, bit2 bot-authored
4    16   colony_id      (first 16B of BLAKE2b-256(genesis block bytes))
20   16   fruiting_id    (zero = colony-scoped op)
36   8    author_seq (u64 LE, mirrors substrate log seq)
44   8    wall_clock_ms (u64 LE) — ADVISORY ONLY, never used for causal ordering
52   2    payload_len (u16 LE)
54   N    payload = TLV stream: tag(u8) len(u16 LE) value[len]
```
Header = 54 bytes. Signature, prev-hash and block hash belong to SUBSTRATE, not APP.

op_type: 0x01 COLONY_GENESIS, 0x02 COLONY_META | 0x10 FRUITING_CREATE, 0x11 FRUITING_META, 0x12 FRUITING_OVERRIDE | 0x20 ROLE_DEFINE, 0x21 ROLE_GRANT, 0x22 ROLE_REVOKE | 0x30 MEMBER_JOIN, 0x31 MEMBER_LEAVE, 0x32 MEMBER_BAN | 0x40 MSG_POST, 0x41 MSG_EDIT, 0x42 MSG_DELETE, 0x43 MSG_REACT, 0x44 MSG_PIN, 0x45 THREAD_OPEN | 0x50 MEDIA_MANIFEST, 0x51 STICKER_PACK, 0x52 BOT_COMMANDS | 0x60 EPOCH_ROTATE.
TLV tags: 0x01 body_utf8, 0x02 reply_to (32B op hash), 0x03 mentions (32B*n), 0x0A media_ref (96B), 0x0B allow_mask (8B), 0x0C deny_mask (8B), 0x0D subject (1B kind + 32B id).

## 2. Colonies
**Creation, no server.** COLONY_GENESIS is a block in the creator's log; colony_id = BLAKE2b-256(genesis bytes). Nothing is registered anywhere. The genesis author is owner implicitly. Block 2 creates #general. A one-participant colony is fully correct: you are owner, sole VAULT, sole INDEX, and every permission check resolves against local state.

**Invite** — out-of-band bearer token (QR/NFC), 174 bytes ≈ 280 base32 chars:
`"SPORE1" || genesis_hash(32) || bootstrap_pubkey(32) || issuer_pubkey(32) || expiry_u32 || max_uses_u16 || nonce(8) || ed25519_sig(64)`.
Join = MEMBER_JOIN quoting the token. Every spore validates it against the issuer's INVITE bit *at the issuer's causal point*, so revoking the issuer later does not retroactively un-join people. `max_uses` is advisory — unenforceable without consensus, stated honestly.

**LAN discovery of a colony's existence.** BEACON multicast carries spore identity plus a 256-bit *colony hint bloom* over held colony_ids — never plaintext colony ids, which would leak membership to everyone on the SSID. A spore that already holds a colony_id tests the bloom in O(1); a stranger learns noise. False positives resolve on the authenticated hypha, where both sides exchange actual colony ids. (Contract conflict #2.)

**Multi-colony on one spore.** Root ed25519 identity; per-colony subkey = HKDF(root_sk, info=colony_id), so cross-colony correlation is opt-in (default uncorrelated). Each colony is an independent substrate namespace with its own logs, epoch keys and replication budget. Hyphae are shared: one TCP connection multiplexes frames for all colonies both spores share, with per-colony flow-control credits so a loud colony cannot starve a quiet one.

## 3. Fruitings
FRUITING_CREATE allocates fruiting_id = BLAKE2b-128(colony_id || name || creator || seq).
**Reply**: MSG_POST with TLV reply_to = target op hash; inline quote if the target is local, "fetching" otherwise. **Thread**: fruiting_id = BLAKE2b-128(parent_fruiting_id || root_msg_hash) — derived, needs no allocation op, inherits parent permissions, may carry its own override, reuses every piece of unread machinery. **Pin**: MSG_PIN(target, bool), LWW by causal rank then op-hash; the pin list is a materialized view. **Edit**: MSG_EDIT is valid only if edit.author == target.author — structurally enforced, no permission needed; LWW by author_seq, history retained. **Delete**: tombstone (see §10).

**Read state and unreads are PER-SPORE LOCAL and never replicated.** Per fruiting: `read_frontier: Map<author_pubkey, u64 seq>` — a vector clock over contributing logs. `unread = Σ_authors (head_seq[a] − frontier[a])`, read straight off substrate's per-log head index: **O(A)** where A = distinct authors in the fruiting, *not* O(messages). Mention count scans only the unread suffix. The frontier advances when the fruiting is focused and the viewport reaches head. No consensus, no op, no gossip.

## 4. Roles and permissions
Bits (u64): VIEW, SEND, EMBED, ATTACH, MENTION_ALL, MANAGE_MSG, PIN, MANAGE_FRUITING, MANAGE_ROLES, KICK, BAN, INVITE, VOICE_CONNECT, VOICE_SPEAK, VOICE_MUTE_OTHERS, RUN_BOT, MANAGE_STICKERS, ADMIN.
Ops: ROLE_DEFINE(role_id, position_u16, allow, deny); ROLE_GRANT/REVOKE(member, role_id); FRUITING_OVERRIDE(subject_kind {0 everyone, 1 role, 2 member}, subject_id, allow, deny).

**Evaluation order** (Matrix state-resolution adapted; deterministic, local, no server call):
1. Resolve effective state at causal point P from ops in P's causal past. Concurrent conflicting ops tiebreak by (grantor role position DESC, then op hash ASC).
2. Banned → deny everything except reading pre-ban history.
3. Genesis author, or any role with ADMIN → allow all except owner-only (ownership transfer, unilateral EPOCH_ROTATE).
4. `base = @everyone.allow &~ @everyone.deny`.
5. Roles: `allow |= ∪ role.allow; deny |= ∪ role.deny; result = (base|allow) &~ deny`.
6. Fruiting overrides in order: @everyone (deny then allow) → all role overrides (all denies, then all allows) → member override (deny then allow). The member override is the final word.

Complexity O(R + O): R = roles held (<16), O = override rows on the fruiting. Cached per (spore, fruiting) keyed by a colony state-version counter, invalidated on any state-op append — amortized O(1) while rendering 200 messages.

**Incomplete state is THREE-VALUED: ALLOW | DENY | UNVERIFIED.** An op whose author's authority cannot yet be traced (the ROLE_GRANT hasn't arrived) is **stored, never dropped** — append-only means dropping is unrecoverable — marked unverified, and its *effects are withheld*: an unverified MSG_POST renders greyed with a "?" badge; an unverified MSG_DELETE / MEMBER_BAN / ROLE_GRANT is **not applied**. Each new state op triggers re-evaluation of the unverified queue indexed by affected author; an op is re-checked at most once per new state op touching its author — amortized O(1) per pending op. Rule: **fail-open for retention, fail-closed for authority.**

## 5. Media
**MEDIA_REF, 96 bytes, inline in the message** (TLV 0x0A):
```
0  32 manifest_hash | 32 8 total_bytes u64 | 40 2 mime_code u16 | 42 2 width | 44 2 height
46 4  duration_ms u32 | 50 1 preview_kind (0 none, 1 blurgrid) | 51 1 preview_len
52 44 preview bytes (blurgrid = 6x6 YCbCr, 4-bit quantized = 36B + pad)
```
**Manifest blob** (content-addressed, fetched as a normal block):
```
0 4 "SPMF" | 4 1 ver | 5 1 chunk_log2 (16 ⇒ 64 KiB) | 6 2 flags (bit0 PACK, bit1 derived)
8 8 total_bytes | 16 4 chunk_count N | 20 32*N chunk hashes (BLAKE2b-256)
```
APP hands SHARDING an *ordered* want-list: video sequential-biased (playback starts at ~5%), stills rarest-first. **While fetching**, the message renders immediately with the 96-byte blurgrid upscaled plus a progress ring driven by SHARDING's per-manifest completion events. There is never an empty box and never a spinner-only state.

**Thumbnails, link previews and key stretching are ENZYMEs.** The poster emits MEDIA_MANIFEST plus an enzyme request (recipes `thumb_256`, `thumb_1024`, `linkpreview`) to ROLES; a FORGE spore returns a derived manifest. Recipes are **deterministic and pinned** — encoder parameters baked into the recipe id — so two forges produce byte-identical output and the derived hash is verifiable by recomputation. A phone accepts the first signed result and verifies lazily or never.

**Phone storage: two namespaces.** CUSTODY = chunks SHARDING assigned me; not unilaterally evictable, must be handed off (offer to N peers, await ack, release; if nobody accepts, custody is retained and quota pressure is reported to ROLES). CACHE = everything else, evicted by `score = w1·recency + w2·(1/mesh_replica_count) + w3·in_open_fruiting − w4·size`. Defaults: 512 MiB cache, 256 MiB custody. Sacrifice order: full-res originals → large thumbs → small thumbs. Inline previews live inside the message and cost nothing. If a chunk's mesh replica count falls to 1 it is auto-promoted from cache to custody.

## 6. Presence and typing — ephemeral, never durable
A SESSION frame type that **bypasses SUBSTRATE entirely**:
```
0  1 EPHEMERAL_MAGIC 0xE5 | 1 1 kind (1 PRESENCE, 2 TYPING, 3 VOICE_RTP, 4 READ_HINT)
2  1 ttl_hops | 3 1 reserved | 4 32 origin_pubkey | 36 8 origin_seq u64 LE
44 16 scope_id (colony_id, or truncated colony||fruiting) | 60 1 state | 61 1 payload_len
62 N payload (≤64B status text/emoji) | then 64B ed25519 sig over bytes 0..62+N
```
presence state: 0 offline, 1 online, 2 idle, 3 dnd, 4 in_voice. typing state: 0 stop, 1 start. Hop-1 is authenticated by the hypha itself; the signature exists so a RELAYed presence cannot be forged by the relay. Dedup: LRU set of 4096 (origin_pubkey, origin_seq). ttl_hops starts at 2.
**Rate limits** (per-hypha token buckets): PRESENCE 1/10 s per origin, burst 3; TYPING 1/3 s per (origin, fruiting) with receiver-side 6 s TTL and auto-expiry. Over budget ⇒ drop and count. Nothing here is ever written to a log; a restart forgets all of it, which is correct.

**Degradation.** <32 members: flood, ttl 2. 32–256: scope-filtered — each hypha advertises a 256-bit bloom of *open* fruiting ids at handshake and on change; forward presence only into blooms that hit. >256: aggregate — a BEACON-scoring spore emits PRESENCE_DIGEST every 10 s (online count + up to 64 recently-active members). The UI shows "214 online" with faces only for people you interact with, and typing collapses to "several people are typing". Presence gets *less precise* as the colony grows; that is the honest trade and the right one.

## 7. Telegram-flavoured speed
**Send state machine**: DRAFT → LOCAL (appended to my own log, rendered at once) → SENT (handed to ≥1 hypha) → WITNESSED (≥1 peer's head-gossip includes my block hash) → DURABLE (≥R vault acks, R = min(3, peers)). **Single-node: LOCAL == WITNESSED == DURABLE instantly**, because I am my own VAULT.
Failure states the UI must show: NOT_DELIVERABLE (no hypha for 30 s — grey clock, "waiting for mesh"; the message stays in my log and ships when a hypha appears) and REJECTED (my SEND bit was revoked concurrently, so peers mark the op unverified/denied — red "!", "your permission changed", offer retry if re-granted).

**The exact reconciliation.** There is no write conflict, because I am the sole writer of my log. The only divergence is *display position*. Timeline order = (substrate causal rank, wall_clock_ms, author pubkey). When concurrent blocks arrive that sort before my optimistic message, it would move. To stop text jumping under the user's thumb the UI applies a **stability window**: anything posted in the last 5 s is frozen in arrival order and only settles when the window closes; a settle that actually moves a message emits `app.send.reordered`. The list is scroll-anchored so the viewport never jumps, and messages older than the window never re-sort.

## 8. Bots and stickers
**A bot IS a spore**: ed25519 identity, joins by invite, holds roles, appends MSG_POST to its own log. No special API, no server, no daemon. It runs in a `worker_threads` sandbox on whichever spore hosts it, handed a capability object (read these substrate views; append to my own log; request enzymes) and **no network of its own** — it speaks only through its host's hyphae. The RUN_BOT bit does not authorize "being a bot"; it gates BOT_COMMANDS registration so clients can render slash-command autocomplete. You can host bots on your own phone with zero peers.

**Sticker/media packs**: a pack is a manifest-of-manifests (SPMF with flag PACK). A STICKER_PACK op carries the pack manifest hash; MANAGE_STICKERS gates adding one. Install = fetch the ~4 KiB pack manifest plus a preview strip; individual stickers lazy-fetch on first render and are then pinned in cache. Stickers are tiny and massively reused, so rarity scoring replicates them aggressively — in a busy colony a sticker is one hop from everyone. This is where BLOOM is most visible to an ordinary user.

## 9. Voice (sketch; most of it deferred)
**Honest statement**: Node's standard library has no audio capture, no playback and no Opus. SP1 ships the transport and the topology, not the codec.
VOICE_RTP rides the ephemeral path (kind=3) with a 12-byte sub-header — ssrc u32, seq u16, timestamp u32, codec u8, flags u8 — unreliable, no retransmit, drop-late, 60 ms adaptive jitter buffer. Bring-up codec: **G.711 µ-law** (8 kHz, 20 ms / 160-sample frames, 160 B/frame, 64 kbps, ~40 lines of pure JS) or IMA-ADPCM (32 kbps, ~80 lines). Both are LAN-fine and both sound like a 1995 phone call. **Opus, capture and playback must come from a native mobile adapter** exposing `capture()/playback()/encode()/decode()` — Android AAudio/AudioRecord + platform Opus, iOS AVAudioEngine + AudioToolbox — behind the same adapter seam as the BLE transport.
**Topology**: ≤4 participants full mesh (N·(N−1) streams at 64 kbps is nothing). ≥5, ROLES elects a **MIXER** spore by capability score (CPU headroom, AC power, hypha degree, RTT centroid); the mixer decodes N, sums with soft-clip, re-encodes N streams (each hears everyone but themselves). Mixer loss ⇒ re-election in ~2 s with an audible gap; participants keep sending and fall back to mesh if ≤4 remain.
**Multi-hop RELAY**: voice takes a strict priority lane in the per-hypha frame scheduler (preempts substrate blocks and media chunks) plus a hop budget — beyond 2 relay hops or 200 ms measured one-way the UI shows a degraded badge and offers push-to-talk, making voice half-duplex and tolerant of 500 ms.
**Deferred**: Opus, AEC, noise suppression, video, screen share, >16 participants.

## 10. Moderation without a central authority
**Enforceable.** (a) **Epoch rotation** — colony content is encrypted under an epoch key; a BAN by an authorized member triggers EPOCH_ROTATE and the new key is distributed to remaining members over authenticated hyphae. The banned spore cannot read anything posted after rotation. This is real cryptographic eviction and the only hard lever that exists. (b) **Compliant-client deplatforming** — honest spores refuse to relay, store or render ops from a banned author, so the banned member vanishes for everyone running the real software. (c) Invite revocation for future joins.
**Not enforceable, stated plainly.** You cannot delete history from devices that already hold it — MSG_DELETE is a tombstone honored only by compliant clients; the bytes persist on any spore that kept them and a patched client renders them. You cannot stop a banned member reading pre-ban history they already replicated. You cannot stop a fork: anyone can take the log and continue it under a new genesis with the same people. You cannot stop screenshots, and invite `max_uses` is advisory. What you *can* guarantee is content integrity — content addressing means nobody can forge or corrupt a block attributed to someone else.

## 11. Scope
**SP1 (mesh core)**: colony genesis/invite/join, LAN colony-bloom discovery, multi-colony on one spore, text fruitings, replies, reactions, pins, roles + permissions + fruiting overrides + three-valued evaluation, local read frontiers, optimistic-send state machine + stability window, media chunking/manifest/inline preview/sharded fetch, ephemeral presence+typing path with rate limits, sticker packs, bot-as-spore in a worker sandbox, ban + epoch rotation, VOICE_RTP frame + µ-law + mixer election.
**SP2**: threads, enzyme thumbnails and link previews, custody handoff and phone eviction tuning, presence digests above 256 members, BOT_COMMANDS autocomplete, cross-device read-state sync, search integration into fruitings.
**SP3**: native audio adapter + Opus + AEC, video/screen share, E2E direct messages, forum-style fruitings, per-colony pseudonymous identity UX, sticker distribution across colonies.

## Interfaces

- `app.encodeOp(opType: u8, colonyId: Buffer16, fruitingId: Buffer16, tlv: TLVList) -> Buffer` — Serializes the 54-byte APP envelope + TLV payload that SUBSTRATE wraps into a block in the caller's own log. The only way APP produces durable bytes.
- `app.decodeOp(blockPayload: Buffer) -> { opType, colonyId, fruitingId, authorSeq, wallClockMs, tlv }` — Parses an APP envelope out of a substrate block. Rejects unknown ENV_VERSION without dropping the block.
- `app.can(spore: PubKey, colonyId, fruitingId|null, bit: PermBit, atCausalPoint?) -> 'ALLOW'|'DENY'|'UNVERIFIED'` — The whole permission model, evaluable locally from replicated state with zero network calls. Three-valued so callers can distinguish 'forbidden' from 'authority not yet replicated'.
- `app.onStateOp(op) -> { revalidated: n, stillUnverified: m }` — Called by SUBSTRATE on every role/member/override op append. Invalidates the permission cache and re-runs the unverified queue for affected authors.
- `app.mediaWantList(manifestHash, mode: 'sequential'|'rarest') -> OrderedChunkHash[]` — The ordered fetch plan APP hands SHARDING for one media manifest. Sequential for video playback, rarest-first for everything else.
- `app.onChunkProgress(manifestHash, have: n, total: N, distinctPeers: p) -> void` — SHARDING calls this; drives the progress ring in the UI and the BLOOM telemetry (distinctPeers is the superlinearity proof for media).
- `app.custody.offerHandoff(chunkHashes[], toSpore) -> Promise<accepted: boolean>` — Lets APP's eviction policy release assigned chunks safely. Custody is never dropped unilaterally, only handed to an acking peer.
- `session.sendEphemeral(hypha, frame: Buffer) / session.on('ephemeral', frame)` — The non-durable path for presence, typing, read hints and VOICE_RTP. Bypasses SUBSTRATE entirely. (See contractConflicts #1.)
- `app.presence.set(colonyId, state: 0..4, statusText?: string) -> void` — Sets local presence; the ephemeral emitter handles rate limiting, ttl_hops and scope filtering.
- `app.typing.ping(colonyId, fruitingId) -> void` — Coalesced typing signal, 1 per 3s per fruiting, receiver-side 6s TTL auto-expiry.
- `app.unread(colonyId, fruitingId) -> { count: n, mentions: m }` — O(distinct authors) unread computation from the purely local read_frontier vector; never replicated, never gossiped.
- `app.send(colonyId, fruitingId, body, mediaRefs[]) -> SendHandle{ state, on('state', s) }` — Optimistic send. Emits DRAFT/LOCAL/SENT/WITNESSED/DURABLE/NOT_DELIVERABLE/REJECTED so the UI can render pending and failed states exactly.
- `app.parseInvite(token: Buffer174) -> { genesisHash, bootstrapPubkey, issuer, expiry, maxUses } | InvalidSignature` — Validates an out-of-band invite before any network contact, so a bad QR fails instantly and offline.
- `app.colonyHintBloom() -> Buffer32` — The 256-bit bloom BEACON multicasts instead of plaintext colony ids, so LAN discovery does not leak membership.
- `roles.requestEnzyme(recipeId: 'thumb_256'|'thumb_1024'|'linkpreview', sourceManifestHash) -> Promise<derivedManifestHash>` — How APP farms thumbnailing and link previews to FORGE spores. Recipes are deterministic and pinned so outputs are hash-verifiable.
- `app.bot.host(botIdentity, programPath) -> WorkerHandle` — Runs a bot in a worker_threads sandbox with a capability object and no network of its own; it speaks only through the host spore's hyphae.

## Telemetry emitted

- app.send.pending / app.send.confirmed{state=WITNESSED|DURABLE} / app.send.reordered / app.send.rejected / app.send.not_deliverable — the optimistic-send funnel, per colony
- app.send.local_to_witnessed_ms histogram (p50/p95) — the honest 'live delivery does NOT get faster' metric; plot it flat as peers join
- app.perm.evals_total / app.perm.cache_hit_ratio / app.perm.unverified_pending / app.perm.resolved_from_unverified / app.perm.effects_withheld{op_type}
- app.perm.state_res_ties_broken — how often concurrent role ops needed the deterministic tiebreak
- app.media.chunks_fetched{manifest, from_n_distinct_peers} — THE BLOOM PROOF for APP: fanout rises as spores join
- app.media.manifest_time_to_first_pixel_ms / time_to_complete_ms, bucketed by peer count
- app.media.preview_rendered_without_fetch — count of messages that showed content with zero network
- app.media.cache_bytes / app.media.custody_bytes / app.media.evicted_bytes{reason} / app.media.custody_handoff{offered,accepted,refused} / app.media.auto_promoted_to_custody
- app.enzyme.requested{recipe} / app.enzyme.completed{recipe, forge_spore, ms} / app.enzyme.hash_mismatch — untrusted-forge detector
- app.presence.sent / app.presence.received / app.presence.relayed / app.presence.dropped_ratelimit / app.presence.dropped_dedup / app.presence.dropped_ttl
- app.presence.mode{flood|scoped|digest} and app.presence.scope_bloom_false_positives — shows the degradation ladder engaging live
- app.typing.coalesced / app.typing.expired_unseen
- app.unread.recomputes / app.unread.authors_scanned — proves unread is O(authors) not O(messages)
- app.colony.created / app.colony.joins / app.invites_issued / app.invites_validated / app.invites_rejected{expired,bad_sig,no_authority}
- app.colony.hint_bloom_hits / app.colony.hint_bloom_resolved_on_hypha
- app.mod.bans_applied / app.mod.epoch_rotations / app.mod.tombstones_honored / app.mod.ops_refused_from_banned
- app.voice.frames_sent / frames_dropped_late / jitter_ms / mixer_elections / mixer_failovers / relay_hops_histogram / degraded_mode_entered
- app.bot.workers_running / app.bot.ops_appended / app.bot.capability_denials
- app.sticker.packs_installed / app.sticker.first_render_fetch_ms{peer_count} — a second, very visible BLOOM curve

## Risks (self-identified)

- Presence and voice need a path that skips SUBSTRATE, but the contract says APP reads and writes through SUBSTRATE only. If the SESSION designer does not expose an ephemeral frame type, typing indicators and voice either get shoved into the durable log (catastrophic write amplification on a phone) or do not ship at all. This is the single highest-risk dependency in the whole APP layer.
- The single-writer-per-(author, colony) log topology is assumed, not agreed. If SUBSTRATE ships a single multi-writer colony log instead, optimistic send becomes a genuine write conflict needing a CRDT, and the entire section 7 reconciliation story has to be redesigned.
- Permission state resolution can be gamed by withholding. A malicious spore that has seen its own role revoked can keep posting to peers that have not yet received the revoke; those peers will render the posts as ALLOW, not UNVERIFIED, because they still believe the old grant. Convergence fixes it eventually, but there is a real exploit window proportional to gossip latency. There is no fix without consensus; the honest mitigation is fast state-op gossip priority and retroactive greying.
- Deterministic enzyme recipes are harder than they look. Any JPEG/PNG encoder difference across platforms or Node versions breaks byte-identical output, which breaks the derived-manifest hash and silently turns every thumbnail into a cache miss. Pinning a pure-JS encoder inside the recipe is the fallback and it will be slow.
- Voice is mostly a promise. With zero dependencies, SP1 can demo LAN voice at 1995 telephone quality and nothing more. If demos are judged on voice, this will disappoint. Marked deferred but worth saying out loud early.
- Media custody on a phone fights the operating system. iOS and Android will evict or suspend a background process holding 256 MiB of assigned shards, so custody guarantees are weaker on mobile than the design implies, and handoff may fail precisely when the network is small.
- Epoch rotation is the only real moderation lever and it is expensive: every ban re-keys the colony and re-encrypts nothing retroactively. In a colony with churn, rotation storms are plausible and there is no rate limit designed for them yet.
- Presence degradation to digests above 256 members means the digest emitter becomes a soft central point. If the elected BEACON spore is partitioned, half the colony sees stale online counts with no obvious error state.
- Threads deriving their fruiting_id from the root message hash means a thread cannot be moved or re-parented, ever. That is a real product limitation users will hit.
- Unread frontiers are per-spore and unsynced in SP1, so a user with a phone and a laptop sees two different unread counts. Telegram users will consider this a bug, not a deferral.

## Contract conflicts raised

- APP needs a non-substrate ephemeral path. The contract says 'APP owns ... and reads/writes through SUBSTRATE only', but presence, typing indicators and voice RTP must NOT enter the durable log — they are high-frequency, worthless after seconds, and would destroy a phone's write budget. Resolution requested: SESSION exposes a typed ephemeral frame (magic 0xE5) that APP may send and receive directly over a hypha, and the contract is amended to 'APP writes DURABLE state through SUBSTRATE only'.
- Colony-membership hints in discovery have no owner. TRANSPORT 'knows nothing about messages or colonies' and BEACON does discovery, yet a spore on a LAN must learn 'does this stranger hold a colony I am in' before a useful hypha exists. Proposed resolution: APP computes an opaque 256-bit colony hint bloom and hands it to BEACON as a byte blob to include in multicast announcements. BEACON forwards received blooms back to APP without interpreting them, so TRANSPORT stays colony-ignorant while the hint still travels.
- Media chunk ownership is ambiguous between SUBSTRATE and SHARDING. Are media chunks substrate blocks (hashed, verified, head-gossiped) or a separate content-addressed namespace that SHARDING owns outright? APP needs the latter: media must be evictable and must support a custody/cache distinction, whereas log blocks in a colony you are a member of are generally not evictable. If media chunks are substrate blocks, phone eviction policy becomes a substrate concern and APP cannot implement section 5 as written.
- Enzyme results need a trust story that ROLES does not currently define. APP asks ROLES for a thumbnail and gets back a derived manifest hash from an arbitrary spore. The contract says ROLES owns 'capability scoring, role assignment, the enzyme queue and work-stealing' but says nothing about result verification. APP proposes deterministic pinned recipes so results are verifiable by recomputation; ROLES must carry the recipe id in the enzyme descriptor and must surface WHICH spore produced a result so a mismatch can be attributed.
- Voice needs frame-level scheduling priority inside a hypha, which nothing in the contract owns. Voice frames must preempt substrate blocks and media chunks on a shared TCP hypha or multi-hop audio is unusable. That is a TRANSPORT/SESSION scheduler concern driven by an APP-level classification. Requested: SESSION's send(frame) accepts a priority class (0 voice, 1 ephemeral, 2 substrate head gossip, 3 blocks, 4 media chunks).
