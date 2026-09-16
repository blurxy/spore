# Substrate: Replicated Logs & Causal Ordering

> SPORE's substrate is a set of single-writer, hash-chained append-only logs (one per identity key), each carrying a Merkle Mountain Range root so any single block can be verified against a pinned root without holding the log. Ordering is a derived-and-checked Lamport clock with a `(lamport, log_id, seq)` total-order tiebreak — a linear extension of causal order that every spore computes identically, adapted from Automerge's `(counter, actorId)` opIds. Permission races are settled by a two-pass resolver adapted from Matrix state resolution v2 (power-ordered control pass, then lamport-ordered ordinary pass, with rejected blocks retained as `soft_failed` rather than deleted), and head reconciliation is layered: delta gossip for the live path, exact version vectors below 512 logs, Negentropy-style range-based set reconciliation above it.

# SPORE SUBSTRATE

## 1. Log structure

**One log per identity key.** A log is single-writer, append-only, and never forks under an honest author. Multi-device users hold one key per device plus a `DEVICE_LINK` block; SPORE never merges two writers into one log, which is what makes chain validity trivial.

`log_id = BLAKE2b-256(ed25519_pub)[0..16]`. 16 bytes, not 8: an 8-byte id can be ground to collision in ~2^32 work, which is an afternoon. Full pubkey lives only in block seq 0 (`IDENTITY`).

### Block certificate — 196-byte fixed header, little-endian

```
off  len  field
  0    1  ver = 0x01
  1    1  type
  2    2  flags            (uint16)
  4   16  log_id
 20    8  seq              (+1 per block, no gaps)
 28    8  lamport
 36    8  wall_ms          advisory only, never used for ordering
 44   16  scope_id         colony_id or fruiting_id
 60   32  prev_hash        block_hash(seq-1); zeros at seq 0
 92   32  mmr_root         MMR over block_hash[0..seq-1]
124   32  auth_ref         block_hash of the AUTH_SNAPSHOT this write claims under
156   32  payload_hash     BLAKE2b-256(payload)
188    4  payload_len
192    2  dep_count
194    2  reserved (0)
196   --  deps[dep_count] × 32 bytes
   +  64  sig  — Ed25519 over BLAKE2b-256(bytes[0 .. 196+32·dep_count))
```

`block_hash = BLAKE2b-256(header ‖ deps ‖ sig)`.

**The signature covers `payload_hash`, not the payload.** This is the single most consequential layout decision. It makes the cert a fixed 260 bytes (388 with 4 deps) independent of payload size, so: (a) a 40 MB video block is a 260-byte cert whose bytes SHARDING fetches separately; (b) redaction (GDPR, moderation) drops payload bytes without breaking `block_hash` or any MMR proof — Matrix needs a bespoke redaction-invariant hash algorithm for exactly this and we get it for free. Payloads ≤ 512 B set `flags.payload_inline` and are stored adjacent, so a chat message is still one fetch.

Header overhead is real: 260 bytes of cert for a 60-byte message. `flags.batch` packs up to 64 ops into one payload TLV, amortizing the header for burst typing and bulk import.

Flags: `0 payload_inline, 1 encrypted, 2 batch, 3 snapshot_anchor, 4 redacted, 5 auth_control`.

Types: `0x01 IDENTITY, 0x02 DEVICE_LINK, 0x10 COLONY_GENESIS, 0x11-13 FRUITING_CREATE/RENAME/DELETE, 0x20-26 MEMBER_JOIN/LEAVE/INVITE/BAN + ROLE_GRANT/REVOKE/POWER_SET, 0x30 AUTH_SNAPSHOT, 0x31 STATE_SNAPSHOT, 0x40-45 MESSAGE/EDIT/DELETE/REACT_ADD/REACT_REM/PIN_SET, 0x50 ATTACHMENT_MANIFEST`.

### Verifying one block from an untrusted peer

`mmr_root` is a **Merkle Mountain Range** over `block_hash[0..seq-1]` (Grin/Beefy; the append-only variant of Certificate Transparency's tree). Append is O(1) amortized, inclusion proof is O(log n) hashes. Given a pinned root for log L at seq S — obtained from a verified snapshot or from any later block of L whose signature checks — a spore verifies an arbitrary block at seq k < S with a ~log2(S)·32 byte proof (640 B at a million blocks) and never touches the rest of the log. `prev_hash` is kept alongside as redundancy: it gives O(1) suffix stitching for the streaming/live path without maintaining MMR state, which matters for RELAY forwarding and for N=1.

**Equivocation (fork) detection.** A malicious author can still publish two blocks at one seq. Every dep entry carries an 8-byte hash prefix, so two spores reporting different prefixes for the same `(log_id, seq)` is cryptographic proof of forking. Substrate emits `fork_detected` with both certs; auth state freezes that log from the fork point (all its blocks at or above soft-fail everywhere). This is **fork consistency** (SUNDR, Keybase sigchains, SSB) — not consensus, but cheating is detectable and self-punishing.

## 2. Causal ordering — the exact rule

Deps are **not** raw hash lists. A dep entry is 32 bytes: `log_id(16) ‖ seq(8) ‖ block_hash_prefix(8)`. Because per-author logs are prefix-replicated, a version-vector delta is an *exact* representation of causality; the 8-byte prefix adds content binding for equivocation detection. Deps list only logs whose head changed since this author's previous block in this scope; the author's own causality is covered by `prev_hash`.

**Lamport rule (derived, not asserted):**

```
lamport(B) = 1 + max( lamport(prev block in B's own log),
                      max over d ∈ B.deps of lamport(block d) )
```

Any spore recomputes this from the deps and **rejects a block whose lamport field disagrees**. This closes the Lamport-inflation attack outright: you cannot simply declare `lamport = 2^60` and pin yourself at the top of history forever. The residual attack — privately building a million junk blocks in your own log to inflate legitimately — costs a million published blocks, is gated by seq-contiguity, and is visible as `log_growth_rate`.

**Delivery:** B is deliverable in scope S when every dep `(L,s,h)` is present, prefix-matching, and itself delivered, and `B.seq == local_head(B.log_id)+1`. Otherwise B parks in a pending buffer keyed by missing deps and substrate adds the gap to `wants()`. Standard causal broadcast.

**Total order (the rule):**

```
ORDER(B) = ( B.lamport:uint64 , B.log_id:16 bytes lexicographic , B.seq:uint64 )
```

Total, because `(log_id, seq)` is globally unique. A linear extension of causal order, because lamport is monotone along `→`. Pure function of block fields, so every spore computes it identically with no clock and no server. This is Lamport 1978's total order, and it is precisely Automerge's `(counter, actorId)` opId comparison generalized to a chat DAG. We do **not** need Yjs/YATA or RGA — those solve concurrent insertion into a shared sequence; chat messages are independent elements, so a sort key suffices.

**Partition then merge.** Both sides converge because ORDER is deterministic. The honest cost: merged messages interleave *by lamport* rather than appending at the end, so text can appear above what you already read.

**Stability watermark** — the mechanism that makes that livable:
- `stable(S) = min over ALL member logs of head_lamport` — safe; nothing can ever be inserted below it. May lag forever behind one offline member.
- `settled(S) = min over logs heard from within PARTITION_HORIZON (5 min)` — the UI default. History below `settled` renders normally; above it renders provisional, with a merge seam marker and an unread badge at the insertion point when a reorder lands.

Stating the gap between `stable` and `settled` honestly, and rendering it, is better than pretending reorders don't happen.

## 3. Head gossip — three layers, with the sizes that justify them

Head record: `log_id(16) ‖ seq ‖ lamport ‖ head_hash(12)`, varint-packed ≈ 34 B. No signature needed: a lie is caught the moment the block is fetched.

Measured estimates:

| mechanism | 200 logs | 5000 logs | failure mode |
|---|---|---|---|
| exact VV (packed) | 6.8 KB, 1 RTT | 170 KB | none — exact |
| RBSR k=16 | 1.2 KB, 2 RTT (d=3) | 5.3 KB, 4 RTT (d=50) | none — degrades gracefully |
| IBLT d=50 | — | 2.7 KB + estimator RTT | **fails to decode** if d exceeds the sizing guess |
| Bloom 1% FP | — | 6.0 KB, bidirectional | false negatives → silently missed blocks |

**Decision.** (1) **Live path: delta head gossip** — only changed heads, ~320 B/s/peer at 5 heads/s. Carries essentially all normal traffic. (2) **Scope ≤ 512 logs: exact version vector**, one round trip, every 60 s. 6.8 KB at 200 members on a LAN is nothing, and exactness beats cleverness. (3) **Scope > 512 logs: range-based set reconciliation**, Negentropy/Willow-style (Meyer 2023) — sort head records by `log_id`, exchange `[range_lo(16)][mode(1)][fingerprint(16) | idlist]` frames, split factor 16, recurse where fingerprints differ. 5000 logs with 50 differences reconciles in ~5.3 KB and 4 round trips.

IBLT is rejected specifically because it requires estimating `d` before you can size the table and then *fails hard* when the estimate is low — unacceptable after a long partition, which is exactly the case where `d` is large and unknown. Bloom is rejected because its error direction causes silently lost messages.

## 4. CRDT semantics

Permission-bearing ops (`auth_control` flag) do **not** go through plain CRDT merge; see §5.

| op | rule | why it's sane |
|---|---|---|
| **message send** | grow-only set keyed by `block_hash`, sorted by ORDER | single-writer log ⇒ no conflict possible; duplicates unrepresentable |
| **edit** | LWW-Register on target, highest ORDER wins; **only the original author may edit** (mod edits rejected outright) | last thing you typed wins, as in every chat app; attribution can never be forged by a mod |
| **delete** | tombstone, **absorbing** — once any valid delete exists the message is deleted forever, even against a higher-ORDER edit | racing an edit against a delete must not un-delete; that would be a moderation hole |
| **reaction add/remove** | **OR-Set**: ADD identified by its own `block_hash`; REMOVE names the add-hashes it observed. Concurrent add+remove ⇒ **add wins** | "I just tapped it, it should be there" — the standard observed-remove intuition |
| **pin** | LWW-Element-Set on `(message, pinned)`, pin list ordered by ORDER of pin blocks; needs `manage_messages` | low-frequency admin state; matches Discord |
| **fruiting create** | `fruiting_id = BLAKE2b(colony_id ‖ creator_log_id ‖ seq)[0..16]`. Concurrent same-named creates produce **two channels**, never merged | merging two independent logs silently interleaves unrelated conversations; two "general"s is ugly but recoverable, lost messages aren't. UI suffixes "(2)" + offers explicit admin merge |
| **fruiting rename** | LWW-Register, ORDER tiebreak | cosmetic |
| **fruiting delete** | tombstone; **wins over rename**, **loses to concurrent sends** — orphan messages survive in an archived view | never destroy content on a race |
| **role grant/revoke** | auth state → §5 power-ordered pass, not lamport | authority decides, not network timing |
| **member join/leave** | state machine `invited → joined → left / banned`; **ban absorbs** (concurrent join+ban ⇒ banned); self leave+join ⇒ LWW | membership fails closed; that is what every moderator expects |

Presence, typing indicators and voice signalling are **not substrate**. They are ephemeral session frames. Putting them in the log would flood it for zero durable value.

## 5. Permission races — Matrix state resolution v2, adapted

Every block pins `auth_ref`, the hash of the `AUTH_SNAPSHOT` the author believed current — this is Matrix's `auth_events` pinning compressed to one hash.

On merge, over the *conflicting* blocks only:

**Pass A — control blocks** (`auth_control` set). Reverse-topological-power sort via Kahn's algorithm, tiebreak `(−sender_power_at_its_auth_ref, lamport, log_id)`. Apply in order, auth-checking each against the partial resolved state. This is verbatim Matrix state-res v2 Pass 1.

**Pass B — ordinary blocks.** Sort by `ORDER(B)` and auth-check each against the state resolved so far. This replaces Matrix's "mainline ordering" — we don't need it, because unlike Matrix we already have a global Lamport total order.

Blocks that fail auth are **retained in the log and marked `soft_failed`** — logs are immutable; rejection is a derived-state verdict, and it is recomputed, never cached as truth.

**The classic race, worked.** A (power 100) demotes B; concurrently B (power 50) bans C, unaware. Pass A sorts by sender power: A's demotion applies first, B drops to 0; B's ban is then auth-checked against post-demotion state, fails the power-50 requirement, and soft-fails. **C is not banned.** Every spore reaches this independently.

The wrinkle, stated plainly: B's client showed the ban succeeding and must now revert it. We surface that as an explicit "action reverted — you were demoted at the time" toast. A silent rollback here would be worse than the race.

Guard rails:
- **Power floor.** The colony genesis block records the founder's `power_floor`; nobody else can demote below it. Kills mutual-demotion deadlock and the partition-heal mod coup.
- **Cascading re-auth, not cascading rejection.** A block whose `auth_ref` transitively depends on a soft-failed control block is *re-checked* against merged state — it may still be valid. A partitioned sub-mesh where someone self-promotes and performs 10,000 actions loses the self-promotion and then each dependent action is judged on its merits.
- **Cost control.** Auth-state snapshots every 512 auth blocks; re-resolution restarts from the last snapshot below the lowest disturbed lamport. Pass A is O(k log k) in *conflicting control* blocks (single digits in practice).

## 6. Compaction & bootstrap

**Snapshots are checkable claims, not trust statements.** Because ORDER and the two-pass resolver are pure functions of the block set, any spore replaying the same cut MUST produce the same `state_root`.

A `STATE_SNAPSHOT` block (written into the publisher's own log) contains: the `cut` (VV: log_id → seq), `state_root` (root of a merkle trie over state keys, so individual entries get inclusion proofs), each included log's `mmr_root` at the cut, and `stable_lamport`.

**Convergent cut selection:** snapshot whenever `stable_lamport` crosses a multiple of 65,536. Since stability guarantees nothing more arrives below that lamport, *every spore derives an identical cut and identical root independently*. Multiple publications are **corroboration, not conflict** — and disagreement is a first-class Byzantine alarm the telemetry renders directly ("snapshot @ L=131072 — 7 agree, 0 dissent").

**Pruning:** with ≥ `min(3, active_spores)` matching publications from distinct log_ids, a spore may drop block *payloads* below the cut, keeping the 260-byte certs and MMR state. It can still serve inclusion proofs. VAULTs retain payloads per SHARDING's replication factor.

**Fresh bootstrap:** (1) fetch ≥3 snapshots for the same cut from distinct logs, verify signatures, require equal `state_root`; dissent ⇒ refuse and full-replay. (2) Fetch the state trie by root — content-addressed, fetched in parallel from many VAULTs; this is a clean BLOOM win. (3) Pin per-log MMR roots (5000 logs × 32 B = 160 KB) so *any* historical block fetched later self-verifies. (4) Replay only the tail above the cut.

The trust downgrade is named, not hidden: the client badges "verified from snapshot (3 corroborations)" vs "verified from genesis", and background full replay upgrades the badge. Full replay of 1M blocks is ~50 s on one core, ~8 s across 6 workers — farmed out as a FORGE enzyme.

## 7. Storage & complexity

`logs/<id>/blocks.dat` (append), `offsets.dat` (8 B per seq ⇒ O(1) seek), `mmr.dat` (~2n nodes), `state/<colony>/`, `pending/`. Per-scope order index: in-memory sorted `(lamport, log_id, seq)` array per open fruiting with periodic sorted dump.

append O(1) amortized · verify-one-block O(log n) · deliver O(dep_count) · order-insert O(log m) · merge with d differences O(d log d + d auth checks + r state re-apply) · VV reconcile O(n) bytes · RBSR O(d log₁₆ n) bytes and O(log₁₆ n) round trips.

## 8. N = 1, exactly

- Boot: generate ed25519 key, write seq 0 `IDENTITY` with full pubkey, `prev_hash` = zeros, `mmr_root` = zeros, `lamport` = 1, `auth_ref` = zeros.
- `COLONY_GENESIS`: founder = self, power 100, `power_floor` 100.
- **Every block has `dep_count = 0`** — deps never list your own log, `prev_hash` covers it. So the entire dep machinery is inert at N=1.
- Delivery: always immediately deliverable. Pending buffer is provably always empty.
- Head gossip runs on its timer and emits to zero hyphae. `heads_local` climbs while `head_gossip_sent` stays 0 — a clean single-node telemetry panel.
- `stable = settled = own head lamport`, since the active member set is {self}. **Nothing is ever provisional and no reorder can occur.** The system is strictly *more* stable at N=1.
- Auth: Pass A always has k=0 conflicting control blocks and short-circuits.
- Snapshots: same deterministic cuts; corroboration threshold degrades to 1, so self-corroboration suffices. Restart loads own snapshot + replays tail.
- **Crash safety:** append → fsync → update offsets → emit. A torn tail is detected by `payload_len` vs file length plus signature failure, and truncated. Critical invariant: **never truncate below `max_gossiped_seq`**, persisted and fsynced *before* any head is gossiped — truncating a gossiped block is indistinguishable from equivocation and would get the node fork-banned by its own peers.

## Interfaces

- `substrate.append(scopeId: Bytes16, type: uint8, payload: Buffer, opts?: {batch?: Op[], inline?: boolean}) -> Promise<{blockHash: Bytes32, seq: uint64, lamport: uint64}>` — APP's only write path. Substrate derives lamport, deps (scope frontier delta), auth_ref, prev_hash, mmr_root, signs, fsyncs, then delivers locally and queues for gossip.
- `substrate.readRange(scopeId, fromLamport: uint64, toLamport: uint64, limit: uint32) -> AsyncIterable<DeliveredBlock>` — APP reads a fruiting's history in ORDER(B) sequence. Yields certs; payloads may be pending (see payloadState field).
- `substrate.get(blockHash: Bytes32) -> Promise<Block | null>` — Random access by hash, for edit/delete/react targets and dep resolution.
- `substrate.verifyBlock(certBytes: Buffer, mmrProof: Bytes32[], pinnedRoot: Bytes32) -> {ok: boolean, reason?: string}` — Stateless verification of one block fetched from an untrusted peer against a pinned MMR root. O(log n). Safe to run in a worker_thread.
- `substrate.ingest(certBytes: Buffer[], payloads?: Map<Bytes32, Buffer>) -> {accepted: n, pending: n, rejected: [{hash, reason}]}` — SHARDING hands fetched blocks here. Substrate verifies signature, recomputes and checks lamport, checks seq contiguity, then delivers or parks in the pending buffer.
- `substrate.frontier(scopeId) -> VersionVector /* Map<logId, {seq, lamport, headHash12}> */` — What I have, for head gossip and for SHARDING's peer-selection. Packed encoding ~34 B/entry.
- `substrate.wants(scopeId) -> Array<{logId: Bytes16, fromSeq: uint64, toSeq: uint64, priority: uint8}>` — Causal gaps substrate needs filled. SUBSTRATE decides WHAT is missing; SHARDING decides WHO to ask and in what order. Priority is higher for blocks blocking delivery of already-held blocks.
- `substrate.stability(scopeId) -> {stable: uint64, settled: uint64, laggingLogs: Bytes16[]}` — The two-tier watermark. APP renders history below `settled` as final and above it as provisional.
- `substrate.snapshotAt(scopeId, lamportCut: uint64) -> Promise<{stateRoot: Bytes32, cut: VersionVector, blockHash: Bytes32}>` — Compute and publish a deterministic state snapshot at a convergent cut. Any spore computing the same cut must get the same stateRoot.
- `substrate.bootstrapFromSnapshot(snapshotRefs: Bytes32[], minCorroborations = 3) -> Promise<{stateRoot, corroborations, dissenters: Bytes16[]}>` — Cold-start path. Verifies N independent snapshots agree before accepting; refuses and falls back to genesis replay on dissent.
- `substrate.on('delivered', (block, scopeId, orderKey: {lamport, logId, seq}) => void)` — Causally-ready block, in order. APP's main read event.
- `substrate.on('reordered', (scopeId, fromLamport: uint64, insertedCount: uint32) => void)` — A merge inserted blocks below the UI's current tail. APP draws the merge seam and unread badge rather than silently repainting.
- `substrate.on('soft_failed', (blockHash, reason: 'no_power'|'banned'|'fork'|'bad_auth_ref', wasApplied: boolean) => void)` — A block was rejected by auth resolution. `wasApplied: true` means the local user saw it succeed and must be told it reverted.
- `substrate.on('fork_detected', (logId, seq, certA, certB) => void)` — Cryptographic proof of equivocation. Two valid signed certs at one seq. Triggers fork-freeze of that log.
- `substrate.setSendFn(fn: (sporeId, frame: Buffer) => void) ; substrate.onFrame(sporeId, frame)` — The entire downward dependency on SESSION/TRANSPORT: one send, one receive. Substrate never sees sockets, keys or peers.

## Telemetry emitted

- substrate.blocks_appended_total (counter, by type) — local write rate; the N=1 proof panel pairs this with head_gossip_sent staying at 0
- substrate.blocks_ingested_total / blocks_rejected_total (counter, by reason: bad_sig, bad_lamport, seq_gap, unknown_log)
- substrate.pending_blocks (gauge) and substrate.pending_oldest_ms (gauge) — the causal-stall indicator; a rising oldest_ms means a dep is unfetchable and SHARDING is failing
- substrate.deps_missing (gauge, by logId) — exactly which logs are holding delivery hostage
- substrate.lamport_local (gauge), substrate.lamport_max_seen (gauge) — divergence between them shows how far behind this spore is
- substrate.stable_lamport / substrate.settled_lamport (gauges) + substrate.lagging_logs (gauge) — renders as a two-tone progress bar over history; the single most legible substrate visual
- substrate.reorder_events_total (counter), substrate.reorder_depth_lamport (histogram) — how violently a partition heal shuffled history
- substrate.head_gossip_frames_sent/recv, head_gossip_bytes_sent/recv (counters) — the cheap live path
- substrate.vv_entries (gauge), substrate.vv_bytes_sent (counter) — watch this cross the 512-log RBSR switchover
- substrate.rbsr_sessions_total, rbsr_rounds (histogram), rbsr_bytes, rbsr_diffs_found (histogram) — proves the O(d log n) claim live, on screen
- substrate.auth_resolutions_total (counter), auth_pass_a_control_blocks (histogram), auth_resolve_ms (histogram) — shows the resolver is cheap in practice
- substrate.soft_failed_total (counter, by reason) and substrate.soft_failed_reverted_total — the second counts user-visible action reversals, the thing that most annoys people
- substrate.fork_detected_total (counter, by logId) + the evidence pair — a red alarm, never a log line
- substrate.snapshots_published_total, snapshot_corroborations (gauge per cut), snapshot_dissent_total — 'snapshot @ L=131072: 7 agree, 0 dissent' is a genuine Byzantine-health readout
- substrate.compaction_bytes_reclaimed_total, substrate.payloads_pruned_total, substrate.certs_retained (gauge)
- substrate.mmr_nodes (gauge), substrate.mmr_proofs_served_total, substrate.mmr_proof_bytes
- substrate.verify_ops_per_sec (gauge, by worker) — rises visibly as FORGE enzymes shard verification across joining spores; this is the BLOOM curve for cold start
- substrate.bootstrap_phase (enum gauge: snapshot_fetch | trie_fetch | tail_replay | genesis_replay) and bootstrap_elapsed_ms
- substrate.payload_inline_ratio (gauge), substrate.block_bytes_total, substrate.cert_to_payload_byte_ratio — makes the 260-byte header overhead visible and arguable
- substrate.log_growth_rate (gauge, by logId) — the lamport-inflation / spam detector

## Risks (self-identified)

- Reordering on partition heal is genuinely unpleasant UX. Merged messages interleave by lamport, so text appears ABOVE what the user already read. The stability watermark bounds and labels it but cannot eliminate it — this is intrinsic to serverless convergent ordering and we should say so in the product copy, not bury it.
- Cert overhead: 260 bytes minimum per operation against a ~60-byte chat message — 4.3x amplification. Batching helps bursts but not conversational back-and-forth. At a million messages a colony's cert set alone is 260 MB before any payload. Pruning keeps certs, so this floor never goes away.
- Snapshot bootstrap is a real trust downgrade, not a cryptographic proof. Three colluding identities can hand a fresh spore a fabricated state_root. Identity is cheap in a LAN mesh, so 'three distinct log_ids' is a weak Sybil barrier. Mitigated only by badging it and offering background genesis replay — which most users will never run.
- state_root determinism is fragile in ways that will bite during development. Any non-canonical serialization (JSON key order, float coercion, JS number precision above 2^53, differing BLAKE2b parameters across Node builds) makes honest spores publish dissenting snapshots and look Byzantine. Requires a strict TLV canonical form with uint64 as raw bytes and zero floats, plus a cross-version determinism test in CI.
- Soft-failed blocks are still stored and replicated. A spammer or a compromised mod's rejected blocks propagate fully before being judged, consuming VAULT space and bandwidth permanently, since logs are immutable. Per-log ingest rate caps are local policy and therefore non-convergent: different spores end up holding different subsets, which is tolerable for spam but muddies the 'everyone computes the same state' story.
- Lamport inflation is reduced but not eliminated. Deriving-and-checking lamport blocks the trivial attack, but an author who genuinely publishes a long private chain still buys permanent top-of-history placement. Detection is behavioral (log_growth_rate), not cryptographic.
- A single offline member pins `stable` forever, so the safe watermark is useless in practice and everyone will rely on `settled` — which means the 'provably final' guarantee is the one nobody actually uses.
- Pass A's power-ordered resolution means a demoted moderator's completed actions can visibly evaporate minutes later. Correct, deterministic, and still the kind of thing that generates angry support tickets. Also: two equal-power admins demoting each other resolves by log_id, which is arbitrary from the users' point of view.
- Per-scope order indexes held in memory scale with open fruitings × blocks. A spore joining twenty busy colonies at once will feel it, and Node's single heap makes this a hard ceiling rather than a soft one.
- MMR proof serving requires keeping mmr.dat (~2n nodes, 64 B/block) even after payload pruning, so aggressive compaction reclaims less than intuition suggests.

## Contract conflicts raised

- SESSION/SUBSTRATE identity binding is unspecified and load-bearing. SESSION authenticates a peer via an X25519 static key; SUBSTRATE authenticates blocks via an ed25519 signing key. Unless the handshake transcript carries a signed binding between the two (or both derive from one identity key), the two layers authenticate different things and 'the peer on this hypha is log X' is unprovable. SUBSTRATE needs `session.remoteLogId(hypha) -> Bytes16` and SESSION needs to guarantee it. This must be resolved jointly, not by either subsystem alone.
- The contract says SUBSTRATE asks TRANSPORT+SESSION only for 'send this frame to that spore', but head gossip is inherently one-to-many and at small N should piggyback on UDP multicast rather than issue N unicasts. Request `session.broadcast(frame, filter)` with a best-effort-multicast hint. Without it, gossip cost is N× what it should be on exactly the LAN case we ship first.
- SUBSTRATE and SHARDING both plausibly own 'what to fetch next'. The boundary must be stated explicitly or it will be implemented twice: SUBSTRATE computes WHAT is missing and why it's urgent (`wants()`, priority from causal-blocking), SHARDING computes WHO to ask, in what order, with rarest-first. Substrate must not name peers; sharding must not reason about causality.
- The payload_hash split breaks the contract's implicit assumption that APP reads whole messages through SUBSTRATE. A block can be delivered (cert verified, causally ready, ordered) while its payload is still in flight. APP must render 'known message, body pending' as a first-class state. Either the contract acknowledges this or SUBSTRATE has to buffer deliveries until payloads land, which reintroduces head-of-line blocking that the split was designed to remove.
- Media is assigned to APP, but SUBSTRATE's by-hash payload store and SHARDING's content-addressed block store are the same thing. Three subsystems would each build a content-addressed blob store. Propose one shared CAS owned by SHARDING, with SUBSTRATE and APP as clients addressing it by BLAKE2b-256.
- Naming collision that will cause real confusion in code review: ROLES owns 'role assignment' (RELAY/VAULT/INDEX/FORGE/BEACON capability scoring), while SUBSTRATE/APP own 'roles' in the Discord sense (admin/mod/member permissions). These are unrelated concepts one keyword apart. Propose renaming: ROLES deals in `capability tiers`, SUBSTRATE/APP deal in `power levels` and `grants`. Decide before any code is written.
- AUTH_SNAPSHOT / STATE_SNAPSHOT computation is expensive and perfectly parallel, making it a natural FORGE enzyme — but that makes SUBSTRATE a client of ROLES, an upward dependency the contract's layering does not anticipate. Suggest inverting it: ROLES polls `substrate.pendingVerificationWork()` rather than SUBSTRATE calling into ROLES.
