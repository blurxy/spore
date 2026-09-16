# ROLES — capability scoring, coordinator-free role assignment, and the enzyme work-stealing scheduler

> Every spore continuously self-measures into five quantized capability scores (0–15) that ride the existing peer-gossip frame; role holders are then chosen by weighted rendezvous (HRW) hashing over the peer table — a pure function of shared state, so it needs no coordinator, converges when the peer table converges, and at N=1 trivially collapses all five roles onto the single spore. Offloadable work is modelled as content-addressed enzymes in a Cilk-style deque: the owner runs LIFO from the bottom, idle remote FORGEs randomly steal from the top under an exclusive lease, and a hedged local fallback fires at a fixed deadline so no enzyme can ever depend on a remote event completing. Trust is handled per enzyme type by verifiability tier — cheap hash/spot-check verification where possible, JPEG DC-only perceptual comparison for thumbnails, and BOINC-style adaptive redundant execution restricted to colony members for anything unverifiable.

## 1. Capability scoring

### 1.1 Sampling

A `CapabilitySampler` runs every 10 s on a timer (never on the hot path). Raw inputs and their stdlib sources:

| Input | Source | Smoothing |
|---|---|---|
| `cores` | `os.availableParallelism()` | static |
| `load` | `os.loadavg()[0] / cores` | EWMA α=0.25 |
| `battery_pct`, `on_ac` | platform probe (`/sys/class/power_supply`, `WMIC`/`powercfg`, `pmset`); unknown ⇒ treat as AC | EWMA α=0.10 |
| `thermal_headroom` | derived: ratio of measured BLAKE2b ops/s in a 20 ms micro-probe to the best-ever observed ops/s, ×100. This is a *throttle detector*, and it works on every OS with zero deps. | EWMA α=0.25 |
| `free_gib` | `fs.statfs()` on the vault path | EWMA α=0.10 |
| `uplink_kbps` | passively measured: bytes ACKed per hypha over 5 s windows, summed, max over the window history | EWMA α=0.25 |
| `metered` | config flag + OS hint; defaults **true** on a cellular-looking interface | — |
| `queue_depth` | local enzyme deque length | instantaneous |

### 1.2 Score function

Normalize: `c = min(cores,8)/8`, `t = thermal/100`, `s = min(free_gib,64)/64`, `u = min(uplink_kbps,100000)/100000`, `p = on_ac ? 1 : battery_pct/200` (battery caps a device at 0.5), `m = metered ? 0 : 1`, `v = min(uptime_s, 86400)/86400`.

Hard gates run **first** (a gate zeroes the score regardless of the weighted sum):

- FORGE = 0 if `metered ∨ (¬on_ac ∧ battery_pct<20) ∨ thermal<15`
- VAULT = 0 if `metered ∨ free_gib<2`
- INDEX = 0 if `free_gib<1`
- RELAY: metered does not zero it (control-plane relaying is cheap) but clamps it to 1
- BEACON is never gated; it costs ~200 bytes/min

Then, quantized to 4 bits:

```
S_FORGE  = q(m · t · p · (0.65c + 0.20t + 0.15u))
S_VAULT  = q(m · (0.70s + 0.20u + 0.10p))
S_INDEX  = q(m · (0.45c + 0.35s + 0.20p))
S_RELAY  = q(0.60u + 0.25p + 0.15c)
S_BEACON = q(0.50v + 0.30p + 0.20u)
q(x)     = max(1, round(15·x))        // floor of 1 unless SHUTTING_DOWN sets 0
```

The **floor of 1** is load-bearing: it means every spore is always a candidate for every role, which is what makes the "≥1 holder" proof trivial and makes N=1 collapse fall out for free.

### 1.3 Anti-oscillation

Three stacked mechanisms:

1. **Quantization to 16 buckets** — a 6.7% deadband. Sub-bucket jitter never produces a frame.
2. **Hold-down** — a changed bucket must persist for 2 consecutive samples (20 s) before it is advertised.
3. **Asymmetric hysteresis** — moving *down* a bucket needs only the hold-down; moving *up* needs the hold-down **and** ≥2 buckets of improvement. Degradation is fast (safety), promotion is slow (stability).

Advertisement fires on a committed bucket change, or as a 60 s keepalive, whichever is sooner.

### 1.4 CAP_ADVERT frame — type `0x30`, 48 bytes fixed

| Off | Size | Field |
|---|---|---|
| 0 | 1 | version (=1) |
| 1 | 1 | frame_type (0x30) |
| 2 | 2 | flags (LE) |
| 4 | 4 | seq (u32, per-spore monotonic) |
| 8 | 8 | spore_id prefix (first 8 bytes of ed25519 pubkey) |
| 16 | 1 | S_RELAY |
| 17 | 1 | S_VAULT |
| 18 | 1 | S_INDEX |
| 19 | 1 | S_FORGE |
| 20 | 1 | S_BEACON |
| 21 | 1 | cores (clamped 255) |
| 22 | 2 | free_gib (u16) |
| 24 | 4 | uplink_kbps (u32) |
| 28 | 2 | enzyme_queue_depth (u16) |
| 30 | 1 | battery_pct (255 = AC/unknown) |
| 31 | 1 | thermal_headroom |
| 32 | 4 | uptime_s |
| 36 | 4 | peer_table_version |
| 40 | 1 | role_claim_bitmap (b0 RELAY … b4 BEACON) |
| 41 | 3 | reserved (zero) |
| 44 | 4 | BLAKE2b-32 of bytes 0..43 |

Flags: b0 metered, b1 on_battery, b2 thermal_throttled, b3 storage_low, b4 headless, b5 accepts_unverifiable, b6 shutting_down, b7 solo_bootstrap.

The frame is carried inside an authenticated hypha, so SESSION already binds it to a verified ed25519 identity; the 8-byte prefix is an index, not the security boundary. At 48 bytes × N peers × 1/min, gossip cost at N=50 is 40 kB/hour. Negligible.

## 2. Role assignment — weighted rendezvous hashing

For role `R`, spore `i`, using each spore's advertised `S_i(R)` from the peer table:

```
h      = BLAKE2b-512(spore_id_i ‖ role_tag ‖ colony_id ‖ peer_table_version)
x      = be_u64(h[0..8]) / 2^64          // x ∈ (0,1)
weight = S_i(R) / (-ln x)                // Ceph's weighted rendezvous (HRW)
```
Sort descending, take top `K_R`. Replication targets:

| Role | K |
|---|---|
| RELAY | clamp(⌈N/4⌉, 1, 8) |
| VAULT | clamp(⌈N/2⌉, 1, 16) |
| INDEX | clamp(⌈N/5⌉, 1, 4) |
| BEACON | clamp(⌈log₂(N+1)⌉, 1, 5) |
| FORGE | **not top-k** — every spore with `S_FORGE ≥ 4`, min 1. Work-stealing wants maximum breadth. |

Note `peer_table_version`, not wall-clock time, seeds the hash — SPORE has no clock sync and must not acquire one.

**Convergence.** Assignment is a pure deterministic function `f(peer_table)`. BEACON gossip is anti-entropy over a version-vectored peer table; on a connected mycelium it converges. Once tables are equal, every spore computes byte-identical assignments. ∎

**Every role always has ≥1 holder.** Let `m` be the spore with globally maximal HRW weight for role R. Every spore's peer table contains itself, so `m`'s own table contains `m`, and `m` ranks first in it — so `m` believes it holds R, at every instant, including during table divergence. ∎ (Divergence can cause *transient over-assignment* — two spores both believing they hold INDEX. That is harmless duplication. Transient under-assignment is impossible.)

**Minimal disruption.** HRW moves only ~K/N of assignments when one spore joins or leaves — the same property that makes it the right choice over modular hashing. Combined with the 16-bucket quantization, a device whose battery drifts 3% reshuffles nothing.

**N=1 collapse.** `top-K` over the singleton `{self}` yields `{self}` for all five roles, because the score floor is 1 and no gate can drive all five to zero (BEACON is ungated). No special case, no `if (N===1)` branch. The solo spore relays to nobody, vaults everything locally, indexes locally, forges locally through its own deque, and beacons to an empty mycelium. Slow but correct.

**Shedding.** Losing a role requires: (a) recomputing yourself out of top-K, **and** (b) observing the new holder's CAP_ADVERT with that role bit set, **and** (c) a 30 s grace period, during which you serve both. Gaining a role on *departure* is immediate — TRANSPORT's disconnect event fires within one RTT, over-provisioning is safe, under-provisioning is not. Graceful shutdown sets `b6 shutting_down`, which zeroes all five scores one advert before the socket closes, so successors are already live.

## 3. The enzyme queue

An enzyme is `{id, type, params, input_cid, deadline_ms, redundancy}`. Its id is content-addressed:

```
enzyme_id = BLAKE2b-256(type ‖ canonical_params ‖ input_cid ‖ executor_version)
```

This single decision makes double execution a *waste* problem rather than a *correctness* problem: identical work has an identical id and an identical (or tolerance-equivalent) result, so duplicate results are dedupable and network-cacheable.

| Type | Cost (per unit, 1 core) | Deterministic? | Cheaply verifiable? |
|---|---|---|---|
| `0x01 THUMB_IMAGE` (3 MP JPEG → 320 px PNG) | ~450 ms (pure-JS baseline JPEG decode + box filter + `zlib.deflateSync` PNG) | Within a pinned decoder version, yes; across versions, no | **Approximately.** Requester does a DC-only JPEG decode (~15 ms, 30× cheaper — skip AC coefficients, yields a free 1/8-scale image), computes a 64-bit aHash, accepts if Hamming ≤ 6 |
| `0x02 KEYFRAME_STRIP` (MP4/WebM container parse → keyframe byte ranges) | ~80 ms/GB | Yes, byte-exact | **Yes** — hash the extracted ranges |
| `0x03 SPORE_PREVIEW` (render a `spore://` link into a title/excerpt card from substrate blocks) | ~20 ms | Yes | **Yes** — re-render locally; only worth offloading in batches |
| `0x04 INDEX_SEGMENT` (64 MB text → sorted varint postings) | ~1.4 s/64 MB | Yes, with canonical tokenizer version + sorted postings + fixed varint encoding | **Yes** — segment hash, plus O(k) spot-check: sample k=32 terms, verify postings against the source blocks |
| `0x05 SEARCH_FANOUT` (query k local index segments, return top-m hits) | ~30 ms | No (depends on which shards the peer holds) | **Partially** — each hit carries `(block_cid, term_offsets)`, so presence is O(1) verifiable. *Absence* is not. Mitigated by querying 2 holders per shard range. |
| `0x06 PUBLIC_POW` (invite/spam-control challenge) | tunable, ~2 s | Yes | **Yes** — one hash |
| `0x06L KEY_STRETCH` | — | — | **PINNED LOCAL. Never offloaded.** Input is a secret. See contractConflicts. |
| `0x07 TRANSCODE_VIDEO` | — | — | **Defined but refused.** No codec exists in the Node stdlib. See contractConflicts. |

## 4. Work-stealing protocol

Cilk / Blumofe–Leiserson, adapted for an untrusted network. Each spore keeps a local deque. **The owner runs LIFO from the bottom** (locality, youngest-first). **Idle remote FORGEs steal FIFO from the top** (oldest, coarsest, least likely to be needed imminently). Thieves pick victims uniformly at random from peers advertising `queue_depth > 0` — randomized stealing, with the classic `O(P·T∞)` expected-steal-attempts bound.

Arbitration is **always by the deque owner**. That is the one structural defence against double execution: a thief never takes work, it *requests a grant*.

Frames (all inside an authenticated hypha):

- `0x32 STEAL_REQ` (thief→victim): `{type_mask u16, max_input_bytes u32, S_FORGE u8, free_workers u8}`
- `0x33 GRANT` (victim→thief): `{enzyme_id[32], type u8, lease_ms u32, redundancy u8, param_len u16, params, input_locator (cid + VAULT holder hints)}`
- `0x34 PROGRESS` (thief→victim, every lease/3): `{enzyme_id[32], pct u8}`
- `0x35 RESULT` (thief→victim): `{enzyme_id[32], exec_ms u32, result_len u32, result, ed25519 sig}`
- `0x36 NACK / ABORT`, `0x37 VERDICT {accepted | rejected(reason)}`

`input_locator` is a **CID plus VAULT hints, never the bytes**. The thief fetches the input from whichever VAULT already holds it — this is the single most important performance decision in the design (see §6).

Per-enzyme state machine on the owner:

```
QUEUED ──grant──> LEASED(thief, expiry) ──RESULT+verify_ok──> DONE
  ^                   │                          │
  │                   ├─ lease expiry ───────────┤
  │                   ├─ 2 missed PROGRESS ──────┤
  │                   ├─ hypha drop ─────────────┤
  └───────────────────┴─ verify_fail ────────────┘   (re-queue at deque top)
```

**The no-hang guarantee.** With `L` = estimated local cost, lease `D = clamp(3·L, 2s, 60s)`:

> At `t_fallback = min(user_deadline, t_steal + D, 2L)` the owner starts local execution **unconditionally**, whether or not a lease is live. First completion wins; the loser's result is discarded (safe, because ids are content-addressed).

This is the hedged-request pattern from Dean & Barroso's *The Tail at Scale*. The invariant it buys: **no enzyme's completion is causally dependent on any remote event.** A peer that vanishes mid-enzyme costs latency, never liveness. At N=1 the fallback is the only path, which is exactly role collapse.

**Never offload what the thief may not read.** An enzyme may only be granted to a spore already entitled to read `input_cid` under colony permissions — typically a spore that could fetch it as a VAULT anyway. This makes offloading leak-free by construction rather than by policy.

## 5. Trust

Three tiers, driven by the verifiability column:

**V1 — cheaply verifiable** (`0x02`, `0x03`, `0x04`, `0x06`, and presence-checks in `0x05`). Accept from anyone; **always verify**, never sample-verify. Verification is 100–1000× cheaper than execution, so it is free. Failure ⇒ discard, reputation −8, re-queue.

**V2 — approximately verifiable** (`0x01` thumbnails). Always verify via DC-only aHash with Hamming tolerance ≤ 6. A determined adversary can hide a subtle perturbation inside the tolerance but cannot substitute a different image. This is acceptable precisely because **a thumbnail is never authoritative**: the full-resolution original is content-addressed in the substrate and re-derivable locally on demand. Corruption is a cosmetic, self-healing failure.

**V3 — unverifiable** (only `0x07`, currently refused). Policy if a codec plugin ever lands: (a) restrict grants to colony members holding an explicit `FORGE_TRUSTED` permission — the invite graph, not the network, is the sybil boundary; (b) BOINC-style **quorum-of-2 redundant execution** with perceptual comparison whenever idle FORGE capacity ≥ 2× demand, dropping to R=1 for spores above a reputation threshold (BOINC's *adaptive replication*); (c) result remains advisory.

Reputation is a **local, per-observer** counter — `score = verified_ok − 4·verified_fail`, exponential decay with a 7-day half-life, persisted locally. It is never gossiped as truth. A spore may publish it as a signed *claim*, which others weight by their own trust in the claimer. Anything else is a reputation-poisoning vector.

## 6. Scaling analysis

Per-device assumptions: 4 cores, 3 FORGE worker threads (one reserved for UI/network), so 6.67 thumbnails/s/spore. Shared 802.11ac medium: **12.5 MB/s aggregate goodput for the whole mycelium** — this is a shared medium, not per-link, and that is the crux. Coordination: ~6 ms STEAL/GRANT RTT, amortized over bundles of 8 enzymes ⇒ 0.75 ms/enzyme.

**Burst: 200 images × 3 MB → 320 px thumbnails.**

*Regime A — cold media (source exists only on the originator).* Offloading costs 3 MB of uplink per image = 0.24 s of shared medium, versus 0.15 s to compute it locally. Shipping is *strictly slower than computing*. The admission rule that falls out:

> Offload a cold enzyme only if `input_bytes / measured_goodput < local_queue_wait`. At 12.5 MB/s and 0.15 s/image that threshold is **1.9 MB** — so a 3 MB photo never leaves, a 400 kB photo does.

Regime A: N=1 → 30.0 s; N=2 → 28 s; N=5 → 26 s; N=20 → 25 s. **Essentially flat. Honest answer: work-stealing does not help a cold local burst.**

*Regime B — media already sharded across VAULTs (the steady state, and the case the sharding subsystem creates).* Compute goes to the data; only the ~40 kB thumbnail returns.

| N | Compute | Return transfer | Coord | Total | Speedup |
|---|---|---|---|---|---|
| 1 | 30.0 s | 0 | 0 | **30.0 s** | 1.00× |
| 2 | 15.0 s | 0.32 s | 0.15 s | **15.2 s** | 1.97× |
| 5 | 6.0 s | 0.64 s | 0.15 s | **6.3 s** | 4.76× |
| 20 | 1.5 s | 0.64 s | 0.15 s + tail 0.3 s | **2.2 s** | 13.6× |
| 50 | 0.6 s | 0.64 s | tail 0.3 s | **1.3 s** | 23× |

**Crossover: N ≈ 24–32.** Beyond that the 8 MB of returning thumbnails on the shared medium (0.64 s) plus the last-enzyme straggler tail (0.15 s granularity) dominate, and each doubling of N buys under 20%.

**Burst: 2 GB full-text index build.** 32 segments of 64 MB; per-spore tokenize throughput 45 MB/s (3 workers × 15 MB/s); each segment emits ~6 MB of compressed postings that must reach the INDEX holders.

| N | Build | Merge+ship to INDEX | Total | Speedup |
|---|---|---|---|---|
| 1 | 45.5 s | 0 (local) | **45.5 s** | 1.00× |
| 2 | 22.8 s | 2.6 s | **25.4 s** | 1.79× |
| 5 | 9.1 s | 3.5 s (1 INDEX holder, 192 MB ÷ 12.5 MB/s partially overlapped) | **12.6 s** | 3.6× |
| 20 | 2.3 s (32 tasks ÷ 20 ⇒ 2 rounds) | 7.7 s (2 INDEX holders, 96 MB each) | **11.0 s** | 4.1× |

**Crossover: N ≈ 8.** Two independent walls: (1) Amdahl — the merge/ship phase is serial at the INDEX holders and grows with corpus size, not with N; (2) granularity — 32 segments cannot use more than 32 spores, and load balance degrades badly above N=16. Both are fixable (smaller segments, hierarchical two-level merge scaling `K_INDEX` with `⌈√N⌉`) and both are *real limits that must be stated rather than hidden*.

## 7. Benchmark and falsification

`bench/roles-burst.js` stands up N in-process spores over loopback TCP with a token-bucket shaper enforcing a shared 12.5 MB/s medium, pre-seeds a 200-image corpus sharded across VAULTs (Regime B), then measures wall-clock to last-thumbnail-verified for N ∈ {1,2,5,10,20}, 7 repetitions, reporting medians and p95. A second harness does the 2 GB index build. Each run also reports: enzymes executed locally vs stolen, duplicate executions, verification failures, and fallback firings.

**Falsifiers, stated in advance:**

- `T(N=5) ≥ 0.8 · T(N=1)` on the Regime-B thumbnail burst ⇒ the BLOOM claim is false for FORGE.
- Speedup at N=5 below **3.5×** ⇒ coordination overhead is larger than modelled; the design is wrong, not the measurement.
- Any run in which an enzyme fails to complete after a peer is SIGKILLed mid-lease ⇒ the no-hang guarantee is broken, which is a correctness bug, not a performance one.
- `duplicate_executions / total > 0.15` at N=20 ⇒ lease arbitration is too loose.
- Role assignment failing to reach a fixed point within 3 gossip rounds after a join/leave, or any role reaching zero holders for any observer ⇒ convergence proof does not hold in practice.

I expect Regime A to show *no* speedup and I am reporting that as a result, not a failure. Claiming otherwise would be the dishonest version of this design.

## Interfaces

- `roles.getAssignment(peerTableVersion?: number) -> { RELAY: SporeId[], VAULT: SporeId[], INDEX: SporeId[], FORGE: SporeId[], BEACON: SporeId[], version: number }` — Pure, deterministic weighted-rendezvous computation over the current peer table. Same input ⇒ same output on every spore. SHARDING calls this to get the VAULT holder set it maps blocks onto; APP calls it to route search and media requests.
- `roles.iHold(role: 'RELAY'|'VAULT'|'INDEX'|'FORGE'|'BEACON') -> boolean` — Fast local predicate including grace-period holds during shedding. Always true for all five roles when N=1.
- `roles.onRoleChange(cb: (gained: Role[], lost: Role[], version: number) => void) -> Unsubscribe` — Fires when this spore's own assignment changes, after hold-down and grace period. SUBSTRATE/SHARDING subscribe to start or stop serving.
- `roles.onAssignmentChange(cb: (assignment, version) => void) -> Unsubscribe` — Fires on any change to the global assignment, including other spores. Used by the telemetry UI and by SHARDING to trigger rebalance.
- `capability.current() -> { scores: {RELAY,VAULT,INDEX,FORGE,BEACON}, flags: number, raw: {cores,battery_pct,on_ac,thermal,free_gib,uplink_kbps,metered,queue_depth} }` — Latest committed (post-hold-down) capability sample for this spore.
- `capability.encodeAdvert() -> Buffer /* 48 bytes, frame type 0x30 */` — Produces the CAP_ADVERT frame for TRANSPORT/SESSION to piggyback on peer-candidate gossip. ROLES never opens its own sockets.
- `capability.ingestAdvert(fromSporeId: SporeId, frame: Buffer) -> void` — Feeds a verified peer's advert into the local peer table. Caller (SESSION) must have already authenticated fromSporeId; ROLES trusts the identity, not the contents.
- `enzyme.submit(req: { type: number, params: object, inputCid: Buffer|null, deadlineMs: number, redundancy?: 1|2, localOnly?: boolean }) -> Promise<{ result: Buffer, executedBy: SporeId, execMs: number, verified: boolean, wasLocalFallback: boolean }>` — The only entry point for offloadable work. Resolves via steal, local execution, or hedged fallback — never rejects due to peer loss. localOnly:true pins KEY_STRETCH and any secret-input work.
- `enzyme.registerExecutor(type: number, fn: (params, inputBytes, signal) => Promise<Buffer>, opts: { verifier?: (params, inputBytes, result) => boolean, versionTag: string }) -> void` — Registers how this spore executes and verifies one enzyme type. versionTag feeds the content-addressed enzyme_id so mismatched executor versions never collide.
- `enzyme.setCapacity(workers: number) -> void` — APP/UI throttle: caps concurrent FORGE workers, e.g. to zero while a voice call is active. Reflected in the next CAP_ADVERT.
- `roles.stats() -> RolesTelemetrySnapshot` — One-shot snapshot of every counter listed in telemetry, for the live UI.
- `roles.onTelemetry(cb: (event: { name: string, fields: object, t: number }) => void) -> Unsubscribe` — Streaming event feed for the live telemetry UI (grants, steals, verifications, fallbacks, role transitions).

## Telemetry emitted

- capability.sample_total, capability.advert_sent_total, capability.advert_suppressed_by_holddown_total — proves anti-oscillation is working; the suppressed/sent ratio is the headline number
- capability.score{role} gauge per spore, plus capability.raw{cores,battery_pct,on_ac,thermal_headroom,free_gib,uplink_kbps,metered,queue_depth} — drives the per-spore capability radar in the UI
- capability.gate_active{role,reason=metered|battery|thermal|storage} counter — explains WHY a spore is contributing nothing, which is the single most-asked question in a live demo
- roles.assignment_version, roles.assignment_recompute_total, roles.convergence_rounds histogram — time from a join/leave to a stable fixed point
- roles.holders{role} gauge and roles.min_holders_observed{role} — the ≥1-holder invariant rendered as a live assertion; any zero is a red alarm
- roles.transition_total{role,direction=gain|shed,cause=join|depart|score_change|shutdown} and roles.grace_period_active{role} — makes graceful shedding visible rather than inferred
- roles.collapse_mode boolean (true at N=1) — the single-node-correctness guarantee shown as a lit indicator
- enzyme.queue_depth gauge, enzyme.queue_wait_ms histogram, enzyme.submitted_total{type}
- enzyme.executed_total{type,where=local|stolen|fallback} — the core BLOOM chart: the stolen fraction is the speedup
- enzyme.steal_req_total, enzyme.steal_granted_total, enzyme.steal_nack_total{reason=empty|ineligible|overloaded|untrusted} — steal success rate, the work-stealing scheduler's health metric
- enzyme.exec_ms histogram{type,where} and enzyme.end_to_end_ms histogram{type} — separates compute time from coordination time
- enzyme.lease_expired_total, enzyme.progress_missed_total, enzyme.hypha_drop_midlease_total, enzyme.requeued_total — every way remote work is lost, counted
- enzyme.local_fallback_fired_total and enzyme.fallback_won_race_total — proves the no-hang rule is armed and how often it actually saves the request
- enzyme.duplicate_execution_total and enzyme.wasted_exec_ms — the cost side of hedging, so the tradeoff is visible, not hidden
- enzyme.verify_total{type,result=ok|fail|skipped}, enzyme.verify_ms histogram, enzyme.thumb_ahash_hamming histogram — the verification tier rendered per enzyme type; the Hamming distribution shows the V2 tolerance in action
- enzyme.redundant_execution_total{R}, enzyme.quorum_mismatch_total — BOINC-style validation, only meaningful for V3
- trust.reputation{peer} gauge, trust.reputation_penalty_total{peer,reason}, trust.grant_refused_untrusted_total — who is being trusted with what, and why someone got frozen out
- bytes.enzyme_input_fetched_total, bytes.enzyme_result_returned_total, transport.measured_goodput_kbps — the shared-medium budget, which is what actually caps the scaling curve
- bloom.effective_forge_workers gauge (sum of free workers across FORGE holders) and bloom.speedup_estimate (baseline_local_rate / observed_completion_rate) — the headline BLOOM number, computed live

## Risks (self-identified)

- REGIME A IS THE COMMON CASE FOR THE DEMO AND IT SHOWS NO SPEEDUP. A user drops 200 photos on one device; nobody else has them yet; shipping 600 MB over a shared radio is slower than decoding locally. FORGE offload only pays once SHARDING has already replicated the media. If the demo is 'I just added photos, watch it get faster', the demo will fail. The mitigation is real but architectural: pipeline sharding replication ahead of thumbnailing, and honestly label the cold case.
- ZERO NPM MEANS NO IMAGE DECODER. The 450 ms/image figure assumes a pure-JS baseline JPEG decoder we have to write ourselves, and that number could easily be 2-3× worse for progressive JPEG or large PNGs. If decode is slower than modelled the compute term grows — which actually *helps* the scaling ratio but hurts absolute usability. Video transcode is simply not achievable; any roadmap that assumes it is lying.
- THE SHARED MEDIUM IS ONE RESOURCE AND EVERY SUBSYSTEM WANTS IT. The scaling table assumes ROLES gets the full 12.5 MB/s. In reality SHARDING's rarest-first fetch, SUBSTRATE head gossip and voice all compete. Under concurrent load the crossover point moves down sharply — possibly to N≈8 for thumbnails. There is no global bandwidth scheduler in this design and there probably needs to be one.
- HEDGED FALLBACK BURNS BATTERY ON THE WEAKEST DEVICE. The no-hang rule guarantees liveness by having the *requester* — often the phone that is out of thermal headroom — duplicate work a peer is already doing. Under a flaky mesh with frequent lease expiry, a low-end device could end up doing nearly 100% of the work locally *plus* paying the coordination cost. Aggressive fallback deadlines make this worse. The tuning of t_fallback is the most fragile constant in the design.
- THUMBNAIL VERIFICATION IS PERCEPTUAL, NOT CRYPTOGRAPHIC. A Hamming tolerance of 6 on a 64-bit aHash leaves room for an adversary to embed a subtly altered or offensive thumbnail that passes. The defence is that thumbnails are advisory and the CID-addressed original is authoritative — but users look at thumbnails, and 'cosmetic' abuse is still abuse. Raising the tolerance to 0 would require full local decode and destroy the point of offloading.
- THE INDEX BUILD CROSSOVER AT N≈8 IS EMBARRASSINGLY LOW. It is caused by a serial merge at a small number of INDEX holders plus coarse 32-segment granularity. Both are fixable, but the fix (hierarchical merge with K_INDEX ~ ⌈√N⌉) is real additional machinery that is not designed here, only gestured at.
- PEER-TABLE DIVERGENCE UNDER PARTITION CAUSES DUPLICATE ROLE HOLDERS. This is safe by design for RELAY/BEACON/FORGE, but two INDEX holders on either side of a healed partition will have built divergent index segments, and two VAULT sets will have made divergent placement decisions that SHARDING must reconcile. ROLES makes the assignment converge; it does not make the *state those roles built* converge. That is SUBSTRATE's problem and this design quietly hands it over.
- CAPABILITY SELF-REPORTING IS UNAUTHENTICATED TRUTH. A spore can advertise 15/15/15/15/15, win every role via HRW, and then serve nothing. Reputation eventually demotes it, but the HRW input is the claimed score, not the earned one. A better design would weight HRW by *observed* completion rate rather than advertised capability; that is a real gap and a straightforward denial-of-service.
- THERMAL HEADROOM VIA A BLAKE2b MICRO-PROBE IS A PROXY, NOT A MEASUREMENT. It conflates thermal throttling with CPU contention from other applications. On a busy laptop it will report throttling that is not thermal, and the spore will refuse FORGE work it could actually do. Conservative in the right direction, but it will cost measurable throughput.

## Contract conflicts raised

- 'Link preview fetch' as an enzyme type directly contradicts the off-web guarantee — it requires an HTTP fetch to the public internet. I have redefined it as 0x03 SPORE_PREVIEW, which resolves spore:// URIs into cards from substrate blocks. If genuine web previews are wanted, they need an explicit per-colony GATEWAY capability that is off by default and clearly labelled as breaking the no-internet property. Please confirm which you want.
- 'Key stretching' must NOT be an offloadable enzyme. Its input is a user password or passphrase; shipping it to a peer hands that peer the secret, and no amount of redundant execution or reputation fixes that. I have pinned it local and defined 0x06 PUBLIC_POW (public-challenge proof-of-work, O(1) verifiable) as the only offloadable member of that family. This is a security hole in the assignment as written, not a design preference.
- 'Video transcode' is not implementable under 'ZERO npm dependencies, Node v24 stdlib only'. There is no codec in the stdlib and a pure-JS H.264 encoder is not a realistic deliverable. I have defined type 0x07 and made it refuse, substituting 0x02 KEYFRAME_STRIP (container-level parsing, no decoding, byte-exact verifiable) as the shippable video enzyme.
- Bootstrapping circularity: the contract puts the peer table under the BEACON role, but ROLES needs the peer table to decide who holds BEACON. Resolved by carrying CAP_ADVERT on TRANSPORT's peer-candidate gossip (explicitly allowed: 'discover() -> emits peer candidates'), so BEACON's job is *serving and amplifying* the table, not bringing it into existence. This needs to be stated in the contract or two subsystems will each assume the other bootstraps.
- SESSION must expose the verified ed25519 peer identity to ROLES. The contract says SESSION 'knows nothing about the substrate', which is fine, but ROLES cannot trust a capability advert without knowing which authenticated spore sent it. Requested addition to the SESSION interface: hypha.peerId -> SporeId (verified), and a guarantee that frames delivered on a hypha are attributable to that id.
- Boundary overlap between ROLES and SHARDING on VAULT. The contract says SHARDING owns 'which spore holds which blocks'. ROLES owns 'which spores are VAULTs'. I have drawn the line as: ROLES outputs the VAULT holder set via roles.getAssignment(); SHARDING maps blocks onto that set and owns all placement and fetch scheduling. ROLES must never pick blocks and SHARDING must never pick holders. Please ratify this split explicitly — it is currently ambiguous.
- Enzyme results that should be persisted (thumbnails, index segments) hit the rule that only APP writes through SUBSTRATE. ROLES therefore returns result *bytes* to the caller and persists nothing. This is workable but means a thumbnail computed on a peer is re-written by APP on the requester, and the result cache is in-memory and per-spore rather than substrate-backed. If cross-session enzyme result caching is wanted, either ROLES needs a narrow substrate write path or APP needs to own the enzyme cache.
- Minor: FORGE is not a top-k role in my design, unlike the other four — it is every spore above a capability threshold, because work-stealing wants maximum breadth. If the contract intends all five roles to be symmetric top-k sets, say so; making FORGE top-k would cap the achievable BLOOM at K_FORGE and defeat the point.
