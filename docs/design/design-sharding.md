# Sharding & Parallel Fetch

> Placement is split in two layers: weighted rendezvous (HRW) hashing decides *storage responsibility* (who is obliged to keep a shard, for durability), while BitTorrent-style HAVE advertisements decide *fetch sources* (anyone who has a block serves it). That separation makes proximity replication fall out for free, tolerates divergent peer tables under phone churn, and keeps placement O(N) with no ring or vnode machinery at N ≤ few hundred. Fetch is rarest-first over 256 KiB blocks with latency/throughput-aware peer selection, per-peer RTO and snubbing, and a duplication-capped endgame. The honest scaling result: on one shared Wi-Fi cell the speedup saturates at ~3.3× (good AP) or ~1.25× (phone hotspot) by N≈5 — the medium, not the scheduler, is the ceiling — and true superlinear-ish growth comes from the number of independent collision domains, not the number of spores.

## 1. Units: shard vs block

Two granularities, deliberately different.

| Unit | Size | Purpose | Id |
|---|---|---|---|
| **block** | 256 KiB (last short) | transfer + verification | `BLAKE2b-256(bytes)` |
| **shard** | ≤ 16 MiB (64 blocks) | placement | see below |

Two shard kinds:
- **Log segment** — SUBSTRATE blocks for one fruiting, chunked into epochs of 1024 log entries (~1 MB). `shard_id = BLAKE2b-256("seg" ‖ colony_id ‖ fruiting_id ‖ epoch_u32)`.
- **Media stripe** — a content-addressed blob is split into 256 KiB pieces; blob id is the BLAKE2b-256 Merkle root of the piece hashes. Blobs ≤ 16 MiB are one shard; larger blobs stripe into 16 MiB shards, `shard_id = BLAKE2b-256("str" ‖ blob_root ‖ stripe_u32)`.

Coarse placement keeps the shard map tiny (a 500 MB colony is ~32 media shards + a few hundred segments, fitting in one gossip frame); fine transfer keeps rarest-first granular enough to parallelise across a dozen peers. **Note the honest decomposition: "500 MB of history" is ~99% media. Logs are kilobytes per thousand messages.**

## 2. Shard assignment — weighted HRW, advisory

`score(shard, spore) = w_spore / (−ln(h / 2^64))` where `h = BLAKE2b-64(shard_id ‖ spore_pubkey)` (Resch's weighted-rendezvous form). Custodians = top-R by score. `w_spore` comes from ROLES' VAULT capability score (free disk × uptime EWMA), so a laptop plugged in outranks a 12%-battery phone.

**Why HRW over consistent hashing:** N ≤ few hundred, so O(N) scoring per shard is microseconds — a 300-spore table is 300 BLAKE2b-64 calls. No ring, no vnode count to tune, no rebalance bookkeeping. On a join or leave exactly the shards whose top-R set changes move: expected fraction `R/N`. Critically, HRW is a **pure function of the peer table**, so two spores with slightly stale tables disagree only about the shards near the boundary and converge silently — which is the normal state on a churny phone mesh. Consistent hashing's ring state is one more thing to gossip and get wrong. Explicit assignment (a coordinator) is rejected outright: it violates single-node correctness and creates a role that must be elected.

**HRW is advisory, not authoritative.** It answers "who *must* keep this so it doesn't die", never "who may serve it". Serving is governed entirely by HAVE bitfields. Three extra rules:
- **Author-pin**: the spore that authored a block keeps it unconditionally, regardless of HRW.
- **Cache-on-fetch**: any spore that fetches a block keeps it (LRU, size-capped) and advertises HAVE.
- **Relay-cache**: a RELAY that forwards a BLOCK caches it — it already paid the airtime.

## 3. Replication factor and the N ≤ 2 problem

`R_log = min(N, 3)`, `R_media = min(N, 2)`, plus pins and caches.

Say the unpleasant part plainly: **at N ≤ 3 no sharding occurs** — every spore holds everything, because R ≥ N. Sharding only begins to bite at N ≥ 4.

- **N = 1.** There is nowhere to replicate. Durability = device durability, and we do not claim otherwise. Mitigations are local: WAL + `fsync` on every SUBSTRATE append, a `durability_debt_bytes` counter surfaced in the UI, and an export-colony-to-removable-media path.
- **N = 2.** The load-bearing mechanism is the **1→2 catch-up copy**: on first hypha to a colony peer, both sides exchange shard maps and copy everything the other lacks, ordered **newest-first** (recent messages are what people need; old media is backfilled at low priority). `durability_debt_bytes` drains visibly. This is the moment the system stops being one device.
- **Re-replication.** A spore that is in the top-(R+2) HRW set for a shard and observes `online_holders(shard) < R` starts a **300 s grace timer**. A 30-second phone dropout must not trigger a copy storm. On expiry the highest-scoring non-holder pulls the shard at ≤ 10% of its measured link rate, yielding to any foreground fetch.

## 4. Wire frames

All sharding frames ride a typed channel (`chan = 0x03`) on a SESSION-authenticated hypha. Common 8-byte header: `[0] u8 chan`, `[1] u8 type`, `[2..4) u16 flags`, `[4..8) u32 payload_len`. Little-endian.

| Type | Layout (offsets after header) |
|---|---|
| `WANT` 0x01 | `8..40` shard_id · `40..44` u32 block_index · `44` u8 priority · `45` u8 dup_tag · `46..48` u16 deadline_ms |
| `HAVE_BITFIELD` 0x02 | `8..40` shard_id · `40..44` u32 n_blocks · `44..48` u32 generation · `48..` ⌈n/8⌉ bytes, LSB-first |
| `HAVE_DELTA` 0x03 | `8..40` shard_id · `40..44` u32 generation · `44..46` u16 count · then count × u32 block_index |
| `BLOCK` 0x04 | `8..40` shard_id · `40..44` u32 block_index · `44..48` u32 byte_len · `48..80` block_hash · `80..` payload ≤ 256 KiB |
| `CANCEL` 0x05 | `8..40` shard_id · `40..44` u32 block_index · `44` u8 dup_tag |
| `SHARD_MAP` 0x08 | `8..10` u16 count · count × {32B shard_id, u32 n_blocks, u8 want_R, u8 online_holders} |

## 5. The fetch scheduler

State: `avail[b]` = number of connected peers advertising block `b`, maintained in **bucket arrays indexed by availability count**, so "pick from the rarest non-empty bucket" is O(1) and a HAVE_DELTA update is O(1) per block.

**Block selection** (priority classes, descending):
1. `INTERACTIVE` — user is staring at it.
2. `SEQUENTIAL_HEAD` — first 8 blocks of a media blob, so a video/image renders progressively. This deliberately overrides rarest-first; BitTorrent does the same for streaming.
3. `RAREST` — pick **uniformly at random within the rarest non-empty bucket**. The randomisation is not decoration: without it every peer converges on the same block and the rare block's single holder is stampeded.
4. `PREFETCH` — background backfill.

**Peer selection** for a chosen block `b`: among peers advertising `b` with a free pipeline slot, `argmin( queued_bytes_p / thr_p + srtt_p/2 )`. Both measured throughput and measured latency enter; a peer with a deep queue loses to an idle slower one.

**Pipelining**: `depth_p = clamp(⌈(thr_p × srtt_p)/262144⌉ + 2, 2, 16)`. At 25 MB/s and 3 ms RTT one block is 10 ms of wire time versus 3 ms RTT, so depth 2–3 fully hides the round trip.

**Anti-stall, three layers** — this is where single-slow-peer failures actually get killed:
- **Per-request RTO** `= SRTT_p + 4·RTTVAR_p + 262144/thr_p` (TCP's estimator). On expiry: send CANCEL, reissue to the next-best holder, halve `depth_p`.
- **Snub**: no BLOCK from a peer for 5×RTO → `depth_p = 1`, weight ×0.25, probe every 10 s. Recovers on first success.
- **Steal-on-slow**: if an outstanding request exceeds 2× the job's median service time and any holder is idle, duplicate it immediately, outside endgame, bounded by a **global duplicate budget of 2% of job bytes**.

**Endgame**: when `unrequested == 0` and `outstanding ≤ max(8, 2×peers)`, duplicate each outstanding request to up to 2 additional holders (**dup cap 3**), CANCEL the losers on first arrival. Worst-case waste with 20 outstanding blocks: `20 × 2 × 256 KiB = 10 MB` — **2% of a 500 MB sync**. Without the cap, 12 peers × 20 blocks would be 61 MB (12%), which is why the cap exists rather than BitTorrent's uncapped classic endgame.

Complexity: O(1) amortised scheduling per block; O(P) peer scan with P ≤ 12 connected hyphae.

## 6. THE SCALING ANALYSIS

**Assumptions, stated so they can be attacked:**

| Quantity | Good AP (Wi-Fi 5, 2×2, 80 MHz) | Phone hotspot |
|---|---|---|
| Cell aggregate goodput | 400 Mbps = 50 MB/s | 150 Mbps = 18.75 MB/s |
| Per-spore sustained TX | 60 Mbps = 7.5 MB/s | 7.5 MB/s |
| Per-spore RX | 200 Mbps = 25 MB/s | 25 MB/s |
| RTT | ~3 ms | ~4 ms |

**The trap everyone falls into:** Wi-Fi is a *shared medium in infrastructure mode*. Every spore→spore byte crosses the air **twice** (up to the AP, down from it). So delivered peer-to-peer payload ≤ cell/2 = **25 MB/s** good AP, **9.375 MB/s** hotspot, no matter how many spores there are.

Sync rate = `min( (N−1)·7.5 , joiner_RX 25 , cell/2 )`. For D = 500 MB:

| N | seeder supply | good-AP time | hotspot time |
|---|---|---|---|
| 1 | — | local verify only, ~0.5–2 s (BLAKE2b ≈ 1 GB/s) | same |
| 2 | 7.5 MB/s | **66.7 s** (seeder upload bound) | 66.7 s |
| 5 | 30 MB/s | **20.0 s** (cell + RX bound) | 53.3 s |
| 20 | 142 MB/s | **20.0 s** | 53.3 s |
| 100 | 742 MB/s | **20.0 s** | 53.3 s |

**Where the curve stops bending, in the order the ceilings are hit:**
1. **Seeder upload** (N = 2–4). Real, and this is where the whole speedup lives.
2. **Joiner radio RX / cell airtime** (N ≈ 5). Both land at 25 MB/s on a good AP; on a hotspot the cell hits first at 9.4 MB/s, at N = 3. **This is the asymptote.**
3. Never reached on LAN: scheduler RTT overhead (hidden by depth-3 pipelining), endgame waste (2%), HAVE-bitfield gossip (a 500 MB colony's full bitfield is 2000 blocks = 250 bytes/shard), BLAKE2b verification (~0.5 s for 500 MB).

**The honest asymptote for a single joiner:** speedup = `min(joiner_RX, cell/2) / seeder_TX` = **3.33× on a good AP, 1.25× on a phone hotspot**, saturating at N ≈ 5. Beyond N = 5 a single joiner gets *no further benefit on one AP.* Saying otherwise would be a lie.

**Where BLOOM is real — the second curve.** Take K simultaneous joiners and one seeder:
- Server model: the seeder uploads the 500 MB *K times*. Cohort completion = `K × 66.7 s`. K = 10 → **667 s**.
- Swarm model: the seeder uploads each block *once* (67 s of its airtime); joiners trade distinct shards. Completion = `max(67, K × 500/25) `. K = 10 → **200 s**, a 3.3× win.
- **Across C independent collision domains** (multi-AP, Wi-Fi Direct groups, future BLE clusters — separate radios, separate airtime), the cell term divides by C: K = 10 across 3 APs → `max(67, 200/3) = 67 s`, a **10× win**, and it keeps improving with C.

**So the honest formulation of the product claim:** sync time scales with the number of *independent radio domains*, and with N only up to the point where one cell saturates (N≈5). Within one cell the gain is a fixed constant — meaningful (3.3×) but bounded. This is the sentence the marketing copy must not delete.

## 7. Proximity replication

- **Cache-on-fetch + relay-cache** (above) alone create the swarm: popularity drives replication with zero coordination.
- **Demand-weighted pinning**: each spore keeps `demand_ewma[shard]` (α = 0.2, per fetch). If `demand_local > 2 × demand_median_of_neighbours` and the shard isn't locally custodied, promote the cache copy to a pin — data migrates toward its consumers, which is exactly what a sticker pack or a hot channel's images should do.
- **Latency model**: with F direct hyphae and fraction p of neighbours holding a block, `P(1-hop) = 1 − (1−p)^F`. For a popular asset at p = 0.5, F = 8: **99.6%** one hop. As N grows, F grows (up to the cap) and p grows for popular content, so median media latency falls toward one hop even though delivery *bandwidth* has already saturated. That is the one genuine latency win from scale.

## 8. The benchmark that proves it

Throttling lives **in a transport adapter** — precisely what the adapter interface exists for. `ThrottledLocalTransport` wraps real TCP loopback with:
1. Per-spore TX and RX token buckets (7.5 / 25 MB/s, configurable).
2. **A global cell bucket that every byte is charged against twice.** Omit this and you measure loopback bandwidth and publish a fake linear speedup.
3. Latency injection, 3 ms ± 1 ms jitter, optional loss.

**Conditions:** *Control A* (server baseline) — same N, all fetches forced to one designated seeder. *Control B* (falsifier check) — cell bucket disabled, to prove the bend is the medium and not the scheduler. *Treatment* — full swarm, N ∈ {1,2,3,5,20,100}, plus a K-joiner flash-crowd run at K ∈ {1,2,5,10} and C ∈ {1,3} simulated cells.

**Measure:** wall-clock `t_sync`; `bytes_received` vs `bytes_duplicate`; per-peer link utilisation %; requests / cancels / timeouts / snubs / endgame-duplicates; and `time_to_first_renderable_message` (the UX number that actually matters).

**Falsifiers.** The claim is dead if: (a) single-joiner time does not drop ≥ 2.5× from N=2 to N=5; (b) duplicate bytes exceed 5% of the transfer; (c) Control B does not run faster than the cell-limited treatment at N=20 — that would mean the throttle isn't modelling the medium and every number above is meaningless; (d) K-joiner cohort completion tracks Control A instead of beating it ~3×; (e) p99 block latency grows with N (a scheduler that degrades under peer count).

## Interfaces

- `sharding.custodians(shardId: Buffer32, peerTable: SporeId[], weights: Map<SporeId, number>, R: number) -> SporeId[]` — Pure weighted-HRW function returning the R spores responsible for storing a shard. Deterministic given the peer table; callable by any subsystem to answer 'should I be keeping this?'
- `sharding.fetch(shardId: Buffer32, blocks: Uint32Array|'all', priority: 0..255) -> FetchJob` — Primary entry point for SUBSTRATE and APP. Returns a job emitting 'block', 'progress', 'done', 'stalled'. Idempotent per (shard, block) — concurrent callers join the same job.
- `FetchJob.on('block', (blockIndex, bytes) => void) / .cancel() / .stats() -> JobStats` — Streaming delivery so APP can render media progressively; stats carries bytesReceived, bytesDuplicate, perPeerUtil, outstanding.
- `sharding.announceHave(shardId: Buffer32, blockIndex: number) -> void` — Called by SUBSTRATE after it verifies and persists a block. Triggers HAVE_DELTA gossip on all hyphae.
- `sharding.localBitfield(shardId: Buffer32) -> { generation: number, bits: Buffer }` — What this spore can serve. Consumed by the HAVE_BITFIELD frame builder and by re-replication decisions.
- `sharding.onPeerTableChange(added: SporeId[], removed: SporeId[]) -> void` — Called by BEACON. Recomputes affected custodian sets (only R/N of shards change) and arms/disarms the 300s re-replication grace timers.
- `sharding.setVaultBudget(bytes: number, policy: 'lru'|'demand') -> void` — ROLES sets how much cache-on-fetch storage this spore contributes, based on its VAULT capability score.
- `sharding.needsFrameSend(cb: (toSpore: SporeId, frame: Buffer) => Promise<void>) -> void` — Injected send path. SHARDING has no transport of its own (see contractConflicts); the host wires this to SUBSTRATE's or SESSION's typed-channel sender for chan 0x03.
- `sharding.onFrame(fromSpore: SporeId, frame: Buffer) -> void` — Inbound demux for chan 0x03 frames (WANT / HAVE_BITFIELD / HAVE_DELTA / BLOCK / CANCEL / SHARD_MAP).
- `sharding.durabilityDebt() -> { shardId, haveHolders, wantR, bytes }[]` — Under-replicated shards, for the UI's durability warning at N=1 and N=2 and for the telemetry panel.

## Telemetry emitted

- sharding.blocks_requested_total / blocks_received_total / blocks_duplicate_total (counters, labelled by peer)
- sharding.bytes_received_total / bytes_duplicate_total / bytes_served_total (counters, per peer)
- sharding.duplicate_ratio (gauge: bytes_duplicate / bytes_received — the endgame-waste proof, must stay under 0.05)
- sharding.peer_throughput_bps and sharding.peer_srtt_ms (per-peer gauges, EWMA — these drive scheduling, so rendering them shows the scheduler thinking)
- sharding.peer_utilization_pct (per-peer gauge: fraction of wall time with a block in flight — the panel that proves parallelism is real and not one peer doing all the work)
- sharding.pipeline_depth (per-peer gauge) and sharding.outstanding_requests (gauge)
- sharding.timeouts_total / cancels_total / snubs_total / steal_on_slow_total (counters, per peer — the anti-stall machinery becoming visible)
- sharding.endgame_active (boolean gauge) and sharding.endgame_duplicates_total (counter)
- sharding.rarest_bucket_histogram (histogram of avail[b] over wanted blocks — renders as the live rarity distribution)
- sharding.availability_min / availability_mean (gauges: rarest block's holder count — the 'is anything about to be lost' number)
- sharding.shards_custodied / shards_cached / shards_pinned (gauges) and sharding.vault_bytes_used / vault_bytes_budget
- sharding.durability_debt_bytes and sharding.under_replicated_shards (gauges — non-zero at N=1 by definition; the honest N=1 indicator)
- sharding.rereplication_active_bytes / rereplication_completed_total (counter+gauge, with grace-timer countdowns)
- sharding.catchup_progress_bytes (the N=1→N=2 newest-first copy, as a progress bar)
- sharding.hrw_recompute_total / hrw_shards_moved_total (counters — should show ~R/N of shards moving per join, which is itself a testable claim)
- sharding.sync_job_duration_ms (histogram) and sharding.time_to_first_renderable_ms (histogram)
- sharding.effective_sync_rate_bps (gauge — the number plotted against N for the BLOOM curve)
- sharding.hop_distance_histogram (hops to the serving spore per block — proves proximity replication lowering over time)
- sharding.demand_ewma_top (top-10 shards by local demand, driving demand-weighted pinning)
- event sharding.bloom(N_before, N_after, rate_before_bps, rate_after_bps) — emitted when effective_sync_rate jumps >25% within 10s of a peer joining; this is the literal BLOOM the UI animates

## Risks (self-identified)

- The headline claim is weaker than the product promises, and this is the top risk. On a single phone hotspot — the exact scenario the pitch leads with — the cold-start speedup asymptote is ~1.25×, not a dramatic curve. On a decent AP it is 3.33× and saturates at N≈5. If anyone markets 'gets faster as peers join' as unbounded, the benchmark will publicly contradict them. The defensible claim is: (a) 3.3× over single-seeder within one cell, (b) K× better cohort completion for flash crowds because the seeder uploads each block once instead of K times, (c) genuine scaling with the number of independent radio domains.
- Wi-Fi's shared medium and double air-crossing may be even worse than modelled. Real 802.11 throughput collapses non-linearly with station count (contention, retries, rate-anomaly where one distant slow client drags the whole cell's airtime). At N=100 associated stations the aggregate could be well under half the 400 Mbps assumed, meaning sync could get *slower* past some N. Mitigation: cap simultaneously-active hyphae per fetch job at 12 regardless of N, and measure the real curve rather than trusting the token-bucket model.
- Cache-on-fetch plus demand-weighted pinning can produce a herd where every spore caches the same popular media and nobody holds the rare tail — exactly inverting rarest-first's intent at the storage layer. HRW custodianship is the counterweight, but if HRW custodians are all offline phones, availability_min goes to zero silently. The availability_min gauge is the early-warning, and it must be surfaced, not just logged.
- Phone churn can make the 300 s re-replication grace window wrong in both directions. Too long and a genuine departure leaves a shard at R=1 for five minutes; too short and a commute through a dead zone triggers a copy storm that eats the airtime budget the foreground fetch needs. This parameter almost certainly needs to adapt to observed session-length distribution rather than being a constant.
- Endgame duplicate waste is bounded analytically at 2%, but CANCEL is advisory: a peer may have already pushed 256 KiB before the CANCEL lands. On a 3 ms LAN that is fine; over a future BLE adapter with hundreds of ms of latency the waste could be several times the model. The dup cap of 3 limits the damage but the endgame trigger threshold should be latency-scaled per transport.
- Single-node correctness is technically satisfied but experientially hollow — at N=1 there is no durability beyond the device, and at N≤3 no sharding actually happens. If a user loses their phone at N=1 they lose the colony. The export-to-removable-media path is the only real answer and it must actually ship, not sit in a backlog.
- The benchmark can be gamed accidentally. If the global cell bucket is misconfigured or its double-charging is dropped in a refactor, the test will report a beautiful linear speedup that does not exist on real hardware. Control B (cell bucket disabled) exists specifically to catch this, and it should be a required CI assertion, not an optional run.
- Weighted HRW depends on capability scores from ROLES. If those scores are manipulable by a peer (claiming vast free disk and perfect uptime), an attacker becomes custodian for everything and can withhold. Custodianship confers no read authority — blocks are encrypted at the SUBSTRATE layer — but a withholding custodian is a durability attack. Needs a reputation decay based on observed serve-success, which is not in this design.

## Contract conflicts raised

- SHARDING has no send path in the contract. The contract grants 'ask TRANSPORT+SESSION to send this frame to that spore' only to SUBSTRATE. SHARDING must move WANT/HAVE/BLOCK/CANCEL frames itself. Resolution needed: either SESSION exposes a typed-channel sender directly (chan 0x03 alongside SUBSTRATE's channel), or SUBSTRATE exposes sendFrame(spore, frame) as a pass-through. I have designed against an injected needsFrameSend() callback so either wiring works, but the contract must pick one explicitly.
- SHARDING needs the peer table and per-spore capability weights, which live in BEACON (peer table) and ROLES (VAULT capability score). The contract gives SHARDING neither. Weighted HRW is not computable without both. Add: BEACON emits peerTableChanged(added, removed) and ROLES exposes vaultWeight(spore) -> number.
- The contract says SUBSTRATE owns 'block hashing/verification' while SHARDING owns 'which spore holds which blocks'. But the fetch path must verify a BLOCK frame before caching and re-advertising it, otherwise a malicious peer poisons every downstream cache. Either SHARDING gets a verifyBlock(shardId, index, bytes) -> bool callback from SUBSTRATE (my assumption), or every fetched block round-trips through SUBSTRATE before SHARDING may announce HAVE. The former is cheaper; the contract should say so.
- The scaling target is stated as '500MB history', but history in the SUBSTRATE sense (append-only message logs) is kilobytes-to-megabytes. The 500MB is overwhelmingly media blobs, which are APP-layer content-addressed objects, not log blocks. The sharding unit, replication factor, and eviction policy legitimately differ between the two, and the contract's single word 'blocks' hides that. I have split them (log segments vs media stripes) and the contract should acknowledge the split.
- 'Media' is listed under APP, and APP 'reads and writes through SUBSTRATE only'. That forces every media byte through the log layer, which is wrong: media is immutable content-addressed bulk data whose only log presence should be a reference (blob root hash + size + mime). The contract should be amended to let APP reference blobs in SUBSTRATE while fetching their bytes through SHARDING directly.
- SHARDING's re-replication and proximity pinning consume bandwidth that competes with SUBSTRATE's head gossip and live message delivery. Nothing in the contract owns cross-subsystem bandwidth arbitration. Some component must hold a global airtime budget with priority classes, or background re-replication will visibly degrade live chat latency. I suggest ROLES owns it, since it already owns enzyme scheduling.
