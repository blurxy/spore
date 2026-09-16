# Discovery & Transport

> Discovery is a fixed admin-scoped multicast group (239.42.66.7:47474, TTL=1) carrying signed HELLO datagrams paced by the Trickle algorithm (RFC 6206), so a lone spore emits one packet per ~8.5 minutes and a 200-spore LAN still only emits ~3 packets per interval, with unicast HELLO_ACK to avoid join storms and an optional advertise-only DNS-SD mirror. Transport is deliberately NOT a byte stream: adapters expose a message-boundary-preserving Link with declared caps (mtu as low as a virtual 64 bytes, ordered/reliable/dialable flags), so a BLE GATT adapter can implement it honestly, and TCP restores boundaries with a u32 length prefix. Multi-hop uses signed link-state advertisements plus Dijkstra and explicit source routing — chosen over distance-vector because at N≤500 the LSDB is tiny and full topology is what lets SHARDING request node-disjoint paths for genuinely parallel fetch.

## 0. Constants

Multicast group `239.42.66.7:47474` (IPv4, admin-scoped 239/8), `ff02::42:5350` (IPv6 link-local). Hypha TCP listener `47475`. Multicast TTL/hop-limit hard-set to **1** — off-web is enforced at the IP layer, not promised in a comment.

Additionally, the dialer enforces a **hard address allowlist**: `10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8, fe80::/10, fc00::/7, ::1`. Any other destination is refused and counted as `tp.dial_refused_public`. This turns "no internet dependency of any kind" into a testable invariant.

## 1. Discovery

### HELLO datagram (all integers little-endian)

```
off  size  field
0    4     magic "SPOR"
4    1     wire_version = 1
5    1     type: 0x01 HELLO, 0x02 HELLO_ACK, 0x03 BYE
6    2     flags (bit0 dialable_lan, bit1 has_ble, bit2 has_aware,
                  bit3 relay_willing, bit4 graceful_bye)
8    32    spore_id (ed25519 public key)  <- the ONLY identity
40   8     boot_id (ms since epoch at process start)
48   4     announce_seq (u32, monotonic per boot)
52   2     tcp_port
54   1     addr_count
55   ...   addr records: 1B family(4|6) + 1B prefix_hint + 4|16B addr
..   2     colony_filter_len
..   N     colony_filter (opaque to TRANSPORT; supplied by APP)
..   1     nick_len ; ..  N  nick (UTF-8 <=32)
..   2     capability hints (role bitmap + device class nibble)
..   8     proof_tag = BLAKE2b-256(network_key || bytes[0..len-72])[0..8]
..   64    ed25519 signature over bytes[0..len-64]
```

Total ≈ 190–400 bytes; hard cap 1200 so it never fragments on a 1280-byte-MTU path.

### Distinguishing SPORE from noise — a staged gate, cheapest test first

1. length in [150, 1200]; 2. magic; 3. wire_version supported; 4. **proof_tag** (one BLAKE2b, ~1 µs); 5. per-source-IP token bucket (8 packets burst, 2/s refill); 6. global ed25519 verify budget (200 verifies/s, drop-and-count beyond); 7. `spore_id !== self`.

Step 7 is not optional. I verified empirically on this runtime that with `setMulticastLoopback(true)` we receive our own datagrams from our own interface address — so self-suppression must be by `spore_id`, never by address. We keep loopback **on** deliberately: it is what lets several spores run on one host for development and what makes the N=1 loopback path real.

The signature is **not** a trust decision — trust comes from the Noise handshake. It exists to (a) make flooding cost the attacker a signature, and (b) bind address→identity so we cannot be tricked into dialing a third party (reflection/amplification). A discovery record only ever produces a *candidate*; a bad candidate costs one rate-limited dial.

### Cadence: Trickle (RFC 6206), not a fixed timer

`Imin = 1s`, `Imax = Imin·2^9 = 512s`, redundancy `k = 3`.

- Interval `I` starts at `Imin`, doubles on expiry to `Imax`. Transmit at `t ~ U(I/2, I)` **iff** counter `c < k`.
- `c++` on each *consistent* HELLO (known spore_id, known boot_id, `announce_seq` ≤ stored, unchanged addr set/colony filter).
- **Reset `I = Imin`** on inconsistency: unknown spore_id, boot_id change (restart), addr set change, colony filter change, our own interface set changed, or any hypha transitioning to DEAD.

Properties this buys, all of which are the point: at N=1 the interval walks to 512s and the node is effectively silent; at N=200 only ~3 spores transmit per interval instead of 200 (announce load is O(k), not O(N)); on any join the whole mesh snaps to 1s and converges in ~2 intervals.

On top of Trickle: an **eager burst** at startup — 3 HELLOs at t=0, ~200 ms, ~600 ms (jittered), mirroring mDNS's announcing behaviour (RFC 6762 §8.3), so cold start feels instant. And a **unicast HELLO_ACK**: on hearing a HELLO from an unknown spore, reply *unicast* to the source after `U(0, 100ms)`, never multicast. This is the mDNS known-answer trick and it is what prevents an N² multicast storm when a group of people walk into a room together.

**BYE**: on graceful shutdown emit 2 multicast BYEs with `graceful_bye`; receivers mark DEAD immediately rather than waiting out the liveness timer.

### DNS-SD mirror (secondary, advertise-only, optional)

`_spore._tcp.local` → PTR `<nick>-<id8>._spore._tcp.local`; SRV prio 0 weight 0 port 47475 target `<id8>.spore.local`; A/AAAA; TXT `txtvers=1 id=<base32(pubkey)> bid= seq= cf=<b64 filter> ad=<caps hex> sg=<16B truncated sig>`. Kept under ~400 bytes of TXT so it fits one packet.

It is secondary on purpose: binding 5353 fights Bonjour/avahi on macOS and Windows, and a SPORE node must stand up with zero system-daemon dependency. Records discovered this way are **unverified hints** and enter the pipeline as plain candidates.

### Phone hotspot, no uplink

- Bind and `addMembership(group, ifaceAddr)` **per interface**, never on the wildcard. This box has Tailscale (100.85.132.85/32) alongside Ethernet (192.168.12.5/24); wildcard joins pick the wrong one.
- No DHCP, gateway, or routable address is ever assumed. 169.254/16 self-assignment works; with no IPv4 at all we use IPv6 link-local with the scope id.
- Hotspot APs (192.168.43/24 Android, 172.20.10/28 iOS) forward multicast but often rate-limit it savagely (sent at the basic rate). So every HELLO is **also** sent to the per-interface subnet-directed broadcast (`x.x.x.255`) and to `255.255.255.255`. Cheap, and it rescues APs with IGMP snooping enabled but no querier on the segment — a very common configuration that silently black-holes 239/8.
- **AP client isolation cannot be defeated at this layer, and we say so.** Detection: we see our own broadcasts looped but no peer ever answers a unicast probe within 3 announce intervals → raise `tp.isolation_suspected`, surface it in the UI, and fall back to the offline invite blob (which carries an addr) and to other adapters.

## 2. The transport adapter interface

```js
Adapter {
  name, caps: {
    mtu,                 // virtual MTU, >= 64 REQUIRED
    physicalMtu,         // may be 20 (BLE ATT default)
    ordered, reliable, duplex,
    maxConcurrentLinks,  // BLE ~4-8, Wi-Fi Aware ~4, TCP 256
    dialable,            // false is legal (BLE peripheral)
    ratedBps, latencyMsHint
  }
  start(); stop(); discover();          // emits 'candidate'
  connect(candidate) -> Promise<Link>;  // rejects if !dialable
  on('link', Link)                      // inbound
}
Link { caps, send(buf)->Promise, on('datagram',buf), on('close',reason),
       close(reason), rtt(), inflightBytes() }
```

The contract is: **one `send` produces exactly zero or one `datagram` at the peer, whole.** Message boundaries are the adapter's responsibility. BLE and Wi-Fi Aware get this for free; the TCP adapter restores it with a `u32 length | payload` prefix (max 65536; a larger prefix closes the link as `oversize` before allocating anything).

An adapter whose `physicalMtu < 64` **must** sub-fragment internally (1 byte: bit0 more-follows, bits1-7 sub-index) to present `mtu >= 64`. That is what BLE stacks do anyway via ATT_MTU negotiation (185 iOS / 247 Android) or L2CAP CoC. Registering an adapter that cannot reach a 64-byte virtual MTU is refused with `tp.adapter_rejected_mtu`. Below 64 bytes, our 20-byte segment overhead leaves no usable payload, and pretending otherwise would ship a BLE adapter that technically connects and practically cannot carry a sentence.

### What upper layers may NOT assume

- **Not a byte stream.** No partial reads, no write-twice-read-once.
- **No large frames.** Budget for `mtu = 64`. Everything chunks.
- **No ordering** unless `caps.ordered`. BLE write-without-response and NAN follow-ups reorder.
- **No reliability** unless `caps.reliable`.
- **No simultaneous connect.** `dialable=false` is legal; the dedup rule below never requires both sides to be able to dial.
- **No address stability.** BLE resolvable private addresses rotate ~15 min. The peer table is keyed by `spore_id` and nothing else; `addr` is an opaque adapter hint.
- **No unlimited concurrency.** Respect `maxConcurrentLinks`; topology must choose which peers to hold.
- **No low latency.** A BLE connection interval is 7.5 ms–4 s. Every timeout derives from `caps.latencyMsHint`; no hardcoded sub-30s timeout is safe.
- **`send` may block.** Always await; backpressure is the promise.

## 3. Segment framing and chunking

A **segment** is one link payload. Its header is **plaintext** (relays must route without decrypting); the body is one SESSION AEAD record with its own tag, so a lossy link can verify and retransmit per segment rather than per megabyte.

**FULL profile** (`mtu >= 256`), 12-byte header:
```
0  1  flags: b0 START, b1 END, b2 RELAY, b3 ACK_REQ
1  3  msg_id (u24)
4  2  seg_index (u16)
6  2  seg_total (u16; 0 = streaming)
8  4  seq (u32, per-hypha; this IS the AEAD nonce input)
12 .. ciphertext + 16B Poly1305 tag
```
**TINY profile** (`mtu < 256`), 4-byte header: `b0-3` flags, `b4-7` msg_id high nibble; byte1 msg_id low 8 (u12 = 4096 in flight); bytes 2-3 `seg_index`; `seg_total` rides in the START segment's first 2 payload bytes. Nonce is derived as `epoch(u32) || msg_id(u12) || seg_index(u16)` — no `seq` on the wire. Overhead 4+16 = 20 bytes; at mtu 64 that is 44 usable bytes, ~69% efficiency. Fine for text, painful for media, and we state that plainly.

`MAX_MSG = 1 MiB`. Anything larger is not a transport concern — it is many content-addressed blocks and belongs to SHARDING. This is the clean cut that keeps reassembly buffers bounded.

**ARQ for unreliable links** (disabled entirely when `caps.reliable`): Selective Repeat with a 64-segment window. START sets ACK_REQ; after a `3·rtt` gap timer the receiver sends `SEG_NACK { msg_id, base_index, u64 bitmap }`; the sender retransmits only the missing indices. This is QUIC's ACK-range idea at its simplest.

## 4. Hypha lifecycle

`CANDIDATE → DIALING → HANDSHAKING → LIVE ⇄ DEGRADED → DEAD → COOLDOWN → CANDIDATE`

- **DIALING** timeout `max(3s, 4·latencyMsHint)`; concurrent dial cap 8 and per-adapter `maxConcurrentLinks`.
- **HANDSHAKING** = Noise XX via SESSION. Timeout 10 s TCP / 60 s BLE (derived, never fixed).
- **LIVE**: keepalive PING every 15 s (TCP) / 45 s (BLE).
- **DEGRADED**: 1 missed keepalive, or NACK rate > 20%, or RTT > 5× EWMA baseline, or sustained backpressure. Still usable; ROLES demotes it for enzyme scheduling and SHARDING deprioritizes it. Returns to LIVE after 2 clean keepalives.
- **DEAD**: 3 missed keepalives, link close, BYE, or auth failure.
- **COOLDOWN**: `delay = min(1s · 2^(fails-1), 300s) · U(0.5, 1.5)` — AWS "Full Jitter". `fails` resets **only after a hypha stays LIVE ≥ 60 s**, not on handshake success; otherwise a peer that handshakes then instantly dies flaps forever. `dial_fails` and `auth_fails` are separate; `auth_fails >= 3` quarantines that `spore_id` for 1 hour (anti-grinding).

### Simultaneous-dial dedup

1. **Who dials, decided before dialing, from the HELLO**: if exactly one side advertises `dialable` for that adapter, it dials. If both can, the side with the **numerically lower 32-byte spore_id** (unsigned big-endian compare) dials. If neither can, no hypha on that adapter. Deterministic, no clock, no negotiation.
2. **When the race happens anyway** (crossed HELLOs, stale caps): both handshakes complete, then each side independently applies *keep the link whose initiator has the lower spore_id; close the other with `dup_hypha`*. Both sides compute the same answer from the same two facts, so they close the same link with no round trip.
3. **Multiple links to one spore are allowed across different adapters.** Dedup is per `(spore_id, adapter)`. The table is `spore_id -> Set<Link>` and SESSION presents **one logical hypha** multiplexed over the currently-best link. This is QUIC-style connection migration, and it is what makes "walk out of Wi-Fi range, BLE takes over" invisible to APP.

## 5. Multi-hop: link-state + source routing

**Choice: link-state (OLSRv2/Babel lineage) with Dijkstra and explicit source routes.** Justification against the stated 1–500 scale:

- The LSDB is genuinely small. 500 spores × degree 8 × 34 bytes ≈ 136 KB worst case; a real LAN mesh is near-complete and 1 hop, so it is trivial.
- **Full topology is what SHARDING needs.** Distance-vector gives you a next hop; it cannot tell you whether two fetch paths are independent. Node-disjoint paths are the precondition for parallel fetch actually being parallel instead of serializing through one relay's uplink — i.e. link-state is load-bearing for the BLOOM guarantee, not an aesthetic preference.
- No count-to-infinity when a mesh partitions and rejoins, which is the normal case when people walk away.
- Honest ceiling: beyond ~1000 spores LSA flooding gets chatty. Documented fallback is OLSR MPR-restricted flooding or a Babel-style DV mode; we do not ship it now.

**LSA**: `origin_id(32) | boot_id(8) | lsa_seq(4) | ttl_ms(4) | n(1) | n×{peer_id(32), cost(1), adapter_class(1)} | sig(64)`. `cost = clamp(round(4·log2(1+rtt_ms)) + adapter_penalty, 1, 255)` — log of RTT so a 5 ms/8 ms difference does not flap routes while LAN (~4-10) still strongly beats BLE (~60-120). `cost = 255` means "never traverse me" and is how a spore that refuses to relay **advertises** that refusal, so Dijkstra routes around it instead of blackholing into it.

Flooding: per-origin `lsa_seq` dedup, forward to all live hyphae except the arrival one (split horizon), origin emits ≤1 LSA/5 s, receiver accepts ≤1 per origin per 2 s. Full LSDB is pushed on handshake completion. Dijkstra recompute is coalesced to ≤1 per 500 ms; `O(E log V)` is nothing here.

**Relay header** (segment with `flags.RELAY`):
```
0   1   relay_ver=1
1   1   hop_count n (max 8)
2   1   hop_index
3   1   ttl (init n+2)
4   16  path_id
20  8n  path[]: first 8 bytes of each spore_id
20+8n.. opaque payload (end-to-end encrypted; relays cannot read it)
```
Loop prevention is **structural, not probabilistic**: `hop_index` strictly increases; a relay drops any packet whose path contains its own id at an index other than `hop_index`; `ttl` decrements and drops at 0; `path_id` sits in a 4096-entry 30 s LRU to kill exact duplicates. Truncated 8-byte path ids are safe because the next hop is verified against the *authenticated* hypha peer id — a collision fails closed, it does not misroute.

Flooding is used **only** for LSAs, BEACON capability gossip, and a last-resort "no route" probe. Never for payload.

`paths(dst, k)` returns up to k node-disjoint paths by successive shortest path with interior-node removal (Suurballe-lite), `O(k·E log V)`.

Relay admission control: per-source token bucket (256 KiB/s, 64 seg/s) and a global relay budget defaulting to 20% of measured link capacity, settable to 0.

## 6. N = 1

- If every multicast join fails (no adapters at all), bind loopback and continue: `tp.state = 'solo'`. No throw, no retry storm. An interface watcher polls `os.networkInterfaces()` every 10 s and re-binds only when the interface-set hash changes — Node has no portable link-change event and the syscall is cheap.
- Trickle walks to `Imax`: steady state is one ~200-byte datagram per 8.5 min plus one interface poll per 10 s.
- The dialer is **event-driven off candidate-added**, not polled, so with zero candidates it holds zero timers. Checkable invariant, exposed as a gauge: **with zero hyphae, exactly two timers are live** (Trickle + interface poll).
- Dijkstra is skipped when `|V| < 2`; `route(dst)` returns `unreachable` immediately.
- **The loopback adapter.** We register an in-process adapter that links the spore to *itself*: `mtu 1 MiB, ordered, reliable, cost 0, latency 0`. The local spore therefore appears in its own peer table as a live hypha. Every upstream code path that says "fetch this block from a VAULT peer" or "farm this enzyme to a FORGE peer" works unmodified at N=1. This is how guarantee #1 is delivered as a transport fact rather than as five separate `if (peers.length === 0)` special cases scattered through SUBSTRATE, SHARDING, ROLES and APP — and it costs roughly 80 lines.

## Interfaces

- `transport.start(opts) -> Promise<void> ; transport.stop(reason) -> Promise<void>` — Bind per-interface multicast/broadcast sockets and the TCP listener, register adapters (including the always-present loopback adapter), begin Trickle. Never throws on 'no network'; enters state 'solo' instead.
- `transport.registerAdapter(adapter: Adapter) -> void` — Slot in lan-tcp / ble-gatt / wifi-aware / loopback. Refuses any adapter whose virtual caps.mtu < 64 with tp.adapter_rejected_mtu.
- `transport.on('candidate', {sporeId, adapter, addr, caps, announceBlob, firstSeen, lastSeen}) -> void` — A verified-but-untrusted discovery hit. APP may inspect announceBlob (the opaque colony filter) via scoreCandidate to decide whether dialing is worth it.
- `transport.on('hypha', {sporeId, state, adapter, rtt, cost, since}) -> void` — Lifecycle transitions CANDIDATE|DIALING|HANDSHAKING|LIVE|DEGRADED|DEAD|COOLDOWN. SESSION, SHARDING and ROLES all subscribe here rather than to raw links.
- `transport.send(sporeId, msgBuf /* <=1 MiB */, {priority, deadlineMs}) -> Promise<void>` — The contract's 'send this frame to that spore'. Chunks into segments, picks the best link or a source route transparently, applies ARQ on unreliable links. Rejects with 'unreachable' when no route exists.
- `transport.on('message', {fromSporeId, msgBuf, viaHops, adapter}) -> void` — Reassembled, decrypted, whole message. Exactly one event per successful peer send(); never partial.
- `transport.route(dstSporeId) -> {path: SporeId[], cost, hops} | null` — Current best path from the link-state DB. Null means unreachable; callers must handle it (at N=1 everything is null and that is correct).
- `transport.paths(dstSporeId, k) -> Array<{path, cost}>` — Up to k node-disjoint paths. SHARDING uses this so parallel block fetch does not serialize through one relay's uplink.
- `transport.forward(segmentBuf, arrivalLink) -> void` — Relay an opaque segment we cannot decrypt toward a spore we may have no session with. Bypasses SESSION by design; enforces hop_index, path membership, TTL, path_id LRU and the relay token bucket.
- `transport.setAnnounceBlob(bytes /* <=256 */) -> void ; transport.setCandidateScorer(fn(blob) -> number) -> void` — The only APP->TRANSPORT coupling. TRANSPORT copies the blob into HELLO and never interprets it; the scorer orders the dial queue so we do not dial 200 strangers who share no colony.
- `transport.peers() -> Array<PeerRecord> ; transport.lsdb() -> {nodes, edges, epoch}` — Snapshot for ROLES capability scoring and for the live telemetry UI's topology graph.
- `transport.stats() -> TelemetrySnapshot ; transport.on('telemetry', delta) -> void` — Every counter below, pollable and streamed, so the live UI can render the machinery rather than a spinner.

## Telemetry emitted

- tp.state — gauge: solo | listening | meshed | isolated_suspected
- tp.timers_active — gauge; MUST equal 2 at N=1 (Trickle + interface poll). The anti-spin invariant, directly renderable.
- tp.announce.sent / .suppressed_by_trickle — counters; the ratio is the visible proof that announce load is O(k) not O(N)
- tp.announce.interval_ms — gauge, walks 1000 -> 512000 at N=1 and snaps back on join; the single best 'is the mesh calm' signal
- tp.announce.trickle_resets{reason=new_peer|boot_id|addr_change|filter_change|hypha_dead|iface_change}
- tp.rx.total / .bad_magic / .bad_version / .bad_prooftag / .ratelimited_src / .verify_budget_dropped / .bad_signature / .self_suppressed — the full noise-rejection funnel, one bar chart
- tp.verify.ed25519_per_sec — gauge vs the 200/s budget
- tp.candidates.total / .new_per_min / .by_adapter{lan,ble,aware,mdns_hint}
- tp.hypha.count{state=dialing|handshaking|live|degraded|dead|cooldown} — gauge; the lifecycle state machine rendered directly
- tp.hypha.transitions{from,to,reason} — counter; reason includes dup_hypha, keepalive_timeout, auth_fail, bye, oversize
- tp.hypha.dup_resolved{winner=self_initiated|peer_initiated} — proves the simultaneous-dial tiebreak is firing and symmetric
- tp.dial.attempts / .ok / .fail{econnrefused,timeout,unreachable,adapter_full} / .refused_public — the last must stay at 0 in any honest off-web run
- tp.dial.backoff_ms_p50/p95 and tp.dial.quarantined_ids — gauge
- tp.handshake.duration_ms histogram, bucketed per adapter (TCP vs BLE separation is the whole point)
- tp.seg.sent / .recv / .retransmit / .nack_sent / .nack_recv / .reassembly_timeout — counter
- tp.seg.profile{full,tiny} — counter; shows at a glance whether a tiny-MTU adapter is carrying traffic
- tp.seg.overhead_ratio — gauge (header+tag bytes / total bytes); the honest efficiency number on BLE
- tp.link.mtu / .ordered / .reliable / .rtt_ms_ewma / .inflight_bytes — per-link gauges
- tp.link.bytes_in / .bytes_out per adapter — feeds the BLOOM capacity chart
- tp.lsdb.nodes / .edges / .diameter / .epoch — gauge; nodes==1 and edges==0 is the N=1 signature
- tp.lsa.sent / .recv / .duplicates_dropped / .ratelimited / .bad_signature
- tp.route.computes / .compute_us_p95 / .unreachable_queries / .path_changes — path_changes is the route-flap detector the log-RTT cost function exists to keep near zero
- tp.relay.forwarded / .dropped{ttl,loop_self,not_next_hop,dup_path_id,budget} — loop_self and not_next_hop must stay at 0 in a healthy mesh; nonzero means a real routing bug, not noise
- tp.relay.budget_used_pct — gauge
- tp.relay.hop_histogram{1..8} — how deep the mesh actually is versus how deep we allow
- tp.iface.count / .changes / .multicast_join_ok / .multicast_join_fail{iface} — catches the Tailscale-vs-Ethernet wrong-interface failure directly
- tp.broadcast_fallback_used — counter; nonzero means multicast is being filtered (IGMP snooping without a querier), the single most common silent LAN failure

## Risks (self-identified)

- AP client isolation defeats us entirely and we cannot fix it at this layer. On many public and some hotspot APs, stations reach the gateway but not each other. Discovery looks healthy (we hear our own broadcasts) while nothing ever connects. We can only detect and report it. This is the most likely cause of a demo failing in a cafe, and it will look like a SPORE bug.
- Multicast is filtered far more often than people expect. IGMP snooping enabled with no querier on the segment causes switches to prune 239/8 entirely; many enterprise APs drop multicast to wireless clients by policy; some hotspots rate-limit it to the basic rate. The subnet-broadcast fallback covers most of this, but broadcast is also filtered on some APs, and then there is no path left.
- The BLE MTU floor is a real capability cut, not a formality. At a 64-byte virtual MTU the segment overhead is ~31%, and a 100 KB image is ~2300 segments over a link with a 7.5 ms-4 s connection interval. BLE will carry text and presence honestly; it will not carry media at a speed anyone tolerates, and the UI must say so rather than showing a progress bar that takes an hour.
- Link-state flooding has a hard ceiling around 1000 spores and degrades badly past it, especially under churn: every join/leave triggers LSAs mesh-wide. A crowded venue where 300 phones drift in and out of range produces continuous LSA churn and continuous Dijkstra recomputes. The 5 s origin rate limit and 500 ms recompute coalescing bound it, but the design is genuinely sized for hundreds, not thousands.
- Relay is a DoS amplifier by construction. A malicious spore can advertise low cost on many edges, attract traffic via Dijkstra, and then blackhole or inspect metadata (it sees source and destination ids even though payload is opaque). The per-source token bucket and relay budget bound throughput damage but not the attraction itself; we have no reputation feedback into the cost function in v1.
- Trickle's slow interval is a double-edged tradeoff. A spore that has been alone for an hour is at a 512 s interval. If a peer appears and its own eager burst is lost (hotspot multicast rate-limiting), worst-case discovery latency is ~8.5 minutes, which feels broken. The eager burst and unicast ACK make this unlikely, not impossible.
- Mobile OS backgrounding will close sockets and stop multicast reception on iOS and Android without notifying us in any portable way. The 10 s interface poll will eventually notice a bind loss, but presence will be wrong in the meantime and the app will look like it is lying about who is online.
- Truncating path ids to 8 bytes and colony filters to a Bloom structure both introduce false positives. Path-id collisions fail closed (verified against the authenticated next hop), but colony-filter false positives cause wasted dials, which at N=500 with a permissive filter could saturate the dial queue.
- Per-segment AEAD with a plaintext routing header leaks a real traffic-analysis surface: any relay or passive LAN listener sees message sizes, segment counts, timing and the source/destination spore ids. We get routing without decryption, and we pay for it in metadata.

## Contract conflicts raised

- connect(peer) -> duplex stream is wrong and should be changed to connect(candidate) -> Link with message boundaries and declared caps. A duplex byte stream cannot be honestly implemented over a 20-byte-MTU, unordered, unreliable BLE GATT link. If we ship the stream signature, every upper layer will silently assume streaming semantics (partial reads, write-coalescing, infinite frames) and all of it breaks the day a BLE adapter is plugged in. Better to make the constraint visible in the type now than to discover it at integration.
- The TRANSPORT/SESSION split needs a third, explicitly-named layer or the two teams will build incompatible chunkers. Chunking must sit BELOW per-segment encryption (so a lossy link can verify and retransmit one 64-byte segment instead of buffering a whole message before the first integrity check), but the contract puts SESSION wholly above TRANSPORT. Proposed written split: TRANSPORT owns the plaintext segment header and reassembly; SESSION owns the AEAD of each segment body; reassembly runs on decrypted bodies. This must be in the contract, not inferred.
- Routing ownership is ambiguous and currently double-assigned. The contract gives BEACON 'peer-table gossip' under ROLES, but multi-hop needs a link-state DB, which is inherently a transport concern and is what route()/paths() read. Proposal: TRANSPORT owns the LSDB and reachability; BEACON gossip carries capability records (role scores, free storage, CPU class) only. If both subsystems own reachability they will disagree, and the disagreement will surface as intermittent unroutable peers that neither team can reproduce.
- 'SUBSTRATE asks TRANSPORT+SESSION only for send this frame to that spore' cannot cover relaying. A relay must forward an opaque segment toward a spore it has no session with and cannot decrypt. This needs an explicit forward(segment, arrivalLink) entry point that bypasses SESSION, otherwise multi-hop is unimplementable within the stated boundary.
- SHARDING's rarest-first parallel fetch needs node-disjoint paths to be genuinely parallel, and nothing in the contract lets it ask for them. Without paths(dst, k), SHARDING will happily schedule eight parallel fetches that all traverse the same relay's uplink and then report that scaling does not work. Add paths() to the contract explicitly.
- TRANSPORT is specified to know nothing about colonies, but dialing 200 strangers who share no colony is exactly the behaviour that makes a large venue unusable. The HELLO must carry an APP-supplied colony filter. Resolved here as an opaque blob plus an APP-supplied scorer callback, so TRANSPORT still never interprets it - but this is a real boundary crossing and should be written down as a callback in the contract rather than left as a silent import.
- The contract implies one connection per peer. Real mobile meshes need multiple concurrent links to the same spore across different adapters (LAN plus BLE) with transparent migration between them. The hypha abstraction should be defined as one logical hypha per spore_id multiplexed over N links, not as a synonym for a connection.
