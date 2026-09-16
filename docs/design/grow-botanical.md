# ANASTOMOSIS

> A peer handshake IS anastomosis — two hyphal tips from genetically distinct mycelia growing toward each other, testing compatibility, and fusing into one continuous cytoplasm. SPORE draws that literally rather than metaphorically: both tips are rendered, each advancing on its own measured handshake progress, so they meet wherever the asymmetry actually puts them. Growth reads as alive because every extension is a quota earned by a real state transition and every stall is a real stall — the tip freezes, it does not idle-wiggle, and the eye learns to read the geometry as a protocol trace.

# ANASTOMOSIS — the biological-realism direction for SPORE

## 0. The telemetry contract (nothing below is allowed to exist without a row here)

`src/` does not exist yet, so this spec **defines** the quantities the core must expose. Every
effect below cites one. The renderer imports `telemetry.js` and holds no free-running clock. The
one permitted use of wall time is `now − t_last_event` — elapsed since a real measured
transition, which is truth. A phase accumulator that advances regardless of events is not.

| id | field | type | source |
|----|-------|------|--------|
| T1 | `peer.hs` | ordinal 0..4 `{discovered, hello, kex, auth, hypha}` + `peer.hs_t` | handshake state machine |
| T1b | `peer.kex_bytes / peer.kex_expect` | 0..1 continuous | key-exchange transcript progress |
| T2 | `hypha.rtt_ms` | EWMA α=0.2 | ack timing |
| T3 | `hypha.bps` | EWMA over 1000 ms | socket accounting |
| T4 | `hypha.inflight[]` | `{bytes, sent_t, expect_t, entry_ids[]}` | send queue |
| T5 | `fruiting.synced / fruiting.known` | 0..1 | substrate replication |
| T6 | `spore.cap_u` | scalar | enzymes completed/s × storage offered |
| T7 | `mesh.dCap` | Δ over 2000 ms window | runtime capacity accounting in `src/`, validated against `bench/curve.js` |
| T7b | `mesh.cap_total` | scalar | Σ of all known `spore.cap_u` |
| T11 | `hypha.hops` | int | routing table path length |
| T8 | `msg.state` | ordinal 0..3 `{local, sent, relayed, quorum}` + `msg.relays[]` | substrate |
| T9 | `peer.miss` | int | heartbeat |
| T10 | `entry.t, entry.pruned` | timestamp, bool | log compaction |

## 1. Thesis in one line

A peer handshake **is** anastomosis: two hyphal tips from genetically distinct mycelia growing
toward each other, testing compatibility, and fusing into one continuous cytoplasm. SPORE draws
that literally. Every other effect follows from getting that one right.

## 2. Layer order (composited back to front, every frame)

0. **Substrate** — flat `#000000`.
1. **Mat** — DLA aggregate = your local substrate log. Persistent bitmap, never recleared.
2. **Reaction field** — Gray-Scott, only integrating while `T7 > θ`. Additive.
3. **Hyphal graph** — space-colonization tubes, cords, septa, apices. Persistent + delta.
4. **Translocation** — pulses. Cleared and redrawn each frame (the only fully dynamic layer).
5. **Text plane** — opaque. Layers 1–3 are luminance-clamped beneath its bounding box.

## 3. Space colonization — hyphae reaching for peers

Runions et al. 2007, in braille-subpixel space (2×4 dots per character cell).

- **Attractor set** = discovered peers (T1 ≥ 0). Ring placement is *deterministic from identity*:
  `θ_peer = 2π · (xor_distance(self_id, peer_id) / 2^64)`, radius = `r_ring · (1 + 0.15·log2(T11))`.
  Same peer, same seat, every session. Nothing is random.
- **Attraction radius** `R_i = 36 dots` (≈18 char cells). **Kill distance** `d_k = 3 dots`.
  **Segment length** `D = 2 dots`.
- **The direction rule is the actual algorithm**, not a label:
  `dir_tip = normalize(Σ_{a ∈ A, |a−tip| < R_i} (a − tip)/|a − tip|)`, where `A` = all discovered
  peers *and* their advertised fruitings. With one attractor this degenerates to straight homing,
  honestly. With several peers seated on the same arc the tip **bends toward the cluster** — and
  `R_i` earns its keep as the distance at which a newly discovered peer starts to pull on tips
  already in flight. Discovering a peer therefore visibly deflects unrelated growth. Attractors
  inside `d_k` are consumed (killed) in the normal Runions way.
- **Tip advance is a quota, not a speed.** `progress_target = P[T1]` where
  `P = [0.10, 0.35, 0.35 + 0.30·T1b, 0.92, 1.00]`. Note index 2: during key exchange the target
  is *continuous* because transcript bytes are continuous — this is where the extra truth comes
  from.
- Because an SC path curves, progress is **fraction of the initial gap closed**, never arc length:
  emit segments while `current_gap > (1 − progress) · gap_at_discovery`. `progress_target = 1.0`
  at auth therefore means "touching" whatever shape the path took, and the `d_k` fusion test can
  never fail for geometric reasons.
- **The only smoothing permitted**: `progress += (progress_target − progress)·(1 − e^(−dt/τ))`,
  **τ = 180 ms**. This interpolates *between two measured samples*. It never extrapolates past
  the newest one, so a tip cannot advance one dot beyond what the handshake has earned.
- **Stall**: if `T1` does not change, progress asymptotes and the tip is frozen within ~1 % after
  5τ = 900 ms. No idle wiggle. Instead the apex glyph desaturates from cyan toward
  `#FFB020` on `clamp((now − peer.hs_t − 1500)/4000, 0, 1)` — elapsed-since-real-event, legal.
- **Reverse**: rejection or timeout sets `progress_target = 0` with **τ = 400 ms** (autolysis is
  slower than extension — real, and it reads as sagging rather than snapping). Segments
  de-materialize apex-first and leave a 1-dot scar in `#24383C` until the mat overwrites it.
- **Negative autotropism**: tips belonging to *the same spore* repel, kernel radius 6 dots,
  force ∝ 1/d². Tips of *different* spores do not. This is literally correct mycology and
  literally correct semantics: no self-connection, yes peer connection.

### Branching is subapical, and it is caused by multiplexing

Extension happens only at the apex; branches emerge **3–6 segments behind it**, never at it.
A mycologist checks this first. A branch is emitted when and only when a new substream opens on
that hypha (a fruiting subscribed, an enzyme channel opened) — so **branch count = active
substreams**, exactly.

- Lateral subapical branch angle: truncated normal **μ = 62°, σ = 14°**, clipped [38°, 88°], sign ±.
- Apical dichotomy (reserved for a colony fork): **μ = 34°, σ = 6°**. Rarer, narrower, reads
  as a different event, which it is.

### Apical dominance

The leading tip depletes the local gradient and suppresses neighbouring branch initiation. Rule:
a branch request from a hypha whose `T3 < 0.25 · max(T3)` within radius **10 cells** is queued,
not drawn, and rendered as a single dim `·` at the intended origin. It emerges the moment its own
throughput rises. Dominance is therefore a live readout of the throughput ranking.

### Cords (rhizomorphs)

When ≥3 hyphae share ≥70 % of their path (same next hop), they bundle. Width in dots =
`clamp(1 + floor(log2(Σbps / 4096)), 1, 4)` → 4 KB/s = 1 dot, 8 = 2, 16 = 3, ≥32 = 4. Cord
thickness is throughput; a mycologist reads bundled parallel hyphae for long-distance transport
and is not being lied to.

## 4. Anastomosis — the centrepiece

Both tips are drawn. You know the peer's handshake state because every hello/kex/auth frame
carries the sender's view of it, so the opposing tip advances on *its* measured progress, not a
mirror of yours. **Each tip's attractor is the other tip's current position**, so they do *not*
meet at the midpoint — they meet wherever the asymmetry puts them. A peer that handshakes slowly
visibly does less of the reaching, and you can read which side is struggling off the geometry.

When both reach `T1 = 4` and separation < `d_k`:

1. **0–90 ms**: the two apex glyphs (`⢸` and `⡇`) migrate to a shared cell.
2. **90–210 ms**: fusion flare. The cell renders `⣿` in `#EAFFFF`, radius-2 dot bloom,
   amplitude eased `1 − (1−u)³` (cubic out) then `u³` back down.
3. **210 ms**: the tube becomes continuous. Septa renumber across the join, and the first
   translocation pulses run **both directions simultaneously** — bidirectional cytoplasmic
   streaming, which is what actually happens post-fusion and also what a duplex session is.
   These are not a scripted flourish: they are the first real T4 frames of the substrate-sync
   exchange in each direction. If the sync exchange stalls, the fused tube sits empty.

Incompatible fusion (cert mismatch, auth failure) is the real biological outcome too: both tips
retract. Same τ = 400 ms reverse integrator, no flare, apices go `#C4563A`.

## 5. DLA — the colonizing mat = your substrate log

- Grid = the full back plane at braille resolution (240×160 dots for a 120×40 terminal).
- **One walker per newly replicated entry (T5).** Not per frame, not per tick. The mat's area is
  the byte count of your local log, permanently 1:1.
- Launch radius `r_launch = r_max + 5`; kill radius `3·r_launch` (walker discarded, entry requeued).
- **Stickiness p = 0.35.** Classic DLA (p = 1.0) gives wispy dendrites, D_f ≈ 1.71. Dropping to
  0.35 lets walkers slide along the aggregate before committing, thickening branches and pushing
  D_f toward ~1.9 — which is what a real mycelial mat looks like, and which also stays legible
  as a texture instead of a scribble.
- Budget: ≤24 walkers in flight, ≤400 steps/walker/frame, relaunch at 2000 total steps. Worst
  case 9600 probes/frame. Occupancy in a `Uint8Array` plus an 8×8 bucket index. **Never
  resimulated** — the aggregate is append-only, like the log it represents.
- Colour by `entry.t`: newest `#00E5FF`, aging to `#0A3A42` across the log's timespan.
- **Pruning withers it**: `entry.pruned` erases that dot. Compaction visibly thins the mat.

## 6. Gray-Scott — BLOOM

96×64 `Float32Array` ×2, ping-pong. Laplacian kernel `[0.05 .2 .05; .2 −1 .2; .05 .2 .05]`,
**Du = 0.16, Dv = 0.08, dt = 1.0, 2 iterations/frame**.

- **F = 0.0545, k = 0.0620** — the travelling-front / U-skate regime: expanding self-replicating
  waves. That is the BLOOM look and it is chosen, not stumbled on.
- **F = 0.037, k = 0.060** — mitosis regime, spots that split. Reserved for a colony fork.
- **The honesty fix for a self-running sim**: integration runs *only while* `T7 (mesh.dCap) > θ`,
  θ = 0.05 (5 % capacity gain per 2 s window). Otherwise the field is multiplied by 0.94/frame
  and is visually gone in ~800 ms. A frozen mesh has a frozen field. That is the point.
- The **propagation speed is bound too**, not just the gate:
  `iterations/frame = clamp(round(4 · dCap/θ), 0, 8)`. A bigger capacity jump drives the front
  outward faster, because in Gray-Scott front velocity scales with integrated time. A marginal
  BLOOM crawls; a mesh doubling in size detonates.
- **Injection**: a joining spore stamps `V = 0.9` in a disc of radius
  `2 + 6·clamp(peer.cap_u / T7b, 0, 1)` at that peer's ring seat. Amplitude is the capacity it
  actually contributed.
- Render: V → `░▒▓█` at thresholds 0.12 / 0.25 / 0.40 / 0.55, magenta→white ramp.

## 7. L-system — the colony/fruiting sidebar

ω: `C`
p1: `C → I(min(members,6)) [ B F ]ⁿ` — one bracket per fruiting, n = actual fruiting count
p2: `F → I(1) M` — M = the unread tip
p3: `I(n)` = an internode of n dots; turtle `+` = +62°, `−` = −62°, `[ ]` = push/pop

Derivation depth = real tree depth, so it cannot run away. When a fruiting is created the
production fires **once**; the new bracket then extends under the same tip integrator.

The binding needs care. `T5 = synced/known` is *not* monotone — when new history is discovered,
`known` jumps and the ratio falls, and a branch bound to it would retract, which would be a lie:
nothing was lost. So **branch length is bound to `synced` absolutely** (monotone, only ever
reduced by real pruning), and `known` is drawn as a faint `#24383C` **ghost tip** further out at
the length the branch will reach. A channel blooms open at exactly the rate its history arrives;
a half-synced channel is a visibly half-grown branch reaching toward a ghost; a stalled sync is a
ghost tip sitting there unreached. Discovering more history extends the ghost, never the branch.

## 8. Translocation — packets as cytoplasmic streaming

For each `T4` entry: `p = (now − sent_t) / rtt_ms`, clamped 0..1. **Transit time is measured RTT**,
so a slow link visibly streams slowly. Alpha = `clamp(0.25 + 0.15·log2(bytes/64), 0.25, 1.0)`
(64 B → 0.25, 1 KB → 0.85, ≥4 KB → 1.0). Septa — perpendicular ticks — mark `entry_ids`
boundaries inside the in-flight window and move with the pulse.

Loss behaviour is biological and honest: past `expect_t` the pulse **halts at p = 1.0 and dims**
at 0.9/frame; on timeout it **runs backward to p = 0 and vanishes** — retrograde translocation,
a real phenomenon, encoding a real retransmit.

## 9. Text: accretion without touching layout

Body text never moves, never typewriters. `T8` drives four tiers, each a 150 ms crossfade:

| state | prefix | colour | contrast vs black |
|---|---|---|---|
| 0 local | `·` | `#5C8288` | 5.0 : 1 |
| 1 sent | `˙` | `#8FB8BE` | 9.1 : 1 |
| 2 relayed | `∴` | `#B4D4D9` | 12.6 : 1 |
| 3 quorum | `⁂` | `#D8E8EC` | 16.7 : 1 |

Real accretion is confined to the right-hand dim gutter, where reflow is harmless: one `·` is
appended per entry in `msg.relays[]` as each relay ack lands. Ten relays, ten dots. It grows
character by character and costs the reader nothing.

Legal reverse transitions are enumerated, because most are impossible: **3 → anything is
forbidden** (a quorum'd entry cannot un-quorum; the substrate is append-only). `2 → 1` happens
when relays are lost to churn. `1 → 0` happens when a send fails and the message returns to the
outbox. Reverse uses the same 150 ms crossfade plus a single `#C4563A` flash on the prefix glyph,
so a regression is never mistaken for progress. Stall is simply the tier holding — and the gutter
dots stop appearing, which is the visible tell.

## 10. Withering

`T9` drives it. miss 1 → −35 % saturation. miss 2 → `✕` vacuole septa appear, cord width
decrements (which is also just T3 collapsing, so it is doubly true). miss 3 → the reverse
integrator at τ = 400 ms. Scars persist until the mat grows over them. Nothing is ever deleted
in one frame.

## 11. Legibility

Text `#D8E8EC` has relative luminance L = 0.784. For ≥4.5:1 the brightest backdrop pixel beneath
the message column needs `L ≤ 0.135`. The enforced ceiling is **L = 0.118** (cyan clamped to
`#006B77`), giving **4.95 : 1**. Implementation: within the message column's bbox, scale each
composited backdrop pixel's *linear* RGB by `min(1, 0.118 / L_pixel)`. This is a per-pixel clamp,
not a global dimming, so the graph keeps its full range everywhere else on screen.

## 12. Performance (canvas path)

60 fps budget 16.6 ms: hyphal graph 4 ms — only *new* segments are stroked, into a persistent
layer that is never cleared — DLA 1.5 ms, Gray-Scott 2.5 ms, pulses 2 ms, composite 4 ms.
Retraction is the only path that clears, and only the affected tube's bbox.

## 13. prefers-reduced-motion

Everything state-driven survives, because that is the truth: segment counts, cord widths, tier
colours, mat area, field amplitude, septa. Removed: the τ low-pass (replaced by a 150 ms
crossfade between discrete measured states), pulses (replaced by a static `⟨12⟩` in-flight count
on the cord), Gray-Scott integration (one static render of the field at injection, **held for as
long as `dCap > θ`** — not a fixed duration, since the gate is the truth — then crossfaded out).
Same information, quantized. Honest because the measurement was always the content and only the
interpolation is gone.

## Growth moments

### A newly discovered spore is seated on the ring and a hyphal tip sprouts from your colony and reaches toward it
- **bound to:** T1 `peer.hs` ordinal 0..4, with T1b `kex_bytes/kex_expect` supplying continuous resolution inside the kex state
- **technique:** Space colonization (Runions 2007) in braille subpixel space. `dir_tip = normalize(Σ_{a∈A, |a−tip|<R_i} (a−tip)/|a−tip|)`, attraction radius R_i = 36 dots, kill distance d_k = 3, segment length D = 2. Tip advance is a quota per handshake state: `progress_target = P[T1]`, `P = [0.10, 0.35, 0.35+0.30·T1b, 0.92, 1.00]`. Progress is fraction of initial gap closed, not arc length: emit a segment while `current_gap > (1−progress)·gap_at_discovery`. Negative autotropism repels same-spore tips (kernel radius 6 dots, force proportional to 1/d²).
- **timing:** Smoothing is a low-pass between two measured samples only: `progress += (progress_target−progress)·(1−e^(−dt/τ))`, τ = 180 ms. Never extrapolates past the newest sample. STALL: if T1 does not change the tip freezes (within ~1% after 5τ = 900 ms) — no idle wiggle; the apex desaturates cyan toward #FFB020 on `clamp((now−peer.hs_t−1500)/4000,0,1)`, which is elapsed-since-a-real-event, not a free-running clock. REVERSE: rejection/timeout sets progress_target = 0 with τ = 400 ms (autolysis is slower than extension), segments de-materialize apex-first and leave a 1-dot #24383C scar.

### Two tips from different spores touch and fuse — the handshake completes and one continuous tube exists where there were two
- **bound to:** T1 reaching 4 on BOTH sides (the peer's own state is carried in every hello/kex/auth frame), plus the first real T4 in-flight frames of the substrate-sync exchange
- **technique:** Anastomosis. Each tip's attractor is the OTHER tip's current position, so they do not meet at the midpoint — they meet wherever the asymmetry puts them, and a slow peer visibly does less of the reaching. Fusion test is separation < d_k = 3 dots. Flare renders `⣿` at #EAFFFF with a radius-2 dot bloom; septa renumber across the join; pulses then run both directions at once (bidirectional cytoplasmic streaming = a duplex session).
- **timing:** 0–90 ms apex glyphs ⢸ and ⡇ migrate to a shared cell. 90–210 ms flare, amplitude eased up by cubic-out `1−(1−u)³` then down by `u³`. At 210 ms the tube is continuous. STALL: if only one side reaches auth, both tips sit frozen at their earned progress and nothing fuses; if the post-fusion sync exchange stalls, the fused tube sits visibly empty. REVERSE: cert mismatch or auth failure is the real biological incompatible-fusion outcome — both tips retract on the τ = 400 ms integrator, no flare, apices go #C4563A.

### The mycelial mat behind everything thickens as your substrate log fills in — history arriving as a colonizing front rather than a progress bar
- **bound to:** T5 `fruiting.synced` (one walker launched per newly replicated entry) and T10 `entry.t` / `entry.pruned`
- **technique:** Diffusion-limited aggregation on a 240×160 braille dot grid. One walker per entry, permanently 1:1, so mat area IS local log size. Launch radius r_max+5, kill radius 3·r_launch. Stickiness p = 0.35 rather than 1.0: walkers slide along the aggregate before committing, thickening branches and pushing fractal dimension from the classic D_f ≈ 1.71 toward ~1.9, which is both what a real mycelial mat looks like and what stays legible as texture. Uint8Array occupancy plus 8×8 bucket index; the aggregate is append-only and never resimulated.
- **timing:** No duration and no easing — a dot appears the frame its entry commits, so the fill rate IS the replication rate. Budget at most 24 walkers in flight, at most 400 steps/walker/frame, relaunch at 2000 total steps. Colour ramps by entry.t from #00E5FF (newest) to #0A3A42 across the log's timespan. STALL: replication stops, no walkers launch, the mat is simply static — correct, because nothing arrived. REVERSE: `entry.pruned` erases that exact dot, so log compaction visibly thins the mat.

### BLOOM — new spores join and a reaction front propagates outward across the whole substrate
- **bound to:** T7 `mesh.dCap` (Δ capacity over a 2000 ms window) for both the gate and the speed; T6/T7b `peer.cap_u / mesh.cap_total` for injection amplitude
- **technique:** Gray-Scott reaction-diffusion on a 96×64 Float32Array pair, ping-pong, Laplacian kernel [0.05 .2 .05; .2 −1 .2; .05 .2 .05], Du = 0.16, Dv = 0.08, dt = 1.0. F = 0.0545, k = 0.0620 — the travelling-front / U-skate regime that gives expanding self-replicating waves (F = 0.037, k = 0.060 is the mitosis/spot-splitting regime, reserved for a colony fork). A joining spore injects V = 0.9 in a disc of radius `2 + 6·clamp(peer.cap_u/mesh.cap_total, 0, 1)` at its ring seat. Rendered to ░▒▓█ at thresholds 0.12/0.25/0.40/0.55 on a magenta-to-white ramp.
- **timing:** The sim is self-running, so both the gate AND the speed are bound. Integration runs only while dCap > θ (θ = 0.05, i.e. 5% capacity gain per window), and `iterations/frame = clamp(round(4·dCap/θ), 0, 8)` — a marginal BLOOM crawls, a mesh doubling in size detonates. STALL/REVERSE: when dCap ≤ θ integration halts and the field multiplies by 0.94/frame, visually gone in ~800 ms. A frozen mesh has a frozen field; capacity loss simply never re-arms the gate.

### A fruiting blooms open as its history genuinely syncs
- **bound to:** T5, split deliberately into `fruiting.synced` (absolute, monotone) for branch length and `fruiting.known` for the ghost tip
- **technique:** Bracketed L-system for the colony/fruiting sidebar. ω: C; p1: `C → I(min(members,6)) [ B F ]ⁿ` with one bracket per real fruiting; p2: `F → I(1) M`; p3: `I(n)` = an n-dot internode. Turtle + = +62°, − = −62°, [ ] = push/pop. Derivation depth equals real tree depth so it cannot run away. The new bracket extends under the same tip integrator as section 3.
- **timing:** The production fires exactly once, at creation; extension thereafter uses the τ = 180 ms low-pass on synced. The binding is deliberately NOT the ratio synced/known, because `known` jumps when new history is discovered and a ratio-bound branch would retract — which would lie, since nothing was lost. Branch length tracks `synced` absolutely; `known` is a faint #24383C ghost tip drawn further out. STALL: the ghost tip sits there unreached — that is the visible stall. REVERSE: only real pruning shortens the branch. Discovering more history extends the ghost, never retracts the branch.

### Packets translocate along a hypha, and a lost one flows back the way it came
- **bound to:** T4 `hypha.inflight[]` {bytes, sent_t, expect_t, entry_ids} and T2 `hypha.rtt_ms`
- **technique:** Cytoplasmic streaming along the tube. Pulse position `p = (now − sent_t)/rtt_ms` clamped 0..1 — transit time is measured RTT, not a constant, so a slow link visibly streams slowly. Brightness `alpha = clamp(0.25 + 0.15·log2(bytes/64), 0.25, 1.0)`: 64 B gives 0.25, 1 KB gives 0.85, 4 KB or more gives 1.0. Septa (perpendicular ticks) mark entry_ids boundaries within the in-flight window and move with the pulse. Cords: 3 or more hyphae sharing 70% or more of their path bundle into a rhizomorph of width `clamp(1 + floor(log2(Σbps/4096)), 1, 4)` dots.
- **timing:** Duration is exactly rtt_ms, linear in p — no easing, because the packet is not accelerating. STALL: past expect_t the pulse halts at p = 1.0 and dims at 0.9/frame. REVERSE: on timeout it runs backward to p = 0 and vanishes — retrograde translocation, a real phenomenon, encoding a real retransmit.

### A message germinates through local → sent → relayed → in-substrate without a single character moving
- **bound to:** T8 `msg.state` 0..3 and `msg.relays[]`
- **technique:** Four brightness/prefix tiers, never a per-character typewriter (which would be a timer). Prefix glyph and colour only: · #5C8288, ˙ #8FB8BE, ∴ #B4D4D9, ⁂ #D8E8EC. Body text position is frozen forever. True character-by-character accretion is confined to the right-hand dim gutter where reflow is harmless: one `·` appended per entry in msg.relays[] as each relay ack lands. On reaching quorum, a septum tick appears on the hypha that actually carried it.
- **timing:** 150 ms crossfade per tier transition, one step per measured state change. STALL: the tier simply holds and gutter dots stop appearing — that is the visible tell. REVERSE is enumerated because most of it is impossible: 3 to anything is forbidden (append-only substrate, a quorum'd entry cannot un-quorum); 2 to 1 on relay loss to churn; 1 to 0 when a send fails and the message returns to the outbox. Regression uses the same 150 ms crossfade plus a single #C4563A flash on the prefix glyph so it is never mistaken for progress.

### A peer withers — its hypha desaturates, vacuolates, and retracts rather than being deleted
- **bound to:** T9 `peer.miss` consecutive heartbeat misses, with T3 `hypha.bps` collapse corroborating
- **technique:** Staged autolysis. miss 1 gives −35% saturation. miss 2 makes `✕` vacuole septa appear along the tube and decrements cord width (which is also just the log2(Σbps) cord formula responding to real throughput collapse, so the signal is doubly true). miss 3 runs the reverse tip integrator. Retracted tubes leave a 1-dot #24383C scar that persists until DLA mat growth overwrites it.
- **timing:** Retraction runs the τ = 400 ms low-pass toward progress_target = 0 — deliberately slower than the τ = 180 ms growth, because autolysis is slower than extension in reality and because it reads as sagging rather than snapping. STALL: a peer stuck at miss 1 or 2 holds that exact appearance indefinitely; it is a real half-dead link and it looks like one. REVERSE of the reverse: a heartbeat arriving resets miss to 0 and progress_target back to 1.0 on the fast τ = 180 ms, so recovery visibly re-turgors. Nothing is ever deleted in one frame.

## Palette

All ratios computed against the substrate #000000 as (L+0.05)/0.05, L = WCAG relative luminance.

SUBSTRATE
- `#000000` oklch(0 0 0) — substrate black, the ground everything grows on.

STRUCTURE / HYPHAE
- `#00E5FF` oklch(0.85 0.13 200) — **13.7 : 1**. Live hypha, newest mat dots, healthy apex.
- `#FFB020` oklch(0.80 0.16 75) — **11.5 : 1**. Stalled apex (handshake not advancing).
- `#EAFFFF` oklch(0.98 0.02 195) — **18.9 : 1**. Anastomosis fusion flare only. Used for ~120 ms, once per peer, which is why it is allowed to be the brightest thing on screen.
- `#C4563A` oklch(0.56 0.14 35) — **4.7 : 1**. Rejection / withering / illegal state regression.
- `#0A3A42` oklch(0.33 0.04 210) — **1.7 : 1**. Aged mat dots. Deliberately near-ground: this is texture, not information, and at 9.9 : 1 against the body text it never competes.
- `#24383C` oklch(0.32 0.02 215) — **1.5 : 1**. Retraction scars and L-system ghost tips. Present but subordinate.

BLOOM
- `#FF2BD6` oklch(0.68 0.30 340) — **6.6 : 1**. Gray-Scott field low band.
- ramps to `#EAFFFF` at V >= 0.55.

TEXT (four tiers = four message states, all pass WCAG AA on black)
- `#5C8288` oklch(0.60 0.03 210) — **5.0 : 1**. state 0, local/composed.
- `#8FB8BE` oklch(0.76 0.03 210) — **9.1 : 1**. state 1, sent.
- `#B4D4D9` oklch(0.85 0.02 210) — **12.6 : 1**. state 2, relayed.
- `#D8E8EC` oklch(0.92 0.02 210) — **16.7 : 1**. state 3, quorum-verified. L = 0.784.

THE CEILING THAT MAKES IT LEGIBLE
The dimmest text tier is 5.0 : 1 on pure black, but text sits over a live mat and a reaction field. For the primary text (L = 0.784) to hold at least 4.5 : 1, the brightest backdrop pixel beneath it needs L <= 0.135. The enforced ceiling is **L = 0.118**, giving **4.95 : 1** — that is cyan clamped to `#006B77`. Implementation: inside the message column's bbox only, scale each composited backdrop pixel's LINEAR RGB by `min(1, 0.118 / L_pixel)`. Per-pixel, not a global dim, so the peer graph keeps its full 13.7 : 1 range everywhere outside the text column and the mesh still looks bioluminescent. In the TUI, where there is no blending, the same rule degrades to: any cell inside the message column renders the text colour and drops the backdrop glyph entirely.

## TUI feasibility

THE HARD CONSTRAINT IS ONE GLYPH AND ONE FOREGROUND COLOUR PER CELL. The layered/blended model in section 2 is the canvas path; the terminal gets a resolved model.

PER-CELL PRIORITY RESOLUTION (replaces compositing): text > pulse > hypha > field > mat. The winning layer picks BOTH the glyph and the colour; every layer below it in that cell is dropped, not blended. Consequences to accept honestly: a cyan hypha crossing the mat hides the mat in those cells; the mat's per-dot age gradient collapses to per-cell (the age of the newest dot in that cell); a ░▒▓█ field cell and a braille cell can never coexist. This is fine because priority order equals information order — the truth that matters most wins the cell.

RENDERS NATIVELY IN PURE ANSI:
- Hyphae, tips, cords, septa, the DLA mat and the L-system sidebar all render in braille U+2800–U+28FF, 2×4 dots per cell. A 120×40 terminal is a 240×160 dot field — enough for the SC segment length D = 2 dots and the d_k = 3 fusion test to be meaningful. Cord width 1–4 dots maps exactly onto braille's 2-dot column width in each half-cell.
- Gray-Scott field in ░▒▓█ (U+2591–U+2588) at the four stated V thresholds.
- All colour via 24-bit SGR (`ESC[38;2;r;g;bm`). Every hex in the palette is emitted exactly, so the contrast ratios hold. Windows Terminal supports 24-bit colour, braille and box drawing.
- Panels and chrome in box drawing U+2500+.
- prefers-reduced-motion equivalent: a `--still` flag plus `NO_COLOR` / `TERM=dumb` detection.

THE REAL TUI CONSTRAINT IS STDOUT BANDWIDTH, NOT FILL RATE. A full 120×40 redraw with per-cell 24-bit SGR is about 40 KB/frame; at 60 fps that is 2.4 MB/s and Node's stdout write queue stalls. So:
- Cap the TUI render at 30 fps; the simulation tick stays decoupled and runs at its own rate so telemetry is never under-sampled.
- Build each frame into a Uint32Array cell buffer (codepoint plus packed fg index), diff against the previous frame, and emit only runs of changed cells with ONE SGR per run. Typical frame delta is under 8% of cells, giving roughly 3–5 KB/frame, about 150 KB/s at 30 fps, which stdout handles comfortably.
- Cursor positioning per run via `ESC[row;colH`; no full-screen clears ever (a clear would also violate the no-instant-deletion principle).

NEEDS THE BROWSER CANVAS PATH:
- Sub-cell alpha and colour blending — so the pulse brightness ramp `0.25 + 0.15·log2(bytes/64)` is continuous on canvas but quantizes to 4 discrete steps in the TUI.
- The anastomosis fusion flare's radius-2 dot bloom with soft falloff (the TUI gets a hard `⣿` at #EAFFFF for the same 120 ms window — still reads, just blunter).
- The per-pixel linear-RGB luminance clamp under the message column; the TUI substitutes the drop-the-backdrop rule above.
- The mat's smooth per-dot age gradient across the full log timespan.
- `imageSmoothingEnabled = false` upscale of the 96×64 Gray-Scott ImageData (the TUI thresholds it to blocks instead, which is arguably the better look).
- The persistent never-cleared hyphal layer with bbox-only invalidation; the TUI achieves the equivalent through cell diffing, which is the same idea at a different granularity.

## Failure mode

Telemetry sparsity makes growth read as jerky, and the fix everyone reaches for is the one thing this direction forbids. The handshake has four discrete states and may complete in ~200 ms on a local link, so a tip gets four quota jumps and then sits. Worse, the τ = 180 ms low-pass is asymptotic: each jump eases toward its target and visually "arrives" around 80%, so the tip appears to hesitate short of where it is going, four times in a row. The eye reads that as broken rather than alive, and the obvious rescue — a small idle wiggle, a breathing phase, a minimum extension rate — is decoration bound to a timer, which fails the non-negotiable principle and quietly turns the whole piece into the thing it was built to avoid.

Detection: instrument, per hypha, the fraction of its lifetime frames where `|progress − progress_target| > 0.02` while T1 is unchanged. Above roughly 40%, the pacing is wrong and the tip is spending most of its visible life asymptotically creeping rather than growing. Also log the wall-clock duration of each T1 state; if the median kex state is under ~150 ms, there is simply not enough time for any interpolation to look like growth.

The legal response is to go get more truth, never to add motion. T1b already does this for key exchange — `kex_bytes/kex_expect` is a continuous measured quantity that turns one jump into a smooth ramp. The same move is available everywhere the design currently uses an ordinal: discovery can expose probe round-trips completed, auth can expose signature-verification steps, and the hello state can expose bytes of the peer advertisement received. If a state still cannot be subdivided into anything measurable, the correct outcome is that the tip jumps — and the design should own the jump (it is a real discontinuity in a real protocol) rather than smooth it over.

A secondary, milder version of the same failure: Gray-Scott drifting away from truth mid-BLOOM. The `iterations/frame = clamp(round(4·dCap/θ), 0, 8)` binding is the guard, but it needs a watchdog asserting that no frame integrates while dCap <= θ — one missed gate check and the field starts running on its own, which is exactly the lie the whole direction is designed to refuse.
