# GROWTH — the unified growth language of SPORE

> A hypha reaches until it touches something, then follows what it touched. Every animated
> property in SPORE is a physical filter — a spring or a bounded follower — whose *setpoint*
> is a live read of a measured quantity. Nothing plays. Everything chases truth, and the chase
> is what you see as growth.

This document is not an average of four designs. It is built on **Thigmotrope** (the
human-factors and craft winner, combined score 73/100) — its setpoint law, its spring bank,
its asymmetry law, its legibility firewall, its N=1 breathing beacon — with five grafts welded
on from the other three directions, two verified arithmetic defects fixed, and one integrator
interaction the grafts themselves would have broken if left unstated. Everything below is
exact: named algorithm, exact constant, exact formula, exact hex, exact millisecond.

Base source: `C:/Users/blizz/spore/docs/design/grow-motion.md` (Thigmotrope).
Grafted from: `grow-demoscene.md` (Mycelium/1), `grow-generative.md` (Tropism),
`grow-botanical.md` (Anastomosis). Probe constraints from `docs/probes/FINDINGS.md`.

---

## 0. The law

**A spring filters, telemetry sets.** For every animated property there is a `target` — a live
read of a row in the telemetry contract (§2) — and a `current` that chases it through a
fixed-step integrator (§1). "BLOOM takes 720ms" is a timer and is not permitted. "BLOOM fill
follows `mesh.capacityTotal` through k=65, c=7.2, m=1, settling in 719ms once the ratio stops
moving" is permitted, because if capacity growth stalls at a 1.15× jump the swell stops at 1.15×
and sits there.

Four supporting disciplines, two from Tropism, two original to this synthesis:

1. **Hold-last-value.** The renderer reads the newest telemetry sample and holds it until the
   next. Interpolating a *measured* quantity is fabrication; only the *filter output* moves
   between samples.
2. **Disclosed EMAs only.** Exactly two exponential averages exist in the whole system —
   `hypha.rttMs` (α=0.25) and `hypha.bytesPerSec` (α=0.18) — both computed in the transport
   layer because they are transport-layer quantities anyway, and both rendered in the `--truth`
   overlay with a `~` suffix (`rtt~`, `bps~`) so every smoothed number is visibly smoothed. No
   third EMA may be added without updating this line.
3. **Fail-loud.** A visual whose `bind:` string resolves to no telemetry row renders U+2298 (⊘)
   instead of a plausible default or a zero. The dev overlay (`--truth`, key `b`) prints every
   animated property beside the source of its setpoint; a clock-derived setpoint renders in
   amber as a visible defect, not a hidden one.
4. **The mandatory stall test.** Every effect in §7 ships with a named kill test: sever the
   real event mid-flight and the motion must stop at exactly the value it last earned, and stay
   there. An effect that keeps gliding to completion after its data source dies is a timer
   wearing a spring costume and does not ship.

---

## 1. The integrator

Semi-implicit Euler, fixed timestep **dt = 1/120 s**, accumulator pattern:

```
v += ((k·(target − x) − c·v) / m) · dt
x += v · dt
```

Fixed-step is non-negotiable: the TUI samples at 30fps and the canvas at 60fps, but identical
substeps mean both renderers produce bit-comparable motion — a peer joining looks the same
curve in a terminal and a browser, just sampled at a different rate.

**Accumulator clamp and the backpressure governor — the interaction the grafts would otherwise
break.** §5 grafts in a frame-rate governor that can drop the TUI to 8fps (125 ms/frame) under
write backpressure. Thigmotrope's original clamp (33 ms, 4 substeps) would silently discard 92
ms of every governor-degraded frame and every spring would visibly run in slow motion — the
follower law is frame-rate independent by design, but a fixed-step integrator with too small a
substep cap is not. Fixed here: **accumulator clamp raised to 250 ms, max substeps raised to
30.** At 8fps, 125 ms / (1/120 s) ≈ 15 substeps — inside the new cap, so no time is lost and no
spring slows down. Cost check: 400 springs × 30 substeps × 3 floats, worst case, once per
governor-degraded frame — negligible against the probe's 66× headroom. Stability check for the
stiffest spring in the bank (RM-INSTANT, k=14400): ω₀ = √14400 = 120 rad/s, ω₀·dt = 120/120 =
1.0, comfortably under the semi-implicit-Euler stability bound of 2.0. The spiral-of-death guard
remains: if the accumulator would need more than 30 substeps to drain (i.e. a stall well past
8fps), the excess is dropped and the sim resumes from where the springs are — a genuine skip,
not a lie, and it only fires below roughly 4fps, which the governor is designed to never reach.

---

## 2. The telemetry contract — the only legal setpoint sources

`src/telemetry` exposes this and nothing else. Every `bound to:` in §7 names a row here.

| signal | derivation | rate |
|---|---|---|
| `beacon.sentAt`, `beacon.intervalMs` | adaptive: `min(1200 · 1.35^failedRounds, 8000)` ms | per beacon |
| `beacon.holdRemainingMs` | `max(0, intervalMs − (now − sentAt))` — elapsed-since-real-event, the one legal raw-wall-time use | per frame |
| `transport[t].readiness` | driver link-layer init, 0..1; per-interface EINVAL (Windows Ethernet, FINDINGS §1) does not zero the transport — readiness reflects whichever interface actually joined | 250 ms |
| `transport[t].viaTailnet` | bool — true when a peer's traffic on this transport arrived over a VPN/tailnet adapter rather than a LAN adapter (FINDINGS §1 secondary finding) | per packet |
| `handshake.stage` (mine), `handshake.stageOfPeer` (theirs) | 0..6: IDLE, HELLO_SENT, HELLO_ACK, E_SENT, EE, SS, OPEN | per frame |
| **PROTOCOL REQUIREMENT** | hello/kex/auth frames MUST carry the sender's own `handshake.stage` ordinal. Without this the far tip in §7's anastomosis mechanic has no truth to advance on — this is a wire-format requirement on `src/`, not a rendering assumption. | — |
| `handshake.progress` (mine/theirs) | `(stage + stageByteFrac)/6`; resets to 0 on failure; `stageByteFrac` is real key-exchange transcript progress during E_SENT/EE/SS, not a guess | per frame |
| `hypha.bytesPerSec` | EWMA α=0.18 over 250 ms ticks (disclosed) | 250 ms |
| `hypha.rttMs` | EWMA α=0.25 (disclosed) | per ack |
| `hypha.heartbeatAgeMs` | `now − lastFrameAt` | per frame |
| `hypha.timeoutMs` | `clamp(4·rttEwma + 750, 1500, 9000)` | per frame |
| `hypha.inflightBytes` | enzyme bytes sent, unacked | per frame |
| `hypha.activeSubstreams` | count of open fruiting subscriptions + enzyme channels multiplexed on this hypha | per open/close |
| `substrate.frontIndex[f]` | highest *contiguous* verified seq | per commit |
| `substrate.synced[f]` | verified byte count for fruiting `f`, monotone except on real pruning | per commit |
| `substrate.known[f]` | announced byte count for fruiting `f` — **not monotone**, jumps when new history is discovered | per commit |
| `substrate.entryAppended` | `{entryId, t, pruned}` — fires once per locally-replicated log entry | per append |
| `enzyme.bytesOut` | EWMA α=0.20 over 1 s — **executed** enzyme work actually completed, never declared capacity | 1 s |
| `enzyme.localQueueDepth` | backlog of this spore's own INDEX/FORGE/VAULT work | per tick |
| `substrate.fsyncLatencyMs` | real disk fsync timing for local appends | per append |
| `index.docsPending` | INDEX backlog on this spore | per tick |
| `substrate.writesSinceBeacon` | count of local substrate appends since the last beacon send; resets to 0 on send | per append |
| `spore.capacityUnits` | **`enzyme.bytesOut`** — executed throughput, never `enzymes/s × declared cores` | 1 s |
| `mesh.capacityTotal` | Σ `spore.capacityUnits` over peers, sampled every 2000 ms | 2 s |
| `mesh.capacityPrev` | the value `mesh.capacityTotal` held at the *start* of the current 2000 ms window | 2 s |
| `mesh.dCapacity` | `mesh.capacityTotal − mesh.capacityPrev` over that same 2000 ms window | 2 s |
| `message.verifyLatencyMs` | receipt → signature verified | per message |

Derived normalizer for all brightness: `B = log1p(bytesPerSec/512) / log1p(262144/512)`, clamped
0..1 — logarithmic because throughput is, and a linear map makes every idle thread look dead.

**Why `capacityUnits` changed.** Thigmotrope and Anastomosis both bound capacity/BLOOM to a
*declared* quantity (`declared cores`, `storage offered`). Against this project's own
established finding — a shared Wi-Fi medium caps real per-joiner speedup at ~3.3× regardless of
what a peer advertises — a declared-capacity binding lets a spore trigger a BLOOM it cannot
actually deliver. `enzyme.bytesOut` is executed work, matching Tropism's and Mycelium/1's
choice, the only two directions the judges found immune to a false BLOOM.

---

## 3. The spring bank, and the asymmetry law

ζ = c / (2√(km)); overshoot = exp(−πζ/√(1−ζ²)); 2% settle (underdamped) ≈ 5.8/ω₀.

| name | k | c | m | ζ | overshoot | settle | used for |
|---|---|---|---|---|---|---|---|
| REACH | 190 | 20 | 1 | 0.7255 | 3.65% | 420.7 ms | hypha tips, node germination, branch tips |
| SETTLE | 180 | 26.8 | 1 | 0.9988 | ~0% | 432.3 ms | thread thickness, front fill, fruiting ladder, metabolism ring |
| WITHER | 42 | 18.1 | 1 | 1.397 (overdamped) | — | ~1.1 s | all decay, all retraction |
| **BLOOM (fixed)** | **65** | **7.2** | 1 | 0.4466 | 20.8% | **719 ms** | global capacity multiplier |
| RM-INSTANT | 14400 | 240 | 1 | 1.0 | 0% | 48 ms | reduced-motion substitute |

**The BLOOM fix, shown.** Thigmotrope specified k=320, c=16 and claimed a 720 ms settle; its own
formula gives 5.8/√320 = 324 ms — a verified arithmetic defect, the one number in an otherwise
exactly-checked table that didn't check out. Rather than just correct the stated number down to
324 ms (too fast for the single biggest, most emotionally loaded event in the design, and
visually indistinguishable from REACH/SETTLE), the constants are corrected instead, holding ζ
and overshoot fixed: solving 5.8/ω₀ = 0.72 for ω₀ = 8.056, k = ω₀² = 64.9 → **k=65**; c =
2ζω₀ = 2·0.4472·8.056 = 7.2. Verified: ω₀=√65=8.062, ζ=7.2/(2·8.062)=0.4466 (≈0.447, matches),
overshoot = exp(−π·0.4466/√(1−0.4466²)) = exp(−1.568) = 20.8% (matches), settle = 5.8/8.062 =
719 ms (matches the original claim). Same character, corrected math.

**WITHER's settle, made exact instead of approximate.** k=42, c=18.1 is overdamped: roots
s = (−c ± √(c²−4km))/2m = (−18.1 ± 12.634)/2 → dominant pole s₁ = −2.733/s, time constant
τ = 1/2.733 = 366 ms. Visual rest at ~3τ ≈ **1.1 s** — the "~1.1 s" in the original document is
correct, and this derivation is what makes it more than an eyeballed number.

**The asymmetry law**, unchanged and the single strongest idea in the set: the same telemetry
value uses REACH rising and WITHER falling. Stiffness drops ~4.5×, damping crosses from
underdamped to overdamped. Growth is eager; death is heavy. You can read the sign of the
derivative off the physics with every label removed.

**Exception, kept from Thigmotrope**: thread tension (bytesPerSec → sag) uses SETTLE
symmetrically in both directions, because throughput genuinely oscillates and an asymmetric
filter would lie about it.

**One filter law, no second clock.** Mycelium/1's exponential follower is not adopted alongside
the spring bank — running two different filter mechanisms in the same design is exactly the kind
of inconsistency a craft review catches immediately. Every animated value, continuous or
ramp-indexed, is filtered by the same spring bank: SETTLE while rising or holding, WITHER while
falling, per the asymmetry law. A thread-thickness bucket or a fruiting-ladder rung is a glyph
*sampled from* a SETTLE/WITHER-filtered continuous value, never a separately-filtered quantity.

**Ramp hysteresis, unified.** Every discrete glyph index sampled from a spring output uses
**1/8-step hysteresis**: the rendered rung changes only when the underlying value crosses
`k/(n-1) ± 0.0625`, so a value hovering on a boundary never strobes. (Thigmotrope's 0.04 and
Mycelium/1's 1/8-step are unified to one number, used everywhere.)

**The closed list of time-boxed exceptions.** Exactly three animations in the whole system are
timers rather than filters, and each is an acknowledgment receipt for a discrete event that has
*already happened* — not growth, and not permitted a fourth member without revising this
document:

1. **Glint sweep**, 120 ms, `cubic-bezier(0.16, 1, 0.3, 1)` — fires once on handshake OPEN.
2. **Island-merge flash**, 1 frame — fires when the colonizing front absorbs a verified island.
3. **Fusion flare**, 90–210 ms (§7) — fires once, exactly at anastomosis.

---

## 4. Node placement and geometry (fills a gap in the base design)

Thigmotrope specified spring physics for hypha tips but not how peer nodes are placed on the
graph. Grafted from Mycelium/1, because it is free and never jitters:

Two distinct quantities, not one — the source directions each specified only half of this and
naming them both `radius` collided:

```
theta = 2π · (xorDistance(selfId, peerId) / 2^64)   // deterministic ring seat, Anastomosis's
                                                      //   xor-distance seating — more principled
                                                      //   than a raw peerId hash
orbit    = ringR · (1 + 0.15·log2(hypha.hops)) · (1 - capNorm) ** 0.5
                                                      // orbit: DISTANCE FROM CENTRE.
                                                      // more hops pushes a peer's seat outward;
                                                      // higher measured capacity pulls the same
                                                      // seat inward. Composed, not competing.
nodeSize = sqrt(spore.capacityUnits) normalized to mesh max
                                                      // nodeSize: the glyph/sprite RADIUS at that
                                                      // seat (§7, "peer node germinates and
                                                      // swells") — capacity read as area, a
                                                      // separate quantity from orbit position.
```

Same peer, same `theta`, every session — a real identity cue. Because `orbit` is a pure function
of `peerId`, `hops`, and measured capacity, and `nodeSize` is a pure function of measured
capacity alone, any motion on screen *is* one of those quantities changing; nothing jitters for
its own sake.

---

## 5. Rendering pipeline — ANSI TUI

**Braille bit map — the correct, non-contiguous one** (Mycelium/1's contribution; every other
direction glossed this and it is, per that document, the single most common implementation bug):

```
x=0: [0x01, 0x02, 0x04, 0x40]   // y = 0,1,2,3
x=1: [0x08, 0x10, 0x20, 0x80]
glyph = String.fromCharCode(0x2800 | bits)
```

Rows 0–2 are the historical 6-dot block; row 3 (`0x40`/`0x80`) was bolted on later and does not
continue the `0x01..0x20` sequence.

**Line rendering**: Xiaolin Wu antialiased coverage per dot, resolved to on/off through a Bayer
4×4 ordered dither (not random — a static thread must not shimmer):

```
BAYER = [[0,8,2,10],[12,4,14,6],[3,11,1,9],[15,7,13,5]]
dotOn = coverage > (BAYER[y & 3][x & 3] + 0.5) / 16
```

This is what makes a hypha at 38% strength read as a genuinely *thin* thread, not a dotted one.

**Colour**: 24-bit `ESC[38;2;r;g;bm`. Every ramp's colour interpolates in **OKLab**, not sRGB — a
straight sRGB lerp from cyan-live to cyan-thread passes through a muddy desaturated trough. Never
computed per frame: each ramp bakes into a 32-entry RGB LUT at startup; the renderer does one
array index, `LUT[(d*31)|0]`, no math, no allocation.

**Synchronized output — closing Thigmotrope's real gap.** FINDINGS.md states synchronized output
(`CSI ?2026h` / `CSI ?2026l`) is mandatory, not optional, and three of the four source
documents — Thigmotrope included — never mention it despite specifying diff+coalescing TUI
paths. Fixed here: every frame is wrapped in `ESC[?2026h` … `ESC[?2026l`, unconditionally.
Terminals that support it composite atomically so a moving pulse never tears; terminals that
don't ignore both sequences harmlessly. This is not a style choice, it is closing a mandatory-
item gap before build.

**Emission per frame:**

1. Damage scan: walk the shadow buffer, build spans of consecutive differing cells. Zero damage
   → zero bytes → skip the frame entirely. An idle mesh is a silent TTY.
2. SGR run coalescing: one `ESC[38;2;r;g;bm` per span, only when fg actually changes.
3. Cursor economy: `ESC[{row};{col}H` only when the next span is not contiguous with the last.
4. Synchronized output wrap (above).

**Byte budget, recalibrated against the probe, not against another design's guess.** The probe's
measured ceiling is **80 KB/s at 60fps** (80,000 bytes/s) for differential rendering on a
comparably-sized grid. The TUI runs at a **30fps cap**, so the equivalent per-frame budget is
80,000/30 = 2,667 bytes ≈ **2.6 KiB/frame (soft budget)** — 2,667×30 = 80,010 bytes/s, matching
the probe number almost exactly. Mycelium/1's own 12 KiB/frame hard cap is 4.5× over this and was
flagged by the craft judge for exactly that reason; it is not adopted. Instead:

- **Soft budget: 2.6 KiB/frame (2,667 bytes).** Typical frames (Thigmotrope's own measured
  neighbourhood: ~1.2 KiB typical) sit well under this.
- **Hard cap: 8 KiB/frame.** A full-screen resize redraw may briefly exceed the soft budget but
  never the hard cap.
- **Priority-ordered degradation** (grafted from Mycelium/1) kicks in once a frame's damage would
  exceed the *soft* budget: spans emit in priority order **text pane > gutter/roster >
  peer graph > background/understory/mat texture**, and the remainder defers to the next
  frame(s). The graph degrades before the text ever does, by construction, every time.

**Backpressure governor** (grafted from Mycelium/1, exact algorithm): if `process.stdout.write`
returns `false` twice consecutively, step the tick **30 → 15 → 8 fps**; recover one step per 2 s
of clean drains. See §1 for why the accumulator clamp had to move to accommodate this.

**Compositing — TUI has no alpha.** "The graph breathing behind the text" is a lie a terminal
cannot tell, so cell-exclusion replaces alpha: the graph occupies **the cells the text does
not**. Compositing order back to front: substrate → mat/understory → braille hyphae/particles →
`[gutter mask: text overwrites this layer unconditionally, including one cell of bleed either
side]` → text → chrome. As the message list empties, the mycelium is revealed; a busy channel is
mostly text with threads glimpsed between paragraphs — clutter is automatically inversely
proportional to how much the user actually has to read.

**Column budget by width** (fixes the human-factors judge's real-estate criticism — Thigmotrope's
fixed ~31 columns of chrome doesn't shrink on a narrow phone terminal):

| terminal width | peer graph pane | roster | gutter |
|---|---|---|---|
| ≥100 cols | 28 cols, right | inline names in pane | 2 cols, left |
| 80–99 cols | 18 cols, right | collapses to glyphs only, no names | 2 cols, left |
| <80 cols (phone) | **none** — graph collapses entirely into the gutter | one aggregate status line, bottom | 2 cols, left, now carrying both colonizing-front fill and a compressed peer-count glyph ramp |

---

## 6. Rendering pipeline — browser canvas

Same simulation, same LUTs, same telemetry bindings, different rasterizer and a different
compositing rule (alpha exists here, unlike the TUI):

- One canvas, one offscreen buffer, dpr capped at 2.
- **Compositing**: field/graph render behind DOM text with `globalAlpha` masked to ~0.14–0.30
  inside each text row's bounding box (not the TUI's cell-exclusion — the browser can actually
  blend). Text itself is a DOM layer above the canvas so glyphs are never composited through any
  glow; only `color`/`opacity` mutate on text nodes — compositor-only, no layout, no repaint.
- **Runtime contrast clamp** (grafted from Tropism): per text row, compute the composited
  background's relative luminance and raise text `L` until contrast ≥ 4.5:1, every frame — the
  background is generative and cannot be checked ahead of time, so the floor is enforced by code.
- Threads batched into 4 stroke calls by luminance tier; additive blending
  (`globalCompositeOperation = 'lighter'`) is available here and used for pulse crossings and
  the BLOOM ignition core, which the TUI cannot do and substitutes with `max()` compositing.
- 60fps target; TUI's 30fps is a different, honest sampling of the identical fixed-step sim, not
  a lesser product.

---

## 7. Growth moments

| moment | bound to (real telemetry) | technique | timing / easing | stall / reverse behaviour | reduced-motion form |
|---|---|---|---|---|---|
| **N=1 breath** — inhale/hold/exhale | `beacon.sentAt`, `beacon.intervalMs`, `substrate.writesSinceBeacon` | Radius setpoint toggled by real beacon events, REACH in / WITHER out, rendered as braille 2×4 radial disc | INHALE REACH 420.7ms to 1.0; HOLD pinned `intervalMs−420`ms; EXHALE WITHER ~1.1s to floor `0.22 + 0.5·clamp(writesSinceBeacon/8,0,1)` (never 0 — alive, and **you type, your own breath brightens**) | Stall: beacon thread hangs → disc holds exact radius indefinitely. Reverse: a reply arrives → `failedRounds` resets, `intervalMs` collapses to 1200ms, the breathing visibly quickens within one cycle — recovery, not decay, so it rides REACH | Two-state glyph alternation `◦`/`✳` on send, held for listen window |
| **Hold countdown arc** (NEW — fixes the "is it hung" criticism) | `beacon.holdRemainingMs` | Shrinking braille-dot arc ringing the breathing disc, drawn directly from real elapsed time since the last real beacon send (legal use of wall time per §2) | No spring — literal real-time countdown, continuously legible | Stall: not possible — it is a direct countdown, always reaches exactly 0 at the next real send. Reverse: n/a, monotone within each interval by construction | Arc replaced by a numeric `Ns` readout beside the glyph |
| **Local metabolism pulse** (NEW — the second, faster N=1 heartbeat) | `enzyme.localQueueDepth`, `substrate.fsyncLatencyMs`, `index.docsPending` — real work from **INDEX, VAULT, FORGE**, the roles doing real local work at N=1 (BEACON *is* the breath above; RELAY has nothing to relay alone) | Small violet ring nested beside the breathing disc; radius = SETTLE-filtered `localQueueDepth` norm; brightness = SETTLE-filtered local completion rate. Runs independently of beacon backoff | SETTLE, 432.3ms | Stall: queue genuinely empties → ring shrinks to a point and holds; it is not required to always show something. Reverse: new local work arrives → ring regrows via the same SETTLE filter (this quantity has no directional asymmetry — a queue fills as readily as it drains) | Ring becomes a static `∘`/`●` two-state glyph on queue-empty/queue-nonempty |
| **Transport stubs** | `transport[t].readiness`, 0..1 per driver (BLE, LAN, USB-OTG, audio modem, QR, LoRa); `transport[t].viaTailnet` | Stub length = readiness × 4 braille subpixels at fixed quadrant angles. A transport whose join failed (Windows EINVAL, FINDINGS §1) renders **no stub**, not a broken one — absence is the signal, since default-interface join success still yields real readiness. A tailnet-reached stub carries a `~` glyph annotation, never silently presented as LAN | SETTLE, 432.3ms | Stall: length freezes. Reverse: a radio dropping mid-session retracts its stub via WITHER (~1.1s) — losing a sense reads heavier than gaining one | Static glyph per transport, filled/hollow |
| **Anastomosis reach** — dual tips advance toward each other | `handshake.progress` (mine) **and** `handshake.progress` (theirs — wire-carried per the §2 protocol requirement: hello/kex/auth frames MUST echo the sender's own stage, or this row binds to nothing) | *Each tip's attractor is the other tip's live position* (Anastomosis's algorithm, replacing a fixed-endpoint bezier). **Corrected gate** (the naive "progress × frozen gap" rule lets two tips at progress 1.0 travel the full distance each and pass through one another): tip `s` advances while `liveGap_s > (1 − progress_s) · G0_s`, where `liveGap_s = \|tip_self − tip_peer\|` measured live every tick and `G0_s` is that same distance frozen at discovery. `progress_s` is REACH-filtered `handshake.progress` for that side. A fast side closes nearly the whole live gap; a slow side's gate barely opens — the asymmetry is visible geometry, not a mirrored animation. Per-substep advance capped at Anastomosis's own **D=2 dots** (braille) / 2px (canvas) | REACH, 420.7ms per stage, 3.65% overshoot per boundary — six small eager taps as the handshake climbs | Stall: `now − lastProgressMonotonic > 400ms` → tip freezes exactly at earned progress, colour drifts to amber-warn `#FFB454` over the WITHER curve while frozen (waiting, not dead). Reverse: handshake failure resets `progress_target=0`; the tip retracts via WITHER (~1.1s), 2.6× slower than it advanced | State-only: 7 discrete stage dots per side, no chase |
| **Anastomosis fusion** — handshake completion IS the fuse | Both `handshake.stage = OPEN` (mine and theirs) and live-tip separation `< d_k` (3 dots) | 0–90ms: both apex glyphs migrate to a shared cell. 90–210ms: cell renders `⣿` bloom-white `#EAFBFF`, amplitude eased cubic-out `1−(1−u)³` then cubic-in `u³`. 210ms: tube continuous, septa renumber, first real in-flight frames of the substrate-sync exchange stream **both directions at once** (duplex session = literal bidirectional cytoplasmic flow) | 90–210ms flare (one of the three permitted receipts, §3) | Stall: if sync exchange stalls post-fusion, the fused tube sits visibly empty. Reverse: n/a — fusion is a one-way commit; incompatible fusion is a distinct terminal outcome, next row | 1-frame colour step, no flare geometry |
| **Incompatible fusion / rejection** | Auth failure or cert mismatch — a real, distinct outcome from timeout | Single `reject-rust #C4563A` flash on both apices (no bloom, no fuse), then both tips retract | WITHER, ~1.1s, τ=366ms dominant pole | Stall: n/a — this is itself a terminal state. Reverse: a fresh handshake attempt after rejection spawns a wholly new pair of tips from scratch, not a resumption — there is no scar to resume from, unlike a graceful timeout (see "reconnection", below) | 1-frame colour step to reject-rust, held |
| **Peer node germinates and swells** | `spore.capacityUnits` = `enzyme.bytesOut`, executed throughput, sampled at 1s | Node doesn't exist until `handshake.progress ≥ 1/6`; appears as `·`; `nodeSize` (§4) = √capacityUnits normalized to mesh max — area reads as capacity | REACH, 420.7ms, 3.65% overshoot on growth | Stall: peer stops reporting → holds last size. Reverse: capacity genuinely drops (throttling, backgrounding) → shrinks via WITHER (~1.1s) — a peer shrinking is visibly sadder than a peer growing, by construction | Instant snap, RM-INSTANT (48ms) |
| **Subapical branching by substream count** (grafted from Anastomosis) | `hypha.activeSubstreams` | New branch emitted **3–6 segments behind the apex, never at it** — a mycologically correct constraint — one branch per open substream, exactly. Lateral angle: truncated normal μ=62°, σ=14°, clipped [38°,88°]. A branch request from a substream whose own `bytesPerSec < 0.25·max` within 10 cells is **queued, not drawn**, rendered as a dim `·` placeholder (apical dominance) | REACH per branch tip, 420.7ms | Stall: queued branch sits as `·` indefinitely until its own throughput rises. Reverse: the substream closes → that branch withers via WITHER, retracting tip-first and leaving a scar exactly like the main-hypha wither mechanic | Branch count shown as a static integer badge, no geometry |
| **Threads pull taut / sag** | `hypha.bytesPerSec`, normalized `B = log1p(bps/512)/log1p(262144/512)` | Bezier control point = midpoint + perpendicular · sag, `sag = 0.18·len·(1−B)` — a rope metaphor with no physics sim, and simultaneously the 4-tier luminance quantization key | SETTLE, symmetric both directions — the one stated exception to the asymmetry law (§3), because throughput genuinely oscillates and an asymmetric filter would lie about it | Stall/reverse: there is no separate reverse case here by design — rising and falling bytesPerSec use the identical SETTLE filter, so a burst tightening the thread and a lull slackening it look like the same physics running both ways, which is the truth | Per-thread sparkline of last 32 samples, redrawn 4Hz |
| **Message germination** | `message.verifyLatencyMs`, msg state RECEIVED→VERIFIED→SETTLED | Brightness-only: text-unverified `#4C5C61` (2.92:1, deliberately below AA) → text-body `#C8D8DC` (13.87:1). DOM `color` only, zero displacement — the legibility firewall's clearest expression | Linear ramp, floor 1 frame (16ms), ceiling 250ms | Stall: stays at unverified colour indefinitely — correct, deliberately uncomfortable to read. Reverse: signature verification fails → drops back to `#4C5C61` and the adjacent gutter rune flashes reject-rust `#C4563A` once | Same ramp, no floor/ceiling change (already instant-scale) |
| **Colonizing front** — history syncs | `substrate.frontIndex[f]`, the highest *contiguous* verified seq | Left gutter column `▏▎▍▌▋▊▉█`, cell *i* fill = `clamp((frontIndex−i·perRow)/perRow,0,1)`. Rows ahead render `·` at cyan-ghost `#0A3A42` (1.64:1, texture only). A verified island beyond the front lights independently at 0.4 luminance and merges in one frame when the front arrives | SETTLE, 432.3ms; merge is 1 of the 3 permitted receipts | Stall: front holds, islands keep appearing ahead of it — gap-filling is watchable. Reverse: on fork detection `frontIndex` genuinely *decreases* — the front **retracts** via WITHER (~1.1s) and glyphs above the new front de-render. The only sanctioned removal of already-shown text, and it is honest: a progress bar cannot do this at all | Same fill values, snapped |
| **DLA mat** — the log itself, literally (grafted from Anastomosis) | `substrate.entryAppended`, 1:1, never resimulated | Diffusion-limited aggregation on the braille dot grid (240×160 @ 120×40). **One walker per newly-replicated entry, no exceptions.** Walker RNG seeded from `hash(entryId)` (FNV1a) — the *count* was already truth in the source design, this seed makes the *shape* deterministic too, so identical logs render identical mats, closing the "decorative randomness" gap. Stickiness p=0.35 (not classic DLA's p=1.0) thickens branches toward fractal dimension ~1.9, matching a real mycelial mat and staying legible as texture. Budget: ≤24 walkers in flight, ≤400 steps/walker/frame. Colour by `entry.t`: newest cyan-live, aging to cyan-ghost | No duration, no easing — a dot appears the frame its entry commits | Stall: replication stops → mat is static, correctly. Reverse: `entry.pruned` **erases that exact dot** — log compaction visibly, permanently thins the mat | Static final mat only, walker animation removed |
| **Fruiting bloom** — a channel opens as its history genuinely syncs | `substrate.synced[f]` (monotone, absolute) for length; `substrate.known[f]` (non-monotone) for a ghost rung only | Glyph ladder ▪→▴→▵→✦, index from `synced`. **Fixed binding** (Anastomosis's key correction): a naive `synced/known` ratio falls when new history is *discovered*, which would falsely retract an already-open channel — a lie. Binding length to `synced` alone and drawing `known` as a faint cyan-ghost **ghost rung** further out solves it: the ladder never un-opens on discovery, and the ghost shows how much further it will reach | SETTLE, 432.3ms per rung, 1/8-step hysteresis | Stall: ladder holds at whatever rung `synced` reached — a half-synced channel reads as a half-open bud, honestly. Reverse: only real pruning can lower `synced` — the ladder then **closes back down** through the same rungs via WITHER, exactly like withering a peer | Ladder shown at final rung + numeral, ghost dropped |
| **BLOOM** — measured mesh capacity really jumps | `mesh.dCapacity ≥ 0.40 · mesh.capacityPrev` over the same 2000ms window (both the trigger ratio and the window unified — no separate "1s" or "2s ratchet" figure anywhere else in this design), **and** ≥2 hyphae reaching OPEN inside that window. `mesh.capacityTotal`/`capacityPrev` built from `enzyme.bytesOut` — executed work, never declared cores/storage | Beat 1 (0 to up to 2000ms, real, not chosen — the gap to the next capacity sample): global luminance → 0.72 via WITHER, breath pauses at current phase — the app visibly darkens while the real capacity tick is still pending. Beat 2: BLOOM spring (k=65, c=7.2, corrected, §3) on global scale, target = `clamp(capacityTotal/capacityPrev, 1, 1.6)`. Beat 3: luminance wave in BFS hop order, per-hop delay = that hop's *measured* rttMs, gaussian σ=2.5 cells. Beat 4: every fruiting whose `synced` rose opens its ladder, staggered by real arrival order. Beat 5: multiplier → 1.0 via SETTLE, breath resumes at its paused phase | Beat 2: 719ms settle (corrected), 20.8% overshoot fixed by ζ, magnitude set by the *real* ratio so a 4× jump and a 1.15× jump land visibly different | Stall: if the next capacity sample never confirms the threshold, luminance simply stays at 0.72 — dark and waiting, honest. Reverse: if a peer drops before the window closes and the ratio no longer clears 0.40, the multiplier returns to 1.0 via WITHER and no bloom fires — a swelling that deflates | 1-frame full-mesh luminance step + a persistent `+N.Nx capacity` readout fading linearly over 4s |
| **Stagger for simultaneous arrivals** | Real `handshake` `openedAt` timestamps per peer | `stagger_i = clamp(openedAt_i − openedAt_0, 40, 200)ms`, applied to node germination, ladder opens, and the BLOOM wave seed order | 40–200ms clamp — three peers within 12ms give a near-unison chord because that is what happened | Stall: a peer that never opens is simply absent from the sequence. Reverse: n/a — stagger only orders forward arrivals, it does not itself animate a value that can fall | Retained but clamped ≤50ms — arrival *order* is information and deleting it deletes truth |
| **Peer withers and departs** | `w = clamp(heartbeatAgeMs/timeoutMs, 0, 1)` | `w≤0.35`: nothing (jitter is normal). `0.35<w≤0.75`: saturation × `(1−smoothstep(0.35,0.75,w))`, hue toward wither-rust `#8A5A3C` — colour warns before motion does. `0.75<w<1`: braille subpixels dropped with probability `(w−0.75)/0.25`, seeded `hash(peerId,cellIndex)` so it doesn't shimmer — the thread becomes lace. `w≥1`: node size→0 via WITHER, thread retracts tip-first, a scar persists at 0.22 length for the session | WITHER, ~1.1s, the slowest motion in the system | Stall: `w` only rises while frames are absent — a stalled peer visibly and continuously decays; this is the one place stall *is* the animation. Reverse: a single heartbeat finally arrives → `w` collapses to 0 and the node/thread re-saturates via REACH in 420.7ms — a visible gasp of recovery, and it cannot be faked because it is the actual return stroke | Saturation/lace steps retained, snapped; scar retained |
| **Reconnection from a scar** | Fresh `handshake.progress` after a prior graceful CLOSED (not after a rejection — see "incompatible fusion", above) | New REACH launches *from the scar*, 0.22 ahead of a cold start — true, because session resumption skips two handshake stages | REACH, 420.7ms, from 0.22 | Stall: if the resumed handshake stalls, the tip freezes at its earned progress exactly as in "anastomosis reach," above. Reverse: a second failure withers the new attempt via WITHER and restores the scar to 0.22 | Instant snap to earned progress |

---

## 7a. Glyph ramps

Every ramp referenced in §7 by name, in full — grafted largely from Mycelium/1's table, indexed
by a spring output (§3) with 1/8-step hysteresis on the boundary, colour from an OKLab-baked LUT
(§5):

| ramp | glyphs | bound to | band thresholds |
|---|---|---|---|
| `RAMP_FRONT` | `▏▎▍▌▋▊▉█` | `substrate.frontIndex[f]` per-cell fill (§7, colonizing front) | eighth-granularity, continuous |
| `RAMP_LADDER` | `▪ ▴ ▵ ✦` | `substrate.synced[f]` (§7, fruiting bloom) | quartiles of the fruiting's total known length |
| `RAMP_THREAD` (roster, non-braille view) | `·` `╌` `─` `━` `═` | `hypha.bytesPerSec` | 0, <1K, <16K, <256K, ≥256K bytes/s |
| `RAMP_NODE` (TUI, cells can't scale) | `·` `∘` `○` `◎` `●` `◉` | `spore.capacityUnits` fraction of mesh mean | 0, <.1, <.25, <.5, <.75, ≥.75 |
| `RAMP_WITHER` | `◉` `●` `◎` `○` `∘` `·` `˙` | `RAMP_NODE` reversed, indexed by `w` (§7, peer withers) | one step per `w` decile past 0.75; terminal `˙` (U+02D9) at `w≥1`, then evicted |
| `RAMP_TRANSPORT` | 0–4 braille subpixels | `transport[t].readiness` (§7, transport stubs) | linear, ×4 subpixels |
| `RAMP_PEERCOUNT` (the narrow-viewport compressed ramp promised in §5's <80-col row) | `· ∘ ○ ◎ ●` | live peer count / mesh historical max | quintiles — this is the entire peer graph on a phone-width terminal: one glyph, one colour, in the gutter |

---

## 8. Legibility firewall

1. No animated property may ever displace a glyph belonging to message text.
2. Growth lives in: gutter (2 cols, or the collapsed single status line under 80 cols, §5),
   peer graph pane (width per the column-budget table, §5), row background luminance,
   interstitial lines. Never the text column.
3. Max 3 luminance-animated text rows at once (newest 3); older rows freeze at final value.
4. Any colour carrying text ≥4.5:1 vs substrate `#050508`, asserted at build time over the
   palette table (§9) — text-unverified `#4C5C61` at 2.92:1 is the one explicitly annotated,
   deliberate exemption (a security affordance, not an oversight).
5. Peer graph caps at 0.55 luminance while the composer is focused. Typing dims the mesh —
   attention is a real state, and this is the single best idea any source direction produced.
6. **Graph occupies the cells the text does not** (§5) — clutter is automatically inversely
   proportional to how much the reader actually has to read.
7. **Priority-ordered byte degradation** (§5): text pane > gutter/roster > peer graph >
   background, enforced by construction whenever the soft byte budget is exceeded.
8. **The three-item closed list** of time-boxed exceptions (§3) may not be extended.

---

## 9. Dormancy and rehydration (grafted from Tropism, closing a real gap)

Thigmotrope's springs are cheap while running but the source document never states what happens
when the phone screen turns off — the single most common real-world state for a messaging app.
Fixed here, verbatim from Tropism's protocol, applied to this design's own state (springs +
followers + LUTs rather than a nutrient field, but the shape of the fix is identical):

On `hidden` / SIGTSTP / TUI focus-out: record `t_hidden`, **stop the loop entirely**. No
simulated ticks accrue while backgrounded — this is not a performance nicety, it is required by
the truth law: simulating a gap you didn't measure is fabrication.

On resume, `dt = now − t_hidden`. What this design actually holds as state is spring `x`/`v`
pairs, DLA occupancy, and the last telemetry sample — there is no nutrient field to decay, so
rehydration is specific to that state:

- **dt < 250 ms**: normal accumulator catch-up (§1).
- **250 ms – 2 s**: up to 8 catch-up substeps, discard the rest.
- **dt ≥ 2 s**: do not simulate the gap. Rehydrate: (a) discard every in-flight pulse and every
  active time-boxed receipt (§3's closed list) — they represented bytes or events that landed
  long ago; keeping them is a lie. (b) Any DLA walker that was mid-walk when the app backgrounded
  is discarded and its entry **relaunched fresh** on resume — the mat stays permanently 1:1 with
  `substrate.entryAppended`, never partially walked. (c) Every spring's `x` (position/value)
  persists exactly as it was; every spring's `v` (velocity) is zeroed — a teleport is inert under
  semi-implicit Euler (§1), so this cannot introduce a spurious impulse. (d) The newest telemetry
  sample is then applied as the new `target` for every spring, and the ordinary REACH/WITHER
  physics carries the interface to the new truth: peers that died while hidden already read
  `w≥1` and wither outward from where they were; new peers spawn at their identity-bearing ring
  seat (§4) and are reeled in by REACH. No scripted transition, no fade-in. Typical settle
  ~1.1–1.2s, governed entirely by the existing spring constants already in §3.

---

## 10. Palette

All ratios verified with a script against **one substrate, `#050508`**, not eyeballed and not
borrowed from a source document with a different substrate (Thigmotrope's own palette used this
substrate and is reused unchanged for that reason; two new hues below were computed fresh):

```
lin(c) = c/12.92 if c<=0.03928 else ((c+0.055)/1.055)^2.4      // c in [0,1]
L = 0.2126·lin(R) + 0.7152·lin(G) + 0.0722·lin(B)
contrast(a,b) = (max(La,Lb)+0.05) / (min(La,Lb)+0.05)
```

SUBSTRATE
- `#050508` — substrate, the ground, 1.00:1 by definition
- `#0B0B12` — gutter/panel ground, 1.04:1

CYAN — self, capacity, health, growth
- `#00E5FF` cyan-live — 13.23:1 — full throughput, DLA newest dot, beacon peak
- `#00C2D9` cyan-strong — 9.42:1 — mid throughput
- `#1A8A9C` cyan-text — 5.00:1 — the one dim cyan tier permitted to carry text
- `#12626F` cyan-thread — 2.91:1 — idle thread, decorative only, never text
- `#0A3A42` cyan-ghost — 1.64:1 — unfetched placeholders, DLA aged dots, fruiting ghost rungs

MAGENTA — other, inbound
- `#FF3DD8` magenta-hot — 6.70:1 — inbound pulses, unread markers
- `#E05CC4` magenta-text — 6.30:1 — peer-authored emphasis
- `#C42CA6` magenta-mid — 4.13:1 — pulse trail, decorative
- `#6E2260` magenta-dim — 2.00:1 — spent pulse residue

VIOLET — self-metabolism (new; the N=1 local-work heartbeat, §7)
- `#B78CFF` metabolism-violet — 7.96:1 — local INDEX/VAULT/FORGE activity, verified fresh against `#050508`
- `#6E4FA3` metabolism-violet-dim — 3.21:1 — resting local queue, decorative only

TEXT
- `#C8D8DC` text-body — 13.87:1 — verified message content
- `#9AAFB5` text-mute — 8.89:1 — metadata, timestamps
- `#4C5C61` text-unverified — 2.92:1 — deliberately below AA; the germination animation (§7) is
  the act of earning legibility

STATE
- `#FFB454` amber-warn — 11.54:1 — orphaned in-flight bytes, stalled tips waiting on a real
  event, the universal "waiting, not dead" signal
- `#8A5A3C` wither-rust — 3.50:1 — slow decay hue target, never carries text
- `#C4563A` reject-rust — 4.59:1 — a sharp, distinct flash for explicit rejection (cert
  mismatch, auth failure), never confused with slow wither because it is a single flash, not a
  hue drift
- `#EAFBFF` bloom-white — 19.14:1 — reserved for the three closed-list receipts (§3) and BLOOM's
  ignition core; nothing else in the product may use this brightness, so its appearance always
  means one of those four specific, real things happened

Build-time assertion: every colour in the text-bearing set computes ≥4.5:1 against `#050508`,
with `text-unverified` as the single explicitly annotated exemption. Decorative tiers are
forbidden from ever being assigned to a text node.

---

## 11. Reduced motion

Kept because it *is* information, not decoration: thread brightness (throughput), node size
(capacity), front fill (sync), wither saturation (heartbeat age), glyph ladders, DLA mat area,
BLOOM's capacity readout, arrival stagger (clamped ≤50ms — order is truth).

Removed: displacement, oscillation, overshoot. All springs switch to RM-INSTANT (k=14400, c=240,
ζ=1.0, 48ms) — since §3 unified every filter onto the one spring bank, this single substitution
covers every animated value in the system, ramps included. The breathing beacon becomes a two-
state glyph alternation held for the real listen window. BLOOM becomes a 1-frame luminance step
plus a persistent numeric readout. Anastomosis fusion becomes a 1-frame colour step with no
flare geometry. The DLA mat keeps its final shape with no walker animation. Values still follow
truth; they arrive without ceremony.

---

## 12. What we cut, and why

Every cut below removes something that could not be bound to a real, measured, executed
quantity, or that the judges verified does not do what its source document claimed.

1. **Gray-Scott reaction-diffusion as the BLOOM centerpiece (Anastomosis).** Verified by direct
   simulation at the document's own exact stated parameters (96×64, Du=0.16, Dv=0.08, F=0.0545,
   k=0.0620, V=0.9 stamp, 6000 steps): it settles into a static ~1.5%-of-grid spot, not the
   claimed expanding self-replicating wave. Its own iteration-count rule additionally
   contradicts its own stated baseline (2 vs 4 iterations/frame at gate-open). BLOOM in this
   document is instead a spring-driven global luminance multiplier (BLOOM spring, §3) whose
   *target* is the real measured capacity ratio and whose propagation wave runs on measured
   per-hop RTT (§7) — Thigmotrope's original mechanic, corrected and rebound to executed
   capacity, not Anastomosis's field and not a new one invented for this document.
2. **Declared-capacity bindings** (`enzymes/s × declared cores`, `enzymes completed/s × storage
   offered`) from both Thigmotrope and Anastomosis. Cut and replaced everywhere with
   `enzyme.bytesOut`, executed work, per §2 — a spore cannot trigger a false BLOOM by advertising
   capacity it cannot serve on a saturated shared medium.
3. **A full continuous 60Hz N-body/reaction-diffusion simulation running whenever the app is
   foregrounded, whether or not anything is happening** (Tropism's own stated design). Its own
   failure-mode section concedes a real mesh at 2KB/s produces "maybe three particles per second"
   and "a perpetually-moving background... is exhausting." This design uses cheap springs and
   followers (§1, §3) instead of a continuous field/N-body sim, and additionally requires the
   dormancy stop-on-hide protocol (§9) so nothing runs at all while backgrounded.
4. **Any idle "breathing" animation not bound to a real event**, proposed nowhere in this
   document and explicitly forbidden: the temptation, named by three of the four source
   documents' own failure-mode sections, is to add a decorative idle drift to make N=1 look less
   dead. The mitigation actually shipped instead is real: the hold-countdown arc and the local-
   metabolism pulse (§7), both bound to telemetry rows that did not exist in any source document
   until this synthesis added them.
5. **A fourth-transport-style random idle wiggle for stalled anastomosis tips** (a temptation
   Anastomosis's own failure-mode section names and rejects). Not adopted; a stalled tip
   desaturates to amber-warn and holds, per the mandatory stall test (§0).
6. **Thigmotrope's uncorrected BLOOM constants** (k=320, c=16, claimed 720ms settle against an
   actual 324ms). Not restated — corrected, with the new constants shown solving the same target
   (§3).

---

## 13. Fixed defects — a summary for the record

| defect | source | verification | fix |
|---|---|---|---|
| BLOOM settle-time arithmetic (720ms claimed, 324ms actual for k=320,c=16) | Thigmotrope | Recomputed 5.8/√320 = 324ms | k→65, c→7.2, same ζ=0.4466/20.8% overshoot, settle now 719ms (§3) |
| Gray-Scott parameters don't produce the claimed expanding front | Anastomosis | Simulated the exact stated parameters for 6000 steps; static ~1.5%-of-grid spot | Cut (§12.1); BLOOM kept as Thigmotrope's spring-driven multiplier + measured-RTT wave, rebound to executed capacity |
| Declared-capacity binding vulnerable to false BLOOM on a saturated shared medium | Thigmotrope, Anastomosis | Cross-checked against the project's own established Wi-Fi shared-medium finding | Rebound to `enzyme.bytesOut`, executed work (§2, §12.2) |
| Missing mandatory synchronized-output framing in the TUI path | Thigmotrope | FINDINGS.md states it is mandatory; base doc's TUI section never mentions `CSI ?2026h/l` | Added unconditionally to the emission pipeline (§5) |
| Byte budget with no backpressure governor, and no stated behaviour under write failure | Thigmotrope | Base doc specifies a frame budget but no governor | Mycelium/1's 30→15→8fps governor grafted in, with the accumulator-clamp fix it requires (§1, §5) |
| Fixed-column chrome doesn't shrink on a narrow terminal | Thigmotrope (human-factors finding) | ~31 of 80 columns spent on chrome, unrevisited for width | Column-budget table by width (§5) |
| Fruiting-bloom ratio binding can falsely retract an open channel on history discovery | Thigmotrope (used a syncRatio-style binding implicitly) | Anastomosis's own documented reasoning about `known` jumping | Bound to `synced` alone (monotone), `known` drawn as a non-retracting ghost rung (§7) |
| DLA mat shape is non-deterministic despite deterministic count | Anastomosis (not addressed in source) | Judge's "decorative randomness" criterion | Walker RNG seeded `hash(entryId)` (§7) |
| N=1 long backoff hold reads as a hung process | Thigmotrope (honestly admitted, not solved) | Both judges named this as the direction's real remaining gap | Hold-countdown arc + local-metabolism pulse, both newly-specified telemetry-bound signals (§7) |
| Integrator/governor interaction: 8fps governor step would starve the fixed-step accumulator | New — surfaced by combining two grafts | Arithmetic: 125ms/frame vs original 33ms clamp | Accumulator clamp raised to 250ms, substep cap to 30, stability re-verified (§1) |
