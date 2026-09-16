# THIGMOTROPE

> Thigmotropism is how a real hypha grows: it reaches until it touches something, then follows what it touched. This direction makes every animated property a second-order filter whose *setpoint* is a live telemetry read — springs smooth, they never drive. Growth reads as alive because it can stall, hesitate, overshoot and reverse exactly when the network does, and because growing and dying use deliberately asymmetric physics: reaching is quick and slightly eager, withering is heavy and slow.

_(full markdown spec below)_

## 0. The setpoint law

One rule governs everything: **a spring filters, telemetry sets.** For every animated property there is a `target` that is a *live read* of a measured quantity, and a `current` that chases it through a fixed-step integrator. "Bloom takes 400ms" is a timer and fails the brief. "Bloom fill follows `substrate.syncRatio` through k=180, c=26.8, m=1, settling in ~430ms once the value stops moving" passes, because if the sync stalls at 0.4 the bloom stops at 0.4 and sits there.

Exactly two time-boxed animations are permitted in the whole app, and both are *acknowledgment receipts*, not growth: the 120ms glint sweep on handshake OPEN, and the 1-frame merge flash when the colonizing front absorbs an island. Everything else is a filter over truth.

## 1. Telemetry table — the only legal setpoint sources

`src/telemetry` exposes this and nothing else. Every `boundTo` in this design names a row here.

| signal | derivation | rate |
|---|---|---|
| `beacon.sentAt`, `beacon.intervalMs` | adaptive: `min(1200 · 1.35^failedRounds, 8000)` ms | per beacon |
| `transport[t].readiness` | driver link-layer init, 0..1 | 250 ms |
| `handshake.stage` | 0..6: IDLE, HELLO_SENT, HELLO_ACK, E_SENT, EE, SS, OPEN | per frame |
| `handshake.progress` | `(stage + stageByteFrac)/6`; resets to 0 on failure | per frame |
| `hypha.bytesPerSec` | EWMA α=0.18 over 250 ms ticks | 250 ms |
| `hypha.rttMs` | EWMA α=0.25 | per ack |
| `hypha.heartbeatAgeMs` | `now − lastFrameAt` | per frame |
| `hypha.timeoutMs` | `clamp(4·rttEwma + 750, 1500, 9000)` | per frame |
| `hypha.inflightBytes` | enzyme bytes sent, unacked | per frame |
| `substrate.frontIndex[f]` | highest *contiguous* verified seq | per commit |
| `substrate.syncRatio[f]` | `verified / announced` | per commit |
| `spore.capacityUnits` | enzymes completed/sec × declared cores | 1 s |
| `mesh.capacityTotal`, `mesh.dCapacity` | Σ over peers; Δ over 1 s window | 1 s |
| `message.verifyLatencyMs` | receipt → signature verified | per message |

Derived normalizer used for all brightness: `B = log1p(bytesPerSec/512) / log1p(262144/512)`, clamped 0..1. Logarithmic because throughput is, and a linear map makes every idle thread look dead.

## 2. The integrator

Semi-implicit Euler, **fixed timestep dt = 1/120 s**, accumulator pattern, max 4 substeps per frame, accumulated time clamped to 33 ms (spiral-of-death guard):

```
v += ((k·(target − x) − c·v) / m) · dt
x += v · dt
```

Fixed-step is non-negotiable because the TUI runs at 30fps and the canvas at 60: identical substeps mean the two renderers produce *bit-comparable motion*. A peer joining looks the same in a terminal and a browser.

## 3. The spring bank, and the asymmetry law

ζ = c / (2√(km)); overshoot = exp(−πζ/√(1−ζ²)); 2% settle ≈ 5.8/ω₀.

| name | k | c | m | ζ | overshoot | settle | used for |
|---|---|---|---|---|---|---|---|
| REACH | 190 | 20 | 1 | 0.726 | 3.6% | 420 ms | hypha tips, node germination |
| SETTLE | 180 | 26.8 | 1 | 0.999 | 0% | 432 ms | thread thickness, front fill |
| WITHER | 42 | 18.1 | 1 | 1.397 | — | ~1.1 s | all decay, all retraction |
| BLOOM | 320 | 16 | 1 | 0.447 | 20.8% | 720 ms | global capacity multiplier |
| RM-INSTANT | 14400 | 240 | 1 | 1.0 | 0% | 48 ms | reduced-motion substitute |

**The asymmetry law:** the same telemetry value uses REACH when rising and WITHER when falling. Stiffness drops 4.5×, damping goes overdamped. Growth is eager; death is heavy. This single rule is the direction's whole emotional signature — you can identify what the network is doing with the labels off because *the weight of the motion tells you the sign of the derivative*.

## 4. Layer order (back→front)

0 substrate `#050508` · 1 understory braille noise (culled peers) · 2 thread sag curves, 4 luminance tiers · 3 packet pulses (additive) · 4 peer nodes + scars · 5 bloom wave (additive gaussian) · 6 row background luminance · **7 TEXT — never touched** · 8 gutter front column + fruiting glyphs · 9 composer.

Thread geometry: quadratic bezier, control = midpoint + perpendicular · sag, `sag = 0.18 · len · (1 − B)`. **Idle threads sag; busy threads pull taut.** Free, true, and the single best signal in the design — mesh tension *is* mesh load.

## 5. Timeline A — cold start, N=1. "The seed."

The loneliest moment, and the one that breaks the principle if faked. A sine-on-a-timer breath is decoration. So the breath **is the discovery beacon.**

| t | beat | bound to |
|---|---|---|
| 0 | black. no cursor, no chrome | — |
| keygen done (40–300 ms, real) | one glyph `·` resolves `#0A3A42` → `#00E5FF` | keypair completion |
| genesis commit / identity seal / listener bind | glyph steps `·` → `◦` → `✳`, **no tween** — three discrete truths get three discrete frames | three real events |
| first beacon | INHALE: radius 0→1, REACH, ~420 ms | `beacon.sentAt` |
| +420 ms | HOLD: radius pinned at 1.0 for `intervalMs − 420` | listen window |
| window close | EXHALE: → 0.22 via WITHER, ~1.1 s. Never to 0 — the spore is alive | — |

Exhale brightness `= 0.22 + 0.5·clamp(writesSinceBeacon/8, 0, 1)`. **You type, your own breath brightens.** Self-sufficiency, rendered.

Backoff is the melancholy: at interval 1200 ms the hold is 780 ms and it pants; after 6 failed rounds the interval is 8000 ms, the hold is 7.6 s, and it breathes like something conserving itself. Nobody animated that. It's the retry schedule.

Around the glyph, six stubs of 2–4 braille subpixels, one per transport (BLE adv, LAN broadcast, USB-OTG, audio modem, QR, LoRa). Stub length = `transport[t].readiness`. A transport that can't init has **no stub** — you can see which senses are open. When a reply arrives, the stub on *that* transport is the one that reaches. Direction is information.

## 6. Timeline B — first peer. "Contact."

| t | beat | bound to |
|---|---|---|
| 0 | reply parsed, sig unverified → **the breathing stub freezes mid-exhale.** Total stillness | `message.verifyLatencyMs` (3–18 ms, floor 1 frame) |
| verify OK | REACH launches; tip position along bezier, setpoint = `handshake.progress` | handshake state machine |
| stage ≥1 | peer node germinates `·` → radius via REACH | their HELLO verified |
| stall | tip **stops and stays**; only the breath layer continues | — |
| stage 6 | SETTLE on thickness + 120 ms glint, `cubic-bezier(0.16, 1, 0.3, 1)` | OPEN |

The anticipation beat is free: signature verification is a real wait, so stillness before motion costs nothing and buys everything. Tip cell sparkles 3 frames at `#EAFBFF`; trail brightness falls as `exp(−d/6)` cells behind it.

## 7. Timeline C — BLOOM, three peers at once

Trigger (both required): `dCapacity/capacityPrev ≥ 0.40` **and** ≥2 hyphae reached OPEN inside the same 1 s window.

- **Beat 1 — held breath.** From 2nd OPEN until the next capacity tick (0–1000 ms, *actual*, not chosen): global luminance multiplier → 0.72 via WITHER, breath pauses at its current phase. **The app gets darker before it blooms.** This is real waiting — the capacity number genuinely is not known yet.
- **Beat 2 — ignition.** BLOOM spring on global scale, target = `clamp(capacityTotal/capacityPrev, 1, 1.6)`. The 20.8% overshoot is fixed by ζ; the *target* is the real ratio, so a 4× jump and a 1.15× jump land visibly differently.
- **Beat 3 — propagation.** Luminance wave in BFS hop order from self. **Per-hop delay = that hop's measured `rttMs`**, not a constant. Gaussian profile, σ=2.5 cells, peak +0.55 additive. The bloom spreads at the speed light actually takes to get there.
- **Beat 4 — fruiting.** Every fruiting whose syncRatio rose opens its glyph ladder. Stagger = arrival order of its first new entry.
- **Beat 5 — settle.** Multiplier → 1.0 via SETTLE. Breath resumes at the paused phase, never reset.

**Stagger is never a constant:** `stagger_i = clamp(openedAt_i − openedAt_0, 40, 200)` ms. Three peers completing within 12 ms give a near-unison chord — correct, because that is what happened.

## 8. Timeline D — history flooding. "The colonizing front."

No progress bar. Left gutter column of `▏▎▍▌▋▊▉█`, cell *i* fill = `clamp((frontIndex − i·perRow)/perRow, 0, 1)`, indexed to the real log — **and it can run backward when a fork is detected.** A progress bar cannot do that.

Rows ahead of the front are `·` placeholders at `#0A3A42` (1.64:1, pure texture): the colony's *extent* is known before its content. An entry verified beyond the front does not advance it — it lights as an isolated island at 0.4 luminance, and when the front arrives the two merge in a single frame. You can watch gap-filling happen.

Message germination is **brightness-only, zero displacement**: unverified text at `#4C5C61` (2.92:1 — deliberately below AA, because unverified content should not be comfortably readable; a security affordance wearing motion's clothes), transitioning to `#C8D8DC` (13.87:1) over `verifyLatencyMs`, floor 1 frame, ceiling 250 ms.

## 9. Timeline E — peer dies mid-transfer. "Withering."

`w = clamp(heartbeatAgeMs / timeoutMs, 0, 1)`.

- `w ≤ 0.35` — nothing. Jitter is normal; do not cry wolf.
- `0.35 < w ≤ 0.75` — saturation falls by `1 − smoothstep(0.35, 0.75, w)`, hue rotates toward rust `#8A5A3C`. **Color warns first, not motion** — the eye catches desaturation without being yanked.
- `0.75 < w < 1` — the thread *thins by subpixel removal*, not a width tween: each braille subpixel is dropped with probability `(w−0.75)/0.25`, deterministically seeded by `hash(peerId, cellIndex)` so it doesn't shimmer. The thread becomes lace.
- `w ≥ 1` — **no snap.** Node radius → 0 via WITHER (~1.1 s, the slowest motion in the app); thread retracts tip-first. At the anchor, a **scar** remains at 0.22 length for the session. A mesh that has lost peers looks like it.

Orphaned in-flight bytes do not vanish: the last pulse stops where it is, pulsing at 0.5 Hz in amber `#FFB454`, until the enzyme is reassigned (pulse REACHes across to the new thread) or its real retry deadline expires.

**Reconnection**: the new REACH launches *from the scar*, 0.22 ahead. Visibly faster than first contact — which is true, because session resumption skips two handshake stages.

## 10. Legibility firewall

1. No animated property may displace a glyph belonging to message text. Ever.
2. Growth lives in: gutter (cols 0–2), peer graph (cols W−28→W), row background luminance, interstitial lines. Never the text column.
3. Max 3 luminance-animated text rows at once (newest 3); older rows freeze at final value.
4. Any color carrying text ≥4.5:1 vs `#050508`, asserted at build time over the palette table.
5. Peer graph caps at 0.55 luminance while the composer is focused. **Typing dims the mesh** — attention is a real state.

## 11. Reduced motion — considered, not killed

Keep every value that *is* information: thread brightness (throughput), node size (capacity), front fill (syncRatio), wither saturation (heartbeat age), glyph ladders. These are readouts, not animation. Remove displacement, oscillation, overshoot: all springs → RM-INSTANT (ζ=1.0, τ≤16 ms). Values still follow truth, they just arrive without ceremony.

Breath becomes a two-state glyph alternation `◦`/`✳` on beacon send, held for the listen window — still communicates the beacon rate with zero continuous motion. BLOOM becomes a 1-frame full-mesh luminance step plus a persistent `+N capacity` readout fading linearly over 4 s. Packet pulses become a per-thread sparkline of the last 32 samples, redrawn at 4 Hz. **Stagger is retained** (clamped ≤50 ms) because arrival *order* is information, and deleting it would delete truth.

## 12. Performance

400 springs × 3 floats × 120 Hz ≈ 576k float ops/sec — free. Canvas: one offscreen buffer, dpr capped at 2, threads batched into 4 stroke calls by luminance tier. Text is DOM, never canvas, and only `color`/`opacity` mutate — compositor-only, no layout, no repaint. TUI: 30 fps cap, cell-granular damage-rect diff, one `write()` per frame, SGR emitted only on tier change with luminance quantized to 24 steps per hue (≈1.2 KB/frame typical, 11 KB worst-case full redraw at 120×40). Above 400 elements, cull by capacity rank into an **understory** — a braille noise field whose density equals the summed capacity of the culled. Nothing is deleted; it merges into the substrate.

## Growth moments

### A lone spore breathes in the dark at N=1 — inhale, long listening hold, slow exhale
- **bound to:** beacon.sentAt and beacon.intervalMs = min(1200 · 1.35^failedRounds, 8000) ms; exhale brightness from substrate.writesSinceBeacon
- **technique:** Radius setpoint toggled by real beacon events, filtered by springs. INHALE target 1.0 on beacon send; HOLD pinned while the listen window is open; EXHALE target 0.22 + 0.5·clamp(writesSinceBeacon/8,0,1) at window close. Rendered as a braille 2x4 radial disc. Never reaches 0 — the spore is alive, not idle.
- **timing:** Inhale REACH k=190 c=20 m=1 (ζ=0.726, 3.6% overshoot, 420 ms settle). Hold = intervalMs − 420 ms, so 780 ms at full rate and 7580 ms after backoff — the loneliness IS the retry schedule lengthening. Exhale WITHER k=42 c=18.1 (ζ=1.397, ~1.1 s). Stall: if the beacon thread hangs, the disc holds its exact radius indefinitely; nothing keeps moving. Reverse is not possible (interval is monotone under failure) but a successful reply collapses the interval to 1200 ms and the breathing visibly quickens within one cycle.

### Six transport stubs around the lone spore show which senses are open
- **bound to:** transport[t].readiness, 0..1 from each driver's link-layer init (BLE adv, LAN broadcast, USB-OTG, audio modem, QR, LoRa)
- **technique:** Stub length = readiness × 4 braille subpixels, drawn radially at fixed quadrant angles. A transport that fails to init renders NO stub — absence is the signal. When a beacon reply arrives, the stub on that specific transport is the one that becomes the reaching hypha, so direction carries information.
- **timing:** SETTLE k=180 c=26.8 (ζ=0.999, 432 ms, zero overshoot) — hardware readiness should not bounce. Polled at 250 ms. Stall: length freezes. Reverse (a radio dropping): WITHER k=42 c=18.1, ~1.1 s retraction, so losing a sense reads as heavier than gaining one.

### Anticipation — the breathing stub freezes mid-exhale the instant an unverified reply lands
- **bound to:** message.verifyLatencyMs (3–18 ms typical), floored to one frame
- **technique:** Setpoint is not changed; the integrator for that stub is paused. Total stillness, no fade, no pre-flash. The pause ends exactly when signature verification returns.
- **timing:** Duration is the real verification wait, floor 16 ms (1 frame), no ceiling. Stall: if verification blocks, the stillness extends — correctly, because the app genuinely does not yet know if this is a peer. Reverse (signature fails): the stub resumes its interrupted exhale from the exact phase it paused at, WITHER ζ=1.397 — a held breath let out.

### A hypha reaches across the void toward a discovered peer
- **bound to:** handshake.progress = (stage + stageByteFrac)/6 over the 7-state machine (IDLE→HELLO_SENT→HELLO_ACK→E_SENT→EE→SS→OPEN)
- **technique:** Tip position p∈[0,1] along a quadratic bezier from self to the peer's graph slot, setpoint = handshake.progress. Braille 2x4 subpixel rasterization via Bresenham-on-quadratic. Tip cell sparkles 3 frames at #EAFBFF; trail luminance falls as exp(−d/6) cells behind the tip.
- **timing:** REACH k=190 c=20 m=1, ζ=0.726 — 3.6% overshoot at each stage boundary gives six small eager taps as the handshake climbs, which is the motion signature of negotiation. Stall: tip stops at exactly stage/6 (0.5 at stage 3) and holds there indefinitely, trembling only on the shared breath layer. Reverse (handshake failure resets progress to 0): switches to WITHER k=42 c=18.1, ζ=1.397 — the reach retracts over ~1.1 s, 2.6× slower than it advanced.

### A peer node germinates and swells to the size of what it contributes
- **bound to:** spore.capacityUnits declared by that peer (enzymes completed/sec × cores), sampled at 1 s
- **technique:** Node does not exist until handshake.progress ≥ 1/6. It appears as a literal '·' and stays a dot until capacity is announced — an unknown contributor is drawn as a seed, not a placeholder circle. Radius = sqrt(capacityUnits) normalized to mesh max, so area reads as capacity.
- **timing:** REACH k=190 c=20 on growth (420 ms, 3.6% overshoot — the settle tap that makes a peer feel like it landed with weight). Stall: a peer that stops reporting holds its last radius. Reverse (capacity drops because the peer is throttling or backgrounded): WITHER k=42 c=18.1, ~1.1 s. A peer shrinking is visibly sadder than a peer growing, by construction.

### Threads pull taut under load and sag when idle
- **bound to:** hypha.bytesPerSec, EWMA α=0.18 over 250 ms ticks, normalized as B = log1p(bps/512)/log1p(262144/512)
- **technique:** Bezier control point = midpoint + perpendicular · sag, where sag = 0.18 · len · (1 − B). Physical rope metaphor with no physics sim. Simultaneously drives the 4-tier luminance quantization used to batch canvas stroke calls. This is the cheapest true signal in the design: mesh tension IS mesh load, readable at a glance with every label off.
- **timing:** SETTLE k=180 c=26.8, ζ=0.999 — zero overshoot, because a bouncing rope would read as instability that isn't there. Symmetric in both directions here (this is the one exception to the asymmetry law: throughput genuinely oscillates, and asymmetric filtering would lie about it). Stall: EWMA decays toward 0 naturally as ticks arrive with no bytes, so the thread sags on its own — correct.

### BLOOM — the app darkens, holds, then ignites when three peers land at once
- **bound to:** mesh.dCapacity/capacityPrev ≥ 0.40 AND ≥2 hyphae reaching OPEN within the same 1 s telemetry window
- **technique:** Beat 1: global luminance multiplier → 0.72, breath paused at current phase. Beat 2: BLOOM spring on global scale, target = clamp(capacityTotal/capacityPrev, 1, 1.6). Beat 3: BFS luminance wave, gaussian σ=2.5 cells, +0.55 additive peak. Beat 5: multiplier → 1.0, breath resumes at the paused phase.
- **timing:** Beat 1 duration is the real gap to the next 1 s capacity tick — 0 to 1000 ms, never chosen. Beat 2 BLOOM k=320 c=16 m=1, ζ=0.447, 20.8% overshoot, 720 ms settle; overshoot ratio is fixed by ζ but the target is the measured ratio, so 4.1× and 1.15× land visibly differently. Beat 3 per-hop delay = that hop's measured rttMs, not a constant. Beat 5 SETTLE, 432 ms. Stall: if the capacity tick never arrives the app simply stays at 0.72 — dark and waiting, which is honest. Reverse (a peer drops before ignition and the threshold is no longer met): the multiplier returns to 1.0 via WITHER over 1.1 s and no bloom fires — a swelling that deflates.

### Peers arriving together stagger by the actual order they arrived in
- **bound to:** handshake openedAt timestamps per peer
- **technique:** stagger_i = clamp(openedAt_i − openedAt_0, 40, 200) ms. Applied to node germination, fruiting glyph opens, and the bloom wave seeds. Never a constant interval.
- **timing:** Three peers completing within 12 ms of each other produce a near-unison chord at the 40 ms floor — correct, because that is what happened. Three peers trickling over 600 ms produce a 200 ms-clamped cascade. Stall: a peer that never opens is simply not in the sequence. Under reduced motion the stagger is retained but clamped to ≤50 ms, because arrival ORDER is information and deleting it would delete truth.

### A fruiting blooms open as its history genuinely syncs
- **bound to:** substrate.syncRatio[f] = verified/announced for that fruiting
- **technique:** Glyph ladder ▪ → ▴ → ▵ → ✦, index = floor(syncRatio · 3.99). Discrete because sync state is discrete; the spring drives an underlying continuous value and the glyph is sampled from it, so the ladder can hold between steps rather than flickering at a boundary (hysteresis of 0.04 on each threshold).
- **timing:** SETTLE k=180 c=26.8, 432 ms. Stall: glyph holds at whatever rung the ratio reached — a half-synced fruiting reads as a half-open bud indefinitely, which is the truth. Reverse (entries fail verification and the ratio drops): WITHER k=42 c=18.1, ~1.1 s, and the glyph closes back down the ladder. Channels can un-bloom.

### History fills in as a colonizing front rather than a progress bar
- **bound to:** substrate.frontIndex[f], the highest CONTIGUOUS verified sequence number
- **technique:** Left gutter column of ▏▎▍▌▋▊▉█; cell i fill = clamp((frontIndex − i·perRow)/perRow, 0, 1). Rows ahead of the front render as '·' placeholders at #0A3A42 (1.64:1, pure texture) so the colony's extent is visible before its content. An entry verified beyond the front does NOT advance it — it lights as an isolated island at 0.4 luminance until the front absorbs it.
- **timing:** SETTLE k=180 c=26.8, 432 ms. Island merge is the one permitted 1-frame flash (an acknowledgment receipt, not growth). Stall: front holds, islands keep appearing ahead of it — you watch gap-filling happen. Reverse: on fork detection frontIndex genuinely decreases and the front RETRACTS via WITHER over 1.1 s. A progress bar structurally cannot do this; that is the argument for the front.

### A message germinates from unverified to trusted without moving a pixel of text
- **bound to:** message.verifyLatencyMs, and msg.state RECEIVED → VERIFIED → SETTLED
- **technique:** Brightness-only interpolation of the text color from #4C5C61 (2.92:1 — deliberately below AA, because unverified content should not be comfortably readable; a security affordance wearing motion's clothes) to #C8D8DC (13.87:1). DOM text, only the `color` property mutates — compositor-only, no layout, no repaint. Zero displacement. This is the legibility firewall.
- **timing:** Duration = real verifyLatencyMs, floored to 1 frame (16 ms) and ceilinged at 250 ms, RM-INSTANT-style linear ramp rather than a spring (overshooting text color would mean momentarily over-bright text). Max 3 rows animating at once; older rows freeze at final value. Stall: text stays at the unverified color and stays uncomfortable to read — correct and deliberate. Reverse (signature fails): drops to #4C5C61 and the gutter rune goes rust.

### A hypha withers when a peer dies mid-transfer, leaving orphaned bytes and a scar
- **bound to:** w = clamp(hypha.heartbeatAgeMs / hypha.timeoutMs, 0, 1), where timeoutMs = clamp(4·rttEwma + 750, 1500, 9000); plus hypha.inflightBytes
- **technique:** w≤0.35: nothing (jitter is normal, do not cry wolf). 0.35<w≤0.75: saturation × (1 − smoothstep(0.35,0.75,w)), hue toward rust #8A5A3C — colour warns before motion does, so the eye catches it without being yanked. 0.75<w<1: subpixel dithering, each braille subpixel dropped with probability (w−0.75)/0.25, deterministically seeded by hash(peerId, cellIndex) so the lace pattern does not shimmer. w≥1: node radius → 0, thread retracts tip-first, a 0.22-length scar persists at the anchor for the session. Orphaned in-flight bytes stop where they are on the thread and pulse at 0.5 Hz in amber #FFB454 until reassigned or expired.
- **timing:** All decay on WITHER k=42 c=18.1 m=1, ζ=1.397 — ~1.1 s, the slowest motion in the app and 2.6× slower than any reach. No snap at w≥1. Stall: w only ever rises while frames are absent, so a stalled peer visibly and continuously decays — this is the one place where stall IS the animation. Reverse (a heartbeat finally arrives): w collapses to 0 and the thread re-saturates on REACH in 420 ms, a visible gasp of recovery. Reconnection launches the new REACH from the scar, 0.22 ahead, so it lands visibly faster than first contact — true, because session resumption skips two handshake stages.

## Palette

All ratios computed via WCAG relative luminance against substrate black #050508 (verified with a script, not estimated).

SUBSTRATE / GROUND
- substrate #050508 — the void, 1.00:1 by definition
- gutter #0B0B12 — panel ground, 1.04:1

CYAN = SELF, CAPACITY, HEALTH
- cyan-live #00E5FF — 13.23:1 — active hypha at full throughput, tip sparkle base
- cyan-strong #00C2D9 — 9.42:1 — hypha at mid throughput
- cyan-text #1A8A9C — 5.00:1 — PASSES AA; the dim tier permitted to carry text (peer names, timestamps)
- cyan-thread #12626F — 2.91:1 — idle thread, decorative only, never text
- cyan-ghost #0A3A42 — 1.64:1 — unfetched row placeholders, understory noise. Texture, not content.

MAGENTA = OTHER, TRAFFIC, THE INBOUND
- magenta-hot #FF3DD8 — 6.70:1 — PASSES AA; packet pulses inbound, unread markers
- magenta-text #E05CC4 — 6.30:1 — PASSES AA; peer-authored emphasis
- magenta-mid #C42CA6 — 4.13:1 — pulse trail, decorative only
- magenta-dim #6E2260 — 2.00:1 — spent pulse residue

TEXT
- text-body #C8D8DC — 13.87:1 — verified message content
- text-mute #9AAFB5 — 8.89:1 — metadata, still comfortably AA
- text-unverified #4C5C61 — 2.92:1 — DELIBERATELY BELOW AA. Unverified content must not be comfortably readable; this is a security affordance, and the germination animation is the act of earning legibility.

STATE
- amber-warn #FFB454 — 11.54:1 — orphaned in-flight bytes, stalled enzymes
- wither-rust #8A5A3C — 3.50:1 — decay hue target, never carries text
- bloom-white #EAFBFF — 19.14:1 — tip sparkle, glint sweep, island-merge flash

Build-time assertion: every color in the text-bearing set must compute ≥4.5:1 vs #050508, with text-unverified as the single explicitly annotated exemption. Decorative tiers are exempt but are forbidden from ever being assigned to a text node.

## TUI feasibility

PURE-ANSI NATIVE (no dependencies, Node + escape codes only):

- Braille U+2800–U+28FF gives 2×4 subpixels per cell, so a 120×40 terminal is a 240×160 subpixel canvas. All hyphae, the breathing disc, transport stubs, the withering dither and the understory noise field rasterize into this directly. Bresenham-on-quadratic walks the bezier; each subpixel sets a bit in the cell's 8-bit braille mask.
- 24-bit colour via ESC[38;2;r;g;bm — the entire palette renders exactly, including the smooth cyan→rust wither hue rotation.
- Block elements ▏▎▍▌▋▊▉█ for the horizontal colonizing front; ▁▂▃▄▅▆▇█ for vertical capacity bars. Eighth-granularity is enough that the front reads as continuous fill.
- Box drawing for panel chrome. Glyph ladders (·◦✳ / ▪▴▵✦) are plain Unicode.
- The entire spring integrator is identical code — fixed dt=1/120 s means TUI and canvas produce bit-comparable motion. This is the reason for fixed-step.
- The wither subpixel dither is arguably BETTER in the TUI than on canvas: braille lace is a texture canvas has to fake.

DEGRADED-BUT-WORKING IN TUI:
- The BLOOM gaussian wave quantizes to 6 luminance steps instead of continuous. Still reads clearly as a ripple crossing the graph; it just has visible banding, which suits the demoscene register.
- Additive blending is unavailable, so overlapping pulses composite with max() instead of add(). Pulses are slightly flatter where they cross. Acceptable.
- Thread sag beziers are chunkier at 2×4 resolution, especially for short threads under ~6 cells. Threads below 4 cells render as straight runs.

BROWSER-CANVAS-ONLY:
- True additive blending for pulse crossings and the bloom wave peak (globalCompositeOperation = 'lighter').
- The 120 ms glint sweep's smooth gradient — TUI substitutes a 3-cell bright run travelling the thread, which works but is coarser.
- Sub-pixel antialiased hypha tips and >6-step gaussian falloff.
- devicePixelRatio-2 crispness and the 4-batched-stroke-call optimization.
- The text layer as DOM with compositor-only color/opacity transitions; the TUI instead re-emits the cell with a new SGR, which is why TUI germination quantizes to 24 luminance steps per hue.

TUI FRAME BUDGET: 30 fps cap with cell-granular damage-rect diffing, one write() per frame using cursor-jump escapes, SGR emitted only when the colour tier changes. Luminance quantized to 24 steps per hue keeps escape-sequence churn bounded: ≈1.2 KB/frame typical after diffing, ≈11 KB worst case on a full 120×40 redraw. 60 fps is a browser-path guarantee only; the TUI's 30 fps is honest and the fixed-step integrator means the motion curves are identical, just sampled half as often.

## Failure mode

The springs quietly become timers, and nobody notices.

A spring filter is externally indistinguishable from a tween. The moment someone ships a setpoint fed by a ramp — a `setTimeout` that walks 0→1 while "waiting for the real value", a fake syncRatio during a demo, a handshake progress that increments on a schedule rather than on stage transitions — the whole principle is dead and the app looks exactly the same. The tell is specific: **it looks great with no peers connected.** If a bloom fires in a demo where nothing is actually blooming, the rot is already in.

Two mitigations, both cheap and both necessary. First, a `--truth` dev overlay that prints every animated property alongside the *source* of its setpoint, rendering any clock-derived setpoint in amber — so the failure is visible rather than invisible. Second, a mandatory stall test per effect: kill the peer mid-handshake, and the motion must stop at exactly stage/6 and stay there. Any effect that keeps gliding to completion after its data source dies is a timer wearing a spring costume, and it does not ship.

The second failure is the honest cost of the principle, and it lands hardest on the moment this direction cares most about. At N=1, after six failed discovery rounds, the beacon interval backs off to 8000 ms, so the app is one glyph, breathing, with a 7.6-second hold between breaths. That is beautiful if you know what you are looking at and indistinguishable from a frozen process if you don't. A first-run user on a phone with no peers in range may reasonably conclude the app has hung and quit inside thirty seconds. The exhale-brightness-from-local-writes binding is a partial answer — it rewards you for typing — but it only helps someone who already tried to use it. I do not have a fix for this that does not involve adding a reassuring animation unbound to any real quantity, which is precisely the thing the brief forbids. Binding to truth means accepting that the truth, at N=1, is sometimes that nothing is happening.
