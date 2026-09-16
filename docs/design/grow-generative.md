# TROPISM

> The interface is not drawn, it is the current state of a nutrient field, a force-directed mycelium, and a particle population that have been running since the process started. Nothing in SPORE plays an animation — events perturb the parameters of that running simulation, and growth is what the perturbation looks like as the physics resolves it. It never looks the same twice because the substrate log, the RTTs, and the byte rates that drive it are never the same twice.

# TROPISM — the generative-systems direction for SPORE

RULE: events do not play animations. Events perturb the parameters of a simulation that is already running. Growth is what the perturbation looks like as the physics resolves it.

## 1. THE FIELD (nutrient lattice)

64x36 logical cells, viewport-independent, bilinear sample. Three Float32Array(2304): N, N_swap, plus Gx,Gy. Runs at 30 Hz (every 2nd sim tick). Per field step:

- **diffuse**: explicit 5-point Jacobi, `N' = N + D*(Nn+Ns+Ne+Nw-4N)`, D = 0.20 **dimensionless per step**. 2-D explicit stability requires D <= 0.25; 0.20 gives spread `sqrt(2*D*rate)` = 3.46 cells/s, which is visible. Neumann (mirrored) edges.
- **decay**: `N *= 0.978` per step -> half-life `ln2 / -ln(0.978)` = 31 steps = 1.04 s. The field is a one-second memory of traffic.
- **deposit**: per peer, bilinear splat of `rxBytesDelta/4096` at its node; local append splats `framesVerifiedDelta*0.08`; each fruiting anchor holds a standing source of `+0.02*min(unread,12)` per step. Cell clamp 1.6.
- **gradient**: central differences into Gx,Gy, cached once per field step.

Cost ~1.9 MFLOP/s. The field is a heat map of where bytes are actually arriving; nothing else feeds it.

## 2. THE GRAPH

**Integrator: semi-implicit (symplectic) Euler, not Verlet.** Verlet stores velocity implicitly as `(x - x_prev)`, so every position injection (viewport resize, node pin, rehydration) becomes a spurious velocity impulse. Semi-implicit Euler keeps x and v separate: a teleport is inert. dt = 1/60 s fixed, accumulator, max 3 substeps per frame, accumulator clamped at 50 ms.

```
v += (F/m)*dt ;  v *= exp(-c*dt), c = 4.0 /s (0.9355/tick, dt-independent) ;  x += v*dt
```

Units: cells, seconds, dimensionless mass.

**Forces**
- hypha spring: `F = k(hs)*(d - L0)*dhat`, `k(hs) = 0.9 * L(hs)`, `L0 = clamp(5 + 0.40*rttEma_ms, 5, 54)` cells. A laggy peer literally sits further out. A half-open handshake is a weak spring.
- repulsion: `F = k_rep*mi*mj/(d^2+eps^2)`, k_rep = 34, eps = 2.0 cells, per-pair cap 180. Spatial hash, cell size 12, 3x3 neighbourhood -> O(N*6).
- mass: `m = 0.55 + 1.45*capShare`, `capShare = peer.enzymeBytesOut / sum over peers` over a 4 s window. Node size IS capacity contributed, and a big contributor physically pushes others away.
- centering: `F = -0.012*(x - mass centroid)`.
- tropism: `F += 3.2 * gradN(x)`. Chemotaxis — a fed node drifts toward the traffic feeding it.
- soft wall: beyond a 2-cell margin, `F += -4.0*overshoot^2`.

Velocity clamp `|v| <= 24` cells/s.

**Stability**: k_max = 0.9, m_min = 0.55 -> omega = 1.28 rad/s; explicit spring integration needs `omega*dt < 2` -> dt < 1.56 s. 94x margin. The genuine hazard is the repulsion singularity, bounded by eps^2 and the 180 cap: worst |a| = 327 cells/s^2 = dv 5.45 per tick, under the 24 clamp. No blow-up is reachable at any k the design admits.

**Spawn**: first sight places a peer on the boundary ring `r = 0.48*min(W,H)` at `theta = (fnv1a(peerId) mod 3600)/3600 * 2pi`. Deterministic, so a given peer always arrives from the same bearing — a real identity cue, not randomness. k = 0 at hs = 0, so it hangs there until the handshake actually begins.

**Wither**: `V = clamp(1 - (staleness_ms - 1500)/(sessionTimeout - 1500), 0, 1)`. `k *= V`, `m = 0.55 + 1.45*capShare*V`. Cull only on a real session CLOSED event, never on a timer.

## 3. PARTICLES

SoA Float32Arrays, pooled, Int32 free-list, zero allocation in the loop. Fields x, y, u, hyphaIdx, kind, frameId.

**Traversal**: Poisson emission per hypha, `lambda = byteRate/512` (one particle = 512 real bytes), capped at 30/s with the excess folded into brightness rather than dropped.

**Travel time is the bound quantity**: `t_cross = max(120 ms, rttEma_ms/2)`, `du/dt = 1/t_cross`. A particle takes as long to cross as a byte actually does. Then wire density = `lambda * t_cross = (bytes/s / 512)*(rtt/2)`, which *is* inflight bytes. A congested hypha is visibly packed with slow particles; a LAN hypha is sparse and quick. Cross-checked against `PeerSample.inflight`; divergence over 25% recalibrates the emitter. (Binding speed *and* rate to throughput would have cancelled out and congestion would never read.)

**Path**: quadratic Bezier, control point offset perpendicular by `0.18*d*sign(hash)`, scaled by `(1 - 0.6*strain)` with `strain = (d - L0)/L0`, and by `(1 - hs)`. An incomplete hypha is slack; a loaded one is taut. Sag is real spring tension, not styling.

**Free motes**: emitted only by facts (unread message, pending enzyme). Advected by `v = 2.4*gradN + 0.6*(toward anchor)`. They die when the fact ends (message read, enzyme returns), never on a lifetime timer. An unread count is literally a cloud.

Cap 1200 desktop / 420 phone.

## 4. DEPOSITS AND THE DAG MARGIN

Layout is reserved at frame-parse and **never reflows**. Growth happens in the ink, not the geometry. That is the legibility guarantee that lets everything else be alive.

Turgor `tau` per message, 0..1, driven by real milestones: parsed (layout reserved, no glyphs) -> sigVerified (0.35) -> appended+fsynced (0.62) -> acks (`0.62 + 0.38*acks/knownPeers`). Per-character reveal is used only for frames larger than one MTU and for attachments, where chunk arrival order genuinely exists.

Transport: closed-form critically damped spring, omega = 11 rad/s.

```
dx = x0 - target ; c1 = dx ; c2 = v0 + omega*dx ; E = exp(-omega*dt)
x1 = target + (c1 + c2*dt)*E
v1 = (c2 - omega*(c1 + c2*dt))*E
```

Unconditionally stable at any dt, zero overshoot. `t95 = 4.744/omega` = 431 ms.

Ink: oklch `L = 0.595 + 0.325*tau`, C 0.022 -> 0.015, h 222 -> 200. **Runtime contrast clamp**: per text row the renderer computes the composited background relative luminance and raises L until contrast ratio >= 4.5. Never below, at any turgor.

**Germination coupling**: the traversal particle carrying that frame's bytes is tagged with frameId. Glyphs are not drawn until *that particle lands* on the local spore. A message arrives along the hypha you watched it travel — the two simulations are one.

**Mycelial margin**: 2 columns (TUI) / 18 px (canvas). Draws the real parent-link DAG of the substrate log — each message a node, edges to causal parents. A fork in the log is a visible fork in the margin; a merge is a visible anastomosis. The ornament is the machinery.

**Colonizing front**: history backfill draws a boundary at `y = f(backfillLow)`. Above it, field only, no glyphs. The front advances as backfillLow genuinely decreases; if a fork is discovered and backfillLow regresses, the front *recedes* and glyphs de-render. The only place text is ever removed, and it is honest.

## 5. TELEMETRY CONTRACT AND COUPLING

`src/telemetry` emits a frozen sample at 20 Hz on a monotonic clock (`hrtime.bigint` / `performance.now`):

```
PeerSample { id, hsState, hsProgressBytes/hsTotalBytes, rttEma_ms, rxBytesDelta,
             txBytesDelta, inflight, enzymeBytesOut, lastSeenMonotonic, sessionState }
SubstrateSample { headSeq, appliedSeq, wantSeq, framesVerifiedDelta, forkCount }
FruitingSample { id, localHead, remoteHead, backfillLow, backfillHigh, unread }
```

**Coupling rule: hold-last-value.** The sim reads the newest sample and holds it for the 3 ticks until the next. No interpolation of a measured quantity — interpolating truth is fabrication. Smoothness comes from the physics (springs have inertia), never from smoothing the input.

Exactly one EMA exists in the whole system: `rttEma`, `alpha = 1 - exp(-dt/tau)`, tau = 2.0 s, computed in `src/transport` because it is a transport-layer quantity anyway, and labelled `rtt~` in the HUD so the smoothing is disclosed.

Every visual carries a `bind:` string naming its source field. A dev overlay (key `b`) prints the live binding table with current values. An unresolved binding renders U+2298 rather than a plausible default — the design fails loudly rather than lying quietly.

## 6. FRAME BUDGET AND RENDER

Phone 16.6 ms: sim 4.2 (64 nodes, 3 substeps, 420 particles, field at 30 Hz), render 6.5, app 3.0, slack 2.9.

One canvas. Layer order per frame:
1. clear to substrate
2. **nutrient**: 64x36 ImageData upscaled via `drawImage` with `imageSmoothingEnabled` — free bilinear and free glow; `globalAlpha` masked to 0.14 inside text rects
3. **hyphae**: `Path2D` per hypha, cached until an endpoint moves more than 0.5 cells; stroke gradient cached in a Map keyed by 16 quantized throughput buckets
4. **particles**: additive points into a half-resolution Uint32 offscreen, then `drawImage` upscaled — the upscale *is* the bloom; no blur filter anywhere
5. **nodes**: pre-baked sprite atlas, 16 radii x 8 hues, `drawImage` only
6. **DAG margin**: `Path2D` cached, invalidated on log append
7. **text**: DOM layer above the canvas, so glyphs are never composited through the glow

LOD: beyond 64 peers, spatial-hash cells become meta-nodes (mass and capacity summed, hyphae carrying summed throughput). Real aggregation, not culling — the number stays true.

Adaptive controller: rolling median frame time over 30 frames. Above 15.0 ms for 3 windows, degrade in order — particle cap x0.7, field rate 30->20->15 Hz, bloom upscale off. **Never degrade graph substeps**: physics is the truth channel, particles are only a sampling of it. Below 11 ms for 6 windows, restore one step.

## 7. DORMANCY AND REHYDRATION

State is three Float32Arrays plus a small header. On `hidden` / SIGTSTP / TUI focus-out, record `t_hidden` and stop the loop. On resume, `dt = now - t_hidden`:

- dt < 250 ms: normal accumulator catch-up.
- 250 ms to 2 s: up to 8 catch-up substeps (133 ms of sim), discard the rest.
- dt >= 2 s: **do not simulate the gap.** Rehydrate: (a) free every particle — they represented bytes in flight that landed long ago, keeping them would be a lie; (b) `field *= 0.978^min(dt*30, 120)`, the decay that genuinely would have happened, bounded; (c) nodes keep positions, velocities zeroed; (d) apply the newest telemetry sample. Peers that died while hidden already have V = 0 and wither outward from where they were; new peers spawn on the boundary ring and are reeled in. The physics carries the system to the new truth over ~1.2 s with no scripted transition. The mycelium was dormant and now rehydrates.

Node TUI takes the same path on SIGCONT. Resize only re-derives the cell-to-field mapping; because positions are in field units, nothing teleports.

**Solo phone**: with zero peers the sim is field plus substrate. The heartbeat is real — each discovery beacon TX deposits 0.30 nutrient at the local spore and emits 6 motes on the outward radial. An alone phone visibly breathes at exactly the rate it is calling out. Cold start drives the colonizing front from `appliedSeq`/`headSeq` as the local log replays.

## 8. REDUCED MOTION

The simulation keeps running. The renderer switches from **trajectory mode** to **state mode**.

- particles: not drawn as moving points. Occupancy is accumulated into the half-res buffer over a 1.5 s box average and drawn as a static density field. Same data, no motion.
- graph: damping c 4.0 -> 14.0, tropism gain -> 0. Settles in ~0.8 s and moves only when topology really changes.
- nutrient: sampled at 4 Hz, crossfaded over 250 ms — no strobe.
- turgor and bloom: omega 11 -> 18 (t95 = 264 ms), critically damped so overshoot is impossible.
- at most one element in transition at a time; a queue serializes.

Everything still grows. Growth is expressed as a settled quantity that changed rather than as a motion.

## Growth moments

### A hypha reaches toward a newly discovered spore and connects
- **bound to:** PeerSample.hsProgressBytes / hsTotalBytes -> hs in 0..1, and hsState
- **technique:** The node spawns on the boundary ring at theta = (fnv1a(peerId) mod 3600)/3600*2pi with spring constant k = 0.9*L(hs), L(p) = (sig(8(p-0.5)) - sig(-4)) / (sig(4) - sig(-4)), sig(z)=1/(1+e^-z). Separately from the spring, a filament is stroked along the first L(hs) fraction of the quadratic Bezier between the two nodes, with a 3-cell bright tip (additive, hypha_cyan) at the parametric head. The tip's lateral wander is 0.9*gradN sampled at the tip, so it feels its way up the nutrient gradient. Rest length L0 = clamp(5 + 0.40*rttEma_ms, 5, 54), so as the first RTT samples arrive the peer is reeled to its true distance.
- **timing:** No fixed duration: the tip advances exactly as handshake bytes advance, typically 180-900 ms on radio. STALL: if now - lastProgressMonotonic > 400 ms the tip stops dead where it is and its lightness falls oklch L 0.82 -> 0.52 over 600 ms (critically damped, omega = 8); it does not retract, it waits, which is the truth. REVERSE / FAIL: on a handshake failure hs snaps to 0, k -> 0, and the filament retracts head-first at 2.2x the speed it grew (du/dt = -2.2/t_grown) while the node drifts back out under repulsion alone.

### A message germinates as a deposit left by the simulation
- **bound to:** frame parse -> signature verify -> substrate append+fsync -> ack count / knownPeers
- **technique:** Layout is reserved at frame parse and never reflows. The traversal particle carrying that frame's 512-byte quanta is tagged with frameId; glyphs stay undrawn until that particle reaches u=1 at the local spore, so the message visibly lands. Then turgor tau steps through milestone targets 0.35 / 0.62 / 0.62+0.38*r and is transported by the closed-form critically damped spring (omega = 11 rad/s): dx=x0-target, c1=dx, c2=v0+omega*dx, E=exp(-omega*dt), x1=target+(c1+c2*dt)*E, v1=(c2-omega*(c1+c2*dt))*E. tau drives oklch L = 0.595+0.325*tau only — never position, never size. A runtime clamp raises L per row until contrast ratio >= 4.5 against the composited background.
- **timing:** t95 = 4.744/omega = 431 ms per milestone; a fully replicated message reaches full ink in whatever time real quorum takes, often several seconds. STALL: if no ack arrives, tau simply rests at 0.62 — a permanently dimmer message is a permanently under-replicated message, and that is correct. REVERSE: if a peer that acked is later found to have forked, r decreases and tau falls back through the same spring; the message visibly de-inks.

### A fruiting blooms open as its history genuinely syncs
- **bound to:** FruitingSample.backfillLow descending toward 0, and appliedSeq vs headSeq
- **technique:** A colonizing front, not a progress bar. The message column is divided by a horizontal boundary at y = f(backfillLow). Below the front, real glyphs; above it, nutrient field only, rendered through the 64x36 ImageData upscale at globalAlpha 0.30 with no text. The front itself is a 2-row band where per-character turgor is a function of distance above the boundary, tau = clamp(1 - dy/2.5, 0, 1), so glyphs materialize along an irregular advancing edge rather than a straight line — the irregularity comes from the nutrient field's own texture at that row, which is real traffic.
- **timing:** Advance rate is exactly d(backfillLow)/dt; a fast peer fills a thousand messages in under a second, a slow one crawls. STALL: if backfillLow is unchanged for 1.5 s the front's leading band desaturates (chroma 0.14 -> 0.03 over 700 ms, omega = 7) — visibly starved, not frozen. REVERSE: on fork discovery backfillLow can increase; the front recedes at the true rate and glyphs above it de-render. This is the only sanctioned removal of text in the product.

### BLOOM — the observable capacity jump when new spores join
- **bound to:** C = sum over peers of measured enzyme throughput, crossing C > 1.35 * C_ema over a 2 s window with at least one hypha entering ESTABLISHED
- **technique:** No canned animation exists. The event writes new values into the live simulation: field diffusion D 0.20 -> 0.24 per step (still inside the 0.25 explicit-stability bound), field decay 0.978 -> 0.991 (half-life 1.04 s -> 76 s), particle cap +40%, and repulsion k_rep 34 -> 41. The consequence is emergent: nutrient stops being consumed as fast as it arrives, spreads 10% faster, floods outward through the whole lattice, the mycelium physically swells as repulsion wins against unchanged springs, and every hypha brightens because its gradient key moves up a throughput bucket. The entire interface expands because the system genuinely got bigger.
- **timing:** Parameters jump in one tick (16.7 ms) and relax exponentially back to baseline with tau = 420 ms via p(t) = p_base + (p_peak - p_base)*exp(-t/420). The visible swell peaks around 700-900 ms after the jump because that is how long the field takes to diffuse outward at 3.46 cells/s. STALL: if C falls back below the threshold before the ratchet confirms at 2 s, the parameters relax early and the swell simply subsides — a false bloom looks like a breath. REVERSE: a capacity drop (peer left mid-bloom) inverts the same parameters below baseline for the same tau, and the colony contracts.

### Data flowing through a hypha, and congestion becoming visible
- **bound to:** rxBytesDelta / txBytesDelta for emission rate; rttEma_ms for travel time; cross-checked against PeerSample.inflight
- **technique:** Poisson emission at lambda = byteRate/512 (one particle = 512 real bytes), cap 30/s with excess folded into stroke brightness so nothing is silently dropped. Travel time t_cross = max(120 ms, rttEma_ms/2) — a particle takes as long as a byte does. Wire density therefore equals lambda*t_cross = inflight bytes: congestion is packed slow particles, a healthy LAN link is sparse fast ones. Particles are additive points in a half-res Uint32 offscreen, upscaled by drawImage — the upscale is the bloom. Cyan travels toward the local spore (rx), magenta away (tx).
- **timing:** Per-particle transit is 120 ms (floor, local radio) to ~400 ms (typical BLE RTT 800 ms). No easing: particles move at constant du/dt because bytes do. STALL: when byteRate hits zero, emission stops and the in-flight particles finish their journey — the wire empties from the tail, which is exactly what happens to the real link. REVERSE: rttEma climbing makes existing particles finish slower (t_cross is re-read each tick), so the hypha visibly thickens with backed-up traffic before throughput has even changed.

### A peer withers and departs
- **bound to:** now - PeerSample.lastSeenMonotonic against the session-layer timeout; removal on a real sessionState = CLOSED
- **technique:** Vitality V = clamp(1 - (staleness_ms - 1500)/(sessionTimeout - 1500), 0, 1) multiplies both the spring constant and the capacity term of mass. The node is not faded out — it loses its physical hold on the colony: k*V weakens, unopposed repulsion pushes it outward, mass falls toward 0.55 so it stops pushing back, and it drifts to the rim under its own momentum. Its hypha thins as the gradient key drops buckets and its glyph shifts oklch h 195 -> 32 (cyan -> wither #af756a, CR 5.38). Remaining particles on that hypha are not deleted; they complete their transit.
- **timing:** Onset at 1500 ms of silence, full withering at sessionTimeout. Drift speed is emergent (repulsion over mass), typically 8-14 cells/s at the rim. STALL: a peer that goes quiet but is not gone hovers mid-drift at partial V — visibly failing, not gone. REVERSE: a single packet resets lastSeen, V snaps to 1, and the spring yanks the node back in; the recovery is a genuine overshoot because the spring is under-damped at c = 4.0, and that overshoot is the most satisfying thing in the product. It cannot be faked because it is the actual return stroke.

### The solo phone breathes while alone
- **bound to:** discovery beacon TX events from src/transport, at the real beacon interval; appliedSeq / headSeq on cold start
- **technique:** With zero peers there is no graph, so the field and the substrate carry everything. Each real beacon transmit deposits 0.30 nutrient at the local spore and emits 6 free motes on outward radials at 6 cells/s, advected by 2.4*gradN. The nutrient pulse then diffuses at 3.46 cells/s and decays with its 1.04 s half-life, producing a ring that expands and dies. Cold start replays the local log and drives the same colonizing front used for backfill, sourced from appliedSeq climbing toward headSeq.
- **timing:** Period is exactly the beacon interval (nominally 1100 ms), so the phone visibly pulses at the rate it is calling out. There is no free-running oscillator anywhere in the system. STALL: if the radio is off, beacons stop, the field decays to zero within ~4 s, and the screen goes genuinely dark except for text — the app looks asleep because it is. REVERSE: not applicable; an unanswered beacon simply produces a ring with nothing to reach.

### Waking from dormancy — the mycelium rehydrates
- **bound to:** monotonic dt since backgrounding, plus the first fresh telemetry sample after resume
- **technique:** For dt >= 2 s the gap is never simulated. Particles are freed wholesale (they stood for bytes that landed long ago). The field is multiplied by 0.978^min(dt*30, 120) — the decay that genuinely would have occurred, bounded at 4 s of decay. Node positions are kept, velocities zeroed. The newest telemetry sample is then applied as targets and the ordinary physics takes over: peers that died while hidden already have V = 0 and wither outward, survivors are pulled to their new L0 by springs, and newcomers spawn on the boundary ring at their identity bearing.
- **timing:** Settling is emergent, typically ~1.2 s to visual rest, governed by damping c = 4.0 (e-fold 250 ms) and the spring omegas. No scripted transition, no fade-in, no duration constant anywhere in this path. STALL: if no telemetry sample arrives after resume (radio still off) the colony stays in its withered dormant configuration rather than snapping to an empty state. REVERSE: if resume reveals the mesh shrank, the same physics contracts the colony; the wake and the collapse are the same code.

## Palette

All values computed in oklch and converted to sRGB; contrast ratios are WCAG 2.1 against the substrate (#04060d) unless stated. Semantic roles are fixed and never decorative.

SUBSTRATE
- substrate `oklch(0.125 0.018 264)` = #04060d — the ground, the unfed lattice. Reference for all CRs.
- substrate_hi `oklch(0.175 0.022 264)` = #0c101a, CR 1.07 — panel separation only, carries no meaning.

DIRECTIONAL SIGNAL (the cyan/magenta axis is semantic, not styling)
- hypha_cyan `oklch(0.820 0.140 195)` = #00e0e0, CR 12.23 — RX. Bytes travelling toward the local spore. Every cyan particle is data arriving.
- hypha_mag `oklch(0.740 0.190 330)` = #eb78e3, CR 8.03 — TX. Bytes leaving. Every magenta particle is data this device is contributing.
A hypha that is bidirectional carries both populations on the same Bezier, so reciprocity is literally visible as counterflow.

NUTRIENT FIELD (background only, never carries text)
- nutrient_lo `oklch(0.240 0.050 175)` = #00271e, CR 1.26
- nutrient_cap `oklch(0.330 0.070 180)` = #004137, CR 1.73 — the hard ceiling for field brightness anywhere. Inside text rectangles the field is composited at alpha 0.14, giving #031818, CR 1.10 against substrate. That mask is what makes the rest of the palette safe.

TEXT (the non-negotiable layer)
- text_body `oklch(0.920 0.015 200)` = #dae8e8 — CR 16.04 on substrate, CR 13.81 over the worst unmasked field, CR 14.2 over the masked field. Fully replicated messages.
- text_dim `oklch(0.660 0.020 220)` = #85959b — CR 6.54 on substrate, 5.78 over masked field. Metadata, timestamps, peer ids.
- text_ghost `oklch(0.595 0.022 222)` = #718288 — CR 5.06 on substrate, **4.58 over the masked field**, solved numerically for the >= 4.5 floor. This is the dimmest ink the product can ever produce, and it is the turgor floor for an unconfirmed message. Turgor interpolates L from 0.595 to 0.920 and nothing below.
- Runtime guarantee: the renderer computes the composited background relative luminance per text row each frame and raises L until CR >= 4.5. The accessibility floor is enforced by code, not by a designer's promise, because the background is generative and cannot be checked ahead of time.

STATE
- amber_warn `oklch(0.800 0.150 75)` = #f5ae39, CR 10.60 — fork detected, quorum lost, backfill regressing.
- wither `oklch(0.620 0.075 32)` = #af756a, CR 5.38 — a departing spore and its dying hypha. Readable as text if a withered message must be shown.
- bloom_white `oklch(0.980 0.045 180)` = #d9fff9, CR 18.89 — reserved exclusively for the BLOOM parameter jump and the hyphal growth tip. Nothing else in the product is allowed this brightness, so when it appears it means capacity genuinely increased.

Chroma is deliberately low on every text colour (<= 0.022) and high only on signal colours, so the readable layer and the machinery layer never compete. Total ink budget: no more than 12% of pixels above CR 8 at any instant, enforced by the particle cap.

## TUI feasibility

The TUI is not a downgrade, it is a different sampling of the same simulation. The simulation is identical in both paths — same integrator, same constants, same telemetry. Only the rasterizer differs.

WHAT IS FULLY TUI-NATIVE

1. **The nutrient field, as background colour.** Each cell gets a 24-bit background via `ESC[48;2;R;G;Bm`, sampled from the 64x36 lattice with bilinear interpolation to terminal cell coords. This is the single highest-value effect and it is free — one SGR per changed cell. The alpha-0.14 text mask is applied by lerping toward substrate in linear light before emitting, identically to the canvas path, so the contrast guarantee holds byte-for-byte.

2. **Hyphae and particles, as braille.** `U+2800..U+28FF` gives a 2x4 subpixel grid per cell. Terminal cells are roughly 1:2 (w:h), so a 2x4 braille grid lands at approximately 1:1 per subpixel — the aspect works out almost exactly right, which is why braille beats sextants (`U+1FB00`) here despite sextants' 2x3 being better covered in some fonts. Effective resolution in an 80x24 terminal is 160x96 subpixels, which is enough to draw the Bezier hyphae with visible curvature and to place particles individually. Constraint: **one foreground colour per cell.** Resolution: per cell, accumulate particle contributions in linear RGB, emit the luminance-weighted mean as the cell fg, and let the dot pattern carry the spatial detail. Counterflow (cyan rx vs magenta tx in the same cell) resolves to the direction with more bytes in that cell this frame — which is itself true information.

3. **Node glyphs.** `◦` idle spore, `◉` bearing load, `✱` fruiting anchor, `⬢` relay, `☓` withering. Radius-as-capacity is expressed by glyph rank plus fg lightness, since cells cannot scale. A 24-bit fg ramp over the 8 capacity buckets is ample.

4. **Message turgor.** 24-bit colour gives far more than the 8 usable lightness steps I worried about — the oklch L 0.595..0.920 ramp quantizes cleanly to 24 perceptually-even steps via `ESC[38;2;...`, which is smoother than the eye resolves at text size. Turgor is fully native.

5. **The DAG margin.** 2 columns of `╭ ╮ ╰ ╯ │ ├ ┤ ┬ ┴ ─` box-drawing with `┄ ┈` for unverified links. Forks and anastomoses render better in the TUI than in canvas, because box-drawing junctions are unambiguous.

6. **60 fps in a terminal**, via damage tracking: keep a shadow buffer of `(glyph, fg, bg)` per cell; each frame diff and emit only changed cells, coalescing runs so cursor positioning (`ESC[row;colH`) is emitted only at discontinuities and SGR only when the colour pair actually changes. A typical frame touches 8-15% of cells, roughly 4-9 KB of escape output at 30 fps. TUI is capped at 30 fps (60 fps of escape output saturates most terminal emulators' parsers before it saturates the CPU); the simulation still steps at 60 Hz and the renderer samples it.

LAYOUT (the TUI has no "behind" — layering does not exist in cells, so panes replace z-order)
- Right 34 columns (or a top strip when width < 100): the mycelium pane — field bg + braille hyphae/particles + node glyphs. This is the only region where the graph draws.
- Centre: messages. Field renders here as background colour only, masked; braille never intrudes on a cell containing a glyph.
- Left 2 columns: the DAG margin.
- Bottom row: HUD with the disclosed `rtt~`, peer count, and live capacity C.
The browser's true overlay — graph breathing *behind* the message list — is the one composition the TUI genuinely cannot reproduce. The pane split is the honest substitute, not an apology for one.

WHAT NEEDS THE CANVAS PATH
- Additive bloom via half-res upscale. TUI substitutes a 3-step fg lightness ramp plus `░▒▓` dithering on the cell below a bright particle.
- Sub-cell smooth motion of text ink (canvas can subpixel-shift; cells cannot).
- Particle trails (previous-position streaks) — braille can show position but not a 2-3 px tail.
- The graph drawn genuinely underneath live text.
- Monochrome fallback (`NO_COLOR`, dumb terminals): density ramp `` .:-=+*#%@`` for the field, braille only for hyphae, turgor expressed as ` ⋅∙●` marks in the gutter rather than as ink lightness.
- Reduced motion in the TUI is honoured via `SPORE_MOTION=calm` and by respecting `NO_COLOR`; it takes the same state-mode renderer path.

## Failure mode

Three, in order of how likely they are to actually kill it.

**1. Real telemetry is bursty and quantized, and the fix for that is the thing that severs the binding.** Byte counters arrive in lumps, RTT samples are sparse, and handshake progress is four discrete states pretending to be a 0..1 continuum. Bound literally, hyphae twitch and nodes jitter — it reads as random, not alive. The obvious remedy is to EMA everything, at which point the "growth is bound to truth" claim quietly becomes "growth is bound to a smoothed reconstruction of truth," and the whole principle is gone. My defence is structural — hold-last-value, exactly one disclosed EMA, and smoothness supplied by mass and springs rather than by filtering the input — but it is a defence, not a solution. The honest failure is that under real radio conditions this design needs a second or third EMA to be watchable, and each one is a small lie. If that happens, the right move is to disclose them in the binding overlay and accept a less smooth product, not to add them silently.

**2. A real mesh is idle almost all the time, so the simulation mostly looks dead — and the demo will lie about this.** Four peers on a phone at 2 KB/s produce maybe three particles per second across the entire graph. A demo with synthetic traffic will look extraordinary and the shipped product will look like a dark screen with some text on it. I have given the solo case a genuine heartbeat (beacon TX) and the field a 1-second memory so bursts linger, but I cannot manufacture activity without breaking the rule. The correct response if this bites is to change what is measured — surface substrate verification work, enzyme scheduling, and beacon cadence as first-class nutrient sources, since those are real and continuous — rather than to add ambient motion. The wrong response, which is also the tempting one, is a slow idle drift "just so it breathes."

**3. A perpetually-moving background behind body text is exhausting, and people will turn it off.** Damping c = 4.0 gives a 250 ms e-fold, so the graph does settle, and the layout-never-reflows rule protects reading. But the nutrient field pulses under every text row on every message, and forty minutes of that is a headache even at CR 4.5. If usage data shows the motion toggle getting flipped on first run, the design has failed on its own terms — it optimized for the first ten seconds. The mitigation I would reach for first is making state mode the default on small screens and trajectory mode the thing you opt into, which is close to admitting the browser version is a demo and the TUI is the product.

Minor but real: the frame budget assumes 64 peers, and 4.2 ms of sim is measured in my head, not on a device. If a mid-range Android's JIT never warms the particle inner loop, the adaptive controller will sit permanently in its most degraded state and nobody will ever see the design as specified.
