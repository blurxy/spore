# MYCELIUM/1 — The Honest Oscillator

> A text grid where nothing moves unless a number moved. There is not one `sin(t)` and not one `setTimeout` driving a visual anywhere: every animated quantity is a display value asymptotically chasing a measured value, so a stalled handshake shows a half-grown hypha frozen indefinitely and a dying peer withers one glyph per missed keepalive. Growth reads as alive precisely because it is unreliable — it hesitates, stalls, backs up, and fills in patchily, the way colonization does and no timer ever would.

# MYCELIUM/1 — a text grid that grows

## 0. The one law: zero free-running oscillators

There is not a single `sin(t)` in this design. No `setTimeout` drives a visual. Every animated quantity on screen is a **display value `d` chasing a measured value `t`**, and the chase is the only animation primitive:

```
alpha = 1 - Math.exp(-dtMs / tau)      // frame-rate independent
d    += (t - d) * alpha
tau   = (t > d) ? TAU_RISE : TAU_FALL  // 120ms rise, 600ms fall
```

Growth is fast, withering is slow — the 5x asymmetry is the whole emotional read. Rise reaches 90% in `2.3 * 120 = 276ms`; fall in `1380ms`. **If telemetry stalls, `d` converges on the last truth and stops dead. If telemetry reverses, `d` walks back down the ramp it climbed.** Nothing decays to finish an animation. A stuck handshake shows a half-grown hypha, frozen, indefinitely. That is the feature.

Each growth moment is therefore only two declarations: which telemetry field is `t`, and which glyph ramp `d` indexes. Everything else is this law.

`d` is stored as float; the rendered glyph is `ramp[Math.round(d * (ramp.length-1))]` with **1/8-step hysteresis** — a glyph changes only when `d` crosses `k/(n-1) ± 0.0625` — so a value hovering on a boundary does not strobe.

## 1. The cell machine

`ui/grid.js` owns two `Uint32Array` planes of `cols*rows*3` (glyph codepoint, packed RGB fg, attr bits). Compositors write `back`; the emitter diffs `back` against `front`.

Per frame:

1. **Damage scan** — walk `back` vs `front`, build spans of consecutive differing cells. No damage anywhere: emit zero bytes, skip the frame. An idle mesh is a silent TTY.
2. **SGR run coalescing** — within a span emit `ESC[38;2;r;g;bm` only when fg actually changes. A typical thread run costs 1 SGR + 14 glyph bytes, not 14 SGRs.
3. **Cursor economy** — emit `ESC[{row};{col}H` only when the next span is not contiguous with the last.
4. **Synchronized output** — wrap each frame in `ESC[?2026h` … `ESC[?2026l`. Supporting terminals composite atomically so a moving pulse never tears; others ignore both sequences harmlessly.
5. **Byte budget** — hard cap 12 KiB/frame. At 30fps that is 360 KB/s, which survives a real SSH link. When damage exceeds budget, spans emit in priority order (text pane > hypha roster > peer graph > background) and the remainder defers to the next frame. The graph degrades before the text ever does.
6. **Backpressure governor** — if `process.stdout.write` returns `false` twice consecutively, step the tick 30 → 15 → 8fps; recover one step per 2s of clean drains. The follower law is frame-rate independent, so an 8fps session shows the *same* curves, coarsely sampled.

Target: **30fps in the TUI.** 60fps with hundreds of elements is the canvas path's promise, not the terminal's, and pretending otherwise over SSH produces a stuttering mess.

## 2. Braille as a 2x4 framebuffer

The peer graph plots into a virtual bitmap of `cols*2 x rows*4` dots. The bit map is non-contiguous, and this is the single most common implementation bug:

```
BIT[x][y]  x=0: [0x01, 0x02, 0x04, 0x40]   // y = 0,1,2,3
           x=1: [0x08, 0x10, 0x20, 0x80]
glyph = String.fromCharCode(0x2800 | bits)
```

Note `0x40`/`0x80` for row 3 — rows 0-2 are the historical 6-dot block and row 3 was bolted on later.

**Lines** use **Xiaolin Wu's algorithm** for per-dot coverage in `[0,1]`, then a **Bayer 4x4 ordered dither** resolves coverage to a binary dot:

```
BAYER = [[0,8,2,10],[12,4,14,6],[3,11,1,9],[15,7,13,5]]
dotOn = coverage > (BAYER[y & 3][x & 3] + 0.5) / 16
```

This is what makes a hypha at 38% strength read as a *thin* thread rather than a dotted one. The dither is ordered, not random, so a static thread does not shimmer.

**Circles** (the BLOOM ring) use midpoint circle with Wu coverage on the radial error term.

**Node placement is deterministic, never a force sim.** `angle = (fnv1a32(peerId) % 3600) / 3600 * 2π`, `radius = R * (1 - capNorm) ** 0.5`. Peers hold station; capacity pulls them inward. Nothing jitters, so every pixel of motion on screen means something changed.

**Fallback ladder**, detected once at startup, never per frame:
- `TERM` contains `linux`, or `SPORE_GLYPHS=quad` — **quadrants** `▘▝▀▖▌▞▛▗▚▐▜▄▙▟█`, indexed by a 4-bit mask `tl | tr<<1 | bl<<2 | br<<3`. Quarter resolution.
- `SPORE_GLYPHS=ascii` — the density ramp below, 1x1.

## 3. The ramps

| Ramp | Glyphs | Bound to | Bands |
|---|---|---|---|
| `RAMP_THREAD` | `·` `╌` `─` `━` `═` | `transport` bytes/sec EMA per hypha | 0, <1K, <16K, <256K, ≥256K |
| `RAMP_DENSITY` | ` ` `░` `▒` `▓` `█` | any 0..1 fraction | quartiles |
| `RAMP_NODE` | `·` `∘` `○` `◎` `●` `◉` | `roles` capacity contributed | 0, <.1, <.25, <.5, <.75, ≥.75 of mesh mean |
| `RAMP_GERM` | `░` `▒` `▓` → text | `substrate` verify stage 0..3 | discrete |
| `RAMP_ASCII` | ` ` `.` `:` `-` `=` `+` `*` `#` `%` `@` | fallback density | coverage 0,.05,.12,.2,.3,.42,.55,.7,.85,1 |
| `RAMP_WITHER` | `◉` `●` `◎` `○` `∘` `·` `˙` | consecutive missed keepalives 0..6 | one step per miss |

`RAMP_WITHER` is `RAMP_NODE` reversed plus a terminal `˙` (U+02D9) — a peer that has missed six keepalives is a speck of dust above the baseline, and then it is gone. **Eviction is the seventh miss, not a timeout.** The glyph is the truth; you can count the misses off the screen.

Glyph *density* carries the bottom of every scale, not colour. Deliberate: a near-zero value shrinks its glyph and keeps its contrast rather than fading into unreadable dark cyan. Colour varies only across the top three steps of any ramp.

## 4. Colour

Ramp colours interpolate in **OKLab**, not sRGB — a straight sRGB lerp from `#00E5FF` to `#00737D` passes through a muddy desaturated trough. Conversion never happens per frame: at startup each ramp bakes into a **32-entry RGB LUT**, and the renderer does `LUT[(d * 31) | 0]`. One array index, no math, no allocation.

**Truecolour vs dither.** If `COLORTERM` is `truecolor` or `24bit`, gradients are colour — per-cell fg from the LUT. Otherwise the LUT collapses to the nearest xterm-256 cube entry and the *glyph* ramp carries the gradient instead, Bayer-dithered between adjacent ramp steps at cell granularity. Gradient information is never lost, only relocated.

**One colour per braille cell.** A braille glyph's eight dots share a single foreground: geometry is subpixel, colour is cell-resolution. Where two differently-coloured hyphae cross in one cell, the higher-throughput one takes the colour and the lower one still contributes its dots. An honest limit, stated up front rather than discovered in review.

## 5. Layer order, and the fact that terminals have no alpha

There is no transparency. "A peer graph breathing behind the message list" is a lie a terminal cannot tell, so we tell a truer one: the graph occupies **the cells the text does not**.

Compositing order, back to front:

1. `L0 substrate` — `#050607` fill.
2. `L1 mycelium` — braille peer graph, full width, full height.
3. `L2 gutter mask` — the 4-column left gutter and every blank row between messages stay transparent to L1. Nothing else does.
4. `L3 text` — message rows. Every cell a glyph occupies **overwrites L1 unconditionally**, including its trailing space and one space of bleed either side.
5. `L4 chrome` — hypha roster (right, 22 cols) and status line.
6. `L5 pulses` — drawn last but **clipped to L1's visible region** by the same mask. A pulse traversing behind a message disappears and re-emerges. Packets pass under the text the way they pass under the floor.

The read: as the message list empties, the mycelium is revealed. A quiet channel is a window onto the mesh; a busy one is mostly text with threads glimpsed between paragraphs. The graph is literally the substrate the messages sit on.

## 6. Calm mode (`SPORE_MOTION=calm` / `--calm`)

There is no `prefers-reduced-motion` over SSH, so: env var, `--calm` flag, and auto-on when `TERM=dumb` or stdout is not a TTY.

Calm mode **keeps every value-to-glyph mapping intact**. State changes stay fully visible and fully truthful — a hypha still shows exactly its handshake stage, a node still shows exactly its capacity, withering still counts down glyph by glyph. What changes:

- `TAU_RISE` and `TAU_FALL` both become `0`; `d` snaps to `t`. Truth without travel.
- Per-element update rate clamps to **1 Hz**, coalescing to latest.
- Travelling pulses are removed entirely and replaced by a **static tick column** in the roster: one cell per hypha running `RAMP_ASCII` on packets-in-last-second. Same information, zero motion.
- The BLOOM ring does not expand; the BLOOM becomes one roster line that appears and remains until the capacity baseline reabsorbs it.

Not a kill switch — the same instrument with the needle damped.

## 7. Layout (80x24 minimum, reflows)

```
┌ colony:deepwater ──────────────────── fruiting:#substrate ─── hyphae 7/9 ─┐
│    ⠀⠠⠤⠒⠉         14:02 ⠸ashfen  the index rebuilt clean                   │
│  ⡠⠔⠊      ⠑⠢⡀         ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                       ◉ ashfen │
│ ⡜            ⠘⡄  14:02 ⠸mora    yes — 1.2M entries, verified    ● mora    │
│ ⡇   ◉    ⠤⠤⠤⠔⠁ ⡇                                                ◎ tessel  │
│ ⠘⡄      ⡠⠊     ⡜   ░░░░░░░░░░░░░░                               ∘ vire    │
│   ⠑⠒⠒⠒⠉      ⠠⠊                                                 · kestrel │
├───────────────────────────────────────────────────────────────────────────┤
│ ⠿ substrate 1203847/1203847 ▏█████▓▓███░░████▒███▏ ⇅ 38K/s  ⊕ BLOOM +2.3x │
└───────────────────────────────────────────────────────────────────────────┘
```

The history bar is **not a progress bar** — it is a colonizing map. Each cell is a bucket of log indices running `RAMP_DENSITY` on the fraction of that bucket actually held. It fills in patches, outward from whichever indices gossip happened to deliver, because that is what really happens. It is not monotonic, and it is allowed to look ugly.

## Growth moments

### A discovered spore sprouts a hypha that reaches across the graph toward it, arriving only when the peer is genuinely authenticated
- **bound to:** session handshake state machine, discretized to 0..1: discovered 0.0, hello-sent 0.2, hello-recv 0.4, key-exchange 0.6, auth-verified 0.8, established 1.0
- **technique:** Xiaolin Wu antialiased line from local spore to the peer's deterministic graph position (angle = fnv1a32(peerId)%3600/3600*2pi), plotted into the braille dot bitmap at cols*2 x rows*4. Line is truncated at arc-length d * fullDistance, so the thread is a growing tip, not a fading whole. Wu coverage on the tip dot is resolved through Bayer 4x4, giving a sub-dot leading edge. Colour C1 #00737D at d=0 lerping in OKLab to C4 #00E5FF at d=1.0 via the 32-entry LUT.
- **timing:** Follower law, TAU_RISE 120ms: each stage transition covers its 0.2 span in ~276ms to 90%. Full handshake with no stalls reads as roughly 1.4s of continuous reach. STALL: d converges on the current stage and the thread stops mid-air, held there indefinitely — a hypha frozen at 0.6 is a visible, diagnosable stuck key-exchange. REVERSE: handshake failure sets t=0 and the thread retracts along its own path at TAU_FALL 600ms (1380ms to 90%), tip receding, never blinking out.

### A hypha thickens and brightens as real bytes move through it
- **bound to:** transport bytes/sec EMA per hypha (EMA window 1000ms), mapped through log2 bands to RAMP_THREAD index 0..4
- **technique:** Two channels at once. (a) Geometry: thread weight sets the Wu line's coverage multiplier, so a thin thread turns on fewer braille dots per cell via the ordered dither — 0 idle, 1 <1KB/s, 2 <16KB/s, 3 <256KB/s, 4 >=256KB/s. (b) Colour: per-cell fg from the cyan LUT indexed by the same d. In the roster list (non-braille), the same d indexes RAMP_THREAD glyphs directly: · then thin-dashed then light then heavy then double. Glyph substitution and subpixel weight are the same value rendered twice at two resolutions.
- **timing:** Follower law with 1/8-step hysteresis on the ramp index, so a hypha sitting at a band boundary does not flicker between heavy and double. TAU_RISE 120ms makes a burst visibly slam the thread thicker; TAU_FALL 600ms makes it sag back slowly, so the eye reads recent history in the sag. STALL: thread holds its last weight. REVERSE (traffic drops to zero): thread thins through every intermediate glyph over ~1.4s and rests at ·, never disappearing — an idle hypha is still a hypha.

### Packets visibly travel the thread and land, or die where the network dropped them
- **bound to:** transport send/ack events; pulse position = (now - sentAt) / measuredRttMs from the per-hypha RTT estimator
- **technique:** A 3-dot braille comet plotted at parametric position p along the already-drawn Wu line, at colour M4 #FF2BD6 (magenta = payload, distinguishing it from the cyan structural thread it rides). Pulse dot-width encodes bytes represented: 1 dot <4KB, 2 dots <64KB, 3 dots above, so coalesced pulses stay quantitatively honest. Rate-limited to at most 1 pulse per 250ms per hypha; suppressed sends accumulate into the next pulse's width rather than being dropped from the record. Drawn on L5, clipped by the text mask so it vanishes behind messages.
- **timing:** Position is strictly LINEAR in elapsed/RTT — no easing, because an eased pulse would lie about where the packet is. Arrival is the ack event, not p=1: an ack arriving early snaps the pulse home, an ack arriving late lets p exceed 1 and the pulse waits, pinned at the far node. NO ACK by 3x RTT p95: the pulse's brightness value takes t=0 and it dims down the magenta LUT at TAU_FALL 600ms, dying in place at the exact fraction of the wire where it timed out. Loss is legible as a position.

### A message germinates out of the substrate, resolving from blocks into readable text only once it is cryptographically verified
- **bound to:** substrate ingest pipeline verification stage 0..3: bytes-received 0, content-hash-ok 1, signature-ok 2, appended-to-log 3
- **technique:** The message row is drawn as a band of RAMP_GERM glyphs whose run length equals the real decoded byte length scaled to column width — so the message's shape is truthful before its content is. Stage 0 renders ░ at C1 #00737D, stage 1 ▒ at C2 #00838F, stage 2 ▓ at C3 #00C2D8, stage 3 replaces the band with the actual glyphs. The text is UNREADABLE until verified, which is simultaneously the growth effect and the correct security affordance: you cannot read an unverified message because we never render one.
- **timing:** Stages are discrete and event-driven — each arrives when the verifier actually finishes, typically 2-40ms apart for local content and arbitrarily long for a message awaiting a missing dependency. The only continuous motion is the post-append colour settle: after the discrete jump to t=3.0, d is still below 3.0 and continues converging at TAU_RISE 120ms, driving text colour from textDim #6E8A8F to textBody #A8C4C8 over ~276ms. That fade is not a flourish — it is the follower finishing its approach. STALL at stage 1 (hash ok, signature pending): the row sits as a ▒ band indefinitely, which is exactly what an unverifiable message deserves to look like. REVERSE (verification fails): t=0, band withers to nothing over 1380ms and the row closes.

### A fruiting blooms open and its history colonizes inward in patches, not as a bar
- **bound to:** substrate log index presence: bucket the index range [0, knownHead] into one bucket per status-line cell; each cell's t = fractionOfBucketActuallyHeld
- **technique:** Per-cell RAMP_DENSITY (space ░ ▒ ▓ █) with independent followers per cell, colour from the cyan LUT. Because gossip delivers ranges out of order, cells light up around whichever indices arrived — the fill front spreads outward from multiple seeds and leaves holes that close later. It is a MAP of what the node holds, so it can and does go backwards when a compaction discards a range. Never normalized, never smoothed into monotonicity. The fruiting's own open animation is the same value aggregated: the channel pane's height target is bound to mean(cellFractions), so a channel with no history opens as a sliver and grows as it syncs.
- **timing:** Per-cell follower, TAU_RISE 120ms so a delivered range visibly snaps in, TAU_FALL 600ms so a discarded range sags out. There is no total duration — the bar finishes when sync finishes, which may be 40ms or never. STALL (peer goes quiet mid-sync): the front stops with visible holes, which is the correct and useful picture. REVERSE: cells step back down through ▓ ▒ ░ individually.

### A spore swells as it contributes real capacity to the mesh
- **bound to:** roles/sharding measured contribution: (enzymesCompletedPerMin * medianEnzymeCost) normalized against the rolling mesh mean, mapped to RAMP_NODE index 0..5
- **technique:** Direct glyph substitution through RAMP_NODE (· ∘ ○ ◎ ● ◉) at the node's fixed graph position, with fg from the cyan LUT on the same d. Simultaneously the node's graph RADIUS is bound to the same value — radius = R * (1 - capNorm)**0.5 — so high-capacity spores are drawn physically inward toward the local spore. Size and position encode one truth twice. Because placement is a pure function of peerId and capacity, nothing ever jitters: any motion of a node is capacity changing.
- **timing:** Follower law on both glyph index and radius. TAU_RISE 120ms on swell; TAU_FALL 600ms on shrink, so a peer that briefly drops work visibly deflates and re-inflates rather than popping. Radius uses the same taus, so a spore joining with real capacity glides inward over ~300ms. STALL: node holds its glyph and station. REVERSE: it shrinks through every intermediate glyph and drifts outward.

### An enzyme is farmed out to a peer and the result comes home
- **bound to:** sharding job lifecycle: dispatched, accepted, in-progress (with peer-reported fraction where the enzyme is chunked), completed or failed
- **technique:** An outbound pulse in bloom #FFB25E (distinct from magenta message traffic) travels the hypha to the assignee. On arrival the assignee node gains a thin braille orbit arc whose swept angle = reported completion fraction * 2pi, drawn with midpoint-circle Wu coverage at radius nodeRadius+2 dots. Completion sends the arc's remainder closing and fires a return pulse carrying the result. A failed enzyme's arc reverses to zero and the pulse returns in alert #FF6B5E.
- **timing:** Outbound and return pulses are linear in elapsed/RTT exactly like message pulses. The orbit arc uses the follower on completion fraction, TAU_RISE 120ms. STALL (peer stops reporting progress): the arc freezes part-swept — a visible stuck enzyme, which is precisely the operational signal you want. Reassignment after the sharding layer's own deadline reverses the arc at TAU_FALL 600ms while a fresh outbound pulse leaves for a different peer, so you watch the work migrate.

### BLOOM — capacity really jumps and a ring expands through the mycelium, then is slowly reabsorbed
- **bound to:** aggregate mesh capacity now, versus an 8-second-tau EMA baseline of the same quantity. Ring radius target = R0 * log2(capNow / capBaseline), fires only when that exceeds 0.35 (a ~27% real jump)
- **technique:** Midpoint-circle braille ring with Wu coverage on the radial error, centred on the local spore, drawn on L1 beneath all text. Colour bloomHot #FFF3D6 at the leading edge lerping in OKLab through bloom #FFB25E to C4 #00E5FF as it expands, via a dedicated LUT. Every hypha the ring crosses takes a one-frame brightness kick to its top ramp step, so the ring propagates visibly THROUGH the structure rather than floating over it. Status line shows the literal multiplier: ⊕ BLOOM +2.3x.
- **timing:** The contraction is the elegant part and it uses no timer at all. Radius follows its target at TAU_RISE 180ms (slightly slower than the standard rise — a bloom should feel weighty), so the ring punches outward in ~410ms to 90%. It then shrinks on its own because the 8s-tau baseline EMA is climbing to absorb the new capacity: the ring's whole lifetime is exactly how long the mesh takes to accept the jump as normal, roughly 18.4s to 90% reabsorption. STALL: if capacity holds, the ring shrinks smoothly to nothing as the baseline catches up. REVERSE (the joining spores leave again): capNow falls below baseline, the log2 goes negative, and the ring inverts — it contracts INWARD past zero as a collapsing ring in wither #8C6A4C. A BLOOM running backwards is a departure, and it looks like one.

### A failing peer withers one glyph per missed keepalive, and is evicted rather than deleted
- **bound to:** session keepalive miss counter, 0..6 consecutive misses. Integer, not a timer.
- **technique:** Direct index into RAMP_WITHER (◉ ● ◎ ○ ∘ · ˙), which is RAMP_NODE reversed plus the terminal dust speck ˙ (U+02D9). In parallel the node's hypha weight target is forced to index 0, so the thread thins to · then its Wu coverage drops below the Bayer threshold and it dissolves dot by dot — the connection literally disintegrates at subpixel granularity rather than being erased. Colour migrates from cyan to wither #8C6A4C across the last three steps. On the seventh miss the node is evicted and its dots simply stop being plotted.
- **timing:** Each miss is a discrete step at the keepalive interval (default 2000ms), so a full wither takes a real 12 seconds and every second of it is countable off the screen. Between steps the follower interpolates at TAU_FALL 600ms — slow, sagging, unmistakably different from the 120ms snap of growth. STALL is not possible here; the counter only moves on measured misses. REVERSE is the good case: a single keepalive arriving resets the counter to 0 and the node swells back at TAU_RISE 120ms — recovery is fast and growth-coloured, so a peer that nearly died and came back is visibly a survivor.

## Palette

All ratios computed against substrate `#050607` (sRGB linearize, L = .2126R+.7152G+.0722B, (L1+.05)/(L2+.05)).

SUBSTRATE
- `#050607` substrate, the ground — 1.00:1 by definition
- `#0A0D10` substrate-raised, panel fills — 1.04:1

CYAN — structure. Hyphae, nodes, verified history. 5-step LUT:
- C4 `#00E5FF` full throughput / established — 13.18:1
- C3 `#00C2D8` — 9.37:1
- C2 `#00A0B4` — 6.46:1
- C1 `#00838F` — 4.48:1
- C0 `#00737D` idle hypha, floor of the ramp — 3.62:1

MAGENTA — payload in motion. Packet pulses only. 4-step LUT:
- M4 `#FF2BD6` live pulse — 6.34:1
- M3 `#E82CC0` — 5.36:1
- M2 `#C728A4` — 4.12:1
- M1 `#AE2690` dying pulse, floor — 3.36:1

EVENT
- `#FFB25E` bloom, enzyme dispatch — 11.38:1
- `#FFF3D6` bloom-hot, ring leading edge — 18.39:1
- `#8C6A4C` wither, decaying node — 4.13:1
- `#FF6B5E` alert, failed enzyme / bad signature — 7.26:1

TEXT
- `#D7E8EA` text-prime, author names, focused input — 16.05:1
- `#A8C4C8` text-body, message content — 11.00:1
- `#6E8A8F` text-dim, timestamps, pre-settle germinating text — 5.50:1

THE CONTRAST CONTRACT
- Any cell carrying readable prose: >= 7:1. Lowest used is text-dim at 5.50:1, and it appears ONLY on timestamps and during the ~276ms germination settle, never as resting body text. Resting text floor is text-body, 11.00:1.
- Any cell whose glyph encodes a value the user must distinguish: >= 3:1. Every step of both LUTs clears it; the weakest is M1 at 3.36:1.
- Magenta is the weak axis — `#FF2BD6` is only 6.34:1 against black where cyan is 13.18:1 — which is why the magenta ramp is 4 steps, not 5, and why magenta is never used for text or for structure, only for transient pulses.
- This is why glyph density carries the bottom of every scale instead of colour: a near-zero value shrinks its glyph and keeps its contrast, rather than dimming into an unreadable dark cyan. There is no colour below 3.36:1 anywhere that encodes information.
- One exception, explicitly non-informational: `#073A40` (1.63:1) is permitted for the resting mycelium texture in empty gutter cells, where it carries no state the user needs to read.

## TUI feasibility

PURE ANSI, ZERO DEPENDENCIES — this is essentially all of it.

Renders natively in the TUI:
- The entire braille framebuffer. U+2800-28FF at 2x4 dots per cell, bit map `x=0:[0x01,0x02,0x04,0x40] x=1:[0x08,0x10,0x20,0x80]`, `glyph = 0x2800 | bits`. Xiaolin Wu coverage plus Bayer 4x4 ordered dither gives genuine antialiased thread weight out of a text grid. On an 80x24 terminal that is a 160x96 dot bitmap — enough for a real peer graph.
- Every glyph ramp: RAMP_THREAD (box-drawing `· ╌ ─ ━ ═`), RAMP_DENSITY (`░▒▓█`), RAMP_NODE (`· ∘ ○ ◎ ● ◉`), RAMP_WITHER, RAMP_GERM. Glyph substitution as a growth mechanic is the one thing a terminal does better than a canvas — a browser has to fake discrete quantization, a terminal gets it free.
- All colour: `ESC[38;2;r;g;bm` 24-bit truecolour, OKLab-baked into 32-entry LUTs at startup so no per-frame conversion.
- Pulses, the BLOOM ring (midpoint circle with Wu radial coverage), enzyme orbit arcs, the colonizing history map. All of it is dot plotting.
- Tear-free compositing via `ESC[?2026h`/`ESC[?2026l` synchronized output, with silent no-op on terminals lacking it.
- Diff-based emission, SGR run coalescing, 12 KiB/frame byte budget, backpressure-driven frame-rate stepping. This is what makes it work over SSH at all.

TUI DEGRADES, HONESTLY:
- **Frame rate is 30fps, not 60.** A 200x50 truecolour full redraw is ~200KB; at 60fps that is 12 MB/s and no SSH link survives it. Diffing plus coalescing keeps typical frames in the 1-4 KiB range, but the ceiling is real. 30fps with the follower law's frame-rate-independent easing looks identical in curve shape, just sampled coarser. The 60fps-with-hundreds-of-elements target belongs to the canvas path.
- **One colour per braille cell.** Eight dots share one foreground. Geometry is subpixel; colour is cell-resolution. Crossing hyphae resolve by higher throughput taking the colour.
- **No alpha, ever.** The "graph behind the text" is achieved by masking (L2 gutter mask, text overwrites L1 unconditionally), not blending. A canvas could do a real 12% overlay; the terminal cannot and does not pretend to.
- **No subpixel motion below one dot.** A pulse moves in 1/2-cell horizontal and 1/4-cell vertical increments. At low throughput on a short hypha this is visibly steppy. Acceptable — arguably desirable, since it reads as demoscene rather than as jank.
- **256-colour and 16-colour terminals** lose colour gradients; the Bayer dither relocates the gradient into the glyph ramp so no information is lost. `TERM=linux` drops to quadrants (`▘▝▀▖▌▞▛▗▚▐▜▄▙▟█`, 2x2, quarter resolution). `SPORE_GLYPHS=ascii` drops to `  . : - = + * # % @` at 1x1.

NEEDS THE BROWSER CANVAS PATH:
- 60fps with several hundred simultaneously animated elements.
- True alpha compositing — the graph genuinely showing through beneath text at low opacity rather than being masked around it.
- Per-dot colour within what was a braille cell, i.e. actual per-pixel gradients along a thread.
- Sub-dot continuous pulse motion and motion blur.
- Glow, bloom falloff, and any additive blending on the BLOOM ring.
- Smooth radius interpolation on node swell (the TUI quantizes to 6 glyph steps; the canvas can do continuous).

The canvas path re-implements the same follower law, the same LUTs, the same telemetry bindings, and deliberately keeps the glyph-ramp quantization as an aesthetic choice rather than smoothing it away — otherwise the two paths would not look like the same product.

## Failure mode

The honest risk is that binding everything to truth makes the screen boring exactly when the product is most fragile: a single-spore SPORE, the one-phone case the brief explicitly says must work, has no peers, no throughput, no handshakes, and therefore — by this design's own law — almost nothing moving. One node, one glyph, a static history map. The demo that stops people requires a live mesh, and the thing people first launch is a mesh of one. The temptation at that moment will be to add a breathing idle animation, and that would break the entire premise.

The mitigation I would actually ship: bind the solo state to the local spore's own real telemetry, which is not zero — disk write latency on substrate appends, local CPU headroom, battery, and the enzyme queue the node runs for itself. A lone spore should show its own metabolism, honestly measured. That is still truth, and it is still interesting. But it is a weaker picture than a mesh, and I would rather say so than pretend the law has no cost.

Three secondary risks. (1) The 12 KiB/frame byte budget is a guess, not a measurement — the priority-ordered deferral may cause the peer graph to visibly lag the text pane on a slow link, which will look like a bug even though it is the designed behaviour; this needs a real SSH benchmark before the constant is fixed. (2) Braille rendering is genuinely unreliable in the wild — many terminal fonts render U+28xx at wrong widths or with visible cell padding that makes lines look dotted and broken; the quadrant fallback exists for this but detection by `TERM` alone will misfire, and there is no reliable capability query, so some users will get an ugly graph and no way to know why. (3) The per-cell independent followers on the history map mean up to ~60 float updates per frame for that widget alone, which is fine, but the same pattern applied to a several-hundred-peer mesh puts thousands of followers in the hot loop; the fix is to only step followers for elements whose target changed this tick, and that optimization must be in from the start rather than retrofitted.
