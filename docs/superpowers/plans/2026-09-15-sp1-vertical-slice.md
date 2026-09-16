# SP1 slice 1 — two spores, one message, growing

**Goal:** cut through every layer at minimum depth. Two spores discover each other over
multicast, complete a real Noise_XX handshake, exchange one signed block, and render it in a
braille TUI where the hypha grows *at the rate the handshake actually progresses*.

Not a mock. Not a simulation. The growth is bound to the real state machine.

## Decisions carried in from review

- **No wall clock.** `boot_id` is random bytes, `not_after = 0xFFFFFFFF` (ARCHITECTURE §1.2).
  Off-web means no NTP; nothing may depend on clocks agreeing.
- **Interface-class gating at bind** (§1.3). Skip `tun*`/`tailscale*`/`utun*`/`wg*`. `100.64/10`
  is dropped from the dial allowlist. The probe found a live tailnet adapter on this machine;
  that is the loophole, and it is closed at bind time, not by a comment.
- **Tolerate per-interface multicast join failure.** Probe finding: Windows Ethernet throws
  `EINVAL` on `addMembership` while the default join carries traffic fine.
- **Differential rendering is mandatory**, not an optimization. Probe 3: 7.2x fewer bytes.
- **Disclosure is in the frame from commit one.** SP1 has zero content confidentiality
  (CORRECTNESS.md C3). The words "NOT ENCRYPTED" appear in plain English, legible to someone
  who has never heard the word *fruiting*. FRV1T styles the frame around the warning; it never
  replaces the warning with vocabulary.

## Build order

1. **`src/telemetry/bus.js`** — event bus, EWMA smoothing, the single source of truth every
   growth animation reads from. Nothing may animate off a timer.
2. **`src/substrate/block.js`** — 196-byte cert exactly per spec, BLAKE2b-256 hash chain,
   ed25519 sign/verify, `ORDER(B) = (lamport, log_id, seq)`.
3. **`src/session/noise.js`** — Noise_XX_25519_ChaChaPoly_BLAKE2b on stdlib, using the verified
   `hkdfSync('blake2b512', ikm, ck, EMPTY, 64)` == Noise HKDF equivalence. `link_sig`,
   `bind_sig`, `Split()`, per-direction keys and counters, SAS.
4. **`src/transport/beacon.js`** — HELLO on `239.42.66.7:47474`, TTL 1, eager burst at
   0/200/600ms jittered, subnet + global broadcast fallback, staged validity gate.
5. **`src/transport/tcp.js`** — listener on `47475`, u32-length-prefix framing, dial allowlist,
   simultaneous-dial dedup by lower `spore_id`.
6. **`src/ui/canvas.js`** — braille 2x4 canvas + differential renderer, lifted from probe 3.
7. **`src/ui/mycelium.js`** — the growing view. Hypha length bound to handshake progress; the
   lone-spore breathing state for N=1.
8. **`bin/spore.js`** — wire it together.

## Tests (`node --test`, three, no more)

- Noise XX: both sides derive identical send/recv keys; nonces do not repeat across reconnect.
- Block: hash chain verifies; a tampered payload_hash fails; `ORDER` is a total order.
- HELLO: a valid datagram parses; a truncated/bad-magic/bad-signature one is rejected.

## Explicitly NOT in this slice

Sharded parallel fetch, work-stealing, the benchmark harness that plots the curve, multi-hop
relay, epoch encryption, colonies and fruitings as real objects, media, presence, voice, bots.

The benchmark harness is slice 2. It is the thing that proves the product claim, so it gets its
own slice rather than being tacked onto this one.

## Definition of done

`node bin/spore.js` on two terminals: they find each other with no configuration, complete a
real handshake, exchange a signed block, and the hypha between them grows as it happens.
One terminal alone: a single seed, breathing, correct.
