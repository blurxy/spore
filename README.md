# SPORE

An off-web mycelial mesh. Runs on one device. Grows as it spreads.

```
node bin/spore.js --nick you
```

No install. No registry. No internet. No bootstrap node. No signalling server.

```json
"dependencies": {}
```

That is not a boast about minimalism, it is the product requirement: a system that needs
the web to stand itself up is not off the web.

## What it is

Discord and Telegram had a baby and it was raised by fungi. Persistent communities with
many channels, roles and presence; fast snappy delivery and rich media — with no server
anywhere, over a LAN, a phone hotspot with no uplink, or eventually a pile of phones
talking directly to each other.

## The vocabulary is literal

Every one of these names a real component, not a theme.

| term | what it actually is |
|---|---|
| **spore** | a node — one device |
| **hypha** | a live authenticated peer connection |
| **mycelium** | the mesh |
| **colony** | a community (Discord's "server") |
| **fruiting** | a channel |
| **substrate** | the replicated append-only log |
| **enzyme** | a unit of work farmed out to a peer |
| **BLOOM** | the observable capacity jump when spores join |

Five roles — RELAY, VAULT, INDEX, FORGE, BEACON — live on every spore and shard out as
peers appear. At N=1 all five collapse onto one device. Slow, correct, and the whole
network.

## Does it really get faster as people join?

For some things, over a bounded range. `docs/ARCHITECTURE.md` §3 has the honest table.
The short version, after three adversarial reviews tore up the optimistic original:

- **Within one Wi-Fi access point, gains saturate around N≈5 at about 3.3×.** Wi-Fi in
  infrastructure mode is a shared medium and every peer-to-peer byte crosses the air
  twice. The 20th phone on one router buys a single joiner nothing.
- **The variable that keeps scaling is independent radio domains** — separate APs,
  hotspots, and eventually Wi-Fi Direct and BLE clusters. Ten joiners across three APs
  finish in the time one takes.
- **Live message latency does not get faster, by design**, and we say so rather than
  letting a slogan imply otherwise.
- **Transcode does not get faster because it does not exist.** It cannot ship under
  zero-dependency stdlib-only and was struck from the claim entirely.

## Status: SP1, and it is not private yet

> **SP1 has zero content confidentiality.** Blocks are signed but not encrypted. Every
> VAULT, RELAY and bystander spore — including one relaying for a colony it does not
> belong to — can read every message body in full.

This is disclosed in a hardcoded, non-dismissable banner in the interface, in plain
English. A banner is a disclosure, not a confidentiality mechanism. Epoch encryption is
SP2. Do not put anything in this you would mind a stranger on your LAN reading.

## Working now

Two spores discover each other on a LAN with no configuration, complete a
Noise_XX_25519_ChaChaPoly_BLAKE2b handshake, and exchange signed blocks each side
verifies against the identity the handshake proved.

```
 29ms  beacon.peer          (no bootstrap, no config)
 38ms  handshake  33%
 48ms  handshake 100%
 50ms  hypha.established
       seq 1 lamport 1  ->  seq 2 lamport 3
```

That Lamport jump from 1 to 3 is causality working: receiving the peer's block advanced
the clock before the next local write. It is derived from deps and rejected if asserted,
which closes the inflation attack.

```
npm test                    # 20 tests, zero dependencies
node bench/render-demo.mjs  # the interface, driven by a real handshake
```

## The crypto is verified against the outside world

Hand-written Noise was named in the design as *"where this design most plausibly fails"*.
It is no longer taken on trust:

- **Noise** replays the official Cacophony vector for `Noise_XX_25519_ChaChaPoly_BLAKE2b`
  with the vector's own fixed keys, and matches all three handshake messages byte for
  byte, the published `handshake_hash`, and the transport ciphertexts derived from
  `Split()`. The pure pattern lives in `NoiseXX`, separate from SPORE's identity binding,
  precisely so it can be checked this way. The fixture is vendored, so the test suite is
  as off-web as the product.
- **BLAKE2b-256** is real RFC 7693, not blake2b512 truncated. It is checked against Node's
  native blake2b512 at `nn=64` over every block-boundary length and 200 fuzz cases — Node
  as the oracle — and against the published 256-bit vectors that truncation gets wrong.

## Everything grows, and every growth is true

The one law: **nothing animates off a timer.** Every growth is a spring pulled toward a
setpoint that came from a measured quantity.

- a hypha's length ← the Noise handshake's actual state-machine position
- a hypha's brightness ← bytes really moved, EWMA-smoothed
- the lone spore's breath ← each real BEACON announce shouted into the dark
- a peer's withering ← the socket actually closing

A stalled handshake is a filament stopped in mid-air, because that is what is true. And
the loneliest state in the product — one spore, nobody answering — is also its most alive
looking, since its pulse is a real announce leaving for an empty LAN.

## Layout

```
src/telemetry/   the single source of truth every animation reads from
src/substrate/   196-byte block certificates, hash chains, causal order
src/session/     Noise_XX on stdlib alone
src/transport/   multicast discovery, TCP hyphae, dial allowlist
src/ui/          braille subpixel canvas, differential renderer, the growing view
docs/            ARCHITECTURE, GROWTH, CORRECTNESS, probes, design, plans
```

`docs/probes/FINDINGS.md` holds the three feasibility probes run before any architecture
was committed, two of which changed it. `docs/CORRECTNESS.md` is the security review —
both lenses returned BROKEN, and what they found is folded into the architecture rather
than filed away.
