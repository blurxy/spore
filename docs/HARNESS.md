# Running SPORE on real devices

`bench/curve.js` measures a model of the network. This measures the network. Everything in
`bench/mesh.js` is the shipped stack — real multicast discovery, real Noise handshakes, the
real substrate, the real rarest-first scheduler over real sockets. The only invented thing
is the corpus, and it is invented identically on every device.

**The target is phones.** Laptops are useful because they are easy, but a laptop mesh does
not test the claim. Run both.

## What you need

- 2+ Android phones with [Termux](https://f-droid.org/packages/com.termux/) (F-Droid build;
  the Play Store one is abandoned)
- Optionally laptops on the same network, to make a mixed mesh
- One Wi-Fi access point everything joins. **Not** a mesh/extender system — those bridge
  cells and will quietly change what you are measuring.
- Client isolation / AP isolation **off** on the router. It is on by default on most guest
  networks and blocks device-to-device traffic entirely, which looks exactly like SPORE not
  working.

## Setup, per phone

```sh
pkg update && pkg install nodejs-lts git
git clone <your spore remote> && cd spore
node --version     # must be 20+; 24 is what this was written against
```

There is no `npm install`. There is nothing to install. That is the point.

## The experiment

One device seeds; one joins and is timed. Add sources one at a time and compare elapsed.

**On each seeder:**

```sh
node bench/mesh.js --seed --corpus alpha --blocks 400
```

**On the joiner, once the seeders are up:**

```sh
node bench/mesh.js --join --corpus alpha --blocks 400 --sources 1
```

Then repeat with `--sources 2`, `3`, `4`, `5`, adding a seeder each time. The joiner
**holds its fetch** until that many sources are visible, so the timer covers a run that
really had them — without that, a joiner starts pulling from the first source while the
others are still booting and reports N while having measured one.

Restart the joiner between runs; it caches what it already has.

### What the numbers should look like

`ARCHITECTURE.md` §3.1 predicts, for a good AP:

| sources | expected |
|---|---|
| 1 | baseline |
| 2 | ~2× |
| 3 | ~3× |
| **4** | **~3.5× — the knee** |
| 5+ | flat, no further gain |

The knee is arithmetic, not a guess: one spore's uplink is ~7.5 MB/s and the P2P-effective
cell is ~25 MB/s, so three sources supply 22.5 and four supply 30 — the fourth is the first
that cannot be spent. A phone hotspot should bend much earlier and much lower.

**If the curve keeps climbing past N=5 on one AP, the model is wrong.** That is a result,
not a failure — report it.

### The line that matters most

```
  served by
    cc51e713    114 blocks   95%
    5b959668      6 blocks    5%

  ⚠ ONE SOURCE SUPPLIED 95% OF THIS RUN.
```

A speedup claim is a claim about using several uplinks at once. If one peer supplied nearly
everything, the others were present and idle, the run used one uplink, and any improvement
in elapsed time came from somewhere else. The harness says so rather than printing
percentages and trusting you to notice.

**Expect this warning on loopback and not on a real AP.** `plan()` prefers the peer with
the most free slots; with no bandwidth limit the first peer's blocks all land in one
event-loop turn, freeing its slots and winning the next round before the second peer has
answered. Real airtime removes that advantage — which is exactly why the number has to be
read on hardware.

If it trips on a real AP with several devices, **that is the single most valuable thing
this harness can tell us**: the scheduler is concentrating on one source, and no number of
extra phones will help until it stops.

## Known limits, stated before you hit them

- **Termux is not a phone app.** It is Node on Android. It proves the protocol runs on
  phone hardware over phone radios; it does not prove SPORE survives Android's background
  execution rules, Doze, or a locked screen. That needs the native bridge (SP3).
- **iOS is not here.** Multicast requires `com.apple.developer.networking.multicast`, which
  Apple grants by application. Android's `MulticastLock` is unprivileged. So Android carries
  the mesh and iOS will arrive as a client onto it.
- **Keep the screen on** during a run, or Android may suspend the process mid-fetch. If it
  does, you will see the churn path exercised for real — which is interesting, but it is
  not the measurement you were taking.
- **The corpus author key is public**, derived from the corpus name so every seeder produces
  byte-identical blocks under one `log_id`. Without that you would measure N separate
  single-source downloads wearing a swarm costume. It also means the harness runs on its
  own network key and cannot touch a real colony.

## What to send back

The full block between the `⊰-•-•⟐` rules for each `--sources` value, plus:

- router model, and whether it is 2.4 or 5 GHz
- how many devices, which are phones
- anything else on the network doing real traffic

Airtime is shared with everything in the room, including things that are not SPORE.
