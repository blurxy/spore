# The first run on real hardware

`docs/TERMUX.md` gets SPORE onto a phone. `docs/HARNESS.md` describes the experiment and its
predicted curve. This is the sheet for the **first** session, where the devices are scarce and
nothing has ever been measured — written to be filled in as you go, because the expensive part
is not the running, it is getting a result you can still trust a week later.

Everything in `HARNESS.md` §3.1's table currently rests on a laptop simulation. No laptop can
measure one shared Wi-Fi cell's airtime, which is the term the whole prediction turns on.

---

## Before anything

- [ ] One AP. Not a mesh system, not an extender — those bridge cells, and the prediction is
      about one cell's airtime.
- [ ] AP/client isolation **OFF**. It is on by default on most guest networks.
- [ ] `termux-wake-lock` held on every phone, screen on. A suspended spore does not fail
      loudly; it stalls mid-fetch and reports a number that is mostly Android's scheduler.
- [ ] Every device on the same commit. `git bundle verify` on the laptop, `git pull` on each
      phone, and `git log --oneline -1` matching everywhere.

## Step 0 — does the stack run here at all

On each device: `npm test`. **Read the `fail` line, not the `pass` line.**

| device | node version | fail count | notes |
|---|---|---|---|
| laptop | | | |
| phone A | | | |
| phone B | | | |

A failure here is a **finding, not a setup problem** — nothing in this repo is
platform-specific by intent. Stop and keep the output.

## Step 1 — see it alone (never been done)

`node bin/spore.js --glass` on one phone, then open Chrome **on that phone** at
`http://127.0.0.1:7777/`. Screenshot it. The spore breathes on a fixed-step integrator, so it
should look identical to a laptop — if it stutters or runs at a different rate, that is a real
finding about the integrator, not a cosmetic one.

- [ ] screenshot taken     · glass port responded: ______

## Step 2 — discovery, isolated from sync

**Keep the laptop in every pair until phone-to-phone discovery is proven.** `beacon.js` answers
a HELLO it hears with a *unicast* reply, so a phone that cannot RECEIVE multicast still gets
discovered by a laptop that heard it. Phone-to-phone, neither hears the other and nobody dials.
Termux has no `MulticastLock` (ARCHITECTURE §1.4), so this is a live possibility, not a
hypothetical.

| pair | discovered? | fused? |
|---|---|---|
| laptop ↔ phone A | | |
| laptop ↔ phone B | | |
| **phone A ↔ phone B** | | |

If the last row fails, do **not** conclude "the network". Run
`node bin/spore.js --nick beta --dial <other-phone-ip>:47474`.

- **It fuses** → sync and the radios are fine, Android multicast receive is the broken part.
  A real finding, and the measurement still goes ahead: `bench/mesh.js` takes `--dial` too.
- **It does not fuse** → now it is the network. Recheck AP isolation.

Result: ________________________________________________

## Step 3 — each uplink, alone

Laptop joins, one phone seeds, `--sources 1`. Do it once per phone. This measures that phone's
uplink by itself, which is the number every later row is built from — and the reason to do it
first is that a shared-cell measurement you cannot attribute is not a measurement.

| seeder | elapsed | MB/s | top source share |
|---|---|---|---|
| phone A | | | |
| phone B | | | |

## Step 4 — downlink

Phone joins, laptop seeds, `--sources 1`. Tells you whether a phone is slower at receiving than
sending, which would bend every later curve for a reason that has nothing to do with the cell.

| joiner | elapsed | MB/s |
|---|---|---|
| phone A | | |
| phone B | | |

## Step 5 — N=2, with attribution

Laptop joins, **both** phones seed, `--sources 2`.

| | elapsed | vs N=1 | top source share |
|---|---|---|---|
| N=2 | | | |

### The line that matters most

```
  served by
    cc51e713    114 blocks   95%
    5b959668      6 blocks    5%
```

**If one source supplied most of the run, the run measured one uplink** no matter how many
phones were in the room. `topShare > 0.8` falsifies the row. The harness prints this; read it
before believing any speedup.

---

## What this session can and cannot tell you

**Can:** whether the suite passes on Android. Whether multicast discovery works there. Whether
phone-to-phone works without a laptop. Each phone's uplink and downlink alone. The N=1 → N=2
slope with attribution.

**Cannot, and do not claim:** the knee, or the cell term. §3.1 puts the knee at **N=4** on the
arithmetic that one uplink is ~7.5 MB/s against a P2P-effective cell of ~25 MB/s — three
sources supply 22.5, four supply 30, and the fourth is the first that cannot be spent. At N=2
the joiner sees `min(2 × uplink, cell)`, and unless that already saturates, **the cell is
invisible**. Two devices de-risk the four-device run; they cannot find the knee.

**Would be a result either way:** a curve that keeps climbing past N=5 on one AP means the
model is wrong, and that is worth reporting rather than hiding. So is a phone hotspot bending
much earlier and much lower, which §3.1 already expects.

## Afterwards

- [ ] Raw harness output kept per run, not just the summary line.
- [ ] `node --version` and the commit hash recorded per device.
- [ ] Anything that halted a step written down verbatim — a runbook that stops on the wrong
      thing has already cost this project one trap per step, and both were found by reading
      rather than running.
