# The Linux emulation harness

> **NEVER RUN. NOT VERIFIED.** Every line below was derived by reading this repo's transport
> code against Linux semantics, not by executing it. This project corrects published claims
> that outran their evidence (see R9, and the README's withdrawn headline), so this document
> says plainly what it is: a plan, with the traps that reading found. Expect the first run to
> discover something here is wrong, and correct this file when it does.

## What it is for, and what it cannot do

A window bound shipped (R10, `FETCH_WINDOW`). Its default is stated as a derivation rather
than a measurement, and `stats.windowStarved` is the falsifier that detects the default being
too small on any ordinary run. **What has not happened is measuring the number.**

`W` trades against head-of-line tolerance, not raw parallelism. One slow source holds the
lowest unfetched block; the fast sources drain the rest of the window; `linkedTo` cannot
advance, so the window cannot slide, so the fast sources idle. Roughly:

> `W ≥ R_fast × T_slow` — the aggregate blocks/s of the other sources, times the seconds the
> slow one takes per block.

At 33,100 B per block and 10 MiB/s aggregate that is ~317 blocks/s, so a source at 1 block/s
needs `W ≈ 320`. The shipped default of 512 covers `T_slow ≤ ~1.6 s`.

**The experiment:** `N-1` sources at full uplink, one throttled `k×` below; sweep `W`; record
elapsed and `windowStarved`. `W*` is where `windowStarved` reaches zero and elapsed stops
improving.

**The default was wrong if** `W*` exceeds 512 for any asymmetry the product claims to handle,
**or** any ordinary harness run shows `windowStarved > 0` while `stats.fromPeer` shows idle
sources.

**What this harness cannot measure:** the knee. Per-source uplink is one `netem rate`, but the
shared *cell* is the term §3.1's N=4 prediction turns on, and emulating it means assuming the
constant the four-device run exists to measure. R10(iii) stays "declared unmeasured" until
four real devices are on one AP.

---

## The rig

One network namespace per spore, on a bridge. `bench/mesh.js` runs unchanged inside each.

```sh
ip netns add s1                      # ... sN
ip link add br-spore type bridge && ip link set br-spore up
echo 0 > /sys/class/net/br-spore/bridge/multicast_snooping

for i in 1..N; do
  ip link add v$i type veth peer name e$i
  ip link set e$i netns s$i
  ip link set v$i master br-spore up
  ip netns exec s$i ip addr add 10.99.0.$i/24 dev e$i
  ip netns exec s$i ip link set lo up
  ip netns exec s$i ip link set e$i up
  ip netns exec s$i ip route add 224.0.0.0/4 dev e$i
  ip netns exec s$i ethtool -K e$i tso off gso off gro off
  ip netns exec s$i tc qdisc add dev e$i root netem delay 5ms rate 60mbit limit 10000
done

ip netns exec s1 node bench/mesh.js --seed --corpus alpha --blocks 400
ip netns exec s2 node bench/mesh.js --join --corpus alpha --blocks 400 --sources 1
```

## Four traps, each found by reading a specific line

**1. Multicast fails SILENTLY without a route.** `beacon.js`'s `announce()` sends to `GROUP`
with no `setMulticastInterface` and an empty send callback. In a namespace with no route to
`224.0.0.0/4` that is an `ENETUNREACH` nobody sees. Subnet broadcast would rescue discovery
anyway — which is worse, because then you are measuring the fallback path and cannot tell.
Hence the explicit route per namespace.

**2. Bridge multicast snooping with no IGMP querier drops groups.** Disable it rather than
relying on flood behaviour.

**3. veth GSO/TSO makes `netem rate` inaccurate.** Offloads batch into 64 KB super-segments
and the shaper sees the wrong packet sizes. Turn them off, and raise `limit` so the qdisc does
not tail-drop at the rates involved.

**4. Keep the host namespace clean, or the tablet dials a bridge.** `dial()` uses
`peer.addrs?.[0] || peer.from` — the first ADVERTISED address, not the one the HELLO arrived
on — and `lanInterfaces()` will happily enumerate `docker0` (172.17/16 passes the `ALLOW`
list), `virbr0`, and `br-spore` itself. Check before the tablet is involved:

```sh
node -e "console.log(Object.keys(require('os').networkInterfaces()))"
```

Better: put `br-spore` in its own namespace so the host has no harness interfaces at all. This
is deferred item **0b** in `ARCHITECTURE.md`, recorded there for the same reason.

## Also true of the box itself

- **`node --version` first.** Distro Node is commonly 18 or 20; this codebase is written
  against 24. That is one command and it saves an hour of confusing failures.
- **Put the machine on Ethernet.** If the dev box is on Wi-Fi, `iw dev wlan0 set power_save
  off` applies to *its* radio too, and the tablet's is supposed to be the only radio in the
  measurement path.
- **`ss -ti` is the real prize.** It reports per-socket `rtt:` and retransmits live during a
  run. `RESULTS-2026-09-17.md` had to back-compute loaded RTT (25/17/14 ms) from throughput;
  here it is a direct reading, which turns the window arithmetic from inference into
  measurement.
- **`core.quotepath=false`** or `git status` mangles `🫐.txt`.
