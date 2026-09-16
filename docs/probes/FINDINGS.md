# Probe findings

Throwaway feasibility probes run before the architecture was committed. Both targeted
assumptions that, if false, would have invalidated large parts of the design.

## Probe 1 — `probe-mcast.mjs`: zero-dep UDP multicast discovery

**Question:** can SPORE discover peers on a LAN using only Node stdlib, with no bootstrap
infrastructure of any kind?

**Result: PASS.** 3/3 beacons received on group `239.255.42.99:47777`.

**Finding that changes the design:** per-interface `addMembership(GROUP, ifaceAddr)` threw
`EINVAL` on the Windows Ethernet adapter while the default-interface join succeeded and
carried the traffic. Interfaces seen: Tailscale `100.85.132.85`, Ethernet `192.168.12.5`.

> BEACON must join the default interface first, then attempt each named interface and
> tolerate per-interface failures rather than treating them as fatal. A spore that dies
> because one adapter refused a join is a spore that does not start on Windows.

Secondary finding: a Tailscale adapter is present and joins successfully. Multicast to a
VPN adapter is a live footgun — SPORE must not treat a tailnet peer as a LAN peer without
saying so, since that silently violates the off-web guarantee.

## Probe 2 — `probe-grow.mjs`: braille subpixel growth rendering

**Question:** can a zero-dependency ANSI terminal render continuous mycelial growth at
60fps, or does the "everything is growing" aesthetic require a browser?

**Method:** space colonization algorithm (140 nutrient attractors, influence radius 34,
kill distance 6, step 2.2) growing hyphae from a single seed, rendered to a 100x26 braille
canvas at 200x104 subpixel resolution with 24-bit colour ramped from cyan core to magenta tips.

**Result: PASS, with enormous headroom.**

| Metric | Value | Budget |
|---|---|---|
| nodes grown | 1,447 | — |
| grow step | 0.182 ms/frame | — |
| draw + serialize | 0.068 ms/frame | — |
| **total** | **0.250 ms/frame** | 16.67 ms |
| headroom | **66.6x** | — |

**Finding that changes the design:** CPU is not the constraint. Terminal write throughput is.
Naive full-frame repaint is 9,824 bytes/frame, which is **576 KB/s at 60fps** — enough to
visibly lag over SSH and to stress even a local terminal emulator.

> Differential dirty-cell rendering is a REQUIREMENT, not an optimization. Frames must
> emit only changed cells, coalesce runs sharing an SGR colour, and wrap each frame in
> synchronized output mode (`CSI ?2026h` / `CSI ?2026l`) to prevent tearing.

The 66x CPU headroom is what buys the simulation-driven aesthetic: there is room to run a
real growth simulation every frame rather than replaying canned animations.
