# The mesh renders its own doubt

**Status:** design note. Implement alongside SP2 rotation (`ENCRYPTION.md` §2.1), not before —
there is nothing to rotate until epochs exist.

## The problem, stated honestly

`ENCRYPTION.md` §3 names one limitation it does not solve:

> A compromised or banned device sitting in an indefinite partition, that no current
> BAN/KICK holder ever notices, keeps receiving `epoch_root`s.

There is no fix. An off-web mesh genuinely cannot distinguish **partitioned** from **gone**.
Both look identical: silence. Any mechanism claiming to tell them apart is either assuming
liveness the mesh cannot guarantee, or it is lying.

Most systems resolve this by picking a comfortable lie. They show a grey dot labelled
"offline" — a statement of *certainty* about something the system does not know. The dot is
not wrong about the bytes; it is wrong about the epistemics. The system knows only that it
has not heard anything. It renders that as knowledge.

## The answer: stop hiding the uncertainty, render it

SPORE's one visual law is that nothing animates off a timer and every growth is bound to a
measured quantity. Applied to absence, that law produces the mechanism directly.

**A member you have not heard from does not go grey. They fade — and the fade rate IS the
colony's epistemic state.**

This is not decoration on top of the problem. It is the only honest display of it. The colony
cannot know whether someone is partitioned or gone, so it shows exactly what it does know:
how far it has travelled without them.

## Bind decay to the substrate, never to a clock

The naive version — fade after N seconds of silence — reintroduces the wall clock SPORE spent
the entire architecture removing. There is no NTP off-web; two spores cannot agree what time
it is; and "seconds since last seen" is unshareable, so two spores would render different
truths about the same member.

So decay is driven by causal distance, which every spore derives identically:

```
absence(M) = own_lamport - lamport(last block delivered from M)
```

Both terms are local, monotonic, and need no agreement. And the meaning is better than the
clock version: a member fades because **the colony has moved on without them**, not because
time passed. A silent colony does not fade its members — correctly, since nothing has
happened that they missed. A busy colony fades an absent member fast, because they are
missing a great deal.

Same law as the rest of the interface: a hypha's length is the handshake's real position, a
spore's breath is a real announce, and a member's fade is real causal distance.

Two signals, since they answer different questions:

| signal | bound to | what it means |
|---|---|---|
| **hypha withering** | the socket actually closing | we lost the *connection* |
| **member fading** | `own_lamport − last_seen_lamport` | we are losing *shared history* |

A member can be faded while connected (present but silent) or unfaded while disconnected
(just left, colony has not moved). Both states are real and neither is currently expressible.

## Rotation is a gesture, not a permission dialog

The obvious next move is a modal: `3 members unseen. Rotate to exclude them? [Y/N]`.

Don't build that. Two reasons, and the second is the real one.

The shallow reason: it presents a decision with no information. Y/N on a question the user
cannot answer, because *the system does not know either* — that is the grey dot again with
extra steps.

The real reason: it frames the colony's own state as a **permission request**, and turns the
interface into an approval queue. The source prompt this project grew out of retires
permission as a plot engine explicitly, and it is right to. The interesting thing here is not
who is allowed to do what. It is the shape of a living thing at its edges.

So: **render the edge dissolving, and let rotation be something the human does to what they
can see.** Pruning a withered hypha, not approving a request. The action exists and is
available; it is never framed as consent to a question the system asked.

The distinction survives into the wire protocol. A rotation that omits a member because they
have not published `wrap_pub_c` is **not yet wrappable**, and must never be rendered or
recorded as **excluded** — silent omission and deliberate exclusion look identical on the
wire, and conflating them is precisely the failure the wrap-set content check exists to
prevent (`ENCRYPTION.md` §2.1 clause d).

## What this does and does not buy

**Does:** makes the unsolvable problem legible instead of hidden; gives a human the one thing
they have that the mesh does not — knowing whether someone is on a plane or gone for good;
adds no clock dependency; costs no new protocol state, since `last_seen_lamport` is already
derivable from delivered blocks.

**Does not:** solve partition detection. Nothing does. A compromised device in an indefinite
partition still holds valid keys until someone rotates. This makes that state **visible**
rather than **silent**, which is the entire available improvement.

## Build notes

- `absence(M)` in the telemetry bus beside the existing rate meters.
- A fade curve in `mycelium.js` reusing `Spring`, driven by `absence`, never by `ms()`.
- The fade must be **reversible**: a block arriving from a faded member restores them, growing
  back rather than snapping. Returning changes what was left behind.
- Implement with SP2 rotation. Until then, a faded member means nothing actionable, and
  showing decay with no available gesture is just anxiety.
