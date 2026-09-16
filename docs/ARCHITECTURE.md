# SPORE — Reconciled Architecture

Status: post-adversarial-review reconciliation. This document is the authority where it
conflicts with any individual `design-*.md` file. Those files remain useful for detail and
for the alternatives-rejected reasoning; where they disagree with this document, this
document wins.

Vocabulary is unchanged and load-bearing: **spore** = node. **hypha** = live peer connection.
**mycelium** = the mesh. **colony** = community/server. **fruiting** = channel. **substrate**
= replicated append-only log. **enzyme** = offloadable work unit. **BLOOM** = observable
capacity jump on join. Roles: **RELAY, VAULT, INDEX, FORGE, BEACON**.

Zero npm dependencies. Node 24 stdlib only. This constraint is scoped explicitly in §7 — it
holds without qualification for the LAN TCP/UDP core and is **not** claimed project-wide.

## 0. The two guarantees, restated with the corrections priced in

1. **At N=1 all roles collapse onto one device.** Slow but fully correct and usable. This
   guarantee is untouched by the adversarial review — every subsystem's N=1 walkthrough
   (transport loopback adapter, substrate `dep_count=0`, roles floor-of-1 scoring, sharding
   "no replication, device durability only") holds up and is adopted as-is.
2. **Cold-start sync, media fetch, search and — see below — index/thumbnail work-stealing
   get faster as spores join, within stated bounds. Live message delivery latency does not,
   and we say so.** Transcode is removed from this guarantee. It does not exist (§5.1). The
   remaining three workloads scale by a real but *bounded* mechanism (§3), not an unbounded
   one, and two of the adversary's four "holes" (verification cost, benchmark CPU
   oversubscription) are closed by changing the design, not just the prose.

## 1. What broke, and what we did about it

This section is the spine of the document. Every fatal and serious adversarial finding is
addressed here with a mechanism, not a caveat.

### 1.1 Transcode does not exist — FATAL, adopted as stated

`0x07 TRANSCODE_VIDEO` stays **defined and refused**: no codec exists in Node stdlib, and a
pure-JS H.264/VP9 encoder is not a realistic zero-dependency deliverable. The only shipped
video enzyme is `0x02 KEYFRAME_STRIP` — container-level byte-range parsing for progressive
seek, not transcoding, byte-exact verifiable. **Transcode is struck from every scaling claim
in this document and must be struck from any product copy.** It is tracked as unshipped
roadmap work requiring a native codec dependency that conflicts with the zero-npm
constraint — see Open Decisions.

### 1.2 Wall clock as a hidden authorization dependency — FATAL, fixed structurally

`design-app.md` states `wall_clock_ms` is advisory-only, never used for causal ordering.
`design-crypto.md` then built real authorization on absolute wall time: link-cert
`not_after`, invite `expiry_u32`, short-code TTL, 7-day cap renewal. A device with a wrong
clock (no RTC battery, VM snapshot, long power-off) fails its very first handshake with no
diagnostic and no NTP-free repair path — directly breaking the "two devices, never met, no
internet" bootstrap the whole system is supposed to deliver.

**Fix, adopted as the contract rule: no SP1 authorization decision reads the wall clock.**

- `boot_id` in the HELLO datagram becomes **8 cryptographically random bytes generated at
  process start**, not "ms since epoch." Trickle's restart-detection trigger (`boot_id`
  change) is unaffected — it only needs the value to change across a restart, which random
  bytes do at least as well as a clock and never move backward.
- `link_sig`'s `not_after` field is set to `0xFFFFFFFF` ("no expiry") for every SP1-issued
  link certificate. The Noise XX handshake never evaluates it against local time in SP1, and
  `cap_expired` cannot fire during initial bootstrap.
- The APP invite token drops `expiry_u32` from the fields that gate admission in SP1. An
  invite is single-use and is burned by the `MEMBER_JOIN` block itself being appended to the
  membership log — a causal fact (has this serial been consumed in causal history?), not a
  temporal one. `max_uses` remains advisory as designed.
- Short-code pairing's 120 s TTL and the 7-day epoch-cap auto-renewal are **deferred to SP2**
  together with the rest of the epoch-encryption machinery (§7). When they ship, every
  wall-clock check must carry an explicit skew-tolerance window (recommend ±24h minimum) and
  the UI must name "clock skew" as the diagnosed cause of a rejection, never a bare
  `cap_expired`.
- `wall_ms` / `wall_clock_ms` remain in the block header and APP envelope, advisory, exactly
  as `design-substrate.md` specifies. The rule is now written down, not just implied: **any
  future feature that wants to read the wall clock for an authorization decision must first
  amend this contract, and must ship a skew window when it does.**

### 1.3 The Tailscale/tunnel loophole — SERIOUS, fixed by interface classification, not range

The dial allowlist enforces address-range membership, and `100.64/10` is both RFC 6598 CGNAT
space and Tailscale's entire pool — the same address the project's own probe recorded
alongside a real Ethernet adapter. A LAN peer sharing that tailnet can dial that address, and
a hypha then rides a WireGuard tunnel that may transit public-internet DERP relays, while
`tp.dial_refused_public` stays at zero. The bug is that the design checked address *range*
when it needed to check physical *locality*.

**Fix, adopted:**

- Every network interface is classified at bind time into `lan` or `tunnel` by name pattern
  (`tun*`, `utun*`, `tailscale*`, `wg*`, `ppp*`, `zt*`, extensible) and, where the platform
  exposes it, by interface flags.
- BEACON only emits multicast/broadcast HELLOs, and only includes address records, from
  `lan`-classified interfaces. A `tunnel`-classified interface is never joined for discovery
  and never contributes an `addr` record to an outgoing HELLO or offline invite blob.
- The dialer additionally requires that a destination be **on-link for a locally bound
  LAN-class interface** (same prefix) or be link-local — not merely "matches a private
  range." `100.64/10` is **removed from the default allowlist**; a Tailscale-only address no
  longer counts as LAN-equivalent under any circumstance.
- New telemetry: `tp.iface.type{lan,tunnel}`, and every candidate/hypha is tagged with its
  interface class so the UI can honestly say "reached via Tailscale, not LAN" instead of
  presenting it as an off-web hypha.
- `tp.dial_refused_public` is redefined to also count a would-be dial to a tunnel-classified
  candidate, restoring it as a meaningful zero-in-a-healthy-run invariant.

### 1.4 "Works on a phone hotspot" scoped honestly — SERIOUS, scope corrected

iOS requires an Apple-granted multicast entitlement (which also gates the broadcast
fallback) and gates plain TCP dials to `192.168.x` behind the Local Network privacy prompt;
Android has no stdlib equivalent of `WifiManager.MulticastLock`, without which the radio
filters incoming multicast. Node has no path to either. BLE and Wi-Fi Aware — the proposed
resilience fallback — have zero Node stdlib API at all.

**Fix, adopted as scope, not as a promised capability:** SP1's supported platform is Node 24
on a laptop/desktop/Raspberry-Pi-class device — Windows, macOS, Linux. "Works on a phone
hotspot" for SP1 means **a laptop joined to a phone's hotspot AP**, which needs nothing
beyond the TCP/UDP LAN transport already designed and probe-verified. A phone *as a spore*
(the literal handheld device running SPORE) requires a native platform shell — an iOS
multicast-entitlement request with fallback UX, an Android JNI bridge for
`MulticastLock` — and is explicitly **SP3, unshipped**. BLE/Wi-Fi Aware adapters are likewise
native, non-stdlib components with their own dependency and build story; "zero npm
dependencies, Node stdlib only" is a claim about the LAN TCP/UDP core, not about the project
as a whole. AP client isolation is detected (`tp.isolation_suspected`) and surfaced, never
silently worked around — this was already honest in `design-transport.md` and is unchanged.

### 1.5 Enzyme verification cost — SERIOUS, table corrected and policy changed

The Regime-B thumbnail scaling table never charged for the owner's serial per-result
verification (~15 ms DC-only decode, always-verify per the V2 trust tier). At N=50, 200
verified thumbnails is ≥3.0 s of owner-side work — more than double the table's claimed
1.3 s total — and verification does not parallelize; it is arbitrated by the single deque
owner, competing with that owner's own compute share.

**Fix, adopted:**

- The scaling table (§3) now carries an explicit **Verify** column:
  `verify_total_s = (n_results × verify_ms × verify_fraction) / 1` (owner-serial, not
  divided by N).
- **Policy change from always-verify to spot-check for V2 (thumbnails).** Always-verify every
  result from every peer does not scale with N; the design already uses O(k) spot-check for
  `INDEX_SEGMENT` (V1) and that pattern is adopted for V2 too: verify 100% of results from a
  peer whose local reputation is below a threshold, dropping to a 1-in-8 sample for peers
  above it (BOINC-style adaptive verification, already gestured at in `design-roles.md` §5
  for V3, pulled forward to V2).
- We do **not** hand-compute a new precise crossover point to replace the discredited N≈24-32
  — that would repeat the same mistake at a different number. The honest statement is:
  **crossover is somewhere in the N≈8-16 range once verification and shared-medium
  contention are priced in, and the benchmark (§6, with the CPU-throttle fix below) is the
  source of truth, not a spreadsheet.** `design-roles.md`'s own Risks section already
  independently arrived at "possibly N≈8 under contention," which corroborates a downward
  correction of similar size.

### 1.6 Benchmark CPU oversubscription — SERIOUS, harness fixed

`bench/roles-burst.js` models N in-process spores, each "owning" 3 dedicated FORGE worker
threads, on one benchmark host. At N ≥ host_cores/3, logical FORGE workers oversubscribe
real silicon and the measured speedup curve bends at the host's own core count —
indistinguishable, as specified, from a genuine coordination-driven crossover. The sharding
benchmark already has exactly this class of falsifier (Control B, cell-bucket-disabled); the
roles benchmark had no equivalent.

**Fix, adopted into the benchmark harness spec (§6):** each simulated spore gets a **fixed
compute-ms token bucket** (or a `worker_threads` scheduling cap) sized to model one real
device's 3-worker allocation, enforced regardless of host core count. A required **Control
run with the CPU cap disabled** must be included alongside every capped run: if uncapped
does not run measurably faster than capped at high N, the capped curve's bend is coordination
overhead, not host oversubscription — proving the measurement is honest. This is a CI
assertion, not an optional run, exactly as the sharding doc already requires for its own
Control B.

### 1.7 Churn was never tested — SERIOUS ×2, benchmark and design both changed

The flash-crowd claim (K=10 joiners completing in ~200s on one cell) assumes the swarm stays
largely intact for the full sync window. At a realistic 30%/min mobile departure rate, only
~31% of a 10-joiner cohort survives 200 s, and the swarm model degrades back toward the
667 s server-upload bound for exactly the scenario the flash-crowd number showcases. The same
churn rate (mean session ~164 s) can outlast the fixed 300 s re-replication grace timer
entirely, and nothing in either design arbitrates the resulting repair traffic against the
cold-start sync it competes with for the same airtime.

**Fix, adopted:**

- The sharding benchmark (§6) gains a **required churn dimension**: stochastic peer
  departure/rejoin injected during Treatment and K-joiner runs, at rates including 30%/min,
  as a first-class benchmark condition, not an optional stress test.
- New falsifier, stated in advance: **swarm completion time under 30%/min churn must stay
  within 2× of the no-churn swarm time for the same N/K, or the flash-crowd claim is
  scenario-dependent and must be labeled as such rather than as a general result.**
- The 300 s re-replication grace timer and its 10%-of-link-rate throttle are named as
  **placeholder constants, not validated ones**, pending the churn-benchmark data. Making
  them adaptive to observed session-length distribution is explicitly deferred to SP2
  (§7) — SP1 ships the fixed constants with this caveat attached in telemetry
  (`sharding.rereplication_active_bytes` is already specified; its grace-timer countdown is
  now documented as provisional).
- **Cross-subsystem airtime arbitration is a real gap both designs flagged independently and
  neither owns.** SP1 ships a minimal version of the *mechanism*, not the full policy: every
  `send()` call across TRANSPORT/SESSION carries a **priority class** (0 voice — deferred to
  SP3 anyway, 1 ephemeral, 2 substrate head gossip, 3 substrate blocks, 4 media/sharding
  chunks), so at minimum live chat never starves behind a re-replication sweep. A true global
  airtime *budget* with adaptive allocation across subsystems is deferred to SP2 and named in
  Open Decisions — SP1's priority-class field exists so SP2 doesn't have to change the wire
  format to add it.

### 1.8 Arithmetic error — ANNOYING, corrected

`design-roles.md` computed CAP_ADVERT gossip cost at N=50 as "40 kB/hour"; the correct
figure is `48 bytes × 50 peers × 60/hour = 144,000 bytes/hour ≈ 144 kB/hour`. Corrected here.
It remains negligible against MB/s transfer budgets — the conclusion survives, only the
number changes. `HAVE_BITFIELD` and `SHARD_MAP` sizing in `design-sharding.md` were
independently re-checked against their frame layouts in this review and are consistent.

### 1.9 "Independent radio domains" is environmental, not engineered — ANNOYING, scoped

Nothing in TRANSPORT or BEACON creates a second radio domain — no Wi-Fi Direct group
formation, no AP/channel selection, no BLE clustering. The C-domain scaling term in §3 is
**conditional on the user's environment already having multiple independently-routed
networks** (a second AP, a phone hotspot plus Wi-Fi). It is documented here, and must be
documented in any product copy, as an environmental precondition SPORE can exploit if
present, not a capability SPORE actively builds. Active domain creation (Wi-Fi
Direct/BLE group formation) is tracked as unshipped roadmap work.

### 1.10 The `correctness` review has now been done

The original `correctness` adversarial pass came back as placeholder/schema-test text with no
actual findings. That gap has since been closed: a full correctness review, from two
independent lenses (crypto and convergence), is recorded in full in `docs/CORRECTNESS.md`.
Every FATAL and SERIOUS finding from that review is folded into this document as §1.11–1.22
below, with corrections to §2 where a prior resolution in this document was itself wrong (not
merely incomplete), and with scope/risk updates to §3, §5, Open Decisions, and Killer Risks.
The `correctness`-pass-was-placeholder risk is removed from Killer Risks accordingly.

### 1.11 EPOCH_ROTATE authorization is contradictory across two source documents — FATAL, fixed by deriving the right instead of granting it

`design-app.md` §4 reserves `EPOCH_ROTATE` to the owner alone ("allow all except owner-only ...
unilateral EPOCH_ROTATE"). `design-crypto.md` §5 says the opposite: rotation requires the
EPOCH_ROTATE right "or any member acting on a membership change they witnessed" — a
self-reported trigger with no defined verification of "witnessed." Neither model has a bit in
APP's own permission bitmask, and §2's earlier "Permission resolution" reconciliation (below)
never noticed the semantics for this specific, safety-critical op were undefined and
contradictory between the two documents it reconciled. Owner-only means a partitioned
sub-mesh with an unreachable owner can never cryptographically exclude a locally banned
member, falsifying `design-app.md`'s own "real cryptographic eviction" claim. The permissive
reading lets a zero-power, Sybil-cheap identity mint a validly signed epoch root and trigger
rotation storms or fork the confidentiality domain at a boundary it chooses.

**Fix, adopted:** `EPOCH_ROTATE` is not a grantable permission at all — it is a **derived
right**. A rotation block is valid if and only if it is authored by the genesis owner, **or**
by the same `log_id` as an already-accepted `MEMBER_BAN`/`KICK`/`LEAVE` block that it cites in
its own `deps`. This requires no new bitmask bit and no subjective "witnessing" check: SUBSTRATE
already resolves whether a `MEMBER_BAN`/`KICK`/`LEAVE` block was accepted, so `authCheck` can
verify the citing rotation deterministically from resolved state. This is recorded as a
correction to the "Permission resolution" entry in §2. Concurrent rotations minted by two
admins across a partition, each citing their own accepted ban, are **not** fully resolved by
this fix — that residual is named explicitly as an SP2 spec item in Open Decisions, not
silently assumed away.

### 1.12 INDEX/FORGE has no read-capability gate — FATAL, gate added ahead of need

`design-crypto.md`'s contract-conflicts section states plainly that ROLES needs
`has_read_cap(colony)` as a hard gate before assigning INDEX/FORGE capability-tier work, because
those roles need plaintext to do their job once encryption ships. §2's cross-subsystem
reconciliation resolved roughly a dozen conflicts and silently dropped this one — it changed
only the HRW hash input and CAP_ADVERT transport for ROLES, never a read-capability
precondition. Once SP2 ships encrypted fruitings, ordinary HRW capability-tier scoring can
hand indexing or thumbnailing duty to any high-scoring spore regardless of colony membership:
either full-text search/thumbnailing silently stop scaling past the (much smaller) set of
members with read caps — contradicting §3's unqualified scaling rows — or plaintext colony
content is handed to a non-member spore, which is the SP2 crux violated one layer above VAULT
storage.

**Fix, adopted:** `ROLES.capability.encodeAdvert`/scoring for the INDEX and FORGE tiers gains a
hard precondition, `has_read_cap(colonyId)`, evaluated before HRW ranking, not after — a spore
without a current read capability for a colony is simply not a candidate for that colony's
INDEX/FORGE work, full stop. In SP1 this predicate is a no-op (everything is plaintext, so
every member trivially has read access) — the interface exists now so SP2 doesn't have to
change the wire/interface shape when the gate becomes load-bearing. §3's "Full-text index
build" and "Search fanout" rows are corrected to say scaling is bounded by *read-cap-holding
member count*, not raw spore count, once SP2 encryption ships (no change for SP1, which is
plaintext).

### 1.13 SP1 ships with zero content confidentiality and no enforced disclosure — FATAL, disclosure made mandatory scope

§4's SESSION/KEYRING scope note and this document's own §5 are explicit that all epoch
encryption is deferred to SP2: SP1 fruitings are signed but not encrypted at the block level.
That means every VAULT, RELAY, and bystander spore — including one relaying for a colony it
isn't a member of, which the design explicitly permits — can read every message body in full.
The only stated safeguard against shipping this to real users was Open Decision #2's
recommendation, which is a non-binding appendix note, not a shipped mechanism. An unenforced
recommendation has to be treated, in a security review, as equivalent to "ships anyway."

**Fix, adopted as SP1 scope regardless of which Open Decision #2 branch is chosen:** a
hardcoded, non-dismissable UI banner stating that a colony's content is not end-to-end
encrypted is **required SP1 scope**, not an optional disclosure. §5 item 3 (Authenticated
hyphae) is updated accordingly. This does not resolve Open Decision #2's underlying
ship/don't-ship question — it makes the disclosure itself non-optional under either answer.

### 1.14 Epoch-wrap key may be the same static used for Noise, undermining the forward-secrecy claim — SERIOUS

`design-crypto.md` defines exactly one `dh_seed` per device and no separate colony-scoped wrap
keypair; `KEYRING.rotateEpoch`/`unwrapEpochRoot` use X25519 ECDH + HKDF against
`memberDhKeys`, never shown to be anything other than the same identity-bound static used for
the Noise handshake. crypto.md §2 claims "compromise of the X25519 static alone yields neither
impersonation nor decryption" — true for live hypha traffic (protected by ephemeral ee/es) but
almost certainly false for the colony layer: retained, signed `EPOCH_ROTATE`/KEYBUNDLE
envelopes are not ephemeral, so a compromised static lets an attacker recompute every epoch
root ever wrapped to that device — the colony's entire retained history.

**Fix, adopted:** SP2's KEYRING design must specify a distinct, colony-scoped DH keypair for
wrapping epoch roots, separate from the identity static used for Noise. Until that ships,
§2's forward-secrecy claim is corrected to state it is scoped to hypha traffic only, not to
colony history.

### 1.15 Global identity key breaks the promised cross-colony unlinkability default — SERIOUS

§2's "Identity binding" resolution (below) mandates one ed25519 identity key per device for
both hypha authentication and log authorship, for the entire pre-SP3 lifetime. This overrides
`design-app.md` §2's stated default that cross-colony correlation is opt-in ("default
uncorrelated") via per-colony HKDF subkeys. Any VAULT or RELAY that stores or relays for two or
more of a user's colonies — routine, since relays are colony-agnostic per crypto.md §2 — can
trivially link that user's activity across communities meant to be unrelated. This cost was
never priced or logged when the identity-binding resolution was made; it was a side effect of
an unrelated fix.

**Fix, adopted:** the cost is now logged explicitly (see §2 correction below) rather than
silently absorbed. Whether to pull a lightweight per-colony pseudonym forward from SP3 into
SP2, versus accepting and loudly disclosing the correlation cost through SP2, is recorded as a
new Open Decision rather than decided unilaterally here.

### 1.16 Invite replay is only partially closed, and the reconciliation overstated the fix — SERIOUS

§2's "Invite token" resolution binds the joiner's proof-of-possession to `genesis_hash` (a
static, colony-wide constant) instead of crypto.md's original `hypha_id` (a live per-session
value), because `MEMBER_JOIN` is asynchronously admitted. This closes observer-replay (a
captured/relayed bearer blob alone cannot be redeemed by an outside observer) but reopens
partition-concurrent replay: an invite QR captured and presented to two admitting members in
separate partitions can be redeemed by both, since neither admitter can see the other's
`MEMBER_JOIN` yet, and no CRDT merge rule resolves two concurrent joins burning the same
serial (unlike the remove-wins rule already defined for `MEMBER_ADD`/`REMOVE`). The original §2
text stated the fix as if it fully closed replay — it does not.

**Fix, adopted:** an explicit merge rule for concurrent `MEMBER_JOIN`s quoting the same invite
serial — causal-order tiebreak on `(lamport, log_id)`, lowest wins, the later one is
soft-failed and the joiner must re-invite. The §2 entry is corrected to state the resolution
prevents observer replay only, not partition-concurrent replay.

### 1.17 Snapshot corroboration threshold is Sybil-cheap — SERIOUS

`design-substrate.md` §6 requires `min(3, active_spores)` distinct log_ids to corroborate a
compaction snapshot's `state_root` for a freshly bootstrapping spore. Identity creation is one
free ed25519 keygen with no proof-of-work, stake, or device attestation anywhere in the
design, so a single attacker process can mint as many identities as needed to satisfy this
trivially — the design's own Risk section already calls this "a weak Sybil barrier," but in
the zero-infrastructure LAN environment SPORE targets, it is closer to no barrier at all
against a single machine.

**Fix, adopted as SP2 scope (compaction itself is already SP2):** corroborators for a snapshot
must be drawn from the colony's own membership log (which costs an admitted invite), not any
log_id observable on the LAN. Weighting by observed uptime/behavioral history is noted as a
further hardening but not required to close the trivial case.

### 1.18 Noise XX wire-size arithmetic doesn't reconcile with its own field layout — SERIOUS

Recomputing MSG2/MSG3 from crypto.md §2's own stated field layout
(`e_pub[32] + AEAD(static)[48] + length[2] + AEAD(168-byte payload)[184]`) gives 266 and 234
bytes; the document claims "measured: m2=256, m3=224" — a 10-byte discrepancy in both.
Separately, canonical Noise XX resets the nonce to 0 at every MixKey boundary, but the
document's own nonce notation (sequential 0 then 1 within a message) reads as one continuing
key rather than two freshly reset ones. The design's own Risks section already admits there
are no Node-stdlib Noise test vectors in-tree, so "transcripts agree, both signatures verify"
proves self-interop, not spec-conformance.

**Fix, adopted as required SP1 scope, not a nice-to-have:** the official Noise_XX test vectors
are imported as an in-tree fixture before code freeze; the byte-count arithmetic is
reconciled against the actual field layout; the cipherstate-per-MixKey-boundary requirement is
made explicit in the spec rather than implied by adjacent nonce numbers. §5 item 3 is updated
to include this as a scope item.

### 1.19 Stale `auth_ref` and self-selected lamport allow retroactive privilege replay in the permission resolver — FATAL

`design-substrate.md` §5's own "classic race, worked" example — the example §2's "Permission
resolution" entry (below) relies on as proof the resolver is safe — implicitly assumes
`sender_power_at_its_auth_ref` reflects the sender's power at the moment they actually acted,
and that `lamport` reflects real recency. Neither is enforced: `auth_ref` is only "the hash of
the AUTH_SNAPSHOT the author believed current," with no tie to the block's own `deps` or
derived lamport; `deps` are self-selected, and "deps list only logs whose head changed" is a
description of honest-client behavior, not something the protocol verifies. This is not a
hypothetical: SPORE's offline-first `DRAFT→LOCAL` write path means a moderator who goes
offline and reconnects later publishes a block whose lamport is anchored to their own frozen
head and whose `auth_ref` can be arbitrarily stale. Pass A's per-block auth-check evaluates
each control block against the *incrementally built partial state at its sort position* — so
any actor who has ever held power ≥ a rival's current power can cite a favorable historical
`auth_ref` and a naturally low lamport, sort early in the power-ordered sequence, and be
auth-checked against a slice of history from before whatever superseded them. Every compliant
spore computes the identical, wrong outcome, because the mechanism is a pure function of
attacker-chosen fields. The worked example is not itself broken by this (B's real power never
exceeds A's), but the general safety property it is used to justify does not hold.

**Fix, adopted:** `auth_ref` must be causally bound to the block's own `deps`/own-log frontier
— it must equal or descend from the most recent `AUTH_SNAPSHOT` reachable from the block's own
dep set at authoring time, **verified by recomputation on ingest, not accepted on the
author's assertion**. A control block whose `auth_ref`/lamport gap from the current resolved
frontier exceeds a bounded threshold is rejected outright (soft-failed, flagged for human
review) rather than merged as if it were current. This is recorded as a correction to the
"Permission resolution" entry in §2 — the worked example demonstrated agreement, not safety,
and this fix is what makes the safety property actually hold.

### 1.20 Ordinary churn permanently freezes compaction's trigger — SERIOUS

`design-substrate.md` §6 gates convergent cut selection on `stable_lamport` crossing a
multiple of 65,536, where `stable(S) = min over all member logs of head_lamport` — a value the
design's own Risks section admits "a single offline member pins forever." Per §1.7's own churn
analysis, ordinary abandonment (lost device, uninstall, no formal `MEMBER_LEAVE`) is the
realistic case, not the exception — so most real colonies will have `stable_lamport` frozen
indefinitely, no `STATE_SNAPSHOT` boundary is ever taken, full genesis replay becomes the
permanent path rather than a fallback, and (compounding §1.19) any disturbing low-lamport
block forces re-resolution of the colony's *entire* history, not a bounded recent window.

**Fix, adopted as SP2 scope (compaction is already SP2):** members unreachable/silent beyond a
defined horizon are excluded from the `stable` computation, analogous to how `settled` already
excludes members not heard from within `PARTITION_HORIZON`, via an explicit, gossiped
"presumed departed" marker distinct from a formal ban/leave. The horizon constant is labeled
**provisional**, the same way the 300 s re-replication grace timer is labeled provisional in
§1.7, pending real churn-benchmark data.

### 1.21 Gossip-propagation lag creates a real, non-transient zero-holder window for a role — SERIOUS

`design-roles.md` §2's "every role always has ≥1 holder ... at every instant" proof assumes a
spore's view of a *rival's* score never overstates that rival's true current standing.
TRANSPORT's fast-disconnect signal only protects spores directly hyphae-connected to a
departing peer; in SP1, where multi-hop routing/LSDB is deferred to SP2, a spore that knows a
peer only via BEACON's gossiped peer table keeps ranking a crashed peer by its last-gossiped
(possibly top) score until anti-entropy catches up. Every spore in that second-hand-knowledge
position independently concludes the crashed peer still holds role R and declines to
self-assign — a genuine, non-transient zero-holder window, not the "harmless transient
over-assignment" the design's proof claims to rule out.

**Fix, adopted:** the invariant's stated scope is corrected — it holds once peer tables are
within one anti-entropy round of convergence, not "at every instant." A liveness signal
independent of cached scores is added: a peer whose last CAP_ADVERT is older than
`N × keepalive-interval` is excluded from top-K candidacy entirely rather than ranked by its
stale value. §4's ROLES entry is updated with this staleness cutoff.

### 1.22 The HRW hash-input fix (§2) removed the only friction against Sybil-grinding a target colony — SERIOUS, prior claim retracted

§2's own "HRW seed and convergence" resolution dropped `peer_table_version` from
`h = BLAKE2b-512(spore_id ‖ role_tag ‖ colony_id)` to fix a genuine convergence bug (two spores
disagreeing on `peer_table_version` computed different hashes). It then claimed this "removes
an entire class of disagreement without weakening anything the version number was buying."
That claim was never checked against the security property the version number incidentally
provided and is very plausibly false: the resulting hash is a fixed, entirely
offline-computable function of an attacker-chosen `spore_id`. Ed25519 keygen is nanoseconds;
an attacker can grind candidate keys against a fixed `(role_tag, colony_id)` target until
`x = be_u64(h[0..8])/2^64` is arbitrarily close to 0, making `weight = S/(-ln x)` enormous even
at the capability score floor of 1 — guaranteeing top-K placement (e.g. permanent VAULT
custodianship, or INDEX membership positioned to poison search) regardless of real capability.
Dropping the version number removed the only thing that previously forced periodic
re-grinding on topology change.

**Correction, not a new fix:** §2's "without weakening anything the version number was buying"
claim is **retracted as stated** — it was asserted, not verified, and does not hold. No clean
replacement is adopted here: a genesis-derived salt is knowable to every VAULT, including
non-members by design, so it does not raise the attacker's cost; and gating the hash on
colony membership contradicts the untrusted-VAULT crux that motivates VAULT existing in the
first place. This tension is recorded as a new Open Decision rather than resolved with another
confident-but-unverified fix — a confidently wrong resolution is worse than an open conflict,
which is the exact failure mode this correctness review exists to catch.

## 2. Cross-subsystem conflicts this review resolved

The six designs disagree with each other at several boundaries that none of the three
adversaries examined (they attacked scaling and off-web claims, not internal consistency).
Each is resolved explicitly below; SP1 code must follow this section over any single
design doc.

**Nonce/AEAD framing (TRANSPORT vs CRYPTO).** TRANSPORT's FULL profile puts `seq` in the
plaintext segment header "as the AEAD nonce input"; CRYPTO specifies the nonce is *always*
the local per-direction counter, the wire value is diagnostic-only, and deterministic rekey
requires a gap-free, in-order frame sequence. **Resolution: SP1 ships TCP only** (ordered,
reliable by `caps`), one segment = one AEAD record, nonce = per-direction counter as CRYPTO
specifies, and the wire `seq` field must equal it or the hypha is torn down. Deterministic
rekey counts segments, not bytes-since-epoch. The TINY framing profile and any adapter that
cannot guarantee order (BLE, Wi-Fi Aware) are **deferred to SP2/SP3**, flagged explicitly as
requiring in-band rekey signalling (`HYPHA_REKEY_REQ/ACK`) instead of the deterministic
scheme — this must be decided before the non-TCP adapter interface is frozen, not after.

**Identity binding (SESSION vs SUBSTRATE vs APP).** SESSION authenticates a peer by X25519
static + ed25519 link/bind signatures; SUBSTRATE authenticates blocks by ed25519 signing key
and needs `log_id` derivable from the authenticated peer; APP's multi-colony design derives a
*per-colony subkey* via `HKDF(root_sk, colony_id)`, which would make "the peer on this hypha"
and "the author of this log" different keys per colony. **Resolution for SP1: one ed25519
identity key per device, used unmodified for both hypha authentication and log authorship.**
`SESSION.remoteLogId(hypha) -> Bytes16` is defined as `BLAKE2b-256(hypha.peerId)[0..16]`,
satisfying SUBSTRATE's contract conflict directly. Per-colony pseudonymous subkeys are
exactly what APP already lists under SP3 ("per-colony pseudonymous identity UX") — this
reconciliation confirms that placement rather than inventing a new one.

**Corrected by the correctness review (§1.15):** this resolution has a cost that was not
logged when it was made — it overrides `design-app.md` §2's stated default that cross-colony
correlation is opt-in, and any VAULT/RELAY shared across two of a user's colonies can now
trivially link that user's activity across communities meant to be unrelated. That cost is
logged here explicitly rather than left implicit. Whether to accept and disclose it through
SP2, or pull a lightweight per-colony pseudonym forward from SP3, is a new Open Decision, not
decided by this correction.

**`colony_id` (three definitions).** APP's §2 uses `BLAKE2b-256(genesis block bytes)[0..16]`
in prose but a 16-byte field in the op envelope; CRYPTO calls COLONY-ID "the colony root
ed25519 pubkey." **Resolution: `colony_id = BLAKE2b-256(genesis_block_hash)[0..16]`** — hash
of the *block hash* (which already covers the genesis payload and signature), truncated to
16 bytes, matching APP's envelope field width and SUBSTRATE's `scope_id` width. The raw
genesis pubkey remains recoverable from block seq 0 for anyone who needs the root key itself
(e.g. cap-chain verification), it is simply not the identifier used on the wire.

**`fruiting_id` (two derivations).** SUBSTRATE derives it from `(colony_id, creator_log_id,
seq)`; APP's prose adds `name` to the hash input. **Resolution: take SUBSTRATE's
derivation** (`BLAKE2b-128(colony_id ‖ creator_log_id ‖ seq)`) as authoritative — it is
already what makes concurrent same-named creates produce two distinct, non-colliding
channels, which is the CRDT behavior APP itself specifies as correct. `name` is state
(renameable), never part of the identifier.

**Media chunk size (three numbers).** CRYPTO and SHARDING both use 256 KiB; APP's manifest
format specifies `chunk_log2 = 16` = 64 KiB. **Resolution: one content-addressed block =
256 KiB**, matching CRYPTO's chunk-key derivation and SHARDING's transfer/verification unit.
APP's manifest `chunk_log2` field is corrected to `18` (256 KiB) in the SP1 wire format.

**Invite token (two shapes).** CRYPTO specifies a bearer token with an embedded
proof-of-possession keypair (`invite_sk` travels only in the QR, never the bearer blob).
APP specifies a 174-byte signed token with no PoP field. **Resolution: APP's wire shape is
authoritative for SP1 (already-specified 174-byte layout, `max_uses`, issuer binding), with
CRYPTO's proof-of-possession folded in**: the QR additionally carries `invite_sk`, and the
joiner's `MEMBER_JOIN` includes `Ed25519(invite_sk, "SPORE-JOIN-v1" ‖ genesis_hash ‖
joiner_id_pub)`, so a captured/relayed bearer blob alone cannot be redeemed. `expiry_u32` is
dropped per §1.2.

**Corrected by the correctness review (§1.16):** the claim that "a captured/relayed bearer
blob alone cannot be redeemed" is overstated. Binding proof to `genesis_hash` (static,
colony-wide) instead of a live per-session value closes *observer* replay only; because
`MEMBER_JOIN` is asynchronously admitted, two admitting members in separate partitions can
each independently accept the same captured invite, since neither sees the other's
`MEMBER_JOIN` yet and no merge rule existed for two concurrent joins burning the same serial.
**Fix, adopted:** concurrent `MEMBER_JOIN`s quoting the same invite serial resolve by
causal-order tiebreak on `(lamport, log_id)` — lowest wins, the later one is soft-failed and
must re-invite. The resolution's claim above is corrected to: prevents observer replay, not
partition-concurrent replay.

**Permission resolution (two resolvers).** SUBSTRATE §5 specifies a two-pass
Matrix-state-res-v2-style resolver operating on generic "control blocks" and "auth_ref";
APP §4 specifies a Discord-shaped bitmask evaluation order operating on roles/overrides.
These are not actually competing — they are two layers that were written as if each owned
the whole problem. **Resolution: SUBSTRATE owns the resolver mechanics** (topological-power
sort of conflicting control blocks, `auth_ref` pinning, `soft_failed` retention) as a *pure
function over the block set*, generic to any auth scheme. **APP owns the semantics**: it
supplies SUBSTRATE an `authCheck(block, resolvedState) -> ALLOW|DENY` callback implementing
the bitmask/override evaluation order from its §4. SUBSTRATE calls this callback during Pass
A/B instead of hardcoding permission semantics itself. This keeps SUBSTRATE colony-agnostic
(it already relays for colonies it isn't a member of, per CRYPTO §2) while giving APP its
Discord-shaped model.

**Corrected by the correctness review (§1.11, §1.19).** This reconciliation resolved the two
resolvers' *mechanics* but left two safety-critical gaps that the worked example this document
leaned on as proof of correctness does not actually close. First, `EPOCH_ROTATE` authorization
is contradictory between `design-app.md` §4 (owner-only) and `design-crypto.md` §5 (any member
"witnessing" a membership change) with no bitmask bit in either — resolved here as a **derived
right, not a granted one**: a rotation block is valid iff authored by the genesis owner, or by
the same `log_id` as an already-accepted `MEMBER_BAN`/`KICK`/`LEAVE` it cites in its own
`deps`, verified from SUBSTRATE's own resolved state. Concurrent rotations citing different
accepted bans across a partition are not fully resolved by this rule and are named as an SP2
spec item in Open Decisions. Second, and more serious: the worked example's tie-break
`(−sender_power_at_its_auth_ref, lamport, log_id)` implicitly assumes `auth_ref` and `lamport`
faithfully reflect when the sender actually acted — neither is enforced, and SPORE's own
offline-first write path means an honestly reconnecting, previously-superseded actor naturally
produces a block with a stale `auth_ref` and a low, frozen lamport. Pass A's per-block
auth-check evaluates each control block against the *incrementally built partial state at its
sort position*, so such a block can sort early and be checked against history from before
whatever superseded its author — letting anyone who ever held power ≥ a rival's current power
retroactively re-win a permission decision, with every compliant spore agreeing on the
exploited outcome. **Fix, adopted:** `auth_ref` must be causally bound to the block's own
`deps`/own-log frontier — verified by recomputation on ingest, never accepted on the author's
assertion — and a control block whose `auth_ref`/lamport gap from the current resolved
frontier exceeds a bounded threshold is rejected outright rather than merged. The worked
example demonstrates *agreement*, not *safety*; this fix is what makes the safety property the
example implied actually hold.

**New: read-capability gate for INDEX/FORGE (§1.12).** `design-crypto.md`'s contract-conflicts
section raised, and this reconciliation pass's original text silently dropped, a requirement
that ROLES carry `has_read_cap(colony)` as a hard gate before assigning INDEX/FORGE
capability-tier work — those roles need plaintext to do their job once encryption ships, and
generic HRW scoring has no concept of colony membership. **Resolution, added by the
correctness review:** `has_read_cap(colonyId)` is a hard precondition on ROLES' INDEX/FORGE
capability scoring, evaluated before HRW ranking. It is a no-op in SP1 (everything is
plaintext) and becomes load-bearing exactly when SP2 encryption ships; the interface exists
now so the wire/interface shape doesn't change later. §3's index/search scaling rows are
qualified accordingly.

**CAP_ADVERT transport (self-contradictory within ROLES).** `design-roles.md` §1.4 says the
frame "is carried inside an authenticated hypha"; its own Interfaces/contractConflicts
section separately proposes piggybacking on TRANSPORT's *unauthenticated* candidate-gossip
HELLO. **Resolution: CAP_ADVERT travels only over authenticated hyphae**, exactly as §1.4
states — a self-reported, unauthenticated capability score gossiped in the clear is a trivial
Sybil vector that undermines HRW role assignment on contact. The HELLO datagram keeps only
the existing coarse 2-byte "capability hints" field (role bitmap + device-class nibble) for
pre-handshake candidate scoring; full `CAP_ADVERT` exchange happens after the Noise handshake,
folded into the same peer-gossip channel SUBSTRATE uses for head gossip.

**Thumbnail verification model (APP vs ROLES).** APP assumes recipes are "deterministic and
pinned" so results are byte-identical and hash-verifiable by recomputation. ROLES states
plainly that a pure-JS decoder's output is only deterministic *within a pinned decoder
version*, and specifies perceptual (aHash, Hamming ≤ 6) verification, not hash equality, as
the actual V2 mechanism. **Resolution: ROLES's model wins** — thumbnails are V2
(approximately verifiable), not V1. APP's `linkpreview` recipe is dropped entirely (it also
independently violates off-web, per ROLES's own contract-conflict note — resolved as
`SPORE_PREVIEW`, resolving `spore://` URIs from local substrate blocks, never an HTTP
fetch).

**"DURABLE" send state (APP references a nonexistent ack).** APP's send-state machine
requires "≥R vault acks" to reach DURABLE; SHARDING defines no such acknowledgment frame.
**Resolution: DURABLE = ≥R distinct custodians (per `sharding.custodians()`) have advertised
`HAVE` for every block of the message**, observed via existing `HAVE_BITFIELD`/`HAVE_DELTA`
gossip. No new frame type is introduced.

**HRW seed and convergence (a blind spot the correctness pass should have caught).**
`design-roles.md` seeds the weighted-rendezvous hash with `peer_table_version`, a number two
spores can disagree on transiently. Two spores computing role assignment against different
`peer_table_version` values compute *different hashes*, not merely different top-K windows
over the same hash — this is a stronger divergence than the "harmless transient
over-assignment" the design claims, because it can also reorder rankings, not just shift the
cut line. **Resolution: drop `peer_table_version` from the HRW hash input entirely** —
`h = BLAKE2b-512(spore_id ‖ role_tag ‖ colony_id)` is already a pure function of identity and
role and needs no version number to avoid replay/precomputation, since scores themselves
(read from the live peer table) already vary over time. This removes an entire class of
disagreement without weakening anything the version number was buying. Flagged as an Open
Decision below since it changes a wire-adjacent hash input late in review.

**Corrected by the correctness review (§1.22): the "without weakening anything the version
number was buying" claim above is retracted as stated — it was asserted, not verified, and is
very plausibly false.** The resulting hash is a fixed, entirely offline-computable function of
an attacker-chosen `spore_id`; ed25519 keygen is nanoseconds, so an attacker can grind
candidate keys against a fixed `(role_tag, colony_id)` target until `x = be_u64(h[0..8])/2^64`
is arbitrarily close to 0, making `weight = S/(-ln x)` enormous even at the capability score
floor of 1 — guaranteeing top-K placement (e.g. permanent VAULT custodianship, or INDEX
membership positioned to poison search) regardless of real capability. Dropping
`peer_table_version` removed the only thing that previously forced periodic re-grinding on
topology change. **No clean replacement is adopted here.** A genesis-derived salt is knowable
to every VAULT, including non-members by design, so it does not raise the attacker's cost;
gating the hash on colony membership contradicts the untrusted-VAULT crux that motivates VAULT
existing in the first place. This tension is recorded as a new Open Decision rather than
resolved with another confident-but-unverified fix.

**Media as a shared CAS (SUBSTRATE/SHARDING/APP each assumed ownership).** All three designs
independently proposed owning the content-addressed blob store. **Resolution: SHARDING owns
the one content-addressed store** (256 KiB blocks, BLAKE2b-256 IDs). SUBSTRATE addresses
payloads in it by hash (already true of its `payload_hash` split) and never duplicates it.
APP references media via `MEDIA_REF`/manifest hash and fetches bytes through SHARDING
directly, never through SUBSTRATE's per-log payload path — consistent with APP's own
contract-conflict request.

**Naming collision: "roles."** ROLES-the-subsystem (RELAY/VAULT/INDEX/FORGE/BEACON capability
tiers) and SUBSTRATE/APP's "roles" (admin/mod/member permissions) are unrelated concepts one
keyword apart, as `design-substrate.md` itself flagged. **Resolution, adopted:** the
subsystem is called **ROLES** and its assignments are **capability tiers**; the
Discord-shaped permission concept is renamed **power levels / grants** throughout code,
telemetry names, and future docs. This document uses the corrected terms.

## 3. Honest scaling table

Grounded in the adversarial findings, not the optimistic originals. **Read the header line
first: within one Wi-Fi AP, gains saturate around N≈5 at a fixed, bounded multiple. The
variable that keeps scaling past that point is the number of independent radio domains
(separate APs, a phone hotspot plus Wi-Fi, future Wi-Fi Direct/BLE clusters) — and today
that is an environmental precondition the user must already have, not a capability SPORE
engineers (§1.9).**

| Operation | Mechanism | Scales with N? | Over what range | Under what conditions | Asymptote |
|---|---|---|---|---|---|
| Cold-start sync, single joiner | BitTorrent-style rarest-first swarm over the mesh | Yes, bounded | N=2 → N≈5 | One shared-medium AP, honest peers, no churn | **3.3× (good AP) / 1.25× (phone hotspot)** vs. single-seeder; flat beyond N≈5 on one AP |
| Cold-start sync, K simultaneous joiners (flash crowd) | Seeder uploads each block once; joiners trade distinct shards | Yes | K=2 → K=10, one AP | **No churn** during the sync window | ~K/3.3× cohort completion vs. K-times-serial upload; degrades toward the serial bound as churn rises (see next row) |
| Cold-start sync, K joiners, under churn | Same swarm mechanism | **Untested at design time; benchmark required (§6)** | — | 30%/min departure, the mobile-realistic case | Falsifier: must stay within 2× of the no-churn swarm time, or the flash-crowd number is scenario-dependent, not general |
| Cold-start sync, across C radio domains | Swarm splits load across C independently-airtime-limited cells | Yes, with C | C=1 → C=3 in the design's own benchmark plan | **C additional APs/hotspots already exist in the user's environment** — SPORE does not create them | Cell term divides by C; ~10× at K=10, C=3 in the modeled case |
| Media fetch, latency-to-first-hop | Cache-on-fetch + relay-cache create ambient replica density | Yes | Grows with F (direct hyphae) and popularity | Popular content, F≈8, replica fraction p≈0.5 | ~99.6% one-hop for popular assets; the one genuine *latency* win from scale (bandwidth is still medium-capped) |
| Media/log fetch, aggregate bandwidth | Same swarm mechanism as cold-start sync | Yes, bounded | Same as single-joiner sync row | Same shared-medium cap | Same 3.3×/1.25×, same N≈5 saturation — it is the same physics, not a separate curve |
| Thumbnail work-stealing, Regime A (cold media, source-only) | FORGE steal, but input must ship over the shared medium first | **No** | Any N | Media not yet replicated (the common "just added photos" case) | Flat — 30.0s → ~25s across N=1→20; offload is strictly slower than local compute below a ~1.9 MB input-size threshold |
| Thumbnail work-stealing, Regime B (media already sharded) | FORGE steal + owner-serial spot-check verification | Yes, bounded | N=2 → crossover | Media already replicated across VAULTs; **spot-check verification (§1.5), not always-verify** | Crossover ≈ N=8–16 (corrected down from the discredited N=24-32; exact value is a benchmark output, not a formula, per §1.5) |
| Full-text index build | Segment-parallel tokenize + merge at INDEX holders | Yes, bounded | N=2 → N≈8 | 2 GB corpus, 32-segment granularity. **SP1 (plaintext): unaffected. Once SP2 encryption ships: bounded by read-cap-holding *member* count, not raw INDEX-capable spore count (§1.12)** | Crossover ≈ N=8 (Amdahl: serial merge at INDEX holders; segment-count ceiling) |
| Search fanout | Query k local index segments in parallel | Yes | Bounded by segment count and INDEX holder count | Presence-verifiable per hit; absence not verifiable (mitigated by querying 2 holders/range). **Same read-cap qualification as the row above once SP2 ships (§1.12)** | Bounded by INDEX holder count and segment granularity, same shape as index build |
| Transcode | — | **No — does not exist** | N/A | N/A | Not shippable under zero-npm/stdlib-only (§1.1); `KEYFRAME_STRIP` container parsing is the only shipped video enzyme and is not transcoding |
| Live message delivery latency | Direct hypha frame delivery | **No, by design, and we say so** | N/A | N/A | Flat at hop-count × hypha-RTT regardless of N; this is a stated non-scaling guarantee, not a gap |
| Durability | Replication factor R = min(N, 2 or 3) | N/A below N=4 | N ≤ 3: **no sharding occurs at all**, R ≥ N | N=1: device durability only; N=2: 1→2 catch-up copy | Durability requires N ≥ 4 before sharding provides any margin beyond full replication |

## 4. Corrected interface contract between the six subsystems

This supersedes each design doc's individually-proposed interface where they conflict. Owner
column names the subsystem whose code defines the function; callers are everyone else.

**TRANSPORT** (owner: TRANSPORT)
- `start(opts)/stop(reason)`, `registerAdapter(adapter)` — unchanged from `design-transport.md` §2, with the loopback adapter always registered.
- `on('candidate', {sporeId, adapter, addr, caps, ifaceType: 'lan'|'tunnel', announceBlob, firstSeen, lastSeen})` — **`ifaceType` added** per §1.3. A `tunnel`-classified candidate is never auto-dialed.
- `on('hypha', {sporeId, state, adapter, ifaceType, rtt, cost, since})` — **`ifaceType` added**, tagging every hypha with its interface class for the UI.
- `send(sporeId, msgBuf, {priority, deadlineMs})` — **`priority` is now a required field**, one of `{0: voice(reserved SP3), 1: ephemeral, 2: substrate_head_gossip, 3: substrate_blocks, 4: sharding_chunks}`, per §1.7.
- `route(dst)/paths(dst,k)` — unchanged; TRANSPORT owns the LSDB (resolving the contract-ambiguity `design-transport.md` raised), **deferred to SP2** along with all multi-hop machinery (§7). SP1's `route()`/`paths()` are stubs returning direct-hypha-or-unreachable only.
- `forward(segmentBuf, arrivalLink)` — **deferred to SP2** with multi-hop.
- `setAnnounceBlob(bytes)/setCandidateScorer(fn)` — unchanged; carries APP's opaque colony-hint bloom.
- `on('close', reason)` / hypha `close(reason)` — **added**, closing the gap CRYPTO flagged: Noise's fatal-AEAD-failure rule requires SESSION to force a close, and the contract previously had no such path.

**SESSION/KEYRING** (owner: CRYPTO design, renamed SESSION+KEYRING per that doc's own split)
- `SESSION.wrap(duplex, {initiator, staticKeys, prologue}) -> Hypha` — unchanged. SP1: TCP-only duplex (ordered+reliable); non-ordered adapters deferred per §2.
- `Hypha.send/on('frame')/on('fatal')/id/peerId/peerCaps/sas()/rekey()` — unchanged.
- `SESSION.remoteLogId(hypha) -> Bytes16` — **added**, resolving the SESSION/SUBSTRATE identity-binding conflict per §2: `BLAKE2b-256(hypha.peerId)[0..16]`.
- `SESSION.setMembershipOracle(fn(colonyId, sporeId) -> {caps, revoked, exp})` — unchanged, with `exp` **advisory-only in SP1** per §1.2 (SP1 does not evaluate it for admission).
- `session.sendEphemeral(hypha, frame)/on('ephemeral', frame)` — unchanged from APP's request; presence/typing bypass SUBSTRATE.
- `KEYRING.identity()/unlock()` — unchanged. **`KEYRING.rotateEpoch`, `unwrapEpochRoot`, `keybundle`, `messageKey` (GGM tree), `sealBlock`/`openBlock` encrypted-block path — all deferred to SP2** (§7): SP1 fruitings are signed but not encrypted at the block level (see §7's SP1 scope call). **Corrected by the correctness review (§1.14): when this ships, `rotateEpoch`/`unwrapEpochRoot` must use a distinct, colony-scoped DH wrap keypair, not the identity static reused for Noise** — reusing the static means a compromised device key decrypts the colony's entire retained history via recorded `EPOCH_ROTATE`/KEYBUNDLE envelopes, not just live traffic. **`EPOCH_ROTATE` authorization (§1.11/§2) is a derived right** — valid iff authored by the genesis owner or by the same `log_id` as an accepted `MEMBER_BAN`/`KICK`/`LEAVE` cited in its own `deps` — not a grantable bitmask bit.
- `Invite.create/prove/verify` — shape per §2's invite reconciliation; `expiry_u32` removed from SP1 admission checks per §1.2. **Corrected by the correctness review (§1.16): concurrent `MEMBER_JOIN`s quoting the same invite serial across a partition must merge by `(lamport, log_id)` tiebreak** — the prior text overstated the fix as closing all replay; it closes observer replay only.
- **`Noise_XX` test vectors (added by the correctness review, §1.18):** the official Noise_XX test vectors are required as an in-tree fixture before code freeze; the documented MSG2/MSG3 byte counts must be reconciled against the actual field layout before the wire format is frozen.

**SUBSTRATE** (owner: SUBSTRATE)
- `append/readRange/get/verifyBlock/ingest/frontier/wants/stability/on('delivered'/'reordered'/'soft_failed'/'fork_detected')` — unchanged from `design-substrate.md` §Interfaces.
- `setSendFn(fn)/onFrame` — unchanged; substrate's channel is `chan 0x01` in the shared typed-channel scheme below.
- `setAuthCheck(fn(block, resolvedState) -> ALLOW|DENY)` — **added**, resolving the permission-resolver split in §2. APP supplies this; SUBSTRATE's two-pass resolver calls it instead of hardcoding bitmask semantics.
- `snapshotAt/bootstrapFromSnapshot` — unchanged in shape; **compaction/snapshot bootstrap is SP2** (§7); SP1 does full genesis replay on cold start, which is honest and correct at SP1's target colony sizes. **Corrected by the correctness review (§1.20): `stability`'s `stable(S) = min over all member logs of head_lamport` must exclude members presumed departed beyond a defined horizon** (gossiped marker, distinct from a formal ban/leave, horizon labeled provisional like the 300 s re-replication timer) — otherwise ordinary churn freezes `stable_lamport` forever and no snapshot boundary is ever taken. **`verifyBlock`'s control-block auth-check (§1.19) must recompute `auth_ref` reachability from the block's own `deps`/own-log frontier**, not accept the author's asserted snapshot pointer, and must reject outright a block whose `auth_ref`/lamport gap exceeds a bounded threshold. **Snapshot corroborators (§1.17, SP2) must be drawn from the colony's own membership log**, not any log_id observable on the LAN.
- Media payload references route through SHARDING's CAS by hash, not through SUBSTRATE's own payload store, per §2's CAS resolution.

**SHARDING** (owner: SHARDING)
- `custodians/fetch/announceHave/localBitfield/onPeerTableChange/setVaultBudget/needsFrameSend/onFrame/durabilityDebt` — unchanged from `design-sharding.md` §Interfaces. This is the **one shared CAS** per §2; SUBSTRATE and APP address it, never duplicate it.
- Frame channel is `chan 0x03`, unchanged; sends carry `priority: 4` by default (§1.7) unless the caller marks a block `INTERACTIVE`, which uses `priority: 3`.
- `sharding.verifyBlock` callback from SUBSTRATE — unchanged, per `design-sharding.md`'s own resolution (cheaper than round-tripping every fetched block through SUBSTRATE before caching).

**ROLES** (owner: ROLES)
- `getAssignment/iHold/onRoleChange/onAssignmentChange` — unchanged **except** the HRW hash drops `peer_table_version` per §2's blind-spot fix: `h = BLAKE2b-512(spore_id ‖ role_tag ‖ colony_id)`. **Corrected by the correctness review (§1.22): this hash input is now cheaply Sybil-grindable offline against a fixed `(role_tag, colony_id)` target** — the "without weakening anything" claim in §2 is retracted; no clean fix is adopted, the tension is recorded as an Open Decision. **Corrected by the correctness review (§1.21): a peer whose last CAP_ADVERT is older than `N × keepalive-interval` is excluded from top-K candidacy entirely, rather than ranked by its stale score** — otherwise gossip-propagation lag past a crashed peer produces a real, non-transient zero-holder window for that peer's role.
- `capability.encodeAdvert/ingestAdvert` — CAP_ADVERT travels **only over authenticated hyphae** (§2), not on TRANSPORT's unauthenticated candidate gossip; the HELLO datagram keeps only the existing 2-byte coarse capability hint for pre-handshake scoring.
- **`has_read_cap(colonyId)` (added by the correctness review, §1.12):** a hard precondition on INDEX/FORGE capability scoring, evaluated before HRW ranking. No-op in SP1 (plaintext); load-bearing once SP2 encryption ships.
- `enzyme.submit/registerExecutor/setCapacity` — unchanged. **SP1 ships exactly one enzyme type: `0x04 INDEX_SEGMENT`** (§7) — pure stdlib, deterministic, V1 hash+spot-check verifiable, sidestepping the verification-cost hole entirely for the SP1 cut. `0x01 THUMB_IMAGE` (V2, needs a hand-rolled JPEG decoder and the corrected spot-check verification policy of §1.5) is **SP2**. `0x07 TRANSCODE_VIDEO` stays defined-and-refused forever (§1.1).
- `roles.stats()/onTelemetry` — unchanged.

**APP** (owner: APP)
- `encodeOp/decodeOp/can/onStateOp` — unchanged, with `can()` implementing the `authCheck` callback SUBSTRATE now calls (§2), and power levels/grants renamed per §2's naming-collision fix.
- `mediaWantList/onChunkProgress/custody.offerHandoff` — unchanged; media chunk size corrected to 256 KiB (§2), `chunk_log2 = 18`.
- `send()` — DURABLE redefined as "≥R custodians advertise HAVE" per §2, no new ack frame.
- `roles.requestEnzyme('index_segment_only_in_SP1')` — thumbnail/link-preview recipes deferred to SP2 alongside the enzyme type itself. `linkpreview` recipe removed; `SPORE_PREVIEW` (local substrate-only rendering) is the SP1/SP2 substitute, never an HTTP fetch, per ROLES's own off-web contract conflict.
- `app.presence.set/typing.ping/unread` — unchanged (ephemeral path).
- Voice, bots, stickers, epoch rotation — **all deferred**, see §7.
- **Non-dismissable "not encrypted" banner (added by the correctness review, §1.13):** required SP1 UI scope, not optional disclosure — every colony view states plainly that content is not end-to-end encrypted, regardless of which Open Decision #2 branch is chosen.

**Shared typed-channel scheme** (new, resolving the channel-ownership ambiguity three designs separately gestured at): a single hypha multiplexes typed channels `chan 0x01` (substrate), `chan 0x03` (sharding), `chan 0x30-0x37` (roles/capability + enzyme), `chan 0xE5` (ephemeral, reserved magic byte per APP's existing framing). Each owning subsystem injects its own sender via the `needsFrameSend`/`setSendFn` pattern already proposed independently by SUBSTRATE and SHARDING; SESSION does not interpret channel contents, only enforces the `priority` class on the underlying `TRANSPORT.send()` call.

## 5. Ruthlessly YAGNI scope for SP1

SP1 ships exactly: discovery, transport, authenticated hyphae, substrate, sharded parallel
fetch, role collapse and work-stealing, a plain shell UI, and a benchmark harness that plots
the real curve. Nothing else. Where a design doc's own "SP1" list (most visibly
`design-app.md` §11) is broader than this, **this document overrides it** — voice, bots,
stickers, and epoch encryption are real, well-designed features, but they are not needed to
prove or ship the core off-web mesh, and each one adds a dependency (native audio, a bot
sandbox, group-key rotation) that would let scope creep hide a regression in the eight items
that actually matter.

**1. Discovery** — UDP multicast HELLO on LAN-classified interfaces per-interface (probe
finding: default-interface join first, then per-interface with tolerated `EINVAL`), Trickle
cadence (RFC 6206) exactly as `design-transport.md` §1 specifies, eager startup burst,
unicast HELLO_ACK, subnet-broadcast + `255.255.255.255` fallback for hotspot APs that filter
239/8, `boot_id` as random bytes (§1.2). **Deferred:** DNS-SD mirror (secondary and
optional by the design's own admission).

**2. Transport** — TCP hypha adapter with u32-length-prefix framing, the FULL segment
profile only (§2 nonce resolution — TINY profile deferred), the dial allowlist minus
`100.64/10` plus interface-class gating (§1.3), hypha lifecycle state machine
(CANDIDATE→...→COOLDOWN), simultaneous-dial dedup, the always-present loopback adapter for
N=1. **Deferred:** BLE/Wi-Fi Aware adapters (native, non-stdlib, §1.4), multi-hop
routing/relay/LSDB (§4), TINY MTU profile, ARQ for unreliable links (moot without a
non-reliable adapter).

**3. Authenticated hyphae** — Noise_XX_25519_ChaChaPoly_BLAKE2b exactly as specified, link
cert with `not_after = 0xFFFFFFFF` (§1.2), bind_sig per-session authentication, deterministic
rekey on the TCP ordered-stream assumption (§2), cookie-reply DoS mitigation. **Added by the
correctness review (§1.18, mandatory SP1 scope, not optional):** the official Noise_XX test
vectors as an in-tree fixture before code freeze, with the MSG2/MSG3 byte-count arithmetic
reconciled against the actual field layout. **Added by the correctness review (§1.16,
mandatory SP1 scope):** the `MEMBER_JOIN` concurrent-invite-serial merge rule (causal-order
tiebreak on `(lamport, log_id)`) for invites redeemed across a partition. **Deferred:** epoch
encryption / GGM secret tree / KEYBUNDLE / EPOCH_ROTATE (§7 below — SP1 fruitings are
signed, not encrypted, at the block level; EPOCH_ROTATE's authorization is now a derived
right per §1.11/§2, and its wrap key must be distinct from the Noise identity static per
§1.14, both binding on SP2), short-code pairing's wall-clock TTL (§1.2), 7-day cap
auto-renewal.

**4. Substrate** — single-writer hash-chained logs, MMR verification, causal ordering with
the derived-and-checked Lamport rule, delivery/pending-buffer, the two-pass permission
resolver calling APP's `authCheck` callback (§2/§4), stability/settled watermarks, fork
detection. **Added by the correctness review (§1.19, mandatory SP1 scope, not optional):**
the permission resolver's `auth_ref` must be verified by recomputation against the citing
block's own `deps`/own-log frontier, not accepted on the author's assertion, and a block whose
`auth_ref`/lamport gap exceeds a bounded threshold is rejected outright rather than merged —
without this, the Pass A tie-break allows retroactive privilege replay by a previously
superseded actor. **Deferred to SP2:** snapshot-based compaction and bootstrap-from-snapshot
(§1's corroboration model is sound but adds real trust-downgrade UX and Byzantine-alarm
surface not needed to prove the core loop) — SP1 does full genesis replay, which is correct
and honest at SP1's target scale (tens to low hundreds of spores, per the sharding doc's own
stated ceiling). **When compaction ships (§1.20):** the `stable` computation must exclude
members presumed departed beyond a labeled-provisional horizon, or ordinary churn freezes it
forever; snapshot corroborators (§1.17) must be drawn from the colony's own membership log,
not any log_id on the LAN.

**5. Sharded parallel fetch** — weighted-HRW custodianship (hash input corrected per §2),
HAVE-bitfield/rarest-first fetch scheduling, per-request RTO/snub/steal-on-slow anti-stall,
capped endgame duplication, the 1→2 catch-up copy, re-replication with the 300 s/10%
constants explicitly labeled provisional (§1.7). **Deferred:** demand-weighted pinning
(proximity replication is real but is an optimization on top of a working swarm, not
required to demonstrate one), reputation-decayed custodian scoring.

**6. Role collapse and work-stealing** — capability self-scoring and quantization,
anti-oscillation (hold-down + asymmetric hysteresis), HRW role assignment (corrected hash),
N=1 collapse, the Cilk-style enzyme deque with hedged local fallback (the no-hang guarantee),
**exactly one enzyme type: `0x04 INDEX_SEGMENT`** (§4). **Added by the correctness review
(§1.21, mandatory SP1 scope, not optional):** a peer whose last CAP_ADVERT is older than
`N × keepalive-interval` is excluded from top-K candidacy rather than ranked by its stale
score — otherwise the "every role always has ≥1 holder" invariant has a real, non-transient
counterexample under ordinary gossip-propagation lag. `has_read_cap(colonyId)` is added as a
no-op-in-SP1 precondition on INDEX/FORGE scoring per §1.12, ahead of SP2 need. The HRW hash's
Sybil-grinding exposure (§1.22) has no adopted fix; it is carried as an Open Decision and a
Killer Risk, not silently accepted. **Deferred:** `THUMB_IMAGE` (V2, needs both a hand-rolled
JPEG decoder and the corrected spot-check policy — real work, not needed to prove
work-stealing scales), `SEARCH_FANOUT`, `SPORE_PREVIEW`, `PUBLIC_POW`, `TRANSCODE_VIDEO`
(permanently refused, §1.1).

**7. A plain shell UI** — enough to see substrate state, hypha lifecycle, and role
assignment change live: a plain-text/ANSI status view driven by the telemetry counters each
subsystem already emits (`tp.*`, `substrate.*`, `sharding.*`, `roles.*`). **Added by the
correctness review (§1.13, mandatory SP1 scope, not optional):** a hardcoded, non-dismissable
banner stating that colony content is not end-to-end encrypted — this is a scope requirement
regardless of which Open Decision #2 branch (ship with disclosure vs. don't ship to real
users) is chosen. **Deferred:** the
braille subpixel growth rendering from Probes 2/3. It is real, probe-verified, and cheap
(0.25 ms/frame, 80 KB/s with differential rendering) — but it is a visualization layer on
top of telemetry that already exists as plain numbers, and SP1's job is proving the mesh
works, not animating it. When the growth UI ships (SP2), differential dirty-cell rendering
with run coalescing and synchronized output remains **mandatory, not optional**, per the
probe finding — that requirement does not get diluted by the deferral, only delayed.

**8. A benchmark harness that plots the real curve** — the `ThrottledLocalTransport`
double-charged cell-bucket model from `design-sharding.md` §8, **with the churn-injection
dimension added** (§1.7) and Control A/Control B falsifiers as required CI assertions; the
ROLES enzyme burst harness **with the per-spore CPU token bucket and uncapped-Control
pairing added** (§1.6). Both harnesses' falsifiers, as corrected in §1, are the acceptance
criteria for the scaling claims in §3 — the numbers in that table are honest projections
pending benchmark confirmation, not final results.

### Explicitly deferred (named, not silently dropped)

- Multi-hop routing, relay, link-state DB (SP2)
- Epoch encryption for fruiting content: GGM tree, KEYBUNDLE, EPOCH_ROTATE (now a derived
  right, §1.11), moderation-by-rekey, distinct wrap keypair (§1.14), `has_read_cap` gate for
  INDEX/FORGE (§1.12) (SP2) — **security-relevant deferral, see Open Decisions**
- `THUMB_IMAGE` enzyme, `SEARCH_FANOUT`, thumbnail/link-preview recipes (SP2)
- Snapshot compaction and bootstrap-from-snapshot (SP2)
- DNS-SD discovery mirror (SP2, optional)
- Adaptive re-replication grace timer, global cross-subsystem airtime budget beyond the
  priority-class field (SP2)
- Demand-weighted proximity pinning, reputation-decayed custodianship (SP2)
- Braille growth-rendering UI (SP2, differential rendering remains mandatory when it ships)
- BLE/Wi-Fi Aware adapters, native mobile shell (iOS multicast entitlement, Android
  MulticastLock) (SP3)
- Voice (Opus/AEC/native audio), bots-as-spores, sticker packs, per-colony pseudonymous
  identity (SP3, per `design-app.md`'s own SP2/SP3 split, which this document adopts
  unchanged for these items)
- Video transcoding (never — no codec exists in the zero-npm constraint; tracked only as a
  roadmap item requiring a dependency-model exception, see Open Decisions)
- Active radio-domain creation (Wi-Fi Direct/BLE group formation) (unscheduled roadmap item,
  §1.9)

## 6. Benchmark harness requirements (summary; full detail in §1.6/§1.7)

Two harnesses, both required before the §3 scaling table's numbers can be called validated
rather than projected:

1. **Sharding benchmark** (`design-sharding.md` §8, corrected): `ThrottledLocalTransport`
   with per-spore TX/RX buckets and the global double-charged cell bucket; Control A (forced
   single-seeder), **Control B (cell bucket disabled — falsifier for "measuring loopback,
   not the medium")**, Treatment across N ∈ {1,2,3,5,20,100} and K-joiner flash-crowd runs at
   K ∈ {1,2,5,10}, C ∈ {1,3} domains, **and a required churn dimension at departure rates
   including 0% and 30%/min**. Falsifiers as stated in `design-sharding.md` §8 plus the new
   churn falsifier from §1.7.
2. **Roles/enzyme benchmark** (`design-roles.md` §7, corrected): N in-process spores with a
   **per-spore compute-ms token bucket modeling one real device's 3-worker allocation**, a
   **required uncapped-CPU Control run** to prove the capped curve's bend is coordination
   overhead and not host oversubscription, Regime A and Regime B thumbnail bursts **only
   after `THUMB_IMAGE` ships in SP2** — for SP1, the equivalent harness runs against
   `INDEX_SEGMENT` only, at N ∈ {1,2,5,10,20}. Falsifiers as stated in `design-roles.md` §7
   plus the CPU-cap falsifier from §1.6.

## Open Decisions

These require a human call; each has options and a recommendation, not a default.

1. **Transcode roadmap.** Options: (a) never revisit — state permanently that SPORE does not
   transcode video; (b) accept a native, non-stdlib codec dependency (e.g. an FFmpeg binary
   shelled out to) as an explicit, clearly-labeled exception to zero-npm for a specific
   optional feature, gated behind user-installed native tooling. **Recommendation: (a) for
   SP1-SP3; revisit (b) only if user demand is proven and only as an opt-in native adapter,
   never a default dependency.**
2. **Epoch encryption timing.** Deferring GGM/KEYBUNDLE/EPOCH_ROTATE to SP2 means SP1
   fruitings are signed-but-plaintext at the block level (relays/VAULTs can read content,
   not just metadata) — a materially weaker privacy posture than the eventual design, shipped
   as a real, working messaging system in the meantime. Options: (a) accept plaintext-at-rest
   for SP1 with loud UI disclosure ("this colony is not yet end-to-end encrypted"); (b) do
   not ship SP1 to real users until encryption lands, using it only as an internal/benchmark
   milestone. **Recommendation: (b)** — the whole point of SP1 is proving the scaling and
   mesh mechanics; shipping unencrypted group chat to real users under the SPORE name risks
   the exact "looks like Signal, isn't" trust problem CRYPTO's own Risks section warns about.
   **Updated by the correctness review (§1.13): whichever branch is chosen, the
   non-dismissable "not encrypted" banner (§5 item 7) is now mandatory SP1 scope, not part of
   this option set** — it was previously only the (a)-branch's mitigation; it is now required
   regardless, since an unenforced recommendation cannot be relied on to prevent (a)-by-default
   shipping.
3. **HRW hash input change (dropping `peer_table_version`).** This is a wire-format decision
   made in this reconciliation pass, not in either original design or by an adversary.
   Recommend confirming it against the ROLES author's convergence proof before freezing the
   `CAP_ADVERT`/assignment wire format, since it changes a load-bearing hash input late.
   **Updated by the correctness review (§1.22): confirming convergence is not sufficient —
   the change also made the hash cheaply Sybil-grindable offline against a fixed
   `(role_tag, colony_id)` target, and no fix is adopted here.** Options: (a) accept the
   grinding exposure through SP1/SP2 as a known, disclosed limitation, since capability-tier
   assignment already assumes a cooperative-majority mesh; (b) bind the hash to a genesis-derived
   salt, which raises attacker cost slightly but is knowable to every VAULT including
   non-members by design, so it is not a real barrier; (c) gate the hash on colony membership,
   which contradicts the untrusted-VAULT crux that motivates VAULT existing at all. **No
   recommendation** — each option trades against a stated design goal; this needs a human call
   informed by how much VAULT/INDEX misassignment actually costs in practice, not asserted in
   this document.
4. **100.64/10 removal from the allowlist.** This closes the Tailscale loophole but also
   means a legitimate CGNAT-only mobile carrier network (not Tailscale, genuine
   carrier-grade NAT) may lose LAN-equivalent treatment it previously had. Recommend
   confirming this tradeoff is acceptable — the interface-class check (§1.3) is the real
   fix; removing the range is a belt-and-suspenders measure that costs a small amount of
   carrier-NAT generality.
5. **Cross-colony pseudonym timing (added by the correctness review, §1.15).** §2's
   identity-binding resolution (one ed25519 key for both hypha auth and log authorship)
   breaks `design-app.md`'s promised default that cross-colony correlation is opt-in. Options:
   (a) accept and loudly disclose the correlation cost through SP2, deferring the fix to SP3
   as originally planned; (b) pull a lightweight per-colony pseudonym for log authorship
   forward into SP2, keeping one key only for hypha auth. **Recommendation: (a) if SP2's
   priority is shipping epoch encryption on schedule; (b) if cross-colony unlinkability is a
   claim the product intends to make publicly before SP3** — this document does not resolve
   the tradeoff, only names it.
6. **Presumed-departed horizon (added by the correctness review, §1.20).** The constant used
   to exclude a silent member from the `stable_lamport` computation (so ordinary churn
   doesn't freeze compaction forever) has no proposed value yet. Recommend deriving it from
   the same churn-benchmark data (§6) already required for the 300 s re-replication timer,
   rather than picking a number now — both are provisional constants pending the same
   measurement.
7. **Concurrent EPOCH_ROTATE across a partition (added by the correctness review, §1.11).**
   The derived-right fix closes single-actor rotation authorization but does not define a
   merge rule for two admins in separate partitions each rotating on their own accepted ban.
   This is named as an SP2 spec item, not resolved here — recommend a CRDT-style rule
   analogous to the invite-serial merge in §1.16 (deterministic tiebreak, not "first seen")
   before EPOCH_ROTATE ships.

## Killer Risks

Most serious first, each with the mitigation adopted in this document. The correctness pass
this list previously called for (placeholder-text risk) has now been done — see
`docs/CORRECTNESS.md` and §1.11–1.22 — and is replaced below with the real residual risks it
found.

1. **SP1 ships with zero content confidentiality at the block level, and the only safeguard
   against that reaching real users is a UI banner, not a technical control.** Every VAULT,
   RELAY, and bystander spore — including one relaying for a colony it isn't a member of —
   can read every message body in full (§1.13). Mitigation: the non-dismissable "not
   encrypted" banner is now mandatory SP1 scope (§5 item 7); Open Decision #2 still needs a
   human call on whether SP1 reaches real users at all before SP2 encryption lands.
   **Not eliminated — a banner is a disclosure, not a confidentiality mechanism.**
2. **Zero-cost identity creation is the root cause behind three separate findings**
   (snapshot-corroboration Sybil, §1.17; HRW hash grinding, §1.22; and the Sybil-cheap
   permissive reading of EPOCH_ROTATE that the derived-right fix in §1.11 specifically had to
   route around), and no proof-of-work, stake, or device attestation exists anywhere in the
   design to raise that cost. Mitigation adopted per-finding (membership-drawn corroborators,
   disclosed grinding exposure, derived rotation right) treats each symptom; **the root cause
   — free identity minting on a LAN with no infrastructure to anchor cost against — is not
   addressed and may not be addressable within the zero-npm/off-web constraint.**
3. **The permission resolver's worked example (`design-substrate.md` §5) demonstrated
   agreement, not safety, and this document originally treated it as proof of both** (§1.19).
   The fix (`auth_ref` recomputation, bounded staleness rejection) closes the specific replay
   this review found; whether it closes every variant of "cite a favorable stale state" is a
   claim this document does not make and has not verified beyond the case traced here.
   Mitigation: fix adopted in §2/§4; **recommend a further adversarial pass specifically
   targeting the corrected resolver before treating it as proven, rather than repeating the
   original mistake of trusting one worked example.**
4. **Cleartext envelope metadata (log_id, seq, lamport, wall_ms, scope_id, deps, payload_len)
   remains a complete, permanent social graph even after SP2 encryption ships** — encryption
   only hides the message body (§1's crypto-lens finding on metadata leakage, not separately
   numbered as it was not newly introduced by this reconciliation, but confirmed accurate by
   this review). Mitigation: none proposed in either source design or this document; named
   here so it is not mistaken for something SP2 fixes.
5. **No forward secrecy for replicated history is inherent to the design, not a bug** — a
   member who ever held an epoch key retains it forever, by construction of a symmetric-key
   scheme with no revocation-from-the-holder mechanism (crypto.md §4/§6, confirmed accurate by
   this review). Mitigation: disclosed, not solved — this is a property to design product
   expectations around, not an open bug to fix.
6. **Noise XX is self-interop-verified only, not spec-conformant, until the official test
   vectors land** (§1.18) — the current "transcripts agree, both signatures verify" claim
   proves two implementations agree with each other, not that either is correct. Mitigation:
   test-vector fixture now mandatory SP1 scope (§5 item 3); **not yet done as of this
   document.**
7. **Equivocation detection is conditional on eventual gossip overlap, not guaranteed within
   any bound** — an attacker who forks cleanly to two sub-meshes that never cross-reference
   evades detection indefinitely; this is inherent to fork-consistency designs generally, but
   the original documents' confident framing ("cryptographic proof of forking") oversold the
   guarantee. Mitigation: none proposed; named here so product copy does not overstate it.
8. **AP client isolation and multicast/broadcast filtering remain undefeatable at the
   transport layer** (`design-transport.md`'s own top self-identified risk). Mitigation:
   detect and surface (`tp.isolation_suspected`), fall back to offline invite blob — no
   stronger fix exists at this layer; accepted as a known limitation, not solved.
9. **The corrected N≈8-16 thumbnail crossover and the churn-adjusted flash-crowd numbers are
   still projections, not measurements**, because the corrected benchmarks (§6) have not
   been run against real hardware as of this document. Mitigation: §3's table is explicit
   that these are benchmark-pending; do not let product copy state them as measured until
   the harnesses in §6 actually run and their falsifiers pass.
10. **Dropping `100.64/10` and gating on interface class could still be bypassed by an
   attacker running a LAN-named virtual interface** (renaming a tunnel adapter to not match
   `tun*/tailscale*/...`). Mitigation: pattern-matching is a heuristic, not a proof;
   recommend also checking for interface characteristics (default gateway presence, DHCP
   lease) as a second signal in SP2, tracked but not blocking SP1.
11. **Verification spot-checking (§1.5) trades a closed correctness hole for an open one**: a
   peer above the reputation threshold now gets only 1-in-8 result verification, meaning a
   sometimes-cheating peer can pass ~7/8 of the time before reputation catches up.
   Mitigation: this is the same tradeoff BOINC and the design's own V3 tier already accept
   deliberately; reputation decay (7-day half-life, already specified) bounds the exposure
   window. Accepted, not eliminated.
