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

> **Caveat, 2026-09-17:** development is moving to Linux. Windows support is a real claim —
> `beacon.js` carries a Windows-only EINVAL branch that exists because someone hit it — but it
> becomes an *untested* claim the moment nobody runs `npm test` there. Either keep a periodic
> Windows run, or drop the platform from this line. Do not leave it asserted and unexercised.
>
> **Last known-good Windows run: 2026-09-17, commit a7a9688 — 121/121, 2.57 s, Node v24.18.0,
> win32 x64 10.0.26200.** Dated so the claim points at evidence rather than at nothing. The
> Android result is separately recorded in RESULTS-2026-09-17.md (119/119 on aarch64).
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

**Fix, as originally adopted:** `auth_ref` must be causally bound to the block's own
`deps`/own-log frontier — it must equal or descend from the most recent `AUTH_SNAPSHOT`
reachable from the block's own dep set at authoring time, **verified by recomputation on
ingest, not accepted on the author's assertion**. A control block whose `auth_ref`/lamport gap
from the current resolved frontier exceeds a bounded threshold is rejected outright
(soft-failed, flagged for human review) rather than merged as if it were current.

**Correction, on implementing it (see R4 below): neither half of that fix closes V1, and the
second half cannot be built at all.** Both were written before anyone tried to satisfy them.

The causal-binding half asks whether the cited grant is the most recent one in the block's own
causal cut. It is — the cut is the attacker's, and a moderator who simply does not cite their
own demotion has a cut in which the stale grant is still current. The same objection kills
every variant that compares the two blocks' lamports, because V1's own wording is *"a naturally
low lamport"*: the attacker chooses that number, and chooses it low. That is not a detail of the
attack, it **is** the attack.

The bounded-gap half measures the gap "from the current resolved frontier", which is a
receiver-local, time-varying quantity. Two honest spores holding an identical set of blocks
would reject differently and never reconcile — it is the arrival-order convergence bug wearing
a different hat, reintroduced by the fix for a different bug. **Not implemented, and it should
not be.**

What an author does not control is their own `seq`. The shipped rule is in R4.

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
| Cold-start sync, single joiner | BitTorrent-style rarest-first swarm over the mesh | Yes, bounded | N=2 → N≈5 | One shared-medium AP, honest peers, no churn | **3.55× measured (good AP) / 1.25× (phone hotspot)** vs. single-seeder; flat beyond N=4 on one AP (§3.1) |
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

### 3.1 One ceiling, and how it took three tries to measure it

The measured curve, with the shipped scheduler modelled correctly:

| N sources | sync | speedup | supply MB/s |
|---|---|---|---|
| 1 | 6.5s | 1.00x | 7.50 |
| 2 | 3.2s | 2.04x | 15.00 |
| 3 | 2.1s | 3.11x | 22.50 |
| **4** | **1.8s** | **3.55x** | **25.00** |
| 5 → 20 | 1.8s | 3.55x | 25.00 |

The knee is at **N=4**, and it is arithmetic rather than an empirical surprise: per-spore
uplink is 7.5 MB/s and the P2P-effective cell is 25 MB/s, so three sources supply 22.5 and
four supply 30 — the fourth is the first that cannot be spent. Supply pins to 25.00 MB/s and
stays there through N=20. Control B, the same scheduler with only the shared air removed,
runs 5.38x at N=5 to **46.14x** at N=20. The gap between 3.55x and 46.14x is the medium and
nothing else.

**Getting that number right took three attempts, and the first two failures are more useful
than the result.**

*Attempt 1* collapsed three distinct caps into one constant. `sync.js` limits requests **per
peer** with no global bound (6 x N outstanding across N peers); the benchmark limited them
**per joiner** (6, full stop) and additionally capped uploads per seeder, which `sync.js`
does not do at all. So twenty seeders behaved like six. Control B reported 4.25x → 4.75x and
failed its own 1.2x threshold. The tempting response — lowering the threshold to match — would
have buried the discrepancy permanently.

*Attempt 2* lifted the cap to 64 and passed at 32.30x. But a control that changes the policy
is not a control: it was now measuring a scheduler nobody ships. The 4.75x/32.30x gap was
written up in this document as a real "second ceiling" caused by request concurrency. **It
was a modelling artifact and that entry was wrong.** The shipped scheduler has no such
ceiling at N=20, because its budget grows with peer count.

*Attempt 3* separated `perPeer` / `globalCap` / `uploadCap` and imported `PER_PEER` directly
from `src/sharding/sync.js`, so the two can no longer drift. Falsifiers 1 and 2 both pass,
and control B differs from the real run in exactly one variable.

The rule this leaves behind, which matters more than the table: **a benchmark's job is to
predict the harness.** The moment it models a different policy than the code ships, a
harness measurement has nothing to check against, and any disagreement between them gets
blamed on the hardware. Constants that exist in both places must be imported, never
restated.

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
detection. **⚠ SUPERSEDED BY R4 — see below; this paragraph mandates a fix the record later
proves cannot work, and is kept because the reasoning that failed is the useful part.**

**Added by the correctness review (§1.19, mandatory SP1 scope, not optional):**
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

## Resolved Decisions

Decisions taken since the reconciliation pass. Each closes an entry below or a question the
SP2 encryption design raised.

**R1. SP1 colonies do not carry forward to SP2. Compatibility is broken deliberately.**

`ENCRYPTION.md` surfaced a migration problem: SP1 `MEMBER_JOIN` blocks predate `wrap_pub_c`,
so existing members cannot be wrapped into an epoch without a migration block and a dual-mode
read path that tolerates both plaintext and encrypted blocks during the transition.

We are not building that. Open Decision 2 was already resolved in favour of (b) — SP1 is an
internal milestone that proves scaling and mesh mechanics, not a release. Its logs contain
benchmark traffic and `pulse` messages. Building a migration path to preserve data that was
never intended to survive is speculative groundwork of exactly the kind that rots: it would
add a permanent dual-mode branch to the block verifier, and the branch's only user is data
nobody wants.

Consequence, stated plainly: **an SP1 colony cannot be upgraded. It is re-founded.** A spore
running SP2 refuses an SP1 genesis outright rather than reading it in a degraded mode, because
a reader that accepts unencrypted blocks is an attack surface that outlives the reason it was
added. `wire_version` is the gate and it is already in the HELLO datagram at offset 4.

This also removes step 0 from `ENCRYPTION.md`'s 12-step sequence: there is no migration block,
no `wrap_pub_c` backfill, and no dual-mode verifier. `MEMBER_JOIN` simply gains a required
`wrap_pub_c` field in SP2, which is the version where it first exists.

**R2. Indefinite partition: the mesh renders its own doubt.** See `docs/PARTITION.md`. The
limitation named in `ENCRYPTION.md` §3 is unsolvable and is not solved. It is made visible
instead — member fade bound to causal distance (`own_lamport − last_seen_lamport`), never to
a clock — and rotation is offered as a gesture on what the human can see, never as a
permission dialog. Implement with SP2 rotation; there is nothing to rotate before then.

**R3. Hardware target is phones, and the mesh path is Android first.** iOS multicast requires
`com.apple.developer.networking.multicast`, which Apple grants selectively by application —
it is not something that can be written blind. Android's `MulticastLock` is unprivileged. So
the SP3 target is: Android carries the mesh; iOS ships as a client onto an Android or laptop
mesh until the entitlement exists. The Braille subpixel renderer does not map to a
touchscreen and needs a canvas path, but the telemetry bus underneath it is already the right
shape and is reused unchanged — every growth stays bound to the same measured quantity.

**R4. `auth_ref` is policed by a seq pin in the revocation, not by causality or by lamport.**

§1.19's adopted fix does not close §1.19. Implementing it is what revealed that; the argument
is written out in full above and in `src/substrate/store.js`, and the short version is that
V1's attacker picks both the lamport and the dep set, so every rule phrased in terms of either
is a rule the attacker satisfies for free.

The one field an author cannot choose is their own `seq`. So:

> `ROLE_REVOKE` carries `(target_log_id, pin_seq)`, where `pin_seq` is the revoker's view of
> the target's head. A block by the target, at `seq > pin_seq`, carrying a non-zero `auth_ref`,
> **stops that log's frontier** — the same deterministic halt a bad lamport or a fork gets.

Single-writer, append-only logs make the pin inescapable: every block the target writes after
the revoker looked is above the pin, whatever lamport it claims, and writing at or below the
pin is not evasion but equivocation, which already ends the log. The rule is a pure function of
blocks held, so two spores holding the same blocks always agree.

Three consequences, recorded rather than fixed:

1. **Deterministic over-revocation.** If the pin lags the target's real head, blocks the target
   wrote in between stop too. The revoker is saying "out, as of what I had seen." Every spore
   over-revokes identically, which is the property that matters.
2. **Link-then-retract is normal here.** A spore that meets the block before the revocation
   links it, then withdraws it when the revocation arrives. That is the existing fork-cascade
   machinery on a second trigger, and it is what `design-substrate.md`'s
   `soft_failed(..., wasApplied: true)` — *"the local user saw it succeed and must be told it
   reverted"* — was always describing.
3. **Grant-of-grant is SP2, and the reason is structural.** Only the colony owner's revocations
   count, and the owner is never revoked, so the owner's frontier can never be stopped by this
   rule, so the set of valid revocations cannot shrink while frontiers are recomputed — which
   is what makes the recomputation reach a fixed point. Under delegation a counter-revocation
   can un-stop a log, which can link a revocation, which stops another; the set stops being
   monotone and the fixed point is no longer guaranteed. Delegation needs that argument
   rebuilt, not just more code.

Block type numbers follow `design/design-substrate.md` (`0x20-26`), not `ENCRYPTION.md`, whose
`0x31 MEMBER_LEAVE` collides with `design-substrate.md`'s `0x31 STATE_SNAPSHOT`.

**R4a. `colony_id = BLAKE2b(founder_log_id ‖ genesis_seq)[0..16]`, a spec addition.**

R4 makes "is this block's author the colony owner" load-bearing, and `design-substrate.md`
defines `scope_id` only as "colony_id or fruiting_id" — it never says how a colony_id is
derived. Left underived, ownership is decided by comparing two blocks anyone can write: a
fresh identity mints `COLONY_GENESIS` with `scope_id = C`, which chains, derives its lamport
and claims no authority, so it links — and about half the time its hash sorts below the real
founder's and takes the colony. Its revocations start counting; the founder's grants stop,
because they no longer come from the owner. One cheap block, whole colony locked out, every
spore agreeing.

The derivation follows the spec's own `fruiting_id = BLAKE2b(colony_id ‖ creator_log_id ‖
seq)[0..16]`, minus the parent a colony does not have, and is the same discipline as
`log_id = BLAKE2b(author_pub)[0..16]`: the name carries its own proof. A genesis whose
`scope_id` is not the derived value is **ignored**, not arbitrated against the real one — a
tiebreak is a race, and anyone can enter it. Two genesis blocks for one scope then require one
founder to have signed both at one seq, which is equivocation, and the log already ends there.

**R4c. The byte budget is best-effort in the presence of authority, and says so.**

R4b's "control blocks are never evictable" has a price, and it is not zero. This once said "nothing bounds how many a colony owner may write", which understates who can reach it: `forgetOldest` exempts a block by its wire TYPE, with no standing check anywhere in the retention path, so **any** identity — with no colony relationship at all, not even a self-founded one — can write blocks typed `ROLE_GRANT` or `ROLE_REVOKE` in their own log and have them retained forever, at the same cost per block as the owner. `#rebuildAuth` computes that they carry no authority whatsoever; retention never asks it. Reviewed and kept as a residual rather than fixed, for the reason below, but the reader should know the exposure is not owner volume. Nothing bounds how
many a colony owner may write, so a spore whose retained authority alone exceeds `maxBytes`
cannot reach it. `#trim` now scans **every** replica in descending byte order before giving up
— the previous version took the fattest, fell back to the fattest other one, and stopped, which
with two founder logs at the top of the ordering left an ordinary member's twelve evictable
messages untouched while the substrate sat 74% over budget. What the substrate guarantees is
the weaker, deliverable property: **nothing evictable is left behind**, and `substrate.over_budget`
fires when the remainder is authority, so the condition is visible rather than silent.

The bound that would close it belongs with grant semantics rather than with eviction: only the
lowest pin per `(target, scope)` can ever decide anything, and a grant matters only while
something cites it. Collapsing on that is SP2, alongside re-grant — which SP1 does not model at
all. A pin below a block's seq stops it, and no later grant lifts that.

**R4b. Eviction may never drop `COLONY_GENESIS`, `ROLE_GRANT` or `ROLE_REVOKE`.**

The byte budget forgets the oldest linked blocks first, and the oldest block in a founder's log
is its `COLONY_GENESIS`. Under the plain rule the budget becomes a laundering channel: forget
the genesis and the colony has no owner, so every member's authority claim stalls; forget a
`ROLE_REVOKE` and its pin goes with it, so the demoted moderator's blocks link again. A spore
would re-admit everyone it had ever removed for no reason except having been running a while,
and nothing would report it. Control blocks are ~290 bytes and they stay; the floor advances
past them and they sit below the chain-verifiable range as authority-only, which is what they
are once their neighbours are gone.

Found with them, in code that predates all of this: **a frontier collapsed on the first
recomputation after any eviction.** `relink()` restarts at `floor` and needs its predecessor's
hash and lamport, which eviction had deleted. It never fired because a full recompute only ran
on a fork and no eviction test forked — authority made recomputation routine. A 20-block log
evicted to floor 15 held `linkedTo 19` until something forced a recompute, then fell to 14 and
promoted nothing, permanently. The replica now keeps the hash and lamport of the block it
forgot at the floor: 40 bytes, and the difference between forgetting old history and forgetting
everything above it.

**R4d. A replica has three frontiers, not one, because ordering and permission are
different questions.**

R4 made "who may write what" load-bearing, and reading it from the wrong frontier put a
cycle in the substrate. Authority was read from `linkedTo`. But an owner who replies to a
member cites that member's block as an ordinary dep, so `linkedTo` for the owner depends on
`linkedTo` for the member, which depends on authority, which depends on the owner. Traced:
the revocation links → the member's block stops → the owner's reply stalls on it as a dep →
the revocation is now above the owner's own frontier and stops counting → the member's block
links again. Round and round, four rounds, then a cap.

It converged identically on every replica, so the convergence property never saw it. It
converged on the wrong thing: **the owner stranded at seq 1, holding an unlinked revocation
they had written themselves.**

| frontier | what it proves | what needs it |
|---|---|---|
| `chainTo` | signature + `prev_hash` continuity | **authority** — who wrote this, and where in their log |
| `orderedTo` | + lamport derives | **deps** — where a block sits in causal order |
| `linkedTo` | + authority | **delivery** — what a reader is shown |

Each is strictly weaker than the next, and the split is what breaks the cycle at the root.
Whether a block was written by this author, and where in their log, is settled by the
signature and the chain; it never needed to wait on some earlier block of theirs having its
lamport confirmed against a dep in somebody else's log. And a block written by someone who
had lost their role still *happened* and still sits at a definite causal position — making
deps wait on delivery is what stranded the owner.

Consequences, all of them found by falsifying rather than by reasoning:

- **Authority is settled once per resolution, not iterated.** It is a pure function of the
  blocks held, so the four-round grow-then-rebuild loop is gone. The remaining loop is the
  genuine one: linking log A can unblock a dep in log B.
- **The trigger is arrival, not linking** — and specifically "an authority block came into
  reach", which is not the same question as "a control block arrived". A revocation can sit
  held-but-unchained above a gap until an *ordinary message* fills it.
- **Deps carry a lamport witness.** Eviction deletes a block and its hash index together, so
  a recomputation that re-resolved deps stranded every log that had cited forgotten history.
  Each block records its deps' lamports when first ordered — `floorLamport` generalised from
  the one predecessor to all N. It is a **fallback, not a cache**: live evidence always wins,
  or a dep retracted by a late fork keeps a stale lamport and the answer depends on arrival
  order again.
- **Ordering progress counts as progress** in the fixpoint. A log whose every block is
  stopped by a revocation still *orders* them, and another log's dep resolves against that.
  Counting only promotions ended the loop early, and which logs had run by then depended on
  `Map` insertion order.

Not fixed, and not introduced by any of this: **a fork at a seq already evicted can no longer
be detected**, because detection is a collision at that seq and nothing is left to collide
with. That is a property of forgetting.

**R4e. The eviction floor can never outrank a fork, and a forgotten block's position is
remembered.** Both found by adversarial review with working repros, both fatal, both the
same shape as everything else in §1.19's family: a bound that was stated in a comment
rather than enforced in code.

*The fork below the floor.* `#recordFork` clamps `chainTo` and `orderedTo` to the fork seq
— and `#resolveFrontiers` then resets every frontier to `floor - 1`, which on a replica
that had already evicted past the contradiction put them straight back above it. The same
gap let `#rebuildAuth` keep honouring a revocation sitting below the floor but above the
fork, because "below the floor" was trusted without ever asking about `forkedAt`. Two
replicas, same blocks, same proof, opposite answers about who held a role. **The floor now
comes down with the fork**, and the floor witness goes with it: it described a block on a
branch we no longer stand behind.

*The dep forgotten before its citer arrived.* R4d's `depLamports` witness carried a comment
claiming "eviction only takes blocks below a frontier, so anything citing them had already
ordered them". True of a citer already held; **false for one that arrives afterwards**,
which never had the chance to resolve it live and so has nothing cached. It stalled
permanently on that replica while another, which happened to meet the citer first, linked
it. A replica now keeps `hash → lamport` for what it forgets, capped at `LOST_CAP = 4096`
with oldest-out; past the cap a citer genuinely stalls, and that stall is honest because
every replica on the same budget forgot the same thing.

**R4f. Re-resolution runs only when the derived authority actually changed.** The trigger
for a full substrate-wide rebuild was a block's *wire type*, evaluated before anything
asked whether its author had standing — so one free identity could mint `ROLE_REVOKE`
blocks in its own log and buy an O(held) rewalk, two BLAKE2b hashes per block, with each
one. The bound is not a cheaper scan: it is refusing to rewalk when the derived authority
is byte-identical to last time, which only someone who really holds authority can change.
A block whose authority changes nothing falls through to the ordinary local relink, so it
still links if it deserves to — skipping both was the first attempt and was worse than the
DoS, because an authority block that changed nothing then never linked at all.

**R5. Glass stays loopback-only. Viewing a spore from another device is what the mesh is.**
The obvious convenience — bind the LAN so a phone can watch a laptop's spore — is building
a second, worse copy of the hypha in HTTP, with a URL token standing in for a Noise
handshake. R3 already settled that the mesh runs *on* Android: the phone runs its own
spore, joins the colony, and sees it in its own glass, authenticated by the protocol that
exists for exactly that. A spore holds a mesh identity and other people's traffic, and a
debug surface that speaks HTTP to the network is the easiest thing in this repo to attack.

**R6. Re-grant: `ROLE_GRANT` carries a pin too, and one ordered list replaces two rules.**

SP1 had no way back in — a pin below your seq was permanent. Both control types now name a
**boundary** in the target's log (a grant governs from `pin_seq`, a revocation from
`pin_seq + 1`) and live in one ordered list per `(target, scope)`, sorted by boundary then
by position in the owner's own log. The block governing any seq is the last boundary at or
below it. That single lookup subsumes the pin scan it replaces; keeping both would have
been two rules that can disagree.

A design written before this and discarded: a grant's *effective* boundary as
`max(pin_seq, k+1)` over every earlier revocation. It is subsumed by "largest boundary
wins", and having both would have meant reconciling them forever.

**V1 stays closed, and for free.** An owner who revoked at `k` and then re-grants at pin 0
has not pardoned the replay at `k+1`: the revocation's boundary `k+1` is still the largest
at or below `k+1`, so it still governs and still stops. Lifting a stop must be said out
loud, with a pin at or above `k+1`, and the tie-break then hands it to the later block.
Intent has to be written down; it cannot be arrived at by accident.

Three things this costs, all recorded rather than fixed:

1. **A member who wrote while revoked is out for good.** `linkedTo` is a contiguous
   watermark over a single-writer hash chain, so a block that stops the frontier stops
   everything above it — no later grant reaches past a hole, because a hole in a hash chain
   cannot exist. Re-grant restores a member who stayed quiet. One who kept writing ended
   their own log at the first unauthorised block, and their remedy is a new identity, which
   is a new log. That is honest: the old log really does contain blocks nobody authorised.
2. **The cited grant must be in force, not latest.** "Cite the newest grant" was written
   first and is retroactively destructive — an owner writing a broader re-grant would
   supersede the original *for seqs already delivered under it*, and history valid when it
   arrived would stop. An owner being generous must not break the past. So the test is that
   the cited grant covers this seq and no revocation reaching this seq superseded it.
3. **A restored member must cite the new grant.** The corollary, and the one that
   falsification caught missing: after revoke-then-re-grant the *governing* entry for the
   member's next seq is the new grant, so a block citing the old one is inside an
   authorised range. Allowing it would make a revocation meaningless to anyone holding the
   old grant's hash — which is everyone, because it is a block and it replicates.

`GRANT_LEN` moves 20 → 28, matching `REVOKE_LEN`. The SP1 wire break is free under R1. The
two payloads now share a layout, so length no longer distinguishes them: the block **type**
does, at header offset 1, inside the signed region. Length-sniffing was never the real
defence; it worked by coincidence while the two differed.

**R7. Second review round: the rule was read two ways, and the tests could not tell.**
Five lenses over the substrate after R6 landed, each strongest finding adversarially
verified, then the rest hand-triaged and a second skeptic pass over what survived. Ten of
twelve findings confirmed, one refuted, one minor. The three worst are below; the fourth
entry is the one that matters most, and it is not a bug.

*Supersession asked the question by the wrong key.* `#authCheck` computed **which statement
governs this seq** by boundary, then computed **was the cited grant superseded** by the
owner's log-write order. R6 exists so there is exactly one rule and the two can never
disagree — and they disagreed, in the commit that introduced R6. Wrong in both directions:
a revocation pinned at 1 cancelled a grant covering seq 5 (whose range begins four seqs
above where the revocation's ends), and a revocation written before a grant never cancelled
it however far its range reached. The layered case stranded six blocks of a sixteen-block
log permanently, on every replica, deterministically. `ownerSeq` breaks a tie at EQUAL
boundary; it is not the comparison. Found independently by three of five lenses.

*`MAX_SEQ` was enforced everywhere except where seq is used.* `decodePairs` and `decodeHave`
checked it; BLOCK never did, because its seq lives inside the signed cert and never passes
through either. That is the one message type that sizes `LogReplica#bits`. A single
~300-byte signed block requested a ~596 MB buffer, and ~59.6 GB was also accepted. Desktop
overcommit makes that nearly free, which is exactly why nothing noticed; the target is a
phone. Now enforced at `insert()` — the single funnel every block passes through — and
ahead of `ensure()`, which was minting a replica for blocks about to be refused.

*The floor could outrank a revocation boundary.* R4e's sentence about forks, never written
for revocations. Under a tight budget a member delivered and then evicted before the
owner's word arrives leaves the floor ABOVE the boundary; `#resolveFrontiers` resets every
frontier to `floor - 1`, above everything the revocation was about, so the rewalk never
examines a revoked block. Revocation last: `linkedTo` 8. Revocation first: `linkedTo` 3.
Both replicas holding that same revocation, which neither can have forgotten because
AUTHORITY is `KEEP_FOREVER`. The clamp respects supersession — only a boundary whose
*governing* entry is a revocation stops the log, or re-grant would break outright.

**Superseded, and the correction belongs here rather than quietly in the code.** The clamp
above shipped and was wrong twice, so it is gone. It was too big: the floor governs
chain-verification and ORDERING as well as delivery, and a revocation is a statement about
delivery alone — dropping the floor onto an already-evicted seq stranded blocks that were
held and perfectly orderable, and other logs resolve their deps against `orderedTo`. And it
was incorrect: the clamp scanned the rule list for a boundary whose *governing* entry is a
revocation, which is a second, hand-rolled answer to "which entry governs" — the
two-rules-for-one-question shape R6 exists to forbid — and it disagreed with `#authCheck`
wherever a re-grant TIES a revocation's boundary. The scan sees a grant win the tie and
lowers nothing; `#authCheck` still stops every block citing the older grant, because the
revocation's boundary is above that grant's. Live divergence: `linkedTo` 8 on a replica that
had evicted past the boundary, 3 on a fresh one, same blocks, same rule list. It is scenario
X in `test/auth.test.js`, with mirror Y guarding against a fix that closes X by breaking
re-grant outright.

No rule computed from `(floor, rule list)` alone can be correct, and that is the lesson worth
keeping: **the verdict for an evicted seq depends on what that block CITED, and eviction had
deleted it.** So the fix is the third witness. `floorHash` witnesses the chain;
`floorLamport` and `lost` witness ordering; nothing witnessed the CLAIM. `LogReplica#claims`
now remembers what forgotten blocks cited, run-length, and `#forgottenStop` re-derives the
delivery frontier by running the same `#authCheck` against it — one reading of the rule, with
nothing left to disagree with.

R7's own argument against the alternative was also wrong, and R8 records why: "a revoked log
stops being evictable" is true of the shipped clamp too, and in fact of every replica before
and after R7, because `forgetOldest` iterates below `linkedTo` and nothing above a permanent
stop ever is. It never discriminated between the designs.

**The residual this leaves, stated rather than discovered later.** Delivery below the floor is
now re-judged from a witness, so it is bounded the way ordering's is: `CLAIMS_CAP` runs per
replica, oldest-out, where a run is one `(scope, auth_ref)` pair — a member citing one grant
costs a single entry however long they write, and only an author alternating citations block
by block reaches the cap, on their own log alone. Past it, the oldest forgotten history keeps
the verdict it was delivered under, which is the pre-R7 behaviour confined to what fell off
the end, and a revocation reaching that far diverges from a replica that still holds the
blocks. Two facts are unchanged by any of this and are recorded so nobody re-derives them: a
log stopped by a revocation cannot shed the blocks above the stop on any replica; and a fork
at a seq this replica has already forgotten cannot be witnessed locally, only learned from a
peer's proof — which is why the property harness now replays `knownForks()` between replicas
before it compares them, as `sync.js` does at every hypha setup.

**What is not closed, and is not mine to claim closed.** The advisor pass that produced this
design ran a wider sweep than the suite does — 300 seeds across three budgets, fresh plus four
tight shuffles — and reported 248 of 900 worlds diverging before these changes and 38 after,
every remaining one on `orderedTo` and none on delivery. That sweep ran on a separate copy, and it has since been
reproduced here independently. A widened harness at 300 worlds with **every** seed tight — the
committed suite makes only one seed in three tight — diverges on 12, which is 4.0% against the
advisor pass's 4.2%, and **every one of the twelve is an ordering divergence, with zero
delivery-only cases**. A first attempt at classifying them reported the opposite and was wrong:
`linkedTo <= orderedTo` holds by construction, so an ordering divergence drags delivery down
with it, and counting that as a delivery fault reports one fault as two. The committed suite is
116 green at 60 seeds, which is a weaker statement than the sweep and is the one the suite
actually defends. The shape it describes is a citer that was ordered, evicted, and whose dep a
later fork in another log withdrew. One instance of that shape — seed 48 — is fixed, because
`lost` now carries the seq and reports a retraction instead of laundering it. Whether others
survive is open. The witness for that class is the dep list, which is the block header, and
keeping headers past eviction would subsume `floorHash`, `floorLamport`, `lost` and `claims`
in one mechanism. **That** is the SP2 storage question — the one this record previously
misfiled the delivery half under.

*Beneath all of it: agreement is not correctness.* Every property in `test/property.test.js`
asserted CONVERGENCE — replicas fed the same blocks in any order reach the same state. The
supersession bug was deterministic, so every replica computed the identical wrong verdict,
agreed perfectly, and passed every seed. No generator and no number of seeds could have
found it, because the property being checked was not the property being violated. That gap
covered every authority rule in the codebase, not just this one. The fuzzer was separately
blind in two ways worth recording — it emitted the revocation before the re-grant
unconditionally, so boundary order and owner-log order never diverged; and members could
only ever cite the first grant, so the supersede path was unreachable. Both are fixed, and
an oracle now checks the frontier against a second, deliberately naive reading of the same
rule list. It is a regression oracle, not a discovery oracle: it catches a CONSUMER
diverging from the rule the PRODUCER built, which is what this bug was. If R6 itself is
wrong, both readings are wrong together and it stays silent.

**R10. What is held above the frontier has a lifetime, and SP1 has a stop rule.** Two
decisions the project had never made, found by an advisor pass that was asked what the session
was systematically avoiding rather than what was next on the list. Neither was deferred or
disputed. Neither had been raised.

*The lifetime of held-but-unlinked state.* `forgetOldest` iterates `[floor, linkedTo)`, so
nothing above the delivery frontier is evictable or counted — and `test/sync.test.js` asserts
`bytes > budget` as the CORRECT outcome for a substrate of unlinked blocks. Separately,
`rarity()` scans `this.total`, which `#totalFor()` sets from the largest head any PEER claims,
and `#recvHaveAdd` allocates a Bitfield per (log, peer) from the same claimed number.

**These are one bound, not three.** Every one of them is sized by a number the peer chooses
rather than one we hold. That is why lowering `MAX_SEQ` could not fix it and never will: the
multiplier is a quantity we do not control, and a bound that depends on an attacker's restraint
is not a bound. Three candidates were considered:

> (a) **Distance from the frontier.** Never request, and never retain, more than a window `W`
> above `linkedTo` per log; evict farthest-first. Bounds the scan, the allocation and the
> unlinked bytes together.
> (b) **Bytes only.** Count unlinked blocks against `maxBytes` and evict them, farthest above
> the frontier first, before any linked history.
> (c) **The delivering hypha's lifetime.** Rejected: an honest late joiner loses partial
> fetches when a peer withers, which is the common case rather than the adversarial one.

**Adopted: (a) and (b) together.** There is no clock in this substrate and there is not going
to be one, so a lifetime has to be expressed in blocks or bytes. (a) alone leaves the cross-log
multiplier — `W` per log still multiplies by `MAX_LOGS` — and (b) alone leaves the scan cost,
which is CPU rather than memory. **`W` itself is deliberately not fixed here**, because it caps
parallel fetch depth and therefore trades against the product claim that distant blocks can be
fetched at once from different peers. It must be justified against the 400-block harness and
against honest colony scale, not chosen to make a test pass.

*The lifetime of SP1 itself.* Every adversarial pass this project has run has found more fatal
bugs, and the list has never had a terminating rule. "Keep hardening until the advisor stops
finding things" is not a condition — it is a description of an unbounded loop, and it is what
the last several sessions have actually been doing.

> **SP1 is done when:** (i) every attacker-chosen number that sizes an allocation or a scan —
> `seq`, `bitlen`, `dep_count`, log count, peer count, claimed head — has a test asserting that
> work scales with what WE hold rather than with what a peer claims; (ii) nothing published
> rests on `bench/curve.js` alone; (iii) the knee is either measured on four devices or
> declared unmeasured in every place it is quoted.

Not "when it is bug-free". Condition (i) is the one that generalises: the five instances of
this project's signature failure — `forks`, `KEEP_FOREVER`, `MAX_SEQ`, `dep_count`, `rarity()`
— are all the same sentence, which is that **the bound was placed on the number and not on the
product.** The check is a test that multiplies.

*A caveat on the whole frame, recorded because it outranks the rest.* The eviction machinery
this decision governs — R4b through R7, `floorHash`, `floorLamport`, `lost`, `claims`,
`#forgottenStop` — defends a process that runs long enough to accumulate `MAX_BYTES`. For text
traffic `docs/RESULTS-2026-09-17.md` puts that at roughly 150–220K messages colony-wide.
Meanwhile `bin/spore.js` regenerates the identity on every launch, nothing in `src/` writes
anything to disk, and `docs/TERMUX.md` records that the target platform kills the process
routinely. **So the subsystem this project has worked hardest on protects state that the
platform's ordinary behaviour destroys first**, and a founder who restarts loses their colony,
because `colony_id` is bound to the founder's `log_id`. Persistence appears in no §5 item and
in no deferred list. It is not a residual; it was invisible. SP2 step 1 is blocked on it
regardless, since `wrap_seed` derives from a `master_seed` assumed to be at rest.

**R9. The first hardware measurement may be measuring us, not the radio.** `docs/RESULTS-2026-09-17.md`
records SPORE running on an Android tablet: 119/119 unmodified, multicast discovery working,
and one source delivering 7.5–13.7 MB/s. The throughput figure is now caveated in place and the
interpretation drawn from it — that §3.1's uplink constant is merely pessimistic — is withdrawn.

`MAX_INFLIGHT_PER_PEER` is 6 and a BLOCK is 33,100 bytes on the wire, so at most 198,600 bytes
are outstanding to one source. At the measured 9 ms RTT that caps a single source at 21.0 MiB/s;
at the 17 ms max, 11.1. Every measured value falls inside that ceiling, and the ~1.8x
run-to-run variance is what RTT jitter against a fixed window produces. `bench/curve.js` models
`RTT_MS = 3`, where the bound sits at ~63 MiB/s — so **the simulation could not exhibit the
limit the hardware may have been hitting, and the two agreed while measuring different
quantities.** That is the worst way for two numbers to agree, and it is worth recording as a
method failure rather than only as a number to fix.

**R8. A fork proof is evidence of one fact, so one is kept — and a proof that moves nothing
is free.** The last of the second round’s fatal findings, and the sharpest instance yet of
this repo’s failure shape: not a bound stated in a comment rather than enforced, but a
comment that misdescribed the line beside it. `this.forks` was declared “seq -> { kept,
other } block hashes” and stored two full certificates — ~520 bytes an entry against the 64
the comment implied, an 8x undercount that is presumably why nobody costed it. Nothing
bounded the map: `#trim` and `forgetOldest` touch only `r.blocks` and `r.bytes`, so
`maxBytes` never saw it however tight it was set, and `acceptForkProof` reached it without
paying the ordinary block-storage path at all.

The CPU half was worse and is the part that matters. `#recordFork` forced
`#resolveFrontiers(true)`, and `force` exists precisely to bypass R4f’s refusal to rewalk
when derived authority is byte-identical. Its gate was `lowered` — a condition the attacker
chooses. Proofs in DESCENDING seq order are each lower than the last, so every one bought a
full substrate-wide rewalk while nothing could possibly have moved: R4f’s own DoS, reopened
one function over, through a door `sync.js` holds open to anyone with no rate limit and then
replays to every new hypha. **The gate is now whether a frontier or the floor actually
shifted.** A fork above everything held retracts nothing and costs nothing; a fork that
genuinely invalidates held history still pays, because that work is real. The test asserts
both directions, so the fix cannot have been bought by refusing real work.

A log that forked at 3 has ended at 3, so only the lowest proof is retained, and
`acceptForkProof` now treats `seq >= forkedAt` as a duplicate — cheaper and stronger than
asking the map for one exact seq.

`#recordFork`’s floor clamp is deliberately untouched. **That** clamp is R4e’s and is sound:
a fork ends chain, ordering and delivery together, so lowering the floor to it strands
nothing orderable. R7’s revocation clamp copied R4e’s sentence “with one word changed”, and
that is exactly where it went wrong, because a revocation ends delivery only. The asymmetry
between the two is the argument for revisiting R7, and R7’s stated reason for rejecting the
`linkedTo` bound — “a revoked log stops being evictable” — does not survive contact with it:
after the shipped clamp, `forgetOldest` iterates `[stop, stop - 1)`, which is empty too. The
objection never discriminated between the two designs. Nor was `orderedTo` the only difference,
as this once said: both clamps were CITATION-BLIND, so the one that shipped was incomplete as
well as costly. R7 has the tied-boundary divergence it could not see, and the witness that
replaced it.

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
   ~~The fix (`auth_ref` recomputation, bounded staleness rejection) closes the specific
   replay this review found.~~ **Superseded by R4: that fix closes nothing.** Implementing it
   is what revealed it — V1's attacker picks both the lamport and the dep set, so every rule
   phrased in terms of either is a rule the attacker satisfies for free. What closes V1 is
   R4's `pin_seq`, refined by R6 and R7.

   The *recommendation* in this entry was right, and was taken: a further adversarial pass ran
   against the corrected resolver rather than trusting the worked example. It found **seven
   fatal bugs**, three of them in the commit that had introduced R6. See R7, R8 and R9.

   The lesson this entry drew — that the worked example demonstrated agreement, not safety —
   turned out to be narrower than the truth. The property suite asserted that replicas AGREE,
   and a deterministic logic error makes every replica agree perfectly on the wrong answer. The
   mistake was not trusting one worked example; it was checking the wrong property.
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
