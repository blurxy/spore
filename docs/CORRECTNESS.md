# SPORE — Correctness Review

Status: **this is the correctness review that was missing.** The original adversarial
`correctness` pass (referenced in `ARCHITECTURE.md` §1.10 as originally written) returned 212
characters of placeholder text and the literal string `"test"` as its conclusion. Nothing
about security or convergence had been checked. This document is that review, done twice,
from two independent lenses, against `docs/design-substrate.md`, `docs/design-crypto.md`,
`docs/design-app.md`, and `docs/ARCHITECTURE.md` (which had already reconciled roughly a
dozen cross-subsystem conflicts in its §2 — this review's job included checking whether those
resolutions were *correct*, not merely decisive).

Every FATAL and SERIOUS finding below has been folded into `ARCHITECTURE.md`: into §1 as a
numbered remediation, into §2 where a prior resolution was itself wrong, into §3/§4 where
scaling claims or interfaces needed qualifying, and into §5/Open Decisions/Killer Risks where
scope or residual risk changed. The cross-reference table at the end of this document lets a
reader verify that every fatal/serious finding actually landed somewhere in the reconciled
architecture, rather than trusting a prose claim that it did.

---

## Lens 1: crypto — verdict BROKEN

**The crux, restated:** shards must be fetchable from untrusted VAULT spores while unreadable
by them, and still readable by a member who joins later. The proposed mechanism
(`design-crypto.md` §5) is "encrypt-then-address" (BlockID = hash of ciphertext, so a VAULT
verifies and serves without ever holding a key) plus an MLS-style GGM secret tree for
per-message keys, with a KEYBUNDLE that wraps every historical `epoch_root` to a new joiner.

In isolation this is not a fantasy: it is structurally the same move Signal's sender-keys and
MLS's ratchet tree make, adapted to avoid MLS's ordered-commit requirement, and the "32 hashes
regardless of index" GGM seek genuinely supports out-of-order, random-access decryption from
many VAULTs at once — exactly what BLOOM-style parallel fetch needs.

But "was it actually solved" has to be answered against what ships. `ARCHITECTURE.md` is
explicit that none of it ships in SP1: `KEYRING.rotateEpoch`, `unwrapEpochRoot`, `keybundle`,
`messageKey` (GGM tree), `sealBlock`/`openBlock` — all deferred to SP2, and "SP1 fruitings are
signed but not encrypted at the block level." So for the actual shipping SP1 product, the crux
is not merely imperfect — it is entirely absent: every VAULT, RELAY, and bystander spore can
read every message in full, because there is no ciphertext, only a signed cleartext payload.
The design is honest about this in prose (Open Decision #2: "signed-but-plaintext at the block
level ... a materially weaker privacy posture," recommending "do not ship SP1 to real users
until encryption lands") — that honesty deserves credit, it is not a buried admission — but it
is only a recommendation sitting in an Open Decisions appendix, not a binding release gate, UI
requirement, or CI check wired into the actual SP1 scope section. A security review has to
treat an unenforced recommendation as equivalent to "will probably ship anyway."

Turning to the SP2 mechanism that is supposed to eventually solve the crux, several
load-bearing pieces are either contradictory or silently dropped by the very reconciliation
pass (§2) that claims to have resolved cross-subsystem conflicts.

**Authorization for EPOCH_ROTATE — the single hard lever the whole revocation/eviction story
depends on — is contradictorily defined.** `design-app.md` §4 reserves it to the owner alone
("allow all except owner-only ... unilateral EPOCH_ROTATE"). `design-crypto.md` §5 says the
opposite: "Rotation requires the EPOCH_ROTATE right (or any member acting on a membership
change they witnessed)" — a permissive, self-reported trigger with no defined verification of
"witnessed." Neither model has a bit in APP's own permission bitmask. `ARCHITECTURE.md` §2
reconciles the *mechanics* of the two permission resolvers (SUBSTRATE's two-pass Pass A/B vs
APP's bitmask) but never notices the semantics for this specific, safety-critical op are
undefined and contradictory between the two documents it reconciles. Owner-only means a
partitioned sub-mesh whose owner is offline can never cryptographically exclude a locally
banned member, directly falsifying `design-app.md`'s "real cryptographic eviction" claim in
exactly the partition scenario this review stress-tested. The permissive reading lets a
Sybil-cheap, zero-power identity mint a validly signed epoch root and force rotation storms,
or fork the confidentiality domain along a partition boundary it chooses — precisely what
crypto.md itself says the signed-block requirement exists to prevent.

**A read-capability gate for INDEX/FORGE was raised explicitly and dropped silently.**
`design-crypto.md`'s contract-conflicts section states plainly: "ROLES must carry a
read-capability predicate: INDEX and FORGE cannot be zero-trust ... Capability scoring
therefore needs `has_read_cap(colony)` as a hard gate." `ARCHITECTURE.md` §2 resolves roughly a
dozen conflicts and this is not one of them; §4's ROLES section only changes the HRW hash
input and CAP_ADVERT transport. Once encryption ships and INDEX/FORGE actually need plaintext
to do their job, generic HRW capability-tier assignment can hand indexing or thumbnailing duty
to any high-scoring spore regardless of colony membership — either the §3 scaling table's
unqualified "Full-text index build"/"Search fanout" rows are wrong once colonies are
encrypted, or plaintext gets handed to a non-member, which is the crux violated one layer
above VAULT storage. Raised, then dropped silently — worse than an open conflict, because the
reconciliation document's silence reads as resolution.

**Revocation in a partition, walked concretely.** Member B is banned by admin A; A's device
appends `MEMBER_BAN` and triggers `EPOCH_ROTATE` to `epoch_root_2`, wrapped only to members A
currently believes are current. If B is simultaneously partitioned off with member D who has
not yet seen the ban, D's local permission evaluation still shows B as ALLOW — this exact
failure mode is self-identified in `design-app.md`'s Risks ("a malicious spore that has seen
its own role revoked can keep posting to peers that have not yet received the revoke") — so B
can write messages D renders as normal for as long as the partition lasts, an unbounded window
since there is no consensus or gossip timeout. On merge, ban absorbs per substrate.md's CRDT
table; B's posts get retroactively soft-failed going forward, but D already rendered and
possibly acted on them — the "un-ring the bell" problem the docs correctly do not pretend to
solve. Critically, even after merge, B permanently retains `epoch_root_1` (and any earlier root
their entitlement policy gave them at join) — a symmetric secret cannot be revoked from a
device that already holds it — so B can decrypt, forever and offline, every message encrypted
under any epoch they once held. This is explicitly and correctly disclosed in crypto.md §4/§6
("essentially no forward secrecy for history you chose to replicate") — confirmed accurate,
not overstated. What is *not* stated in one place: the flat SP1 consequence — with no
encryption, `not_after = 0xFFFFFFFF` permanently and `exp` advisory-only, a SP1 "ban" has zero
cryptographic content and is purely a rendering hint compliant clients choose to honor.

**The KEYBUNDLE's "readable by a later joiner" half is structurally sound but relocates,
rather than eliminates, a trust dependency.** A joiner's ability to decrypt history depends on
a *live admitting member* holding and correctly wrapping every historical `epoch_root` at
admission time — not on VAULTs, which never see keys. If the admitting device is offline,
crashed, or its identity key rotated between `MEMBER_JOIN` and KEYBUNDLE delivery (a path
unspecified in both docs), a legitimately admitted member has no keys, with no interface event
surfacing this failure.

**Noise XX wire arithmetic does not reconcile with its own field layout.** MSG2 =
32 (`e_pub_r`) + 48 (encrypted `s_pub_r`) + 2 (length prefix) + 184 (168-byte payload + 16-byte
tag) = 266 bytes; MSG3 = 48 + 2 + 184 = 234 bytes — both exactly 10 bytes larger than the
doc's claimed "measured" 256 and 224. Independent of whether this is a typo or a spec bug, a
load-bearing wire format that doesn't reconcile with its own documented layout is a red flag.
Separately, canonical Noise XX resets the nonce to 0 at every MixKey boundary, but the doc's
own notation shows sequential nonces 0 then 1 within msg2 and again within msg3 in a way that
reads as one continuing key rather than two freshly reset ones. The design's own Risks section
already flags "no Node-stdlib Noise test vectors in-tree" and calls "transcripts agree, both
signatures verify" self-interop rather than spec-conformance — correct, and this needs the
official Noise test vectors before it can be called correct, not assumed correct because the
prose is confident.

**Equivocation detection is real but conditional, not universal.** Two conflicting blocks at
one `(log_id, seq)` are only detected when some third party's `deps` bring both hash prefixes
into a single spore's view — an attacker who equivocates cleanly to two sub-meshes that never
gossip with each other evades detection indefinitely. Inherent to fork-consistency designs
generally, not unique to SPORE, but the doc's confident framing ("cryptographic proof of
forking") undersells that detection requires gossip overlap it does not guarantee within any
bound.

**Snapshot poisoning requires only `min(3, active_spores)` distinct log_ids.** Identity
creation is one free ed25519 keygen with no proof-of-work, stake, or device attestation
anywhere in the design, so a single attacker process can mint as many identities as needed to
satisfy this trivially. The design's own Risk calls this "a weak Sybil barrier" — in the exact
zero-infrastructure LAN environment this system targets, it is closer to no barrier at all
against a single machine.

**Metadata leakage is a complete social graph, quantified directly from the 196-byte
substrate cert plus crypto.md's own two-tier cleartext outer envelope.** Any VAULT or RELAY —
including one relaying for a colony it isn't a member of, which the design explicitly permits
— reads `type`, `log_id` (permanent identity, unchanged across colonies since §2 dropped
per-colony subkeys), `seq`/`lamport` (exact causal/temporal position), `wall_ms` (near-exact
real time), `scope_id` (colony + fruiting), `deps` (whose recent activity this author was
causally following — a social graph), and `payload_len` (bucketed size). Only the message body
is hidden once SP2 ships. The design's own Risks section calls this "worse than the message
content" for some threat models — accurate, not overstated. Compounding it: §2's
identity-binding resolution (one global ed25519 key for hypha auth *and* every colony's log
authorship) silently overrides `design-app.md`'s stated default ("cross-colony correlation is
opt-in, default uncorrelated" via per-colony HKDF subkeys) — a privacy regression introduced as
a side effect of an unrelated conflict resolution and never priced or logged as a cost.

**Net assessment:** the crux's proposed SP2 mechanism is a legitimate design pattern in
outline, but it is not shown to hold. It does not ship in SP1 at all (an honest but unenforced
deferral). As specified for later, its sole enforcement lever is gated by a permission two of
the four reconciled documents define contradictorily and that ARCHITECTURE's reconciliation
pass never touched; its declared read-capability precondition for INDEX/FORGE was raised and
then dropped without a fix; and several supporting cryptographic claims (X25519-static forward
secrecy for the wrap path, invite non-replayability, Noise wire sizes) are either unverified or
weakened by later changes without comment.

### Crypto lens — Failures

**[FATAL-C1]** A member with a granted role but not ADMIN/owner witnesses a `MEMBER_BAN` in
their partition and, per crypto.md §5's "or any member acting on a membership change they
witnessed," attempts to mint `EPOCH_ROTATE` to exclude the banned peer locally; app.md §4
reserves `EPOCH_ROTATE` strictly to the owner, with no bitmask bit for it at all.
- *Mechanism at fault:* app.md §4 permission evaluation order vs crypto.md §5's EPOCH_ROTATE
  trigger rule, unreconciled by ARCHITECTURE §2's permission-resolver merge.
- *Consequence:* Owner-only ⇒ a partitioned sub-mesh with an unreachable owner can never
  cryptographically exclude a locally banned member, falsifying app.md §10's "real
  cryptographic eviction" claim in exactly the partition scenario this review stress-tested.
  Permissive ⇒ a zero-power, Sybil-cheap identity can mint a validly signed epoch root and
  trigger rotation storms or fork the confidentiality domain at a boundary it chooses.
- *Fix:* Derive the right, don't grant it: valid iff authored by the genesis owner, or by the
  same `log_id` as an accepted `MEMBER_BAN`/`KICK`/`LEAVE` it cites in its own `deps` — no new
  subjective "witnessing," no new bitmask bit. (Adopted into ARCHITECTURE §2/§4; see
  cross-reference table.)

**[FATAL-C2]** Once SP2 ships encrypted fruitings, ROLES assigns `INDEX_SEGMENT`/`THUMB_IMAGE`
work via ordinary HRW capability-tier scoring to whichever spore scores highest, with no check
that the recipient holds a colony read capability.
- *Mechanism at fault:* crypto.md's contract-conflicts note ("has_read_cap(colony) as a hard
  gate") raised and never adopted anywhere in ARCHITECTURE §2 or §4's ROLES section.
- *Consequence:* Either full-text search/thumbnailing silently stop scaling past the (usually
  much smaller) set of members who hold read caps, contradicting the unqualified §3 scaling
  rows, or plaintext colony content is handed to a non-member spore — the crux violated one
  layer above VAULT storage.
- *Fix:* Add `has_read_cap(colonyId)` as a hard precondition in ROLES' capability scoring for
  INDEX/FORGE tiers; qualify §3's search/index scaling rows by member-count once encryption
  ships.

**[FATAL-C3]** SPORE is packaged and distributed as the "off-web Discord x Telegram" platform
at SP1, which defers all epoch-encryption machinery to SP2 and states "SP1 fruitings are
signed but not encrypted at the block level."
- *Mechanism at fault:* ARCHITECTURE §4 SESSION/KEYRING scope note and §5 SP1 scope, versus
  Open Decision #2's unenforced recommendation.
- *Consequence:* Every VAULT, RELAY, and bystander spore — including ones relaying for a
  colony they don't belong to — can read every message body in full. The stated crux does not
  exist for SP1; the only safeguard is a non-binding appendix recommendation.
- *Fix:* Wire the disclosure into shipped scope itself: a hardcoded, non-dismissable UI banner
  naming the colony as unencrypted. (Adopted into §5 regardless of which Open Decision #2
  branch is chosen — see cross-reference table.)

**[SERIOUS-C4]** An attacker compromises one device's long-term X25519 static (`dh_seed`-
derived) key. crypto.md defines exactly one `dh_seed` per device and no separate colony-scoped
wrap keypair; `KEYRING.rotateEpoch`/`unwrapEpochRoot` use "X25519 ECDH + HKDF" against
`memberDhKeys`, never shown to be anything but the same identity-bound static used for Noise.
- *Consequence:* crypto.md §2's claim "compromise of the X25519 static alone yields neither
  impersonation nor decryption" is true for live hypha traffic (ephemeral ee/es-protected) but
  almost certainly false for the colony layer: the attacker can recompute the ECDH shared
  secret for every retained, signed `EPOCH_ROTATE`/KEYBUNDLE envelope ever addressed to that
  device, yielding the colony's entire retained history.
- *Fix:* Specify a distinct, colony-scoped DH keypair to wrap epoch roots; if the identity
  static is reused instead, scope §2's forward-secrecy claim to hypha traffic only.

**[SERIOUS-C5]** ARCHITECTURE §2's identity-binding resolution mandates one ed25519 key per
device for both hypha auth and log authorship, overriding app.md §2's stated default that
cross-colony correlation is opt-in.
- *Consequence:* Any VAULT/RELAY storing or relaying for two or more of a user's colonies —
  routine, since relays are colony-agnostic — can trivially link that user's activity across
  communities meant to be unrelated. A real privacy regression introduced as a side effect of
  an unrelated fix, never logged as a cost.
- *Fix:* Either accept and loudly disclose the correlation cost for SP1/SP2, or pull forward a
  lightweight per-colony pseudonym for log authorship (keeping one key only for hypha auth)
  instead of deferring it entirely to SP3.

**[SERIOUS-C6]** An invite QR is captured and presented by two different joiners to two
different admitting members who are in separate partitions at the time.
- *Mechanism at fault:* crypto.md §4 invite proof-of-possession vs ARCHITECTURE §2's invite
  resolution, which binds the joiner's proof to `genesis_hash` (a static, colony-wide constant)
  instead of crypto.md's original `hypha_id` (a live per-session value), because `MEMBER_JOIN`
  is asynchronously admitted.
- *Consequence:* This closes observer-replay but reopens partition-concurrent replay: both
  admissions can independently succeed since neither admitter can see the other's
  `MEMBER_JOIN` yet, and no CRDT merge rule resolves two concurrent joins burning the same
  serial. ARCHITECTURE nonetheless states the fix as if fully closing replay.
- *Fix:* Define an explicit merge rule for concurrent `MEMBER_JOIN`s quoting the same invite
  serial (causal-order tiebreak, e.g. lowest `(lamport, log_id)` wins; the loser is soft-failed
  and must re-invite), and correct the resolution's claim to note it only prevents observer
  replay, not partition-concurrent replay.

**[SERIOUS-C7]** A single attacker process mints several ed25519 identities (free, instant, no
PoW/stake/attestation) and presents them as the ≥3 distinct `log_id`s substrate.md §6 requires
to corroborate a compaction snapshot's `state_root` to a freshly bootstrapping spore.
- *Consequence:* The design's own Risk section calls this "a weak Sybil barrier"; in the
  zero-infrastructure LAN environment this system targets, it provides close to no resistance
  against a single machine once snapshot compaction ships in SP2.
- *Fix:* Weight corroboration by observed uptime/behavioral history rather than raw
  distinct-identity count, or require corroborators to be drawn from the colony's own
  membership log rather than any log_id on the LAN.

**[SERIOUS-C8]** Recomputing MSG2/MSG3 byte counts from crypto.md §2's own stated field layout
gives 266/234 bytes; the document claims "measured: m2=256, m3=224" — a 10-byte discrepancy in
both.
- *Consequence:* A load-bearing wire format doesn't reconcile with its own documented layout;
  separately, the nonce notation reads inconsistent with Noise's per-MixKey-boundary reset
  rule. No in-tree Node-stdlib Noise test vectors exist, so "transcripts agree" proves
  self-interop, not spec-exactness.
- *Fix:* Import the official Noise_XX test vectors as an in-tree fixture before code freeze;
  reconcile the byte-count arithmetic; make the cipherstate-per-MixKey-boundary explicit.

**[ANNOYING-C9]** A user registers two devices via `DEVICE_LINK`; an admin issues `MEMBER_BAN`
against the identity/log tied to device A only. Neither `MEMBER_BAN`'s single-`subject` field
nor any other document specifies whether banning one linked device excludes its `DEVICE_LINK`
siblings from future epoch envelopes and rendering filters — if not, device B retains full
membership and posting ability after the user is nominally "banned."
- *Fix:* Specify that `MEMBER_BAN` targets a person-level identity and recursively excludes
  every `DEVICE_LINK`'d key from the next epoch's wrap list, or explicitly require banning
  each linked device individually with the UI surfacing that requirement. (Recorded here for
  completeness; not folded into ARCHITECTURE.md's §1 remediation list per task scope — it is
  ANNOYING severity, not FATAL/SERIOUS.)

### Crypto lens — honest restatement

SPORE's crypto design does not demonstrate, for the product it actually ships (SP1), the
stated crux of serving encrypted shards from untrusted VAULTs that stay unreadable by them
while remaining readable by later-joining members: ARCHITECTURE's own SP1 scope defers every
piece of epoch encryption, so SP1 fruitings are signed but plaintext, and the recommendation
not to expose this to real users is an unenforced Open Decision, not a shipped safeguard. The
deferred SP2 mechanism — encrypt-then-address plus an MLS-style GGM sender-key tree with
KEYBUNDLE wrapping for late joiners — is architecturally sound in outline and does
structurally support out-of-order random-access decryption, but its sole enforcement lever
(EPOCH_ROTATE) had contradictory, unreconciled authorization rules across design-app.md and
design-crypto.md with no corresponding permission bit; a read-capability gate crypto.md itself
demanded for INDEX/FORGE was raised and then dropped by the reconciliation; and several
supporting claims (X25519-static forward secrecy for the wrap path, invite non-replayability
under partition, Noise message sizes, Sybil-resistant snapshot corroboration, cross-colony
unlinkability) are either unverified, silently weakened by later changes, or not true as
stated. The honest claim is: the crux is outlined but not solved, and the mechanism intended
to solve it had not been shown to hold under this review's threat model — the fatal/serious
items above are now folded into ARCHITECTURE.md so that claim is corrected rather than
repeated.

---

## Lens 2: convergence — verdict BROKEN

`ARCHITECTURE.md`'s central correctness claim rests on `design-substrate.md` §5's "classic
race, worked" example: A (power 100) demotes B; concurrently B (power 50) bans C. Pass A sorts
control blocks by `(−sender_power_at_its_auth_ref, lamport, log_id)`, applies A's demotion
first (100 > 50), then auth-checks B's ban against the post-demotion state and rejects it.
`ARCHITECTURE.md` §2 adopts this mechanism unchanged and treats the cross-subsystem conflict
as resolved. This lens traced the mechanism concretely rather than accepting the worked
example at face value.

**The unstated assumption:** that `sender_power_at_its_auth_ref` faithfully reflects the
sender's power at the causal moment they actually acted, and that `lamport` faithfully
reflects real recency. Neither is enforced. `auth_ref` is defined only as "the hash of the
AUTH_SNAPSHOT the author believed current" — nothing ties it to the block's own `deps`/lamport
computation. `deps` are self-selected: "deps list only logs whose head changed since this
author's previous block" is a normative description of an honest client, not something the
protocol verifies. A client can omit deps it is actually aware of. This is not even a
hypothetical adversarial trick: SPORE's own core value proposition is offline-first writes —
`app.send`'s DRAFT→LOCAL transition appends to the author's own log immediately, with whatever
deps reflect their state *at that moment*, regardless of hypha availability — so a moderator
who goes offline, then reconnects and publishes a queued control action long after, produces
exactly this artifact: a block whose lamport is anchored to their own frozen head, and whose
`auth_ref` can be arbitrarily stale relative to what has since happened in the colony.

**Combining the two:** Pass A's per-block auth-check evaluates each control block against the
incrementally built partial resolved state at that block's *sort position* — not against a
state anchored to when the block was actually observed or published. Any actor who has *ever*
held power ≥ a rival's currently claimed power can construct a new control block citing a
favorable historical `auth_ref` and a naturally low lamport (from dormancy). It sorts early in
Pass A's power-ordered sequence and is auth-checked against a slice of state from *before* the
rival's superseding action — because that superseding action, despite being earlier in
real/gossip time, sorts *later* in the tie-break ordering. The worked example itself is not
broken by this (B's real power, 50, never exceeds A's 100 regardless of which historical
`auth_ref` B cites) — but the general mechanism it exemplifies is: any actor who has ever held
power equal to or greater than whoever currently exercises authority over them can, at any
future point — arbitrarily far in wall-clock time, not just "minutes later" as the design's
own Risks acknowledges — mint one new block that retroactively re-litigates a permission
decision in their favor, and every compliant spore will deterministically agree, because the
mechanism is a pure function of attacker-chosen fields. "Authority decides, not network
timing" (the design's stated virtue) becomes "whichever historical vantage point you
strategically cite decides." That property was asserted by the worked example, not
demonstrated, and does not survive scrutiny of `auth_ref` and dep freedom.

**A compounding problem.** §5's "Cost control" says re-resolution "restarts from the last
snapshot below the lowest disturbed lamport." §6's convergent cut selection triggers only when
`stable_lamport` crosses a multiple of 65,536, and `stable(S) = min over all member logs of
head_lamport` — a value the design's own Risks admits "a single offline member pins forever."
Since normal churn (device lost, uninstalled, no formal `MEMBER_LEAVE`) is the realistic case
per ARCHITECTURE §1.7's own churn analysis, most real colonies will have `stable_lamport`
frozen indefinitely at whatever a long-gone member's head last was — no `AUTH_SNAPSHOT` past
that point is ever taken, and a disturbing low-lamport block forces re-resolution of the
*entire* colony history back toward genesis, not a bounded "single digits" window. A dormant
high-power identity reactivating can therefore trigger both a privilege-replay *and* an
unbounded, expensive full-history re-audit, and the design's self-criticism of `stable` never
connects this dot to compaction's total dependence on it.

**HRW proofs (`design-roles.md` §2), given the review ARCHITECTURE.md explicitly called for.**
Two problems survive the §2 "blind-spot fix" (dropping `peer_table_version` from
`h = BLAKE2b-512(spore_id ‖ role_tag ‖ colony_id)`).

*Security:* the new hash input is a fixed, entirely offline-computable function of an
attacker-chosen `spore_id`. Ed25519 keypair generation is nanoseconds; grinding candidate keys
against a fixed `(role_tag, colony_id)` target to find one whose `x = be_u64(h[0..8])/2^64` is
very close to 0 is trivially feasible on commodity hardware, and since `weight = S/(-ln x)`, a
near-zero `x` makes weight enormous even at the score floor of 1 — guaranteeing top-K
placement regardless of actual capability. ARCHITECTURE §2 claims dropping the version number
"removes an entire class of disagreement without weakening anything the version number was
buying" — the security implication (the version number at least forced periodic re-grinding on
every peer-table topology change) is never checked, so the claim is asserted, not verified, and
is very plausibly false.

*Correctness:* the ∎-proof for "every role always has ≥1 holder ... at every instant" assumes
a spore's own view of rivals' scores never overstates a rival's true current standing.
TRANSPORT's fast-disconnect signal only protects spores directly hyphae-connected to a
departing peer. Spores that know a peer only via BEACON's gossiped peer table — necessarily
common in SP1, since multi-hop routing/LSDB is deferred to SP2 — continue ranking a crashed
peer using its last-gossiped (possibly top) score until anti-entropy catches up. During that
window every live spore in that second-hand-knowledge position believes the crashed peer still
holds role R and declines to self-assign, producing a genuine (not transient) zero-holder
window — directly contradicting the stated invariant as written.

**CRDT table checked row by row.** Message-send (grow-only, block_hash-keyed), reaction OR-Set
(add-wins, order-independent), fruiting-create (collision-free by construction), and
fruiting-delete-vs-send ("delete wins over rename, loses to concurrent sends") are all
genuinely sound and convergent, unaffected by the staleness problem because none of them touch
Pass A. Edit/delete racing is handled correctly — delete absorbs unconditionally, so a
backdated low-lamport edit cannot resurrect a deleted message; this row is robust to the
lamport-gaming problem precisely because "absorbing" semantics don't depend on order. Ordinary
permission checks (MSG_POST, moderator MSG_DELETE) are also safe from this specific replay
trick, because Pass B checks against Pass A's *final*, fully resolved output, not an
incrementally built partial state — the vulnerability is narrowly, but seriously, confined to
Pass A's own handling of concurrent *control* blocks, which is exactly the mechanism the
worked example showcases as proof of correctness. The total-order tiebreak
`(lamport, log_id, seq)` itself is total and deterministic across all spores — the issue is
that its inputs are gameable in ways that matter specifically for authority resolution.

### Convergence lens — Failures

**[FATAL-V1]** Founder/moderator M once held power P at a historical `AUTH_SNAPSHOT S_old`,
then was superseded (demoted, banned, or simply dormant since). Long after — whether M is
malicious, or simply an honest client reconnecting after being offline, since offline-first
DRAFT→LOCAL writes are core to SPORE — M publishes a new control block citing
`auth_ref = S_old` and a naturally low lamport.
- *Mechanism at fault:* substrate.md §5 Pass A tie-break combined with the unconstrained
  `auth_ref` field and self-selected `deps`/derived-lamport rule of §2; adopted unchanged by
  ARCHITECTURE §2's permission-resolver reconciliation.
- *Consequence:* M's block sorts early using the stale, favorable power P, and is auth-checked
  against a slice of history from before whatever superseded M. Every compliant spore computes
  the identical (wrong) outcome. A demoted/banned actor can retroactively re-win a permission
  decision they actually lost, arbitrarily far after the fact.
- *Fix:* Require `auth_ref` to be causally bound to the block's own deps (must equal or descend
  from the most recent AUTH_SNAPSHOT reachable via the block's own dep set/own-log frontier at
  authoring time, verified by recomputation, not author-asserted), and/or resolve the sender's
  power from the resolver's own running partial state at the point corresponding to the
  block's lamport, not from an author-chosen historical pointer. Bound how far in the past an
  `auth_ref`/lamport gap may be before a control block is rejected outright rather than merged.

**[SERIOUS-V2]** Ordinary churn (device lost, uninstalled, no formal `MEMBER_LEAVE` — the
realistic case per ARCHITECTURE §1.7) freezes a member's log `head_lamport` forever.
- *Mechanism at fault:* substrate.md §6 convergent cut selection gated on `stable_lamport`,
  combined with §2's own admitted risk ("a single offline member pins stable forever") and
  §5's re-resolution-from-last-snapshot claim.
- *Consequence:* `stable(S) = min over all member logs of head_lamport` never advances past the
  frozen value, so no `STATE_SNAPSHOT` boundary is ever taken for any realistically long-lived,
  churned colony. Full genesis replay becomes the permanent path, not a fallback, and any
  disturbing low-lamport block forces re-resolution of the colony's entire history (compounding
  V1), not a bounded recent window.
- *Fix:* Exclude members unreachable/silent beyond a defined horizon from the `stable`
  computation (analogous to how `settled` already excludes members not heard from within
  PARTITION_HORIZON), with an explicit, gossiped "presumed departed" marker distinct from a
  formal ban/leave.

**[SERIOUS-V3]** In SP1 (no multi-hop routing/LSDB), spore X knows spore J only via BEACON's
gossiped peer table, not a direct hypha. J crashes or is forcibly disconnected from everyone
except spores that haven't yet gossiped the change to X.
- *Mechanism at fault:* design-roles.md §2's "every role always has ≥1 holder" proof, which
  only established the property for a spore's own self-knowledge and implicitly assumed no
  spore's view of a *rival* overstates that rival's true current standing.
- *Consequence:* X's cached CAP_ADVERT for J still shows J's last (possibly top) score for role
  R; X's HRW computation ranks J above itself and concludes J still holds R. Every other spore
  in the same second-hand position reaches the same false conclusion simultaneously. No spore
  self-assigns role R for the duration of the gossip lag — a real, non-transient zero-holder
  window, contradicting the "transient under-assignment is impossible" proof.
- *Fix:* State the invariant's actual scope (holds once peer tables are within one
  anti-entropy round of convergence, not "at every instant"); add a liveness signal
  independent of cached scores — treat a peer whose last CAP_ADVERT is older than
  N × keepalive-interval as absent from top-K computation rather than ranked by its stale
  value.

**[SERIOUS-V4]** An attacker wanting guaranteed custodianship/index membership/relay standing
over a target colony generates many candidate ed25519 keypairs offline (nanoseconds each) and
keeps the one whose `x = be_u64(h[0..8])/2^64` is closest to 0 for the target
`(role_tag, colony_id)`.
- *Mechanism at fault:* design-roles.md §2 HRW hash construction as amended by ARCHITECTURE §2
  ("HRW seed and convergence"), reiterated as an Open Decision without addressing the grinding
  property.
- *Consequence:* `weight = S_i(R)/(-ln x)` becomes arbitrarily large even at the capability
  score floor of 1, guaranteeing the attacker wins top-K placement regardless of real
  hardware/capability — e.g. permanent VAULT custodianship to selectively withhold/corrupt
  shards, or INDEX membership to poison search. ARCHITECTURE §2's removal of
  `peer_table_version` (a real convergence-bug fix) eliminates the only variable that
  previously forced periodic re-grinding, and its "without weakening anything" justification
  is asserted, not checked, against this Sybil-targeting cost.
- *Fix:* No clean fix exists without new tension (see cross-reference table / Open Decisions
  in ARCHITECTURE.md) — a genesis-derived salt is knowable to every VAULT, including
  non-members by design, and a membership gate on the hash contradicts the untrusted-VAULT
  crux. Recorded as an Open Decision, not resolved here.

### Convergence lens — honest restatement

SPORE's substrate can honestly claim that all honest spores deterministically compute
byte-identical resolved state from the same block set (a real, sound property of Pass A/B
being pure functions), and that its permission-race and HRW mechanisms converge in that narrow
agreement sense. It cannot honestly claim, as the worked example and ARCHITECTURE.md §2
implied, that the converged outcome is *safe* against a participant who strategically chooses
a stale `auth_ref` and an honestly-low (offline-drafted) or deliberately-low lamport: such an
actor can retroactively re-win a permission decision they lost, and every compliant spore will
agree with the exploited result. Nor can it claim the compaction/snapshot pipeline actually
engages for realistically churned colonies, since its trigger is frozen by ordinary member
abandonment. Nor can it claim HRW role assignment guarantees at least one holder "at every
instant" — that holds only once gossip has converged, not during ordinary propagation lag, and
the underlying hash is now cheaply gameable by an attacker who pre-grinds identity offline for
a specific target colony and role. The fatal/serious items above are now folded into
ARCHITECTURE.md so this claim is corrected rather than repeated.

---

## Cross-reference: finding → ARCHITECTURE.md remediation

| Finding | Severity | Landed in ARCHITECTURE.md |
|---|---|---|
| C1 — EPOCH_ROTATE authorization contradiction | FATAL | §1.11 (new); §2 "Permission resolution" paragraph corrected; §4 SESSION/KEYRING and APP entries |
| C2 — INDEX/FORGE lacks read-cap gate | FATAL | §1.12 (new); §2 new paragraph "Read-capability gate for INDEX/FORGE"; §3 index/search rows qualified; §4 ROLES entry |
| C3 — SP1 ships with zero content confidentiality, unenforced | FATAL | §1.13 (new); §5 item 3 adds mandatory UI banner; Open Decision #2 updated |
| C4 — epoch-wrap key may equal Noise static, breaking FS claim | SERIOUS | §1.14 (new); §4 SESSION/KEYRING entry notes distinct wrap keypair for SP2 |
| C5 — identity binding breaks cross-colony unlinkability | SERIOUS | §1.15 (new); §2 "Identity binding" paragraph corrected with cost logged; Open Decision added |
| C6 — invite replay under partition, concurrent-join merge undefined | SERIOUS | §1.16 (new); §2 "Invite token" paragraph corrected; §5 item 3 adds merge rule |
| C7 — snapshot corroboration Sybil-cheap | SERIOUS | §1.17 (new); §4 SUBSTRATE entry notes membership-drawn corroborators (SP2) |
| C8 — Noise wire-size arithmetic / nonce-reset inconsistency | SERIOUS | §1.18 (new); §5 item 3 adds Noise test-vector fixture as a scope item; §6 |
| C9 — DEVICE_LINK vs MEMBER_BAN scope undefined | ANNOYING | Not folded into ARCHITECTURE.md (task scope: FATAL/SERIOUS only) — recorded here only |
| V1 — stale `auth_ref`/lamport enables privilege replay | FATAL | §1.19 (new); §2 "Permission resolution" paragraph corrected (same paragraph as C1, different clause). **CLOSED in code, by a rule §1.19 did not propose** — see ARCHITECTURE R4. The fix §1.19 adopted does not close V1: "a naturally low lamport" is attacker-chosen, so causal binding and lamport bounds both pass the attack, and the bounded-gap clause is measured against a receiver-local frontier and is non-convergent. `ROLE_REVOKE` pins the target's log at a seq instead. `test/auth.test.js` |
| V2 — churn freezes `stable_lamport`, compaction never engages | SERIOUS | §1.20 (new); §4 SUBSTRATE entry notes presumed-departed exclusion; §5 item 4 |
| V3 — gossip-lag creates real zero-holder windows for a role | SERIOUS | §1.21 (new); §4 ROLES entry adds staleness cutoff; §5 item 6 |
| V4 — HRW hash is cheaply Sybil-grindable after dropping the version seed | SERIOUS | §1.22 (new); §2 "HRW seed and convergence" paragraph corrected (claim retracted, not silently re-resolved); Open Decision #3 updated |

Killer Risks item 1 (the placeholder-correctness-pass risk) is removed from
`ARCHITECTURE.md` and replaced with the residual risks these two lenses actually found,
since the review the item called for has now been done.
