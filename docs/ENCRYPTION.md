# ENCRYPTION.md — SP2 epoch encryption, reconciled design

> ## Reconciled against the decision record, 2026-09-17 — read this first
>
> This document was written before R1 and R4 and contradicts both in places. Two specific
> defects are fixed inline below (§6 steps 1–2, and two guarantee-table rows). The rest is
> language, and this banner supersedes it globally rather than by surgery, because rewriting
> prose that is merely *worded* around an obsolete mechanism risks changing what it means.
>
> **Wherever this document appeals to §1.19 — its `auth_ref`/`deps` causal-binding
> recomputation, its "staleness window", its "lamport-gap window", or a
> `ROTATE_LAMPORT_WINDOW` "derived from §1.19's own threshold" — none of that exists.**
> ARCHITECTURE.md R4: *"§1.19's adopted fix does not close §1.19. Implementing it is what
> revealed that... V1's attacker picks both the lamport and the dep set, so every rule phrased
> in terms of either is a rule the attacker satisfies for free."* The one field an author
> cannot choose is their own `seq`, so what shipped is R4's `pin_seq`, refined by **R6** (one
> ordered list of boundaries, so grants and revocations can never be read by two rules) and
> **R7** (a claim witness, so a delivery verdict survives eviction).
>
> Read every "§1.19-hardened" as "R4/R6/R7-hardened", and every bound expressed as a lamport
> or staleness window as **unbounded until an honest holder acts** — which is weaker than this
> document claims, and is the honest statement.
>
> **Clause (a)'s narrative** (a demoted author's past rotations "soft-fail", the trigger
> becoming "re-citable") also predates R4/R6. Under the rule that shipped, a revocation governs
> from `pin_seq + 1` **in the author's own log**: rotations at or below the pin stay valid,
> and above it the log *stops* (R6 cost 1). Nothing soft-fails and nothing above the pin
> delivers at all.
>
> **Type numbers below follow design-app.md. The implementation follows design-substrate.md,**
> which is what R4 says governs. `block.js` is the authority: `MEMBER_JOIN 0x20`,
> `MEMBER_LEAVE 0x21`, `MEMBER_BAN 0x23`, `ROLE_GRANT 0x24`, `ROLE_REVOKE 0x25`,
> `FRUITING_CREATE 0x11`. The two schemes also disagree about what `0x11` and `0x12` mean, so
> a reader who implements from this document's numbers writes blocks the substrate will not
> recognise.

This document resolves CORRECTNESS.md's four open contradictions (EPOCH_ROTATE authorization,
the INDEX/FORGE read-capability gate, the late-joiner KEYBUNDLE path, and the untrusted-VAULT
crux) with concrete mechanisms. It supersedes design-crypto.md's epoch-encryption sections
(§4's revocation/rotation language and §5's GGM-tree crux) wherever they conflict with what
follows; Noise XX, the two-tier block cert, and everything in design-crypto.md §1–§3 (identity,
handshake, invites) are unchanged and out of scope here.

## 0. Which design, and why

Two independent designs (A, B) were produced and each was attacked by a refuter. **Design A is
the base** (verdict SOUND_WITH_FIXES: correctly deriving EPOCH_ROTATE from Pass A/B instead of
granting a bitmask bit, correctly splitting `has_read_cap` into a public eligibility gate and a
private possession check, correctly de-singularizing KEYBUNDLE minting). Design B was BROKEN —
its EPOCH_ROTATE rule never validated *who a rotation wraps*, and its `has_read_cap` live
challenge is relayable and breaks HRW's convergence — but two of its ideas are strictly better
than A's and are grafted in:

1. **The flat HKDF sender-key chain replaces the GGM secret tree.** B's refuter is right that
   this isn't a simplification-for-its-own-sake: KEYBUNDLE ships the raw `epoch_root`, not tree
   leaves, so the tree's one real advantage (forward-secure deletion of a consumed leaf prefix)
   was never exploitable in SPORE to begin with. §4 below reverifies this from scratch rather
   than taking either side's word for it.
2. **`root_commit`** (a public hash-commitment to `epoch_root`, published in cleartext at
   mint time) is B's best idea and both refuters left it unattacked. It is reused here as the
   concrete mechanism for KEYBUNDLE self-verification (fixing a real gap) *and*, this document's
   own addition, as the local self-test underlying `has_read_cap`'s Layer 2 — cheaper and more
   honest than A's "attempt to open the actual job target" and safer than B's own live
   challenge, because it is never presented to a peer as proof of anything.

Every FATAL/SERIOUS break either refuter found against A's other three mechanisms is fixed
below with a named, checkable rule — not by argument.

---

## 1. Complete key schedule

```
// ══════════════════════════════════════════════════════════════════
// DEVICE IDENTITY — unchanged from design-crypto.md §1
// ══════════════════════════════════════════════════════════════════
master_seed           = 32 random bytes, at rest under scrypt+AEAD (identity.key)
id_seed               = HKDF(master_seed, info="SPORE/id/ed25519/v1")   -> ed25519 (id_priv, id_pub)
dh_seed               = HKDF(master_seed, info="SPORE/dh/x25519/v1")    -> X25519 static, NOISE HYPHAE ONLY
SPORE-ID              = id_pub                          // raw 32B ed25519 public key, no hash
log_id                = BLAKE2b-256(id_pub)[0..16]
colony_id             = BLAKE2b-256(genesis_block_hash)[0..16]
fruiting_id           = BLAKE2b-128(colony_id ‖ creator_log_id ‖ seq)

// ══════════════════════════════════════════════════════════════════
// COLONY-SCOPED WRAP KEYPAIR — fixes C4 (§1.14). MUST bind colony_id.
// ══════════════════════════════════════════════════════════════════
// Design A's original spec — wrap_seed = HKDF(master_seed, info="SPORE/colonywrap/…")
// with NO colony_id in the derivation — was a real bug: it produces the SAME X25519
// keypair for every colony a device joins, adding a SECOND cross-colony correlation
// channel beyond the already-disclosed C5 (permanent ed25519 identity) one, and it was
// caught by A's own refuter. Binding colony_id below fixes the ADDED channel; it does
// NOT close C5 — id_pub itself is still one key across colonies, unaddressed here.
wrap_seed(colonyId)   = HKDF(master_seed, salt=colonyId, info="SPORE/colonywrap/x25519/v1")
                        -> X25519 (wrap_priv_c, wrap_pub_c)   // one keypair PER COLONY
// wrap_pub_c is published in cleartext inside this device's MEMBER_JOIN payload for
// that colony — discoverable without a live hypha, never used for Noise.

// ══════════════════════════════════════════════════════════════════
// PER-FRUITING EPOCH STATE
// ══════════════════════════════════════════════════════════════════
epoch_root   = 32 CSPRNG bytes, minted fresh by KEYRING.rotateEpoch(fruitingId); NEVER derived
epoch_hash   = block_hash(signed EPOCH_ROTATE block)      // = BLAKE2b-256(header‖deps‖sig),
                                                            // the SAME field substrate already
                                                            // computes for every block — content-
                                                            // addressed, never sequential
root_commit  = BLAKE2b-256("SPORE-ROOT-COMMIT-v1" ‖ epoch_root)   // published in the
                                                            // EPOCH_ROTATE block's CLEARTEXT
                                                            // payload at mint time

// op codes, extending design-app.md's existing table (0x60 EPOCH_ROTATE already reserved):
//   0x61 KEYBUNDLE            0x62 HISTORY_POLICY_SET

// EPOCH_ROTATE (0x60) cleartext payload — Pass-B block, scope = ONE fruiting (never colony-wide):
EPOCH_ROTATE.payload = {
  root_commit: Bytes32,
  wraps: [ { recipient_log_id: Bytes16, eph_pub: Bytes32, wrapped: AEAD_ct }, ... ]
}
// recipient_log_id is CLEARTEXT (not merely inside an AAD another spore can't see without the
// key) — every spore, including a VAULT, must be able to compute the wrap-set content check
// in §2.1(d) directly from this payload.

// Per-recipient wrap (KEYRING.rotateEpoch), against member m's colony-scoped wrap_pub_m.
// NOTE: this is keyed on root_commit, NOT epoch_hash. epoch_hash = block_hash(this very
// EPOCH_ROTATE block) = hash(header‖deps‖sig), and header.payload_hash covers these wraps —
// so epoch_hash cannot exist yet when the wraps are being built (both original designs had
// this circular dependency; neither refuter caught it). root_commit has no such problem: the
// minter computes it from epoch_root FIRST, before wrapping to anyone, so it is available as
// a domain separator and is itself collision-resistant (a BLAKE2b-256 preimage of epoch_root).
eph        = X25519.generateKeyPair()                                 // fresh per (root_commit, m)
shared     = X25519(eph.priv, wrap_pub_m)
wrap_key   = HKDF(shared, salt=root_commit, info="SPORE-EPOCHWRAP-v1" ‖ m.log_id, len=32)
wrapped    = AEAD-Seal(wrap_key, nonce=0^12, AAD=root_commit‖fruiting_id‖m.log_id, pt=epoch_root)

// Unwrap (KEYRING.unwrapEpochRoot), by m — root_commit is read straight off this block's own
// cleartext payload, so it is available before epoch_hash is (or ever needs to be):
shared'    = X25519(wrap_priv_m, eph_pub)
wrap_key'  = HKDF(shared', salt=root_commit, info="SPORE-EPOCHWRAP-v1" ‖ m.log_id, len=32)
epoch_root'= AEAD-Open(wrap_key', nonce=0^12, AAD=root_commit‖fruiting_id‖m.log_id, wrapped)
assert BLAKE2b-256("SPORE-ROOT-COMMIT-v1" ‖ epoch_root') == root_commit   // self-verifying:
                                                                            // a corrupt or lying
                                                                            // wrap is self-detecting
// epoch_hash itself remains the epoch's IDENTIFIER everywhere else (message payloads, §2.1's
// authCheck, KEYBUNDLE) — by the time anything else references it, this block is finished,
// hashed, and replicated, so no circularity applies there. KEYBUNDLE's own wraps (§2.3) DO
// use epoch_hash as salt/AAD, precisely because that epoch's EPOCH_ROTATE block already
// exists by the time a KEYBUNDLE for it is minted — the two derivations differ for this reason.

// ══════════════════════════════════════════════════════════════════
// SENDER-KEY CHAIN — flat HKDF, replaces the GGM tree (see §4)
// ══════════════════════════════════════════════════════════════════
// Author identity is ALWAYS the block's own header.log_id — an existing, unforgeable
// substrate field (a block's log_id is the single-writer log that signed it) — NEVER a
// payload-embedded field. There is deliberately no separate device_id: crypto.md §1 already
// establishes one identity key == one device ("the key IS the device; rotation means a new
// SPORE-ID"), so log_id already uniquely names the sending device; boot_nonce (below)
// separates successive process instances of that SAME device.
boot_nonce      = CSPRNG(16), drawn ONCE at process start, held only in memory, never persisted
sender_root(log_id) = HKDF(epoch_root, salt=fruiting_id,
                            info="SPORE-SENDER-v1" ‖ log_id ‖ boot_nonce, len=32)
message_key(i)  = HKDF-Expand(sender_root, info="SPORE-MSG-v1" ‖ LE64(i), len=32)   // ONE hash
// i is a PURE IN-MEMORY monotonic counter, reset to 0 on every process start — no
// write-ahead log, no crash-recovery skip-ahead margin needed (see §4's boot_nonce analysis).

// Block sealing (KEYRING.sealBlock, called by the author on its own log so log_id == own
// log_id trivially) — fits the EXISTING 260-byte cert unmodified; the signature already
// covers payload_hash, not payload, so an encrypted block changes only what payload_hash
// covers, never the cert's shape:
payload     = epoch_hash[32] ‖ boot_nonce[16] ‖ i_u64[8] ‖ ciphertext
inner_sig   = Ed25519(id_priv, "SPORE-INNER-v1" ‖ real_payload)
ciphertext  = AEAD-Seal(message_key(i), nonce=0^12,
                  AAD = BLAKE2b-256(epoch_hash‖boot_nonce‖i‖own_log_id‖fruiting_id),
                  pt  = inner_sig ‖ real_payload)
BlockID = payload_hash = BLAKE2b-256(payload)     // == existing cert field, no new concept

// Opening (KEYRING.openBlock), by any current epoch_root holder, any order, zero round-trips:
//   1. verify outer sig + payload_hash (any spore, incl. a VAULT with no key, can do this)
//   2. read header.log_id from the BLOCK'S OWN (already-verified, unforgeable) header —
//      never from payload; this is what closes the re-seal/misattribution attack below
//   3. sender_root = HKDF(epoch_root, salt=fruiting_id,
//                          info="SPORE-SENDER-v1"‖header.log_id‖boot_nonce)  // boot_nonce
//                          from the payload's own cleartext prefix
//   4. message_key(i) = HKDF-Expand(sender_root, info="SPORE-MSG-v1"‖LE64(i))   // O(1)
//   5. AEAD-Open with AAD recomputed using header.log_id (not a payload field); a ciphertext
//      copied verbatim into someone else's block fails here, because the AAD — and the key
//      derived in step 3 — depend on the NEW block's own header.log_id, which differs
//   6. verify inner_sig against header.log_id's identity key (id_pub, from that spore's
//      own IDENTITY/MEMBER_JOIN record)
//
// Why pinning to header.log_id matters: the original two-designs' payload-embedded
// author_id/device_id fields let a reader derive the chain from attacker-controlled cleartext.
// A member who holds epoch_root could copy another author's (ciphertext, inner_sig) into a
// new block under its own log and have naive derivation misattribute or, worse, succeed. With
// derivation pinned to the SIGNING block's own header.log_id, that copy decrypts under the
// copier's OWN chain — which is not the key the ciphertext was sealed under — and fails AEAD
// outright. The outer signature (already existing, over payload_hash) is what makes header.log_id
// unforgeable in the first place: substrate's single-writer-log model means only that log's
// owner can produce a validly-signed block bearing that log_id. Given that, the INNER signature
// is not "the only thing preventing forged attribution" — the outer signature/log model already
// does that. Inner_sig is defense-in-depth for contexts where ciphertext travels without its
// header (payload-only forwarding, or SUBSTRATE's own payload redaction, which by design keeps
// block_hash/header intact while dropping payload bytes) — it lets a client that later reunites
// payload with a *different* provenance claim still verify who actually wrote it.
```

---

## 2. The four contradictions, resolved

### 2.1 EPOCH_ROTATE authorization

**Classification.** EPOCH_ROTATE is a **Pass-B** block: it consumes resolved auth state but
never modifies the permission bitmask itself. design-substrate.md §5 already establishes that
Pass-B is checked against Pass-A's **final** resolved output, not an incrementally-built
partial one — this is the asymmetry that makes ordinary permission checks safe from the §1.19
staleness-replay trick, and EPOCH_ROTATE inherits it for free by being classified this way.

**authCheck(R: EPOCH_ROTATE) = ALLOW iff all four clauses hold**, evaluated at two *different*,
deliberately distinct points — conflating them is exactly how both refuters' attacks work:

```
Let final  = resolvedState AFTER cascading re-auth over the full delivered block set (the
             existing, §1.19-hardened Pass A/B output every other control-block check uses).
Let cut(R) = the state resolved from R's OWN causal cut — the AUTH_SNAPSHOT reachable from
             R.deps ∪ R.author's own-log frontier at authoring time, RECOMPUTED on ingest per
             §1.19 (never accepted on R's own auth_ref assertion). This is §1.19's existing
             mechanism; EPOCH_ROTATE introduces no new "anchor" concept.

(a) POWER      [checked against FINAL]
    R.author == genesis_owner
    OR resolvedState_final.holds(R.author, BAN|KICK, R.fruiting_id) == true

(b) TRIGGER    [checked against FINAL]
    genesis_owner is exempt (may rotate unconditionally — heartbeat/hygiene; this does mean
    the owner alone can storm-rotate without limit, same as it always could as owner, and is
    accepted as an owner-trust assumption already implicit everywhere else in the design).
    Otherwise R.deps must cite an ACCEPTED (in resolvedState_final)
        MEMBER_BAN(0x23) | MEMBER_LEAVE(0x21) | ROLE_REVOKE(0x25, removing VIEW for
        R.fruiting_id) | FRUITING_OVERRIDE(unimplemented; design-app 0x12 collides with
        design-substrate's 0x11/0x12 range — resolve before use)
    targeting some spore X — OR cite a causal hygiene fact:
        message_count(R.fruiting_id) since the nearest ANCESTOR-ACCEPTED rotation ≥ 100_000
        OR lamport_delta since that ancestor rotation ≥ ROTATE_LAMPORT_WINDOW
    (no wall clock in either branch). Both counts are taken over R's OWN causal ancestry
    (deps-transitive-closure ∪ R.author's own-log prefix) — a pure function of the delivered
    block set, exactly like clause (c)'s exhaustion walk, not a global count — so the trigger
    is well-defined under partition with no additional machinery.
    HYGIENE MINTER DESIGNATION (closes the concurrent-hygiene-race break, §2.1 "residual"
    below): a hygiene-cited R is valid only if R.author is the LOWEST log_id among all spores
    holding BAN|KICK for R.fruiting_id in cut(R). This applies ONLY to the hygiene branch —
    any current holder may still mint a ban/leave/revoke-triggered rotation (needed for the
    watchdog fix below) — because "who goes first" has no security meaning for a wall-clock-
    free periodic trigger, so designating one minter avoids routine concurrent hygiene forks
    in a fully-connected mesh without weakening exclusion. Under a genuine partition each
    side's designated minter is computed from its OWN cut and may differ, producing the same
    accepted graceful fork as any other concurrent trigger — not solved further, not new.
    ROTATE_LAMPORT_WINDOW has no adopted numeric value here; it is PROVISIONAL, to be derived
    from the same churn-benchmark data already required for §1.19's own staleness threshold
    (both are provisional constants pending the same measurement, per ARCHITECTURE's own
    convention for §1.19/§1.20).

(c) EXHAUSTION [checked by walking R's own causal ancestry — deps-transitive-closure ∪
                R.author's own-log prefix; a pure function of the delivered block set]
    If (b) cited event D: R soft-fails if any OTHER accepted EPOCH_ROTATE R', with R'
    causally ANCESTOR of R, already cited D. A rotation cannot re-spend a trigger its own
    causal past already spent.
    Two rotations in DISJOINT partitions that each cite D independently are NOT each
    other's ancestor — both remain valid. This is the accepted graceful fork (below), not
    a bug, and no separate merge rule is needed: see "Healing".
    If (b) cited hygiene: the message-count/lamport-delta window resets at each
    ancestor-accepted rotation, so a second rotation in the SAME causal line cannot
    re-cross the threshold without new activity accruing.

(d) WRAP-SET CONTENT   [checked against cut(R), R's OWN causal cut — NOT final]
    Every entry in R.payload.wraps names a recipient_log_id that holds VIEW for
    R.fruiting_id in cut(R). If ANY wrap entry names a spore cut(R) already shows as
    banned/left/revoked-VIEW, R soft-fails outright — structurally invalid, not merely
    unwise, and checkable by every spore from data already in R's own cleartext payload.

    The evaluation point (cut(R), not final) is deliberate: using final state here would
    let a LATER ban of some legitimately-wrapped member retroactively soft-fail a
    rotation that was correct when minted — exactly the confusion §1.19 exists to
    prevent for every other control block. cut(R) asks only "was this wrap-set correct
    given what the minter could see and had cited," which is the right question for an
    irrevocable, already-distributed secret.

    This clause does NOT check that no currently-eligible member was left OUT of the
    wrap set. Omission is an AVAILABILITY problem, repaired by KEYBUNDLE / supplemental-
    wrap redundancy (§2.3) — never by rejecting the rotation, which would only punish
    the omitted member twice.
```

**A note on verifiability latency.** `R.payload.wraps` is O(N) in colony size (crypto.md's own
measured ~84 ms / 78 KiB at 1000 members scales to roughly 96 KB of wrap entries) — far past the
512 B inline threshold, so the payload is fetched separately from the header (SHARDING). Clause
(d) needs the payload to evaluate. Per app.md's existing three-valued ALLOW/DENY/UNVERIFIED
model, an EPOCH_ROTATE whose payload has not yet arrived is **UNVERIFIED, not ALLOW** — its
effects (the new epoch, the wraps) are withheld exactly like any other op with an
authority-relevant payload in flight, until the payload is delivered and clause (d) can run.

**Convergence, three lines.** (1) `resolvedState_final` and every `cut(R)` are pure functions
of the delivered block set — the existing, §1.19-hardened Pass A/B guarantee; no wall clock, no
receipt-order dependence. (2) Clauses (a)/(b)/(c) are evaluated purely against `final` and R's
own immutable fields (author, deps, payload); (c)'s ancestry walk is a pure function of the DAG
below R. Clause (d) is evaluated purely against `cut(R)`, itself a pure function of R.deps/own-
log prefix. (3) Therefore ALLOW/soft_failed(R) is a pure function of the delivered block set
for every R — two spores holding the identical block set compute an identical verdict for every
EPOCH_ROTATE block, hence an identical set of live `epoch_hash` values, regardless of gossip
order. A partition produces a *different* block set, not a disagreement on the same one — that
surfaces as the graceful fork in (c), not a convergence violation.

**Healing needs no new mechanism.** An ordinary EPOCH_ROTATE `R_merge` whose `deps` include
*both* fork tips computes `cut(R_merge)` as the union of both partitions' resolved state, so its
own clause-(d) check naturally yields "every member currently eligible across both partitions,
minus anyone banned/left in EITHER" — the restrictive union falls out of the rule already given;
it answers ARCHITECTURE's Open Decision #7 without a bespoke CRDT rule.

**What this fixes, concretely, against both refutations:**
- *Demoted-moderator-forever-armed (A-refuter, FATAL).* Closed, with the consequence stated
  rather than hidden: clause (a) is checked against `final`, exactly like every other
  control-block check — once a demotion is delivered, `holds()` is false under `final`, and
  **every** rotation that author minted citing their own now-lost power soft-fails under
  cascading re-auth, past ones included, not merely future ones. This is the same
  "evaporating decision" behavior Pass A already accepts for ordinary control blocks
  (design-substrate.md's own disclosed UX cost), now composed with an irrevocable secret
  distribution — but the composition is bounded, not catastrophic: ciphertext already sealed
  under the since-soft-failed `epoch_hash` stays cryptographically valid and readable forever
  by anyone who received the wrap (see "Soft-failure vs. an already-distributed secret"
  below); soft-failure only means that epoch is no longer treated as authorized for **sealing
  new content**; the trigger it consumed becomes re-citable under clause (c) since that
  citation is now void; and any spore relying on the now-unauthorized epoch as "current" is
  exactly the case the watchdog rule (any current holder may cite the same trigger) exists to
  immediately repair with a fresh, honestly-authorized rotation.
- *Watchdog can't execute the liveness fix (A-refuter, SERIOUS).* Closed: clauses (a)/(b) never
  require `R.author == D.author` — any current BAN/KICK holder may cite anyone's accepted
  trigger, including one they didn't author.
- *Leave-triggered rotation depends on the leaver's own incentive (A-refuter, ANNOYING).*
  Closed by the same fix: any current holder, not only the leaver, may cite a LEAVE.
- *Colluding moderator cites a real ban but still wraps the excluded member in (B-refuter,
  FATAL).* Closed by clause (d): the wrap-set content is now checkable, and this is checkable,
  not merely discouraged.
- *Rotation-storm via unbounded re-citation of the same ban (B-refuter, SERIOUS).* Closed by
  clause (c): a trigger can be spent at most once per causal line.
- *`resolve(D, anchor=B.auth_ref)` is an undefined operation (A-refuter, SERIOUS).* Closed:
  there is no separate "anchor" concept — clause (b)/(c) read `final` exactly like every other
  control-block check, and clause (d) reuses §1.19's existing recomputation, named as such.

**Residual, disclosed not hidden.** Within the §1.19 lamport-gap window, a colluding-but-still-
current BAN-holder can mint R citing trigger D (excluding victim X) from a causal cut that has
not yet incorporated some *other* already-accepted ban of a different member Y, and so legally
wrap Y in. This is bounded by the same staleness threshold every other control block already
accepts, and it is closed the moment any honest current holder mints R′ citing Y's ban
(unconsumed per (c)). Clause (d) stops "ban X, still equip X"; it cannot make R.author cite a
ban it has not yet seen — no mechanism can, without a wall clock or consensus, both of which are
out of scope by design.

**Soft-failure vs. an already-distributed secret.** If R later soft-fails under `final` (e.g.
its citing author is demoted before some spore ingests the demotion), messages already sealed
under `epoch_hash_R` remain cryptographically valid and decryptable — soft-failure is a
statement about R's *authorization*, not about the AEAD validity of ciphertext already produced
under the `epoch_root` it distributed, which cannot be un-sent. Every spore that observes R's
soft-failure MUST treat `epoch_hash_R` as superseded for *sealing new content* and mint or await
a fresh rotation. This is a one-way, non-reversible side effect unique to EPOCH_ROTATE among
control blocks; it is disclosed, not solved.

**DM exception.** design-crypto.md §5 models a DM as a 2-member fruiting rotating on **every
fresh ephemeral contribution** — a Double Ratchet analog that needs frequent, low-latency
rotation. Gating that on clause (b)'s ban/leave/hygiene triggers would cap DM rotation far
below "every contribution," so for a fruiting with exactly two VIEW-holders and no role-grant
history, **clauses (b) and (c) are waived entirely**: either member may author EPOCH_ROTATE at
will, subject only to clause (d) (never wrap someone who has left this DM). A rotation storm in
a two-party fruiting costs only the two parties who chose to have it and has no third party to
protect, so the exhaustion/hygiene machinery that exists to bound *colony-wide* rekey traffic
has no role here. Neither source design specified this and it does not fall out of the general
N-member rule automatically.

---

### 2.2 has_read_cap for INDEX/FORGE

**Granularity.** Eligibility and possession are evaluated **per (colonyId, fruitingId)**, not
per colony — a colony member can hold no VIEW on a private fruiting, and `epoch_root` is minted
and wrapped per fruiting. Design A's colony-wide `eligible()` was too coarse; fixed here.

```
Layer 1 — ELIGIBILITY (public, keyless, hard precondition BEFORE HRW ranking):
    eligible(S, colonyId, fruitingId) = resolvedState.hasView(S, fruitingId) == true
    Computed identically by any spore, including a non-member or a VAULT, from cleartext
    control-plane blocks — no decryption involved. A spore failing this is never a candidate
    for that fruiting's INDEX/FORGE work, full stop, per §1.12's adopted fix.

Layer 2 — POSSESSION (private, self-attested, PROVED TO NO ONE):
    possess(S, epoch_hash) = S's local KEYRING holds an unwrapped epoch_root for epoch_hash
                              AND BLAKE2b-256("SPORE-ROOT-COMMIT-v1" ‖ epoch_root)
                                  == that epoch_hash's published root_commit
    This is a single local hash compare against material S already has cached — no network
    round-trip, no fetch of the job's actual target content (possession is an EPOCH-scoped
    property, not a content-scoped one, so there is no reason to touch a VAULT to test it).
```

**Stated plainly, because the task asks how a spore "proves" this: Layer 1 is proved, publicly,
from resolved state. Layer 2 is not proved to anyone — it is a local self-test S runs on itself,
consumed only as S's own accept/decline decision on a specific job offer.** ROLES never treats
`possess()` as a ranking input or a third-party-checkable claim. A candidate that lies about it
can at worst claim capacity it cannot fulfill — the same failure shape ROLES already tolerates
for a slow or crashed peer, not a new one.

*Why not Design B's live challenge instead?* B's refuter is correct that a symmetric-group-
secret challenge-response is relayable (any entitled-but-key-less candidate forwards the
requester's nonce to an actual holder and returns the answer as its own) and, worse, makes
eligibility depend on live network timing, breaking HRW's requirement that every spore compute
an identical candidate set from identical cached state. `root_commit` avoids both: it requires
no interaction with a third party at all, so there is nothing to relay and nothing to make
non-deterministic.

**Consumption in ROLES.** `eligible()` gates candidacy before HRW scoring (§1.12). `possess()`
gates only whether a *ranked* candidate accepts the specific job it is offered: on failure it
emits `roles.capability.declined{reason:'no_read_cap'}`, and **this explicit, already-verified
decline is an immediate re-rank/promote trigger** — distinct from, and not subject to, the
§1.21 `N × keepalive-interval` staleness cutoff, which stays reserved strictly for the silent/
crashed-peer case it was built for. (This also fixes both of A's "annoying" findings: no large
content download before declining, and no timeout tax on an already-observed decline.)

**When INDEX/FORGE legitimately cannot read**, i.e. zero candidates for a (colony, fruiting)
pass both layers: that fruiting gets no search index and no thumbnails. Clients fall back to
SP1's existing local-only search path, and the UI states *why* ("no eligible member device can
currently index/thumbnail this channel") rather than silently degrading or erroring mid-job.

---

### 2.3 The late-joiner KEYBUNDLE path

**Envelope** (block type `0x61 KEYBUNDLE`, not `auth_control` — it grants no permission,
membership is already decided by MEMBER_JOIN):

```
KEYBUNDLE.payload = {
  recipient_log_id: Bytes16,
  entries: [ { epoch_hash: Bytes32, root_commit: Bytes32, eph_pub: Bytes32,
               wrapped: AEAD_ct }, ... ]
}
// root_commit is duplicated here (not only read off the corresponding EPOCH_ROTATE block)
// so a bundle is self-contained and verifiable the instant it arrives, with no additional
// causal dependency — a mismatch against the EPOCH_ROTATE block's own root_commit, once that
// block also arrives, is a SECOND, independently detectable form of tamper evidence.

wrap_key = HKDF(shared, salt=epoch_hash, info="SPORE-KEYBUNDLE-v1" ‖ recipient_log_id, len=32)
wrapped  = AEAD-Seal(wrap_key, nonce=0^12, AAD=epoch_hash‖fruiting_id‖recipient_log_id,
                      pt=epoch_root)
// Unlike EPOCH_ROTATE's own wraps (§1, keyed on root_commit for a stated reason), KEYBUNDLE
// may key on epoch_hash directly: the target epoch's EPOCH_ROTATE block already exists,
// finished and hashed, by the time any KEYBUNDLE for it is minted — no circularity here.
// on unwrap: assert BLAKE2b-256("SPORE-ROOT-COMMIT-v1"‖epoch_root') == entry.root_commit —
// a corrupt or malicious entry fails silently and is ignored, logged as
// keyring.keybundle_commit_mismatch{minter}
```

**Minter.** Any current member S for which `eligible(S, colonyId, fruitingId)` (§2.2 Layer 1)
holds AND `possess(S, epoch_hash)` (§2.2 Layer 2) holds for *every* `epoch_hash` in the
entitlement set MAY mint a KEYBUNDLE for a newly-admitted recipient — the same predicate INDEX/
FORGE candidacy already uses, reused rather than invented. Minting is not exclusive: multiple
independently-minted bundles for the same joiner are harmless (fresh ephemerals differ per
entry; the joiner needs only one working entry per epoch; `root_commit` makes a bad one self-
detecting rather than silently corrupting state).

**Liveness watchdog.** Any minting-eligible member observing an accepted MEMBER_JOIN with no
KEYBUNDLE addressed to that recipient within a bounded causal horizon (measured in the
observer's own appended-block count — never wall time) mints one. This converts the single-
admitter dependency CORRECTNESS.md flagged into an ordinary gossip/repair problem the substrate
already knows how to handle.

**Supplemental wraps for an existing member who missed a rotation — not only new joiners.**
§2.1(d) deliberately does not check that a rotation's wrap set includes every currently-
eligible member, and the guarantee table (§3) leans on "KEYBUNDLE / supplemental-wrap
redundancy" to repair that omission — this is the rule that actually does it, stated once here
rather than left implicit. Any member M with `possess(M, epoch_hash)` for a fruiting's current
live epoch, observing — in the delivered block set — some spore N that `resolvedState_final`
shows holding VIEW for that fruiting, with **no** wrap entry for N in that epoch's
`EPOCH_ROTATE.payload.wraps` and **no** KEYBUNDLE entry for N covering that `epoch_hash`, MAY
mint `KEYBUNDLE{recipient_log_id: N, entries: [{epoch_hash, root_commit, ...}]}` addressed to
N. This is the exact same block type and the exact same minting predicate as the late-joiner
case above — no new machinery, just a second trigger condition ("VIEW-holder missing a live
epoch's wrap," not only "freshly admitted") for minting the same thing.

**History policy**, made concrete (`0x62 HISTORY_POLICY_SET`, `auth_control`, gated by
`MANAGE_FRUITING`): `payload = {policy: FROM_GENESIS|FROM_JOIN, effective_from_epoch_hash}`,
default `FROM_JOIN`. Every minter resolves this policy **as of the recipient's own MEMBER_JOIN
causal position**, never the minter's current view — a pure function of (resolved state, a
fixed causal point), so independent honest minters compute byte-identical entitlement sets.

**Delivery with no server.** A KEYBUNDLE block is an ordinary substrate block — cleartext outer
cert, opaque wrapped entries — replicated and served by any untrusted VAULT exactly like message
ciphertext. The crux mechanism (§4) is reused unmodified for key material; it is not a special
case. The joiner's own `substrate.wants()` marks its pending recipient-KEYBUNDLE dep at maximum
fetch priority, since every other fetched block is useless until it arrives.

**Residuals, disclosed plainly, not softened.** `historyPolicy` is enforced by minter honesty,
not cryptography or consensus: because minting is deliberately decentralized (to remove the
single-admitter point of failure), any current eligible-and-possessing member can grant
`FROM_GENESIS` history to a joiner even when the colony has set `FROM_JOIN` — nothing in the
protocol restricts *which* epoch_hashes a mint may include, only *who* may mint. This is a
policy-not-cryptography boundary, exactly like "no crypto mechanism distinguishes an honest
member from an authorized leaker" — state it as such in product copy, never as something the
protocol enforces. Separately: a symmetric `epoch_root`, once delivered, cannot be un-granted —
flipping the policy later never revokes bundles already issued. And if every member who ever
held a given `epoch_root` goes permanently offline before any joiner arrives, that epoch's
history is unrecoverable for that joiner — an honest consequence of "no server holds keys,"
which the UI must surface plainly rather than fail silently.

---

### 2.4 The crux — untrusted VAULTs serving shards they cannot read

**Encrypt-then-address, verified.** `BlockID = payload_hash = BLAKE2b-256(payload)`, where an
encrypted block's `payload` tail is ciphertext. A VAULT's existing `verifyBlock` (hash +
outer ed25519 signature check) requires **zero new logic and zero secret material** — the same
verification SP1 already performs, now covering ciphertext instead of plaintext bytes. This
reduces standardly to AEAD confidentiality, which reduces to key secrecy, and no key or key-
derivable material ever transits a VAULT-only code path: a VAULT sees only ciphertext, the
cleartext prefix (`epoch_hash`, `boot_nonce`, `i`) plus the block's own signed header (which
already carries `log_id`), and hash-verifiable BlockIDs. **This is the crux's actual claim, and
it holds.**

**GGM tree verified against that same claim, and dropped — as a *result*, not a shortcut.** The
tree's one real advantage over a flat chain is forward-secure deletion of a *consumed leaf
prefix*: discard internal nodes for messages already read, keep the ability to derive later
ones, forget earlier ones. SPORE never uses this capability: KEYBUNDLE ships the raw
`epoch_root` itself (§2.3), by construction — both history policies require reconstructing an
entire epoch's message-key range from one shared secret — and `epoch_root` is retained
indefinitely by every device that ever validly held it (there is no forward secrecy for
retained history in this model at all, §3/§5). Therefore `sender_root`, and every
`message_key(i)`, is always fully re-derivable in **O(1)** by anyone who ever held `epoch_root`,
whether or not a tree node was ever deleted. The tree protects a secret that is one derivation-
hop from total recoverability via the very mechanism (retained `epoch_root`) that makes the
rest of the design's from-genesis history model work at all. It buys nothing SPORE uses, at 32
HKDF evaluations per open instead of 1, and a second, harder-to-test data structure exactly
where design-crypto.md's own Risks section already names merge/re-wrap logic as the most
bug-prone surface. **Adopted: the flat chain (§1), and the GGM tree code path is deleted rather
than shipped alongside it.** Random-access, out-of-order, zero-round-trip decryption from any
VAULT in any order is preserved exactly — arguably strengthened to true O(1) — because that
property comes from HKDF-as-PRF over a directly-addressable label, not from tree structure.

**Authenticity, and an overclaim corrected.** Because `epoch_root` is shared, any member can
derive any other member's `message_key(i)` — but, per §1's fix, authorship attribution is
pinned to the block's own `header.log_id`, which is unforgeable already (substrate's
single-writer-log model: only that log's owner can produce a validly-signed block bearing that
`log_id`), so the outer signature/log model, not the inner one, is what actually prevents a
member from posting content attributed to someone else. The mandatory inner ed25519 signature
is **defense-in-depth**, not "the only thing preventing forged attribution" (both source
designs overclaimed this): it protects a payload that is later separated from its header —
forwarded standalone, or surviving SUBSTRATE's own payload redaction, which by design drops
payload bytes while keeping `block_hash`/header intact — so provenance is still checkable when
reunited with a *different* context. The tree (or its absence) never provided intra-colony
confidentiality either way; conflating "VAULT stays blind" with "members stay blind from each
other" is exactly the review's "looks like Signal, isn't" failure mode, and this design does
not make that conflation.

**Compromise of `wrap_priv_c` — the honest scope of the §1.14 fix.** `wrap_priv_c` is a
long-term static per colony with no rotation mechanism of its own. Its compromise exposes
every `epoch_root` ever wrapped to that device in that colony, past **and future**, until the
device is banned and a subsequent rotation's wrap-set check (§2.1 clause d) excludes it — the
same "recorded envelope" exposure C4 originally flagged for reusing the Noise static, now
disclosed as the real residual scope of giving colony-wrap its own key: a distinct wrap key
narrows the blast radius to one colony, it does not add forward secrecy or post-compromise
security to that key itself.

**Nonce/key-reuse safety, reverified with `boot_nonce` folded into `sender_root` itself** (not
only into the AAD, as both original designs had it): `sender_root` now depends on `boot_nonce`,
so a process that restarts — from a crash, an ordinary reboot, or a cloned identity file copied
to a second device and started as its own process — draws a **fresh** `boot_nonce` and
therefore derives a **different** `sender_root`, making `(key, nonce)` collision across restarts
or clones **prevented**, not merely detected, with zero extra bytes on the wire (`boot_nonce`
already had to ride in cleartext for recomputation). This also means the in-memory counter `i`
needs no write-ahead persistence or crash-recovery skip-ahead margin at all — it may safely
restart at 0 every boot, because a stale on-disk `i` value from a previous boot can never
collide with the current boot's `sender_root`. **The one residual case genuinely unaddressed:**
a live VM snapshot restored *without restarting the process* — `boot_nonce` lives only in
memory, so a resumed (not restarted) process image carries the identical `boot_nonce` forward,
and if it also carries a stale in-memory `i` that gets reused, the collision is real. This is a
narrower, more honestly-scoped residual than either original design disclosed, and it should be
listed as the one item for the targeted re-review in §6.

**What a VAULT still learns — quantified, not asserted:**
1. The full cleartext substrate cert: author `log_id`, `seq`, `lamport`, `fruiting_id`, `deps`
   (a permanent, durable social graph), and `payload_len` — cross-colony-linkable via the same
   ed25519 identity key across colonies (the disclosed, unresolved C5 regression; not fixed by
   the wrap-key colony-scoping in §1, which only prevents a *second* such channel).
2. The cleartext payload prefix (`epoch_hash`, `boot_nonce`, `i`) combined with the block
   header's `log_id` reveals each device's exact send cadence over time, and epoch-rotation
   cadence, without reading one message body.
3. EPOCH_ROTATE / KEYBUNDLE / MEMBER_* blocks are themselves cleartext control blocks: a VAULT
   or RELAY — member or not, colony-agnostic relaying is explicitly permitted — sees the
   complete membership roster, every ban/kick/leave, every joiner's admission timing, and
   (from which `epoch_hash` entries a KEYBUNDLE grants) roughly how much history that joiner
   received — all without ever seeing an `epoch_root`.
4. **Live per-request fetch timing and ordering from a specific requester reveals, in real
   time, which specific block that spore is reading right now** — this is not media-only, the
   way crypto.md's original Risks section framed it. Because the flat chain makes any
   `(author, device, epoch_hash, i)` independently fetchable, a requester's live fetch pattern
   is an equally strong "what are they reading right now" signal for text history as for media
   chunks.
5. Bucketed ciphertext size class (if padding per crypto.md §5 is adopted) is a well-studied
   side channel revealing rough content type even under padding.

**Net:** a VAULT/RELAY reconstructs a complete, cross-colony-linkable social graph, membership
timeline, per-device activity fingerprint, and a live-viewing signal, while learning **nothing**
about content. This is confidentiality-of-content only — it is not, and must not be marketed
as, metadata-minimizing in the sealed-sender sense. This matches design-crypto.md's own "worse
than the message content" self-assessment; do not soften it in product copy.

---

## 3. Guarantee table

| Guarantee | Provided? | Under what assumption | What breaks it |
|---|---|---|---|
| Content confidentiality against a VAULT/RELAY that never held `epoch_root` | **Yes** | AEAD security; `epoch_root` never transits a VAULT-only code path (§2.4) | A VAULT that is *also* a current or former member |
| Full forward secrecy + PCS at the hypha/transport layer | **Yes** (unchanged from SP1) | Noise XX `ee`/rehandshake correctness, verified vs. Cacophony vectors | Compromise of both parties' live ephemeral state — untouched by SP2 |
| Zero-round-trip, out-of-order decryption of any block from any VAULT | **Yes** | Requester already holds `epoch_root` for that block's `epoch_hash` | Requester missed a rotation (partition) with no KEYBUNDLE/supplemental wrap yet |
| Deterministic, order-independent agreement on which `epoch_hash` is valid | **Yes** | ARCHITECTURE.md **R4**'s `pin_seq` rule is live — NOT §1.19's `auth_ref` recomputation fix, which R4 records as not closing §1.19 at all; `final`/`cut(R)` are pure functions of the delivered block set (§2.1) | A spore that has not yet delivered the same block set — a knowledge gap, not a convergence failure; surfaces as a graceful fork, heals per §2.1 |
| A rotation citing a ban never wraps the banned member | **Yes** | Wrap-set content check (§2.1 clause d) at the rotation's own causal cut | A ban not yet in the minter's causal cut. **Unbounded** — the §1.19 staleness window this once cited does not exist (R4). Closed only when some honest current holder mints citing the unconsumed ban, which nothing schedules |
| Exclusion from *future* content once rotation propagates | **Yes, partition-limited** | Rotation reaches the excluded device's partition; some current BAN/KICK holder notices and mints | An indefinite partition no reachable holder ever notices — named open |
| `has_read_cap` correctly excludes non-members from INDEX/FORGE candidacy | **Yes** (Layer 1) | Per-fruiting VIEW resolution converges (existing Pass A/B property) | None known — hard, public, keyless precondition |
| INDEX/FORGE never assigned work it cannot perform | **Best-effort** | Candidate is honest about its own `possess()` self-check | A malicious candidate lying about possession — fails exactly like a slow/crashed peer already does |
| Nonce/key-reuse safety across process restart or a cloned identity file | **Yes, prevented** | `boot_nonce` fresh per process start, folded into `sender_root` (§1, §2.4) | A live VM snapshot resumed without restarting the process |
| Post-compromise security at the fruiting layer | **Yes, at rotation granularity, partition-limited** | The compromised device is subsequently BANNED, so the next rotation's wrap-set check (§2.1 clause d) excludes it | A compromised-but-not-yet-banned device keeps receiving every future `epoch_root` exactly like any legitimate member — PCS here means "eviction eventually excludes it," not "compromise is automatically detected" |
| Forward secrecy for retained fruiting history | **No, by design** | — | Any device that ever held `epoch_root_k` decrypts everything under `epoch_hash_k` forever, offline |
| Intra-colony confidentiality (members from each other) | **No, by design** | — | Any current/former `epoch_root` holder derives any other member's `message_key(i)` and can read it; the outer signature/log model (not the inner signature) is what actually prevents forged attribution — see §2.4's corrected overclaim |
| Metadata privacy from VAULT/RELAY | **No** | — | Full cleartext cert + control blocks give a permanent social graph, cadence, size class, live-fetch signal (§2.4) |
| Deniability | **No** | — | Every block carries a non-repudiable outer *and* inner signature, by design |
| Instant or partition-crossing revocation | **No** | — | A symmetric secret cannot be revoked from a device that already holds it; no consensus mechanism exists to make revocation synchronous |

---

## 4. What a removed member can still read, and what a VAULT learns — plainly

**Removed member, walked concretely.** Admin A bans member M in partition 1 and mints
`EPOCH_ROTATE R1` citing that ban; `R1`'s wrap-set, checked at `cut(R1)`, correctly excludes M.
Partition 2, holding M and other members, has not yet seen the ban. Unless some current
BAN/KICK holder in partition 2 independently notices and mints (citing the same,
still-unconsumed ban), M keeps reading and writing under the pre-ban `epoch_root` in partition 2
for the entire partition duration — unbounded, with no wall-clock fallback. On merge: M's future
writes are denied the instant partition 2's `final` state incorporates the ban (ordinary,
unchanged Pass A/B); any subsequent or merge-covering rotation automatically excludes M via
clause (d). But M **permanently retains**: every `epoch_root` validly held before exclusion
(decrypts all history under those epochs forever, offline — no way to revoke a symmetric secret
from a device that already has it), plus everything anyone in partition 2 sent during the entire
partition window before the ban propagated. **Product copy must say:** "removing a member stops
new reads once the removal reaches your mesh; it does not erase what they already downloaded."
**Never:** "removed means can no longer read this colony."

**What a VAULT learns anyway** (full detail in §2.4): a complete, cross-colony-linkable social
graph via `deps` and the permanent ed25519 identity; a complete membership/ban/join timeline via
cleartext control blocks; a per-device activity-rate fingerprint via the cleartext `epoch_hash`/
`i` prefix combined with the header's `log_id`; and — new relative to crypto.md's own
disclosure — a live, real-time signal of exactly which block (text or media) a specific spore is
fetching right now, from fetch timing and ordering alone. None of this requires ever seeing an
`epoch_root` or a plaintext byte. This is not a minor residual for metadata-sensitive threat
models; say so, don't soften it.

---

## 5. Constraints, confirmed met

**No wall clock, anywhere in this document.** EPOCH_ROTATE's hygiene trigger uses
`message_count`/`lamport_delta` (causal), replacing crypto.md's original "7 days"; §1.19's
staleness bound uses a `lamport`-gap, not wall time; KEYBUNDLE's liveness watchdog uses "the
observer's own appended-block count," not wall time; `boot_nonce` is per-process-start
randomness, not a timestamp. (SP1's unrelated 7-day *capability* expiry and short-code TTL,
mentioned in design-crypto.md §4, are pairing/revocation-latency mechanisms out of this
document's scope and are not touched here.)

**Zero npm dependencies, Node 24 stdlib only.** Every primitive above — X25519 (`generateKeyPair`
/ `diffieHellman`), Ed25519 (`sign`/`verify`), ChaCha20-Poly1305 (`createCipheriv`), HKDF
(`hkdfSync`), BLAKE2b (the in-tree RFC 7693 implementation already verified for SESSION) — is
stdlib, already in use elsewhere in the design. No new primitive is invented; dropping the GGM
tree *reduces* surface area rather than adding any.

---

## 6. SP2 build sequence

Each step is independently testable against a concrete scenario before the next begins.

> **Reconciled against the decision record, 2026-09-17.** This sequence was written before
> R1 and R4 and contradicted both. Two steps below are struck through rather than deleted,
> because the reasoning that failed is the useful part and a reader who finds the old text
> quoted elsewhere should be able to see what happened to it.

1. ~~**Land the §1.19 `auth_ref`/`deps` causal-binding recomputation fix, substrate-wide.**~~
   **VOID — this step was an instruction to reintroduce a bug the project has already
   disproved.** ARCHITECTURE.md R4: *"§1.19's adopted fix does not close §1.19. Implementing
   it is what revealed that... V1's attacker picks both the lamport and the dep set, so every
   rule phrased in terms of either is a rule the attacker satisfies for free."* A
   causal-binding recomputation is precisely a rule phrased in terms of the dep set.

   What shipped instead is R4's `pin_seq`: `ROLE_REVOKE` carries the revoker's view of the
   target's head, and a block by the target above that pin carrying a non-zero `auth_ref`
   stops the log. The one field an author cannot choose is their own `seq`. Refined since by
   R6 (one ordered list of boundaries, so grants and revocations cannot be read by two
   different rules) and R7 (a claim witness, so a verdict survives eviction).

   **Nothing to land. The test this step asked for already exists** — CORRECTNESS.md's V1
   scenario is `test/auth.test.js`, and it has been green since the pin landed.
2. **Implement per-colony `wrap_seed(colonyId)`**, distinct from `dh_seed`, published in
   `MEMBER_JOIN`. This is now **step 1**, and it is where SP2 actually begins.

   ~~SP1 colonies' existing `MEMBER_JOIN` blocks predate this field, so every pre-existing
   member must publish `wrap_pub_c` via a small dedicated block...~~ **VOID — R1 deleted this
   migration.** *"SP1 colonies do not carry forward to SP2. Compatibility is broken
   deliberately... We are not building that."* An SP2 colony has `wrap_pub_c` in every
   `MEMBER_JOIN` by construction, so there is no un-migrated member to gate step 5 on and no
   dual-mode read path. A member absent from a wrap-set is absent, full stop — which is a
   simpler and stricter rule than the one this step was hedging around.

   Test: two colonies on one device produce different `wrap_pub`; assert it never equals the
   device's Noise static.
> ## Resolved: neither `EPOCH_ROTATE` nor `KEYBUNDLE` is `KEEP_FOREVER`.
>
> The question was misframed. It assumed retention is keyed on whole-block wire type, which is
> what `store.js` does — but the design already commits to cert and payload being separately
> retainable (`design-substrate.md` §1 and §6, `FLAG.REDACTED` in `block.js`, and §1 of this
> document). Under that split the tension dissolves.
>
> **The substrate derives from neither type.** R4b retains exactly the three types
> `#rebuildAuth` reads. That is a derivation dependency, not a "control block" class. Neither
> `EPOCH_ROTATE` nor `KEYBUNDLE` is read by `#rebuildAuth` or `#authCheck`, so evicting them
> moves no frontier, and R4b's laundering argument — forget a revoke and the pin goes with it —
> has no analogue. The substrate's instinct is "keep" only for what the substrate *computes
> from*.
>
> **The payload cannot cross the wire at design scale anyway.** `MAX_BODY` is 65512 and a wrap
> entry is 96 bytes, so an `EPOCH_ROTATE` block cannot be sent above ~678 members, and a
> FROM_GENESIS `KEYBUNDLE` not above ~452 epochs. §2.1 already says the payload is fetched
> separately from the header; `sync.js` has no such path and `BLOCK` is cert+payload atomic.
> **The cert/payload split is therefore a step-5 prerequisite regardless of retention**, and it
> is the same mechanism R7 names as the SP2 storage question. Three problems, one mechanism.
>
> **And the DM case settles it on its own.** §2.1: a two-member fruiting rotates on every fresh
> ephemeral contribution. `KEEP_FOREVER` would make every DM turn's companion rotation
> unevictable, which makes DM logs unevictable.
>
> The cert should survive — `epoch_hash` *is* `block_hash`, cert-only, and later rotations walk
> it — at R4b's ~290-byte cost class. **Churn-proportional state is unavoidable when membership
> is a replicated log; the honest line is O(1) per membership event, not O(N), and not inside
> the substrate's unevictable set.**
>
> **There must be no post-eviction fetch path.** `insert()` refuses `seq < floor` deliberately
> (see the below-floor commit): re-admission below the floor *was* the byte-budget leak, since
> `forgetOldest` only iterates `[floor, linkedTo)`. Recipients who miss a wrap are served by
> KEYBUNDLE from any possessor, which §2.3 already designs; verifiers are served by an
> app-layer witness. Below the floor is decided, not unknown.
>
> **Three decisions step 5 will otherwise make by accident**, recorded here so it does not:
> (1) `KEEP_FOREVER` and `AUTHORITY` are currently the *same Set object*, and `MEMBER_*` /
> `FRUITING_CREATE` are evictable today while clause (d), `eligible()` and KEYBUNDLE
> entitlement all read them — they must join `KEEP_FOREVER` **without** joining `AUTHORITY`, so
> the two must be split before the first `.add()`. (2) This document never says what `auth_ref`
> an `EPOCH_ROTATE` carries, and `#authCheck` matches scope exactly, so a fruiting-scoped
> rotation cannot cite a colony-scoped grant — either rotations are colony-scoped with
> `fruiting_id` in the payload, or grants become per-fruiting. (3) The four-clause check belongs
> in the KEYRING/app layer consuming `'linked'`, never gating delivery: adding membership
> semantics to walk two would make delivery depend on blocks that are not retained.

3. **Implement the flat sender-key chain** with `boot_nonce` folded into `sender_root`; do not
   build the GGM tree. Test: derive `message_key(i)` at `i = 0, 1000, 4_000_000` in O(1); confirm
   a simulated process restart (fresh `boot_nonce`) never collides with a prior boot's keys at
   the same `i`.
4. **Implement the two-tier cert reuse**: cleartext prefix + ciphertext with mandatory inner
   signature; confirm `verifyBlock` needs zero shape changes. Test: a spore holding no
   `epoch_root` ingests, verifies, and serves a sealed block via hash+outer-sig alone, and
   cannot produce plaintext.
5. **Wire EPOCH_ROTATE as a Pass-B block with the four-clause `authCheck`.** Test: reproduce
   every attack from both refutations — demoted-moderator replay, colluding-wrap-of-a-banned-
   member, rotation-storm via repeated citation, non-author watchdog rotation — and confirm each
   is now handled as specified; reproduce a two-partition fork-then-merge and confirm convergent
   healing via an ordinary `deps`-citing merge rotation.
6. **Implement `has_read_cap`**: Layer 1 (per-fruiting VIEW, hard precondition before HRW) and
   Layer 2 (local `root_commit` self-check, decline-is-immediate-promote) in ROLES' INDEX/FORGE
   enumeration. Test: a non-member is never ranked; a ranked candidate lacking the current root
   declines within one message and the next candidate is promoted immediately, not after a
   keepalive-multiple timeout.
7. **Implement KEYBUNDLE (`0x61`)** with `root_commit`-verified entries, de-singularized
   any-eligible-and-possessing-member minting, and the causal-horizon liveness watchdog. Test:
   kill the original admitter mid-flight; confirm a second member supplies a working bundle;
   feed a bundle with a mismatched `root_commit` and confirm it's silently ignored with
   `keyring.keybundle_commit_mismatch` telemetry firing.
8. **Implement `HISTORY_POLICY_SET` (`0x62`)**, default `FROM_JOIN`, resolved at the joiner's
   own `MEMBER_JOIN` causal position. Test: two independent minters computing entitlement for
   the same joiner under the same policy produce byte-identical `epoch_hash` sets.
9. **Import the official Noise_XX test vectors** (already mandatory per §1.18) and confirm
   SESSION's framing is unmodified once KEYRING/epoch code lands on top of it. Test: vector
   suite passes; existing handshake byte counts (32/256/224) unchanged.
10. **Replace the SP1 non-dismissable "not encrypted" banner** with a per-(colony, fruiting)
    status indicator (plaintext / encrypted-pending-rotation / encrypted), gated on a positive,
    verifiable local signal. Test: a fruiting with an accepted `EPOCH_ROTATE` but no locally-held
    root still shows "pending," never "encrypted."
11. **Extend the ROLES enzyme-burst benchmark harness** with a read-cap-gated treatment
    (a controlled fraction of HRW-ranked candidates lacking Layer-2 possession). Test: the
    harness produces a measured INDEX/FORGE crossover number with a confidence interval, not an
    asserted formula.
12. **Commission a targeted adversarial re-review** of exactly three things before calling SP2
    shipped: completeness of §1.19's fix against the new EPOCH_ROTATE consumer; the merge-
    rotation healing convention against real partition-heal traces; and whether folding
    `boot_nonce` into `sender_root` actually eliminates crash/restart key reuse in practice
    (versus only the disclosed live-snapshot-resume residual).
