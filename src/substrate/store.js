// The substrate: what a spore actually holds.
//
// Single-writer hash-chained logs, one per identity, replicated by everyone who cares.
// This file is the thing block transfer moves blocks INTO, and the thing the scheduler
// asks "what am I missing".
//
// The design decision that makes parallel fetch possible at all:
//
//   A block's signature is SELF-CONTAINED. It covers the header (which includes prev_hash
//   and payload_hash) and nothing else. So a block that arrives out of order is already
//   provably authentic — we know the author wrote it, at that seq, with that payload,
//   before we have seen a single one of its predecessors.
//
// That is what lets us fetch seq 900 and seq 12 simultaneously from different peers. If
// authenticity required the chain, fetch would be strictly sequential, there would be no
// parallelism, and the entire "gets faster as spores join" claim would be arithmetic about
// a thing that cannot happen. Rarest-first scheduling is only meaningful because a lone
// block verifies alone.
//
// What the chain buys is separate and still needed: prev_hash linkage proves the AUTHOR
// did not later rewrite their own history. So the store tracks two different facts about
// every block, and never conflates them:
//
//   held   — signature verified under the log's author key. Immediate, order-free.
//   linked — reachable by prev_hash from seq 0. Contiguous, arrives as gaps close.
//
// Scheduling reads `held`. Ordered delivery reads `linked`.

import { EventEmitter } from 'node:events';
import { createPublicKey } from 'node:crypto';
import {
  verifyBlock, decodeBlock, logIdMatches, hash256, HEADER_LEN, SIG_LEN,
  TYPE, decodeGrant, decodeRevoke, colonyIdFor,
} from './block.js';
import { Bitfield } from '../sharding/scheduler.js';
// MAX_SEQ is a wire constant, but the thing it protects lives here: seq sizes LogReplica#bits.
// It is enforced at insert() rather than at decode, because insert() is the single funnel every
// block passes through — hypha, disk replay or test — and a bound checked on one transport is a
// bound one new transport silently loses.
import { MAX_SEQ } from '../sharding/wire.js';

export const CERT_MIN = HEADER_LEN + SIG_LEN;

/**
 * The most logs one substrate will hold.
 *
 * Membership does not gate log creation in SP1: any block whose signature verifies under
 * a key matching its log_id opens a replica, and anyone can mint keys for free. Without a
 * cap a peer can make a spore track unbounded logs, each carrying its blocks and
 * bitfields. Matches sync.js MAX_LOGS deliberately — one number, one meaning.
 */
export const MAX_LOGS = 256;

/**
 * How many bytes of block data one spore keeps before it starts forgetting.
 *
 * Without this the substrate grows forever: every block ever seen, plus a hash index
 * entry each, with no eviction and no persistence. That was survivable while a spore held
 * `pulse` traffic. It is not survivable on a phone, and it is invisible to everything we
 * measure — tests run for seconds, the harness moves 400 blocks. It would surface as a
 * device dying after a day with nothing pointing at the cause.
 *
 * Eviction takes the OLDEST LINKED blocks first, and only strictly below `linkedTo`:
 *   - below the frontier the history is already verified and delivered, and a peer that
 *     needs it can fetch it from somebody who still has it;
 *   - the block AT the frontier must survive, because relink() reads its hash and its
 *     lamport to validate the next one;
 *   - above the frontier nothing is evictable, because those blocks are the only reason
 *     the frontier will ever advance.
 *
 * Forgetting a block clears its HAVE bit. A replica that advertises what it cannot serve
 * is lying to the swarm, and the cost lands on the requester as a wasted round trip.
 */
export const MAX_BYTES = 64 * 1024 * 1024;

/**
 * One author's log, as far as this spore has it.
 *
 * `authorPub` is not taken on trust. It is checked against log_id on first sight
 * (`logIdMatches`), and every block in the log is then verified under it — so a peer
 * cannot hand us a log claiming to be someone else's.
 */
/**
 * The control blocks that decide who may write what. Eviction may never drop them
 * (LogReplica#forgetOldest) and Substrate#rebuildAuth reads exactly these.
 */
const AUTHORITY = new Set([TYPE.COLONY_GENESIS, TYPE.ROLE_GRANT, TYPE.ROLE_REVOKE]);

/** How many forgotten blocks' positions one replica remembers. See LogReplica#lost. */
export const LOST_CAP = 4096;
const KEEP_FOREVER = AUTHORITY;

export class LogReplica {
  constructor(logId, authorPub) {
    this.logId = Buffer.from(logId);
    this.key = this.logId.toString('hex');
    this.authorPub = Buffer.from(authorPub);
    this.blocks = new Map(); // seq:number -> { cert, payload, hash, lamport }
    this.bits = new Bitfield(1); // held-set, grows with the log
    this.head = -1; // highest seq we hold
    this.floor = 0; // bottom of the chain-verifiable range; below it, only AUTHORITY is kept
    // What sat at floor-1 before it was forgotten. Without these, the first recomputation
    // after any eviction collapses the frontier back to the floor and never recovers:
    // relink() restarts at `floor` and asks for its predecessor's hash and lamport, which
    // eviction has just deleted. Measured before it was fixed: a 20-block log evicted to a
    // floor of 15 kept linkedTo 19 until something forced a recompute, then dropped to 14
    // and promoted nothing, permanently. Two 8/32-byte fields are the whole cost of not
    // having to choose between forgetting and re-deriving.
    this.floorHash = null;
    this.floorLamport = 0n;
    // hash -> lamport for blocks this replica has forgotten.
    //
    // depLamports on the citing block was only ever half of this, and the half that
    // assumed the citer was already here. A block that arrives AFTER its dep was evicted
    // never got the chance to resolve it live, so it has nothing cached and stalls — on
    // this replica, forever, while a replica that happened to meet the citer first linked
    // it. Same blocks, different delivery, which is the shape this substrate exists to
    // rule out. The review found it and was right; the comment claiming "the question was
    // asked and answered before the evidence went" was true only of citers we hold.
    //
    // A lamport is 8 bytes and a hash key is 64 chars of hex, so this is ~2 KB per
    // thousand evicted blocks — small, but not free and not unbounded: see LOST_CAP.
    this.lost = new Map();
    this.bytes = 0;
    this.forgotten = 0;
    this.linkedTo = -1; // highest seq reachable by prev_hash from 0, AND lamport-derived
    // Highest seq reachable by prev_hash alone. Weaker than linkedTo on purpose, and it
    // is what AUTHORITY is read from — see Substrate#rebuildAuth. Whether a block was
    // written by this author, and where in their log, is settled by the signature and the
    // chain; it does not wait on some earlier block of theirs having its lamport confirmed
    // against a dep in somebody else's log.
    this.chainTo = -1;
    // Highest seq whose prev_hash AND lamport check out, regardless of authority. This is
    // what a DEP resolves against, because ordering and permission are different
    // questions: a block written by somebody who had lost their role still happened, still
    // sits at a definite causal position, and its lamport was derived and checked like any
    // other. Making deps wait on `linkedTo` meant an owner who replied to a member and
    // then revoked them stranded their OWN log forever on a dep that could never resolve.
    this.orderedTo = -1;
    this.pendingDeps = false; // frontier is waiting on a dep in another log
    this.forks = new Map(); // seq -> { kept, other } block hashes
    this.forkedAt = Infinity; // lowest seq the author signed twice; the log ends here
  }

  get forked() { return this.forkedAt !== Infinity; }

  get held() { return this.blocks.size; }
  has(seq) { return this.blocks.has(seq); }
  get(seq) { return this.blocks.get(seq) || null; }
  hashAt(seq) { return this.blocks.get(seq)?.hash || null; }

  /**
   * Forget the oldest verified block. Returns what was dropped, or null if nothing can be.
   *
   * Strictly below linkedTo: the frontier block itself is what relink() chains and derives
   * the next lamport from, so dropping it would stall the log permanently.
   *
   * CONTROL BLOCKS ARE NEVER DROPPED. The oldest block in a founder's log is its
   * COLONY_GENESIS, so the plain rule hands the budget a way to launder a revocation:
   * forget the genesis and the colony has no owner, so every member's authority claim
   * stalls; forget a ROLE_REVOKE and the pin goes with it, so a demoted moderator's blocks
   * link again. A spore that had simply been running long enough to reach its byte budget
   * would re-admit everyone it had ever removed, silently. They are ~290 bytes each and
   * they stay; the floor advances past them, so they sit below the chain-verifiable range
   * as authority-only, which is exactly what they are once their neighbours are gone.
   */
  forgetOldest() {
    for (let s = this.floor; s < this.linkedTo; s++) {
      const b = this.blocks.get(s);
      this.floor = s + 1;
      if (!b) continue;
      if (b.hash) { this.floorHash = b.hash; this.floorLamport = b.lamport; }
      if (KEEP_FOREVER.has(b.type)) continue; // authority outlives the byte budget
      this.blocks.delete(s);
      if (s < this.bits.size && this.bits.has(s)) {
        this.bits.bits[s >> 3] &= ~(1 << (s & 7));
        this.bits.count--;
      }
      this.bytes -= b.bytes;
      this.forgotten++;
      // Remember where it sat, so a citer that has not arrived yet can still be ordered.
      // Bounded, and oldest-out: past the cap a citer genuinely stalls, and that stall is
      // honest — every replica running the same budget forgot the same thing.
      this.lost.set(b.hash.toString('hex'), b.lamport);
      if (this.lost.size > LOST_CAP) {
        const oldest = this.lost.keys().next().value;
        this.lost.delete(oldest);
      }
      return b;
    }
    return null;
  }

  /** How many blocks we hold strictly below `limit`. Used to measure a forked log. */
  countBelow(limit) {
    let n = 0;
    for (const seq of this.blocks.keys()) if (seq < limit) n++;
    return n;
  }

  /**
   * Advance the chain frontier as far as prev_hash alone allows.
   *
   * Same walk relink() does, minus lamport and minus authority — which is the entire
   * point. Cheap: it only ever moves forward, and only when the block that just landed
   * closes the gap at chainTo + 1.
   *
   * Returns true if the walk brought an AUTHORITY block into reach. That is not the same
   * question as "is the block that just arrived a control block": a revocation can sit
   * held-but-unchained above a gap for as long as it takes an ORDINARY message to fill it,
   * and the moment it does, who may write what changes. Triggering only on control-block
   * arrival made the outcome depend on whether the gap-filler came before or after the
   * revocation — which the convergence property caught, on seed 3.
   */
  extendChain() {
    let authority = false;
    for (let s = this.chainTo + 1; s < this.forkedAt; s++) {
      const b = this.blocks.get(s);
      if (!b) break;
      const prev = s === 0 ? null : (s === this.floor ? this.floorHash : this.hashAt(s - 1));
      const d = decodeBlock(b.cert);
      const chained = s === 0
        ? d.prevHash.every((x) => x === 0)
        : d.prevHash.equals(prev || Buffer.alloc(0));
      if (!chained) break;
      this.chainTo = s;
      if (AUTHORITY.has(b.type)) authority = true;
    }
    return authority;
  }

  /** Grow the held-bitfield so index `seq` is representable. */
  reserve(seq) {
    if (seq + 1 > this.bits.size) this.bits.grow(seq + 1);
  }

  /**
   * Advance the linked frontier as far as prev_hash AND lamport allow.
   *
   * Called after every insert, because the block that just landed may be the one that
   * closes a gap and promotes a long run at once. Genesis (seq 0) is linked when its
   * prev_hash is all zero; every later block when its prev_hash equals the block before.
   * It never advances to or past a fork. See `recordFork`.
   *
   * LAMPORT IS CHECKED HERE AND NOWHERE ELSE, for the same reason prev_hash is: the rule
   * is `lamport = 1 + max(own previous, all deps)`, and you cannot evaluate it without
   * holding the previous block. Linking is precisely the point at which we do.
   *
   * Two rules, and the difference between them matters:
   *
   *   STALL  a dep we do not yet hold, or hold but have not LINKED, stops promotion here
   *          until it links. Reading a dep's lamport before that dep is validated would
   *          mean trusting the exact number we are trying not to trust.
   *   STOP   a lamport that does not equal the derived value halts the frontier at s-1,
   *          permanently and identically on every replica — the same deterministic stop
   *          a fork gets. Rejecting the block instead would make the outcome depend on
   *          arrival order, which is the bug class this substrate already shipped once.
   *
   * `resolve(depHash)` returns { lamport, linked } for a block in ANY log, or null.
   * A LogReplica cannot see other replicas, so the Substrate supplies it.
   *
   * `authOf(replica, seq, decoded)` judges the block's auth_ref claim and returns
   * 'ok' | 'stall' | 'stop' — the same two-outcome discipline a third time, for the same
   * reason. See Substrate#authCheck.
   */
  relink(resolve, authOf, lost = () => null) {
    this.pendingDeps = false;

    // WALK ONE — ORDERING. prev_hash and lamport, nothing else. Monotone: once a block's
    // position is settled it is settled for good, so this never re-examines anything.
    for (let s = this.orderedTo + 1; s < this.forkedAt; s++) {
      const b = this.blocks.get(s);
      if (!b) break;
      const d = decodeBlock(b.cert);

      // At the floor the predecessor has been forgotten, so its hash and lamport come from
      // the witness kept when it went. Verified once, on arrival; not re-derivable now.
      const prevHash = s === 0 ? null : (s === this.floor ? this.floorHash : this.hashAt(s - 1));
      const chained = s === 0
        ? d.prevHash.every((x) => x === 0)
        : d.prevHash.equals(prevHash || Buffer.alloc(0));
      if (!chained) break; // a real break in the author's own chain; stop, do not skip it

      let m = s === 0 ? 0n
        : (s === this.floor ? this.floorLamport : this.blocks.get(s - 1).lamport);
      let stalled = false;

      // Resolve each dep live; fall back to the witness ONLY where the evidence is gone.
      //
      // The witness exists because eviction deletes a block and its byHash entry together,
      // so a recompute that insisted on re-resolving would strand every log that had ever
      // cited forgotten history. Eviction only takes blocks below a frontier, so anything
      // citing them had already ordered them: the question was asked and answered before
      // the evidence went, and this is floorLamport generalised from the one predecessor
      // to all N deps.
      //
      // It is a FALLBACK, not a cache, and the difference is a convergence bug. Trusting
      // it whenever present meant a dep retracted by a late-arriving fork kept the lamport
      // it had been frozen with, so whether a log linked depended on whether it was
      // ordered before or after the fork turned up — the exact arrival-order dependence
      // this substrate exists to avoid. The property harness caught it on seed 5.
      //
      // Not fixed and not introduced here: a fork at a seq already evicted can no longer
      // be DETECTED, because detection is a collision at that seq and nothing is left to
      // collide with. That is a property of forgetting.
      const got = [];
      for (let i = 0; i < d.deps.length; i++) {
        const dr = resolve(d.deps[i]);
        if (dr) {
          if (!dr.ordered) { stalled = true; break; }
          got.push(dr.lamport);
        } else if (b.depLamports && i < b.depLamports.length) {
          got.push(b.depLamports[i]); // we answered this once, while the block was here
        } else {
          // Never answered it, because the dep was forgotten before this block arrived.
          // The substrate may still remember where it sat; that recollection is the only
          // thing standing between this citer and a permanent, replica-local stall.
          const recalled = lost(d.deps[i]);
          if (recalled === null) { stalled = true; break; }
          got.push(recalled);
        }
      }
      if (!stalled) {
        b.depLamports = got;
        for (const dl of got) if (dl > m) m = dl;
      }

      if (stalled) { this.pendingDeps = true; break; }
      if (d.lamport !== m + 1n) break; // asserted, not derived. The log ends here.
      this.orderedTo = s;
    }

    // WALK TWO — DELIVERY. Authority, over the ordered range only, and re-run from
    // linkedTo every time: a grant can arrive late, and when it does the run it was
    // blocking has to promote. An earlier version folded this into the walk above with a
    // sticky flag, which meant that once authority had stopped a log, nothing ever asked
    // again and a late grant was silently ignored forever.
    const promoted = [];
    for (let s = this.linkedTo + 1; s <= this.orderedTo; s++) {
      const b = this.blocks.get(s);
      if (!b) break;
      if (authOf) {
        const verdict = authOf(this, s, decodeBlock(b.cert));
        if (verdict === 'stall') { this.pendingDeps = true; break; }
        if (verdict === 'stop') break; // the authority claim fails. Delivery ends here.
      }
      this.linkedTo = s;
      promoted.push(s);
    }
    return promoted;
  }
}

/**
 * Every log this spore holds, plus the local one it writes.
 *
 * Events:
 *   'block'        { logId, seq, from, block, payload }  a block was accepted
 *   'linked'       { logId, seqs }                       blocks joined the verified chain
 *   'equivocation' { logId, seq, a, b }                  the author signed two blocks at one seq
 *   'retracted'    { logId, seqs }                       linked history withdrawn behind a fork
 */
export class Substrate extends EventEmitter {
  constructor({ telemetry = null, maxBytes = MAX_BYTES } = {}) {
    super();
    this.tel = telemetry;
    this.maxBytes = maxBytes;
    this.bytes = 0;
    this.logs = new Map(); // logIdHex -> LogReplica
    // block_hash -> { key, seq }. Deps name blocks by hash and may point into ANY log,
    // so validating a dep's lamport needs a substrate-wide index; a replica only sees
    // itself.
    this.byHash = new Map();
    // Derived authority, rebuilt from the linked set — never accumulated incrementally,
    // because a retraction can withdraw a grant and an accumulator has no way to notice.
    this.auth = { owners: new Map(), grants: new Map(), revokes: new Map(), rule: new Map() };
    this.authSig = null;
  }

  /**
   * What a dep points at, for lamport derivation. null if we do not hold it.
   *
   * `ordered`, not `linked`: a dep asks WHERE a block sits, not whether its author was
   * allowed to write it. See LogReplica#orderedTo.
   */
  resolveDep(depHash) {
    const at = this.byHash.get(Buffer.from(depHash).toString('hex'));
    if (!at) return null;
    const r = this.logs.get(at.key);
    const b = r?.get(at.seq);
    if (!b) return null;
    return { lamport: b.lamport, ordered: at.seq <= r.orderedTo, replica: r, seq: at.seq, block: b };
  }

  /**
   * Where a forgotten block sat, if any replica still remembers. Anything evicted was
   * below a frontier, so its position was settled and is not re-derivable — only recalled.
   */
  lostLamport(depHash) {
    const key = Buffer.from(depHash).toString('hex');
    for (const r of this.logs.values()) {
      const l = r.lost.get(key);
      if (l !== undefined) return l;
    }
    return null;
  }

  /**
   * Is this block's `auth_ref` claim good? 'ok' | 'stall' | 'stop'.
   *
   * CORRECTNESS.md [FATAL-V1]: a moderator demoted while offline reconnects and publishes
   * a block citing the grant they used to hold, "with a naturally low lamport". Their
   * counter is frozen at their own head, so the block sorts BEFORE the revocation and gets
   * auth-checked against history from before the demotion — and every compliant spore
   * computes the same wrong answer, which is what makes it fatal rather than annoying.
   *
   * That rules out every fix which asks a question the author gets to answer:
   *   - compare the two lamports: the author picks theirs, and picks it low;
   *   - ask whether the revocation is causally before the block: the author picks the deps
   *     and simply does not cite it;
   *   - require auth_ref to descend from the most recent snapshot in the author's own
   *     causal cut: true of the stale grant, because the cut is the author's too.
   *
   * ARCHITECTURE.md 1.19 also proposes rejecting a block whose auth_ref/lamport gap from
   * "the current resolved frontier" exceeds a threshold. That one is NOT implemented, and
   * should not be: the current frontier is receiver-local and time-varying, so two honest
   * spores holding identical blocks would reject differently and never reconcile. It is
   * the arrival-order bug wearing a different hat.
   *
   * What an author does not control is their own seq. The log is single-writer and
   * append-only, so a revocation pinning the target at seq k condemns every block the
   * target writes above k, whatever lamport it claims. Writing at or below k instead is
   * not an escape: it is an equivocation, and the log already ends at a fork.
   *
   * There is deliberately NO rule that the grant's lamport must fall below the block's.
   * It reads as an obvious sanity check and it is not one: lamport only advances through
   * cited deps, and a block claiming under a grant does not have to cite it, so an honest
   * member whose counter is behind the owner's writes perfectly good blocks that sit
   * "before" their own grant. The rule was written, and it stopped every legitimate block
   * in the tests below. It also bought nothing — an attacker can cite the grant as a dep
   * and satisfy it for free, since the grant is old and its lamport is low. Position in
   * time is not what authorises; the absence of a pin is.
   *
   * Well-foundedness: only the colony owner's revocations count, and the owner is never
   * revoked, so the owner's frontier can never be stopped here. The set of valid
   * revocations therefore cannot shrink while frontiers are recomputed, and
   * #resolveFrontiers reaches a fixed point instead of oscillating. Delegated
   * grant-of-grant is deliberately SP2 for exactly that reason: with delegation a
   * counter-revocation can un-stop a log, which can link a revocation, which stops
   * another, and the set is no longer monotone.
   */
  #authCheck(replica, seq, d) {
    if (d.authRef.every((x) => x === 0)) return 'ok'; // claims nothing, needs nothing

    // Who owns the colony this block is written in? Derived from the linked
    // COLONY_GENESIS, so a retraction that withdraws one takes the ownership with it.
    const scope = d.scopeId.toString('hex');
    const owner = this.auth.owners.get(scope);
    if (!owner) return 'stall'; // we do not know this colony yet; not the author's fault

    const ref = Buffer.from(d.authRef).toString('hex');
    const g = this.auth.grants.get(ref);
    if (!g) {
      // Not a grant we recognise. Distinguish "have not got it" from "got it and it is
      // not one", because the first must wait and the second must not.
      const at = this.byHash.get(ref);
      const held = at && this.logs.get(at.key)?.get(at.seq);
      if (!held) return 'stall';                              // never seen it
      if (held.type !== TYPE.ROLE_GRANT) return 'stop';       // held, and not a grant
      return 'stall';                                         // a grant, chain not yet joined
    }
    if (g.owner !== owner) return 'stop'; // granted by someone with nothing to give
    if (g.target !== replica.key) return 'stop'; // somebody else's grant
    // Revocation pins carry a scope, so grants must too, or the two are asymmetric: an
    // owner of two colonies who removes someone from one has not removed them from the
    // other, yet their grant in the first would still authorise writes in the second.
    if (g.scope !== scope) return 'stop';

    // WHICH statement of the owner's governs THIS seq. The last boundary at or below it;
    // ties to the later block in the owner's own log, so an owner who changes their mind
    // has their latest word win without anything having to compare wall clocks.
    const list = this.auth.rule.get(`${replica.key}|${scope}`);
    let governing = null;
    if (list) {
      for (const e of list) {
        if (e.boundary > seq) break; // sorted, so nothing after this can govern either
        governing = e;
      }
    }
    // The owner has said nothing that reaches this seq. STALL: they may yet, and deciding
    // against the author now would make the answer depend on what has arrived.
    if (!governing) return 'stall';
    // NO TEST DIES IF YOU DELETE THIS LINE, and that is now true by construction rather
    // than by oversight. To get past it a block must cite a grant we hold, that is ours,
    // is a grant, targets this log and matches scope — and any revocation governing this
    // seq necessarily sorts after that grant, so the supersession loop below returns stop
    // too. Mutation-tested: removed, the full suite still passes.
    //
    // Kept anyway, as the plain statement of the rule at the point it is decided, and
    // deliberately not defended by a test that could only be a tautology. It is redundant
    // BECAUSE the loop below is correct; if that loop is ever changed, this stops being
    // redundant, which is the reason not to delete it now.
    if (governing.kind === 'revoke') return 'stop';

    // Governed by a grant. The cited one must be IN FORCE here — covering this seq, and
    // not superseded by a revocation that reaches it — but it need not be the LATEST.
    //
    // "Cite the latest" was written first and is retroactively destructive: an owner who
    // writes a forgiving re-grant at boundary 0 would supersede the original grant for
    // seqs already delivered under it, and history that was valid when it arrived would
    // stop. An owner being generous should not invalidate the past. V1 is closed by the
    // revocation boundary, which is a statement about a RANGE, not by forcing every block
    // to name the newest piece of paper.
    const cited = list.find((e) => e.kind === 'grant' && e.hash === ref);
    if (!cited) return 'stall';               // held, ours, but not yet chain-reachable
    if (cited.boundary > seq) return 'stop';  // that grant does not reach this far back
    // Superseded BY THE SAME ORDERING the governing lookup above used, and that is the
    // whole point. Asking this question by owner-log position instead was two rules for
    // one question — the exact thing the single ordered list in #rebuildAuth exists to
    // prevent — and it was wrong in both directions: a revocation whose range ended below
    // a later grant's range still cancelled it, and a revocation written before a grant
    // never cancelled it however far its range reached. ownerSeq breaks a tie at EQUAL
    // boundary. It is not the comparison.
    for (const e of list) {
      if (e.boundary > seq) break;
      if (e.kind !== 'revoke') continue;
      const after = e.boundary > cited.boundary
        || (e.boundary === cited.boundary && e.ownerSeq > cited.ownerSeq);
      if (after) return 'stop'; // the owner withdrew this grant before this block was written
    }
    return 'ok';
  }

  /**
   * Rebuild owners and revocations from the linked set. Returns a signature of the result
   * so #resolveFrontiers can tell whether another pass could change anything.
   *
   * Only LINKED blocks count. An unlinked revocation has not proven it is the owner's, and
   * honouring it would mean trusting exactly the chain we have not verified yet — the same
   * mistake as reading an unlinked dep's lamport.
   */
  #rebuildAuth() {
    const owners = new Map();
    const grants = new Map();
    const pending = [];
    for (const r of this.logs.values()) {
      // Iterate what is HELD rather than a seq range: eviction keeps control blocks below
      // the floor, and those are exactly the ones that must not stop counting.
      for (const [seq, b] of r.blocks) {
        if (!AUTHORITY.has(b.type)) continue;
        // Chain-reachable, or kept from below the floor — which was chained before it was
        // forgotten. NOT `linkedTo`: see the note above on why that was a cycle.
        if (seq > r.chainTo && seq >= r.floor) continue;
        if (b.type === TYPE.COLONY_GENESIS) {
          // A colony names its own founder. A genesis whose scope_id is not the derived
          // value is ignored outright — not tiebroken against the real one, because a
          // tiebreak is a race and anyone can enter it with one cheap block.
          if (!colonyIdFor(r.logId, seq).equals(b.scopeId)) continue;
          owners.set(b.scopeId.toString('hex'), { key: r.key, hash: b.hash });
        } else {
          pending.push({ author: r.key, seq, block: b, scope: b.scopeId.toString('hex') });
        }
      }
    }

    // Grants and revocations are the same kind of statement — "from this seq onward" — so
    // they go in ONE list per (target, scope), ordered, and the block that governs a given
    // seq is simply the last boundary at or below it. Two separate rules (a grant lookup
    // and a pin scan) could disagree; one ordered list cannot.
    const revokes = new Map();
    const rule = new Map();
    const add = (target, scope, entry) => {
      const k = `${target}|${scope}`;
      const list = rule.get(k) || [];
      list.push(entry);
      rule.set(k, list);
    };

    for (const p of pending) {
      const o = owners.get(p.scope);
      if (!o || o.key !== p.author) continue; // not the owner's word, so no power
      if (p.block.type === TYPE.ROLE_GRANT) {
        let g;
        try { g = decodeGrant(p.block.payload); } catch { continue; }
        const hash = p.block.hash.toString('hex');
        const target = g.target.toString('hex');
        grants.set(hash, { owner: p.author, target, scope: p.scope });
        // A grant governs FROM its pin.
        add(target, p.scope, { boundary: Number(g.pinSeq), ownerSeq: p.seq, kind: 'grant', hash });
        continue;
      }
      let rv;
      try { rv = decodeRevoke(p.block.payload); } catch { continue; }
      const target = rv.target.toString('hex');
      const list = revokes.get(target) || [];
      list.push({ pinSeq: Number(rv.pinSeq), scope: p.scope });
      revokes.set(target, list);
      // A revocation governs from ONE PAST its pin: the pin is the last seq it leaves
      // alone. That single +1 is what keeps V1 closed under re-grant.
      add(target, p.scope, { boundary: Number(rv.pinSeq) + 1, ownerSeq: p.seq, kind: 'revoke' });
    }

    // Sorted by boundary, then by position in the OWNER'S log — which is the tie-break,
    // and which is why ownerSeq has to come from the owner's log and not the member's.
    for (const list of rule.values()) {
      list.sort((a, b) => (a.boundary - b.boundary) || (a.ownerSeq - b.ownerSeq));
    }

    this.auth = {
      owners: new Map([...owners].map(([k, v]) => [k, v.key])), grants, revokes, rule,
    };

    // A signature of what was DERIVED, so a caller can tell a real authority change from a
    // stranger shouting into their own log. Sorted, so it is a function of the content and
    // never of Map iteration order — which is insertion order, which is arrival order.
    const parts = [];
    for (const [scope, o] of [...owners].sort()) parts.push(`o:${scope}:${o.key}`);
    for (const [h, g] of [...grants].sort()) parts.push(`g:${h}:${g.target}:${g.scope}`);
    for (const [k, list] of [...rule].sort()) {
      for (const e of list) parts.push(`${e.kind[0]}:${k}:${e.boundary}:${e.ownerSeq}`);
    }
    return parts.join('|');
  }

  /**
   * Relink every replica until nothing more moves.
   *
   * A block stalled on a cross-log dep becomes linkable the moment that dep links, and
   * the dep lives in a different replica — so linking one log can unblock another, and a
   * single pass over the log that just changed is not enough. The loop is bounded by
   * progress: each round must promote at least one block or it is the last.
   */
  #relinkAll(seed) {
    const resolve = (h) => this.resolveDep(h);
    const authOf = (r, seq, d) => this.#authCheck(r, seq, d);
    const lostOf = (h) => this.lostLamport(h);
    const out = new Map();
    let round = [seed];
    for (;;) {
      let moved = false;
      for (const r of round) {
        const wasOrdered = r.orderedTo;
        const got = r.relink(resolve, authOf, lostOf);
        if (r.orderedTo > wasOrdered) moved = true; // ordering unblocks deps too
        if (!got.length) continue;
        moved = true;
        const prev = out.get(r) || [];
        out.set(r, prev.concat(got));
      }
      if (!moved) break;
      // Only replicas actually waiting on a dep can have been unblocked by that progress.
      // `pendingDeps` is sufficient, and the wider filter that was briefly here was not:
      // ordering stops for exactly four reasons, and three of them (a gap, a broken chain,
      // a bad lamport) stop it permanently or stop chainTo with it. Only a stalled dep is
      // waiting on news from elsewhere, and only it sets this flag.
      round = [...this.logs.values()].filter((r) => r.pendingDeps);
      if (!round.length) break;
    }
    return out;
  }

  get size() {
    let n = 0;
    for (const r of this.logs.values()) n += r.held;
    return n;
  }

  replica(logIdHex) { return this.logs.get(logIdHex) || null; }

  /**
   * Get or create the replica for a log, binding it to its author ON CREATION ONLY.
   *
   * Read that again, because it is the whole trap. `logIdMatches` runs when the replica
   * is new. For a log we already track it does not run, and it must not — the authority
   * is the key we recorded the first time, not whatever the current message supplies.
   *
   * So the returned replica's `authorPub` is the ONLY key a caller may verify against.
   * Verifying against the caller's own `authorPub` argument and then calling this is how
   * a forgery gets in: the signature checks out under the forger's key, this hands back
   * the real author's replica, and the block lands in someone else's log.
   */
  ensure(logId, authorPub) {
    const key = Buffer.from(logId).toString('hex');
    const existing = this.logs.get(key);
    if (existing) return existing;
    if (!logIdMatches(logId, authorPub)) {
      this.tel?.count('substrate.reject.log_author_mismatch');
      return null;
    }
    if (this.logs.size >= MAX_LOGS) {
      this.tel?.count('substrate.log_cap_reached');
      return null;
    }
    const r = new LogReplica(logId, authorPub);
    this.logs.set(key, r);
    this.tel?.gauge('substrate.logs', this.logs.size);
    return r;
  }

  /**
   * Accept a block from anywhere — a live push, a fetch response, or our own append.
   *
   * `authorPub` is the claimed writer. It is verified against log_id, then the signature
   * is verified against it, then the payload against payload_hash. Nothing about the peer
   * that delivered this is consulted: a block is authentic on its own terms or it is not
   * admitted. That is what makes a RELAY untrusted-by-construction rather than by policy.
   */
  insert(cert, payload, authorPub, from = 'local') {
    if (cert.length < CERT_MIN) return { ok: false, reason: 'cert_short' };

    // Decode before verifying, because WHICH KEY to verify under is a property of the
    // log, not of the message. Doing it the other way round — verify under the supplied
    // key, then look the log up — is a forgery: the signature is real, it is simply not
    // the author's, and the log lookup happily returns the victim's replica.
    let d;
    try {
      d = decodeBlock(cert);
    } catch (e) {
      this.tel?.count('substrate.reject.decode');
      return { ok: false, reason: `decode: ${e.message}` };
    }

    // Before anything is allocated. seq sizes LogReplica#bits, and ensure() below creates a
    // replica keyed by a log_id the sender chose — so the free check goes first, or a block
    // that is about to be refused has already cost us an allocation.
    const seq = Number(d.seq);
    if (!Number.isSafeInteger(seq) || seq < 0 || seq > MAX_SEQ) return { ok: false, reason: 'seq_range' };

    const r = this.ensure(d.logId, authorPub);
    if (!r) return { ok: false, reason: 'log_author_mismatch' };

    // The replica's stored key, never the wire's. For a new log the two are the same by
    // construction (ensure just checked the binding); for a known log this is what makes
    // the binding hold for every block after the first, which is the entire point.
    const v = verifyBlock(cert, edKeyOf(r.authorPub), payload);
    if (!v.ok) {
      this.tel?.count(`substrate.reject.${v.reason.split(':')[0]}`);
      return { ok: false, reason: v.reason };
    }
    const b = v.block;

    // The signed seq must be the one we bounds-checked above; decode and verify read the
    // same field, and a mismatch would mean the two disagree about the cert's own layout.
    if (Number(b.seq) !== seq) return { ok: false, reason: 'seq_range' };

    const prior = r.blocks.get(seq);
    if (prior) {
      if (prior.hash.equals(b.blockHash)) return { ok: true, duplicate: true, seq };
      // The author signed two different blocks at the same seq. This is not a network
      // fault and not something a peer can fake — both signatures verify under the
      // author's own key. We keep what we had, record the proof, and surface it.
      this.#recordFork(r, seq, prior.hash, b.blockHash, prior.cert, cert);
      return { ok: false, reason: 'equivocation', seq };
    }

    const bytes = cert.length + payload.length;
    r.blocks.set(seq, {
      cert: Buffer.from(cert),
      payload: Buffer.from(payload),
      hash: b.blockHash,
      lamport: b.lamport,
      type: b.type,
      scopeId: Buffer.from(b.scopeId),
      bytes,
    });
    r.bytes += bytes;
    this.bytes += bytes;
    r.reserve(seq);
    r.bits.set(seq);
    const reachedAuthority = r.extendChain();
    if (seq > r.head) r.head = seq;
    this.byHash.set(b.blockHash.toString('hex'), { key: r.key, seq });

    this.tel?.count('substrate.blocks', 1);
    this.emit('block', { logId: r.logId, seq, from, block: b, payload });

    // An authority block changes who may write what, anywhere — including in logs whose
    // frontiers are already past the point it governs, which #relinkAll cannot take back.
    // The trigger is ARRIVAL, not linking: authority is read from the chain now, so a
    // revocation counts the moment its chain joins, and waiting for it to link is the
    // cycle described in #resolveFrontiers.
    // A full re-resolution only when the authority actually CHANGED. When it did not —
    // which is every forged control block from someone with no standing — this falls
    // through to the ordinary local relink, so the block still links if it deserves to.
    // Skipping both was the first version of this and it was worse than the DoS: an
    // authority block that changed nothing simply never linked.
    if (reachedAuthority && this.#resolveFrontiers()) {
      this.#trim();
      return { ok: true, seq, linked: this.#linkedSince(r, seq) };
    }

    const moved = this.#relinkAll(r);

    // 'linked' is announced only for what SURVIVED that, and only after it. Emitting on
    // the way through and retracting in the same call would put a message on screen and
    // take it off again before insert() returned — true to the internals, useless to a
    // reader, and indistinguishable from a flicker bug.
    for (const [rep, seqs] of moved) {
      const alive = seqs.filter((x) => x <= rep.linkedTo);
      if (alive.length) this.emit('linked', { logId: rep.logId, seqs: alive });
    }
    this.#trim();
    return { ok: true, seq, linked: (moved.get(r) || []).filter((x) => x <= r.linkedTo) };
  }

  /**
   * The author signed two different blocks at one seq. Stop the log there, for everyone.
   *
   * The obvious handling — keep whichever arrived first, reject the other — is a
   * CONVERGENCE BUG, and a quiet one. "First" is arrival order, and arrival order differs
   * per spore. A spore that meets branch A first keeps A and links forward along it; a
   * spore that meets branch B first keeps B and links forward along that. Each then
   * rejects the other's blocks as equivocation, permanently. Two spores, both behaving
   * correctly by that rule, hold different logs under the same log_id and never reconcile.
   * The replicated log stops being replicated, and nothing reports an error.
   *
   * No choice of winner fixes it, because any rule that depends on what you saw first
   * depends on the network. So the resolution is not to pick: the log ENDS at the fork.
   * Hold both blocks, link neither, and stop the frontier at seq-1. Every spore that has
   * seen both branches computes the same frontier from the same facts, with no vote, no
   * coordinator, and no clock.
   *
   * This retracts history if we had already linked past it. That is the honest outcome
   * and it is why 'retracted' exists: we accepted those blocks, and now we have proof the
   * author was writing more than one history, so our confidence in that prefix was
   * misplaced. A mesh that cannot say "I was wrong about this" is worse than one that can.
   *
   * A restore-from-backup equivocates innocently and is punished the same way. There is no
   * way to distinguish it from malice without a clock, and off-web there is no clock.
   */
  /**
   * Which of this replica's blocks are linked at or above `from`, after a full resolution.
   * A full resolution has no notion of "newly" promoted — it recomputes everything — so
   * this reports what the caller can actually rely on being readable now.
   */
  #linkedSince(r, from) {
    const out = [];
    for (let s = from; s <= r.linkedTo; s++) if (r.blocks.has(s)) out.push(s);
    return out;
  }

  /**
   * Recompute every frontier from the bottom, to a fixed point.
   *
   * A retraction does not stop at the log that forked. Another log may have linked a
   * block whose dep pointed above the new fork point — it was linked on the strength of
   * history this substrate has now withdrawn, so it has to be withdrawn too, and that can
   * cascade again through anything citing IT.
   *
   * relink() cannot do this by itself: it only ever walks FORWARD from linkedTo, so it
   * never re-examines a block it has already accepted. An earlier version of this file
   * carried a comment claiming frontiers were "recomputed from scratch next time anything
   * moves". They were not, and the result was order-dependent: whether a log ended up
   * linked past a retracted dep depended entirely on whether the fork arrived before or
   * after the citing block. Two honest replicas, same blocks, different answers. The
   * property harness found it on its first run.
   *
   * Frontiers reset to `floor - 1` rather than -1, because everything below floor has been
   * evicted. Those blocks were verified when they arrived and cannot be rechecked now;
   * re-deriving them is neither possible nor necessary.
   *
   * A withdrawn ROLE_REVOKE is the second thing that can cascade this way, and it arrives
   * by the opposite route: the revocation LINKS, and blocks that were linked above its pin
   * have to come back out. Same machinery, same event.
   */
  #resolveFrontiers(force = false) {
    const before = new Map();
    for (const r of this.logs.values()) before.set(r, r.linkedTo);

    // Authority first, and ONCE. It is a pure function of the blocks held — chains and
    // signatures, nothing that waits on a lamport — so there is nothing to iterate.
    //
    // This used to be a four-round fixed point over grow-then-rebuild, and that loop was
    // hiding a genuine cycle rather than resolving it. Authority was read from LINKED
    // blocks, and an owner who replies to a member cites that member's block as an
    // ordinary dep, so: the revocation links, the member's block stops, the owner's reply
    // stalls on it, the revocation is now above the owner's own frontier and stops
    // counting, the member's block links again. Round and round. It converged identically
    // on every replica, so the convergence property never saw it — it just converged on
    // the wrong thing, with the owner stranded at seq 1 holding an unlinked revocation
    // they had written themselves.
    //
    // Reading the CHAIN instead breaks the cycle at the root. Whether a block was written
    // by this author, and where in their log, is settled by the signature and prev_hash.
    // It has nothing to do with whether an earlier block of theirs has had its lamport
    // confirmed against somebody else's log, and it never should have waited on one.
    //
    // And if it derives the SAME authority as last time, stop here. Recomputing frontiers
    // is O(held) with two BLAKE2b hashes per block re-walked, and the trigger upstream is
    // a block's wire TYPE — so before this check, any stranger could mint ROLE_REVOKE
    // blocks in their own log, none of which mean anything, and buy a full substrate-wide
    // re-resolution with each one. The bound is not a cheaper scan; it is refusing to
    // rewalk when nothing changed, which only someone who really holds authority can cause.
    const sig = this.#rebuildAuth();
    if (sig === this.authSig && !force) return false; // nothing to re-resolve; caller relinks
    this.authSig = sig;
    this.tel?.count('substrate.resolved');

    const resolve = (h) => this.resolveDep(h);
    const authOf = (r, seq, d) => this.#authCheck(r, seq, d);
    const lostOf = (h) => this.lostLamport(h);
    for (const r of this.logs.values()) {
      r.linkedTo = r.floor - 1;
      r.orderedTo = r.floor - 1;
      r.pendingDeps = false;
    }
    // The remaining loop is the real one: linking log A can unblock a dep in log B.
    // It is bounded by progress — each round promotes at least one block or is the last.
    for (;;) {
      let moved = false;
      for (const r of this.logs.values()) {
        // Ordering progress counts as progress. Linking is not the only thing that can
        // unblock another log: a log whose every block is stopped by a revocation still
        // ORDERS them, and another log's dep resolves against orderedTo. Counting only
        // promotions ended the loop early, and which logs had already run when it ended
        // depended on Map insertion order — so the answer depended on arrival order.
        //
        // The identical fix in #relinkAll is what the property harness actually caught, on
        // seed 33. No seed currently reaches this copy of the bug, because a full
        // resolution resets every frontier and the first round usually orders everything.
        // It is here because it is the same bug in the sibling loop, not because a test
        // demanded it — said plainly rather than left to look load-bearing.
        const wasOrdered = r.orderedTo;
        if (r.relink(resolve, authOf, lostOf).length || r.orderedTo > wasOrdered) moved = true;
      }
      if (!moved) break;
    }

    for (const [r, was] of before) {
      if (r.linkedTo >= was) continue;
      const seqs = [];
      for (let x = was; x > r.linkedTo; x--) seqs.push(x);
      this.tel?.count('substrate.retracted', seqs.length);
      this.emit('retracted', { logId: r.logId, seqs: seqs.reverse() });
    }
    return true;
  }

  #recordFork(r, seq, keptHash, otherHash, certA, certB) {
    if (!r.forks.has(seq)) {
      // The certs, not just the hashes. A fork proof is the two certificates — anyone can
      // verify it alone — and we cannot produce one later from a digest.
      r.forks.set(seq, { a: keptHash, b: otherHash, certA: Buffer.from(certA), certB: Buffer.from(certB) });
    }
    const lowered = seq < r.forkedAt;
    if (lowered) {
      r.forkedAt = seq;
      // The chain ends at the contradiction as surely as the link does, and authority is
      // read from the chain — so an equivocating owner's control blocks above the fork
      // stop counting, which is the point of stopping the log there at all.
      if (r.chainTo >= seq) r.chainTo = seq - 1;
      if (r.orderedTo >= seq) r.orderedTo = seq - 1;

      // AND THE FLOOR COMES DOWN TOO. Clamping the frontiers here is useless on its own,
      // because #resolveFrontiers resets them to `floor - 1` about two lines later: on a
      // replica whose eviction had already carried the floor past this seq, the reset put
      // the frontier straight back ABOVE the fork and undid the clamp. The same gap let
      // #rebuildAuth keep honouring a revocation that sat below the floor but above the
      // contradiction, because "below the floor" was trusted without ever asking about
      // forkedAt. One replica went on enforcing a grant that another had thrown away.
      //
      // The floor means "the bottom of what can still be chain-verified", and a fork means
      // nothing at or above it can be. So the floor cannot outrank the fork. The witness
      // goes with it: it described a block on a branch we no longer stand behind.
      if (r.floor > seq) {
        r.floor = seq;
        r.floorHash = null;
        r.floorLamport = 0n;
      }
    }

    this.tel?.count('substrate.equivocation');
    const f = r.forks.get(seq);
    this.emit('equivocation', { logId: r.logId, seq, a: keptHash, b: otherHash, certA: f.certA, certB: f.certB });

    // Every frontier, not just this log's. A fork withdraws history other logs may have
    // linked against, and that can cascade further. #recomputeAll emits the retractions.
    if (lowered) this.#resolveFrontiers(true);
    return lowered;
  }

  /**
   * Record a fork we were TOLD about rather than witnessed.
   *
   * Both certs are self-authenticating: they carry signatures that verify under a key
   * which must hash to the log_id they claim. So this needs no trust in the messenger —
   * the proof is the thing, and a spore that has only ever seen one branch would
   * otherwise keep a longer frontier than everyone else and never find out why.
   */
  acceptForkProof(certA, certB, authorPub) {
    let da;
    let db;
    try {
      da = decodeBlock(certA);
      db = decodeBlock(certB);
    } catch {
      return { ok: false, reason: 'proof_undecodable' };
    }
    if (!da.logId.equals(db.logId)) return { ok: false, reason: 'proof_different_logs' };
    if (da.seq !== db.seq) return { ok: false, reason: 'proof_different_seq' };
    if (da.blockHash.equals(db.blockHash)) return { ok: false, reason: 'proof_same_block' };

    // Same reorder as insert(): resolve the log first, then verify under ITS key. A proof
    // is a claim about a specific author contradicting themselves, so verifying it under
    // a key the messenger chose would let anyone stop anyone else's log.
    const r = this.ensure(da.logId, authorPub);
    if (!r) return { ok: false, reason: 'log_author_mismatch' };

    const va = verifyBlock(certA, edKeyOf(r.authorPub));
    const vb = verifyBlock(certB, edKeyOf(r.authorPub));
    if (!va.ok || !vb.ok) return { ok: false, reason: 'proof_bad_signature' };

    const seq = Number(va.block.seq);
    if (r.forks.has(seq)) return { ok: true, duplicate: true, seq };
    this.#recordFork(r, seq, va.block.blockHash, vb.block.blockHash, certA, certB);
    return { ok: true, seq };
  }

  /**
   * Every fork we know about, as replayable proofs.
   *
   * A fork found before a peer arrived is a fork that peer never hears about, because the
   * broadcast went out to an empty hypha set. Same shape of mistake as a full HAVE that is
   * skipped on an empty store: an announcement made once, to whoever happened to be
   * listening, is not a replicated fact. So proofs are replayed at hypha setup too.
   */
  knownForks() {
    const out = [];
    for (const r of this.logs.values()) {
      for (const [seq, f] of r.forks) {
        if (f.certA && f.certB) out.push({ logId: r.logId, authorPub: r.authorPub, seq, certA: f.certA, certB: f.certB });
      }
    }
    return out;
  }

  /**
   * Forget until we are under budget.
   *
   * Always from the replica currently holding the most, so a single noisy log cannot push
   * everyone else's history out. Stops when nothing is evictable — a substrate made
   * entirely of unlinked blocks cannot shrink, and pretending otherwise by dropping them
   * would just mean fetching them again.
   *
   * RESIDUAL, STATED RATHER THAN FIXED: the budget is not a hard ceiling, because control
   * blocks are never evictable (see forgetOldest) and nothing bounds how many of them a
   * colony owner may write. A spore whose retained authority alone exceeds `maxBytes` ends
   * this loop over budget with nothing left to give, and counts `substrate.over_budget` so
   * the condition is visible rather than silent. What IS guaranteed is that nothing
   * evictable is left behind — which is the invariant the tests assert, because it is the
   * one this function can actually deliver.
   *
   * The bound that closes it belongs with grant semantics, not here: only the lowest pin
   * per (target, scope) can ever decide anything, and a grant matters only while something
   * cites it. Collapsing on that is SP2 work, alongside re-grant, which SP1 does not model
   * at all — a pin below a block's seq stops it, and no later grant lifts that.
   */
  #trim() {
    let guard = 0;
    while (this.bytes > this.maxBytes && guard++ < 1000000) {
      // Largest first, so one noisy log cannot push everyone else's history out — but try
      // EVERY replica before giving up. The previous version took the fattest, and on a
      // null fell back to the fattest OTHER one, then stopped. That predicate asked "does
      // this replica have a range" rather than "is there anything evictable in it", and
      // once control blocks stopped being evictable, two founder logs at the top of the
      // ordering were enough to end the scan while an ordinary member sat below them
      // holding nothing but blocks the budget was allowed to take.
      const order = [...this.logs.values()]
        .filter((r) => r.bytes > 0)
        .sort((a, b) => (b.bytes - a.bytes) || (a.key < b.key ? -1 : 1));
      let gone = null;
      for (const r of order) {
        gone = r.forgetOldest();
        if (gone) break;
      }
      if (!gone) break; // nothing anywhere is evictable; see the note on residual overage
      this.bytes -= gone.bytes;
      this.byHash.delete(gone.hash.toString('hex'));
      this.tel?.count('substrate.forgotten');
    }
    if (this.bytes > this.maxBytes) this.tel?.count('substrate.over_budget');
  }

  /** Everything we hold, as HAVE advertisements. One entry per log. */
  advertise() {
    const out = [];
    for (const r of this.logs.values()) {
      out.push({
        logId: r.logId,
        authorPub: r.authorPub,
        bitlen: r.head + 1,
        bits: r.bits.bits.subarray(0, Math.ceil((r.head + 1) / 8)),
      });
    }
    return out;
  }

  fetch(logIdHex, seq) {
    const r = this.logs.get(logIdHex);
    if (!r) return null;
    const b = r.get(seq);
    if (!b) return null;
    return { cert: b.cert, payload: b.payload, authorPub: r.authorPub };
  }
}

// ed25519 raw-32 -> KeyObject, memoised. Verification happens per block, and rebuilding
// the SPKI wrapper for every one of them showed up immediately once fetch ran at rate.
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const keyCache = new Map();
export function edKeyOf(raw) {
  if (typeof raw?.export === 'function') return raw;
  const k = Buffer.from(raw).toString('hex');
  let ko = keyCache.get(k);
  if (!ko) {
    ko = createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });
    if (keyCache.size > 1024) keyCache.clear();
    keyCache.set(k, ko);
  }
  return ko;
}

export { hash256 };
