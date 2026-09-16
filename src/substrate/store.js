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
 * Block types eviction may never drop. See LogReplica#forgetOldest.
 */
const KEEP_FOREVER = new Set([TYPE.COLONY_GENESIS, TYPE.ROLE_GRANT, TYPE.ROLE_REVOKE]);

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
    this.bytes = 0;
    this.forgotten = 0;
    this.linkedTo = -1; // highest seq reachable by prev_hash from 0
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
  relink(resolve, authOf) {
    const promoted = [];
    for (let s = this.linkedTo + 1; s < this.forkedAt; s++) {
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
      for (const dep of d.deps) {
        const r = resolve(dep);
        if (!r || !r.linked) { stalled = true; break; }
        if (r.lamport > m) m = r.lamport;
      }
      if (stalled) { this.pendingDeps = true; break; }
      this.pendingDeps = false;

      if (d.lamport !== m + 1n) break; // asserted, not derived. The log ends here.

      if (authOf) {
        const verdict = authOf(this, s, d);
        if (verdict === 'stall') { this.pendingDeps = true; break; }
        if (verdict === 'stop') break; // the authority claim fails. The log ends here too.
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
    this.auth = { owners: new Map(), revokes: new Map() };
  }

  /** What a dep points at, for lamport derivation. null if we do not hold it. */
  resolveDep(depHash) {
    const at = this.byHash.get(Buffer.from(depHash).toString('hex'));
    if (!at) return null;
    const r = this.logs.get(at.key);
    const b = r?.get(at.seq);
    if (!b) return null;
    return { lamport: b.lamport, linked: at.seq <= r.linkedTo, replica: r, seq: at.seq, block: b };
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

    const at = this.resolveDep(d.authRef);
    if (!at || !at.linked) return 'stall'; // the cited grant has not arrived, or not linked

    if (at.block.type !== TYPE.ROLE_GRANT) return 'stop';
    if (at.replica.key !== owner) return 'stop'; // granted by someone with nothing to give
    let g;
    try { g = decodeGrant(at.block.payload); } catch { return 'stop'; }
    if (g.target.toString('hex') !== replica.key) return 'stop'; // somebody else's grant
    // Revocation pins carry a scope, so grants must too, or the two are asymmetric: an
    // owner of two colonies who removes someone from one has not removed them from the
    // other, yet their grant in the first would still authorise writes in the second.
    if (!at.block.scopeId.equals(d.scopeId)) return 'stop';

    const pins = this.auth.revokes.get(replica.key);
    if (pins) for (const pin of pins) if (pin.scope === scope && pin.pinSeq < seq) return 'stop';
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
    const pending = [];
    for (const r of this.logs.values()) {
      // Iterate what is HELD rather than the seq range: eviction keeps control blocks
      // below the floor, and those are exactly the ones that must not stop counting.
      for (const [seq, b] of r.blocks) {
        if (b.type !== TYPE.COLONY_GENESIS && b.type !== TYPE.ROLE_REVOKE) continue;
        // Linked, or kept from below the floor — which was linked before it was forgotten.
        if (seq > r.linkedTo && seq >= r.floor) continue;
        if (b.type === TYPE.COLONY_GENESIS) {
          // A colony names its own founder. A genesis whose scope_id is not the derived
          // value is ignored outright — not tiebroken against the real one, because a
          // tiebreak is a race and anyone can enter it with one cheap block.
          if (!colonyIdFor(r.logId, seq).equals(b.scopeId)) continue;
          owners.set(b.scopeId.toString('hex'), { key: r.key, hash: b.hash });
        } else {
          pending.push({ author: r.key, scope: b.scopeId.toString('hex'), payload: b.payload });
        }
      }
    }

    const revokes = new Map();
    for (const p of pending) {
      const o = owners.get(p.scope);
      if (!o || o.key !== p.author) continue; // not the owner's word, so no power
      let rv;
      try { rv = decodeRevoke(p.payload); } catch { continue; }
      const target = rv.target.toString('hex');
      const list = revokes.get(target) || [];
      list.push({ pinSeq: Number(rv.pinSeq), scope: p.scope });
      revokes.set(target, list);
    }

    this.auth = { owners: new Map([...owners].map(([k, v]) => [k, v.key])), revokes };

    const parts = [];
    for (const [scope, v] of [...owners].sort()) parts.push(`o:${scope}:${v.key}`);
    for (const [t, list] of [...revokes].sort()) {
      for (const pin of list.slice().sort((a, b) => a.pinSeq - b.pinSeq)) {
        parts.push(`r:${t}:${pin.scope}:${pin.pinSeq}`);
      }
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
    const out = new Map();
    let round = [seed];
    for (;;) {
      let moved = false;
      for (const r of round) {
        const got = r.relink(resolve, authOf);
        if (!got.length) continue;
        moved = true;
        const prev = out.get(r) || [];
        out.set(r, prev.concat(got));
      }
      if (!moved) break;
      // Only replicas actually waiting on a dep can have been unblocked by that progress.
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

    const seq = Number(b.seq);
    if (!Number.isSafeInteger(seq) || seq < 0) return { ok: false, reason: 'seq_range' };

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
    if (seq > r.head) r.head = seq;
    this.byHash.set(b.blockHash.toString('hex'), { key: r.key, seq });

    this.tel?.count('substrate.blocks', 1);
    this.emit('block', { logId: r.logId, seq, from, block: b, payload });

    const moved = this.#relinkAll(r);

    // A control block that just linked can change who may write what, anywhere — including
    // in logs whose frontiers are already past the point it governs. #relinkAll only walks
    // forward, so it cannot take anything back; this is the same hole the fork cascade had.
    if (this.#linkedAuthority(moved)) this.#resolveFrontiers();

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
  /** Did this promotion link a block that governs authority? */
  #linkedAuthority(promoted) {
    for (const [r, seqs] of promoted) {
      for (const seq of seqs) {
        const t = r.blocks.get(seq)?.type;
        if (t === TYPE.COLONY_GENESIS || t === TYPE.ROLE_REVOKE) return true;
      }
    }
    return false;
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
  #resolveFrontiers() {
    const before = new Map();
    for (const r of this.logs.values()) before.set(r, r.linkedTo);

    const resolve = (h) => this.resolveDep(h);
    const authOf = (r, seq, d) => this.#authCheck(r, seq, d);
    const grow = () => {
      for (const r of this.logs.values()) {
        r.linkedTo = r.floor - 1;
        r.pendingDeps = false;
      }
      for (;;) {
        let moved = false;
        for (const r of this.logs.values()) if (r.relink(resolve, authOf).length) moved = true;
        if (!moved) break;
      }
    };

    // Growing the frontiers can link a COLONY_GENESIS or a ROLE_REVOKE, which changes the
    // authority that governs the growth — so it is a fixed point, not a single pass. Two
    // rounds always suffice under owner-only authority (see #authCheck on
    // well-foundedness): the owner's log is never stopped, so it grows to the same place
    // every round and the derived authority is settled after the first. The cap is a
    // guard against that argument being quietly invalidated by a later change, not a
    // number tuned to make some case pass; if it ever fires, the assumption broke.
    let sig = '';
    let round = 0;
    for (; round < 4; round++) {
      grow();
      const next = this.#rebuildAuth();
      if (next === sig) break;
      sig = next;
    }
    if (round >= 4) this.tel?.count('substrate.auth_unsettled');

    for (const [r, was] of before) {
      if (r.linkedTo >= was) continue;
      const seqs = [];
      for (let x = was; x > r.linkedTo; x--) seqs.push(x);
      this.tel?.count('substrate.retracted', seqs.length);
      this.emit('retracted', { logId: r.logId, seqs: seqs.reverse() });
    }
  }

  #recordFork(r, seq, keptHash, otherHash, certA, certB) {
    if (!r.forks.has(seq)) {
      // The certs, not just the hashes. A fork proof is the two certificates — anyone can
      // verify it alone — and we cannot produce one later from a digest.
      r.forks.set(seq, { a: keptHash, b: otherHash, certA: Buffer.from(certA), certB: Buffer.from(certB) });
    }
    const lowered = seq < r.forkedAt;
    if (lowered) r.forkedAt = seq;

    this.tel?.count('substrate.equivocation');
    const f = r.forks.get(seq);
    this.emit('equivocation', { logId: r.logId, seq, a: keptHash, b: otherHash, certA: f.certA, certB: f.certB });

    // Every frontier, not just this log's. A fork withdraws history other logs may have
    // linked against, and that can cascade further. #recomputeAll emits the retractions.
    if (lowered) this.#resolveFrontiers();
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
   */
  #trim() {
    let guard = 0;
    while (this.bytes > this.maxBytes && guard++ < 100000) {
      let victim = null;
      for (const r of this.logs.values()) {
        if (r.bytes > 0 && (!victim || r.bytes > victim.bytes)) victim = r;
      }
      if (!victim) break;
      const gone = victim.forgetOldest();
      if (!gone) {
        // This replica cannot give anything up. Try the next largest that can.
        const others = [...this.logs.values()].filter((r) => r !== victim && r.linkedTo > r.floor);
        if (!others.length) break;
        const next = others.reduce((a, r) => (r.bytes > a.bytes ? r : a), others[0]);
        const g2 = next.forgetOldest();
        if (!g2) break;
        this.bytes -= g2.bytes;
        this.byHash.delete(g2.hash.toString('hex'));
        this.tel?.count('substrate.forgotten');
        continue;
      }
      this.bytes -= gone.bytes;
      this.byHash.delete(gone.hash.toString('hex'));
      this.tel?.count('substrate.forgotten');
    }
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
