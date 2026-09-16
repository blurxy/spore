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
import { verifyBlock, decodeBlock, logIdMatches, hash256, HEADER_LEN, SIG_LEN } from './block.js';
import { Bitfield } from '../sharding/scheduler.js';

export const CERT_MIN = HEADER_LEN + SIG_LEN;

/**
 * One author's log, as far as this spore has it.
 *
 * `authorPub` is not taken on trust. It is checked against log_id on first sight
 * (`logIdMatches`), and every block in the log is then verified under it — so a peer
 * cannot hand us a log claiming to be someone else's.
 */
export class LogReplica {
  constructor(logId, authorPub) {
    this.logId = Buffer.from(logId);
    this.key = this.logId.toString('hex');
    this.authorPub = Buffer.from(authorPub);
    this.blocks = new Map(); // seq:number -> { cert, payload, hash, lamport }
    this.bits = new Bitfield(1); // held-set, grows with the log
    this.head = -1; // highest seq we hold
    this.linkedTo = -1; // highest seq reachable by prev_hash from 0
    this.equivocations = [];
  }

  get held() { return this.blocks.size; }
  has(seq) { return this.blocks.has(seq); }
  get(seq) { return this.blocks.get(seq) || null; }
  hashAt(seq) { return this.blocks.get(seq)?.hash || null; }

  /** Grow the held-bitfield so index `seq` is representable. */
  reserve(seq) {
    if (seq + 1 > this.bits.size) this.bits.grow(seq + 1);
  }

  /**
   * Advance the linked frontier as far as prev_hash allows.
   *
   * Called after every insert, because the block that just landed may be the one that
   * closes a gap and promotes a long run at once. Genesis (seq 0) is linked when its
   * prev_hash is all zero; every later block when its prev_hash equals the block before.
   */
  relink() {
    const promoted = [];
    for (let s = this.linkedTo + 1; ; s++) {
      const b = this.blocks.get(s);
      if (!b) break;
      const d = decodeBlock(b.cert);
      const ok = s === 0
        ? d.prevHash.every((x) => x === 0)
        : d.prevHash.equals(this.hashAt(s - 1) || Buffer.alloc(0));
      if (!ok) break; // a real break in the author's own chain; stop, do not skip it
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
 *   'equivocation' { logId, seq, kept, rejected }        the author signed two blocks at one seq
 */
export class Substrate extends EventEmitter {
  constructor({ telemetry = null } = {}) {
    super();
    this.tel = telemetry;
    this.logs = new Map(); // logIdHex -> LogReplica
  }

  get size() {
    let n = 0;
    for (const r of this.logs.values()) n += r.held;
    return n;
  }

  replica(logIdHex) { return this.logs.get(logIdHex) || null; }

  /**
   * Get or create the replica for a log, binding it to its author.
   *
   * Returns null if `authorPub` is not the key this log_id names. That check is the
   * whole reason third-party replication is safe: the binding lives inside the signed
   * header, so it cannot be restated by whoever is relaying.
   */
  ensure(logId, authorPub) {
    const key = Buffer.from(logId).toString('hex');
    const existing = this.logs.get(key);
    if (existing) return existing;
    if (!logIdMatches(logId, authorPub)) {
      this.tel?.count('substrate.reject.log_author_mismatch');
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

    const v = verifyBlock(cert, edKeyOf(authorPub), payload);
    if (!v.ok) {
      this.tel?.count(`substrate.reject.${v.reason.split(':')[0]}`);
      return { ok: false, reason: v.reason };
    }
    const b = v.block;

    const r = this.ensure(b.logId, authorPub);
    if (!r) return { ok: false, reason: 'log_author_mismatch' };

    const seq = Number(b.seq);
    if (!Number.isSafeInteger(seq) || seq < 0) return { ok: false, reason: 'seq_range' };

    const prior = r.blocks.get(seq);
    if (prior) {
      if (prior.hash.equals(b.blockHash)) return { ok: true, duplicate: true, seq };
      // The author signed two different blocks at the same seq. This is not a network
      // fault and not something a peer can fake — both signatures verify under the
      // author's own key. We keep what we had, record the proof, and surface it.
      r.equivocations.push({ seq, kept: prior.hash, rejected: b.blockHash });
      this.tel?.count('substrate.equivocation');
      this.emit('equivocation', { logId: r.logId, seq, kept: prior.hash, rejected: b.blockHash });
      return { ok: false, reason: 'equivocation', seq };
    }

    r.blocks.set(seq, {
      cert: Buffer.from(cert),
      payload: Buffer.from(payload),
      hash: b.blockHash,
      lamport: b.lamport,
      type: b.type,
    });
    r.reserve(seq);
    r.bits.set(seq);
    if (seq > r.head) r.head = seq;

    this.tel?.count('substrate.blocks', 1);
    this.emit('block', { logId: r.logId, seq, from, block: b, payload });

    const promoted = r.relink();
    if (promoted.length) this.emit('linked', { logId: r.logId, seqs: promoted });

    return { ok: true, seq, linked: promoted };
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
