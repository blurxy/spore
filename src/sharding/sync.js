// Where the scheduler stops being arithmetic and starts moving bytes.
//
// Until now `FetchScheduler` had never touched a socket. It was proven correct in a
// simulation whose token buckets we wrote ourselves, which is a good way to be confidently
// wrong: a benchmark cannot discover a bug in the assumptions it was built from. This file
// is the scheduler wired to real hyphae, real frames, and real peers that lie, vanish
// mid-transfer, and answer requests for blocks they no longer hold.
//
// Three things it has to get right, in descending order of how badly they hurt:
//
// 1. RESERVATION HYGIENE. `plan()` reserves a block the moment it assigns it, and its
//    contract is explicit that a reservation the caller does not honour strands that block
//    permanently. Every path that ends a request — block arrives, peer says NOBLOCK, peer
//    disappears, request times out — must release. This is the bug the benchmark already
//    found once, in its safest possible form. On a real network there are four more ways
//    to hit it, and a stranded block does not fail loudly; the sync just never finishes.
//
// 2. PER-PEER BUDGET ACROSS LOGS. The scheduler runs per log, but a peer is one socket.
//    Planning Alice's log and Bob's log independently would happily queue 2x the pipeline
//    depth at the same peer. The budget is therefore held here, globally per peer, and
//    handed to the scheduler as that peer's remaining capacity.
//
// 3. CACHE-ON-FETCH, ANNOUNCED. The instant a block lands we tell every hypha we have it.
//    This is not bookkeeping — it is the entire mechanism by which supply grows with peer
//    count. Without the announcement, every joiner keeps pulling from the original seeder,
//    and the measured curve flattens at 1.0x no matter how many spores are present.
//
// On clocks: this file uses `process.hrtime.bigint()` for request deadlines, which is not
// a violation of the no-wall-clock rule. That rule exists because two spores cannot agree
// what time it is, so nothing SHARED or ASSERTED may depend on a clock — not block
// validity, not ordering, not key expiry. A local timeout is none of those. It is one
// spore deciding how long its own patience lasts, is never transmitted, and would change
// no other spore's view of anything if it were wrong.

import { EventEmitter } from 'node:events';
import { FetchScheduler, Bitfield } from './scheduler.js';
import {
  MSG, encodeHave, decodeHave, encodePairs, decodePairs,
  encodeBlockMsg, decodeBlockMsg, msgType, WireError,
} from './wire.js';
import { CERT_MIN } from '../substrate/store.js';

export const MAX_INFLIGHT_PER_PEER = 6;
export const REQUEST_TIMEOUT_NS = 8_000_000_000n; // 8s of local patience
const PUMP_MS = 25;

const peerHexOf = (h) => Buffer.from(h.peerId).toString('hex');

/** Rebuild a peer's advertised bitfield from the wire form. */
function bitfieldFrom(bitlen, bits) {
  const b = new Bitfield(Math.max(1, bitlen));
  let count = 0;
  for (let i = 0; i < bitlen; i++) {
    if (bits[i >> 3] & (1 << (i & 7))) {
      b.bits[i >> 3] |= 1 << (i & 7);
      count++;
    }
  }
  b.count = count;
  return b;
}

/** Per-log fetch state: who has what, what we've asked for, and from whom. */
class LogSync {
  constructor(logId, authorPub) {
    this.logId = Buffer.from(logId);
    this.key = this.logId.toString('hex');
    this.authorPub = authorPub ? Buffer.from(authorPub) : null;
    this.sched = new FetchScheduler(1);
    this.peers = new Map(); // peerHex -> { have, inflight:Set, maxInflight }
    this.inflightGlobal = new Map(); // seq -> outstanding request count
    this.deadlines = new Map(); // `${peerHex}:${seq}` -> hrtime deadline
  }
}

/**
 * Drives block transfer over live hyphae.
 *
 * Events:
 *   'complete' { logId, blocks }   a log has no more gaps below its known head
 *   'progress' { logId, held, total }
 */
export class Syncer extends EventEmitter {
  constructor({ substrate, hyphaManager, telemetry = null, selfPub, selfLogId }) {
    super();
    this.store = substrate;
    this.mgr = hyphaManager;
    this.tel = telemetry;
    this.selfPub = selfPub;
    this.selfLogId = selfLogId;

    this.logs = new Map(); // logIdHex -> LogSync
    this.peerInflight = new Map(); // peerHex -> total outstanding across all logs
    this.timer = null;
    this.stats = { requested: 0, served: 0, received: 0, noblock: 0, cancelled: 0, timedOut: 0, released: 0 };

    this.mgr.on('hypha', (h) => this.#onHypha(h));
    this.mgr.on('message', ({ hypha, payload }) => this.#onMessage(hypha, payload));
  }

  start() {
    if (this.timer) return this;
    this.timer = setInterval(() => this.pump(), PUMP_MS);
    this.timer.unref?.(); // never hold the process open just to poll for work
    return this;
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  #log(logId, authorPub) {
    const key = Buffer.from(logId).toString('hex');
    let l = this.logs.get(key);
    if (!l) {
      l = new LogSync(logId, authorPub);
      this.logs.set(key, l);
    } else if (!l.authorPub && authorPub) {
      l.authorPub = Buffer.from(authorPub);
    }
    return l;
  }

  // --- outbound -------------------------------------------------------------------

  /** Full advertisement. Sent when a hypha comes up, in both directions. */
  sendHave(hypha) {
    const entries = this.store.advertise();
    if (!entries.length) return;
    const { body, dropped } = encodeHave(entries);
    if (dropped) this.tel?.count('sync.have.dropped_logs', dropped);
    try { hypha.send(body); } catch { /* hypha died mid-send; its close handler cleans up */ }
  }

  /**
   * Announce a block we just acquired, to everyone.
   *
   * Cache-on-fetch is worthless unheard. A joiner becomes a source the instant a block
   * lands, and this is the sentence that says so.
   */
  announce(logId, seq) {
    const body = encodePairs(MSG.HAVE_ADD, [{ logId, seq }]);
    for (const h of this.mgr.hyphae.values()) {
      try { h.send(body); } catch { /* ignore, close handler cleans up */ }
    }
  }

  /** Push a block we just authored to every hypha. The live path; deliberately not scheduled. */
  push(cert, payload, authorPub = this.selfPub) {
    const body = encodeBlockMsg(cert, payload, authorPub);
    let n = 0;
    for (const h of this.mgr.hyphae.values()) {
      try { h.send(body); n++; } catch { /* ignore */ }
    }
    this.tel?.count('sync.pushed', n);
    return n;
  }

  // --- inbound --------------------------------------------------------------------

  #onHypha(hypha) {
    const peer = peerHexOf(hypha);
    this.peerInflight.set(peer, 0);
    hypha.on('close', () => this.#dropPeer(peer));
    this.sendHave(hypha);
    this.pump();
  }

  /**
   * A peer is gone. Release every reservation it was holding.
   *
   * Skipping this is silent and fatal: the blocks that peer owed us stay reserved in
   * `inflightGlobal` forever, `plan()` refuses to re-issue them, and the log never
   * completes while reporting no error at all.
   */
  #dropPeer(peer) {
    this.peerInflight.delete(peer);
    let released = 0;
    for (const l of this.logs.values()) {
      const p = l.peers.get(peer);
      if (!p) continue;
      for (const seq of p.inflight) {
        this.#releaseReservation(l, seq);
        l.deadlines.delete(`${peer}:${seq}`);
        released++;
      }
      l.peers.delete(peer);
    }
    if (released) {
      this.stats.released += released;
      this.tel?.count('sync.released_on_wither', released);
    }
    this.pump();
  }

  /** Drop one outstanding reservation on `seq`. Never goes below zero. */
  #releaseReservation(l, seq) {
    const n = l.inflightGlobal.get(seq) || 0;
    if (n <= 1) l.inflightGlobal.delete(seq);
    else l.inflightGlobal.set(seq, n - 1);
  }

  #clearRequest(l, peer, seq) {
    const p = l.peers.get(peer);
    if (p?.inflight.delete(seq)) {
      this.peerInflight.set(peer, Math.max(0, (this.peerInflight.get(peer) || 1) - 1));
    }
    l.deadlines.delete(`${peer}:${seq}`);
    this.#releaseReservation(l, seq);
  }

  #onMessage(hypha, body) {
    const peer = peerHexOf(hypha);
    let type;
    try { type = msgType(body); } catch { return hypha.close('empty_frame'); }
    try {
      switch (type) {
        case MSG.HAVE: return this.#recvHave(peer, body);
        case MSG.HAVE_ADD: return this.#recvHaveAdd(peer, body);
        case MSG.REQUEST: return this.#recvRequest(hypha, body);
        case MSG.BLOCK: return this.#recvBlock(peer, body);
        case MSG.CANCEL: return; // we are the server side; serving a cancelled block is harmless
        case MSG.NOBLOCK: return this.#recvNoblock(peer, body);
        default:
          this.tel?.count('sync.unknown_type');
          return;
      }
    } catch (e) {
      // A malformed frame from an authenticated peer is a protocol violation, not noise.
      // The hypha is already proven to be who it claims, so this is that spore being
      // broken or hostile; either way we stop talking to it.
      this.tel?.event('sync.malformed', { peer: peer.slice(0, 12), code: e.code || e.message });
      hypha.close(e instanceof WireError ? e.code : 'sync_error');
    }
  }

  #recvHave(peer, body) {
    for (const e of decodeHave(body)) {
      const l = this.#log(e.logId, e.authorPub);
      l.peers.set(peer, {
        have: bitfieldFrom(e.bitlen, e.bits),
        inflight: l.peers.get(peer)?.inflight || new Set(),
        maxInflight: MAX_INFLIGHT_PER_PEER,
      });
    }
    this.pump();
  }

  #recvHaveAdd(peer, body) {
    for (const { logId, seq } of decodePairs(body)) {
      const l = this.logs.get(Buffer.from(logId).toString('hex'));
      if (!l) continue; // a log we have never been advertised; the next full HAVE covers it
      const p = l.peers.get(peer);
      if (!p) continue;
      if (seq + 1 > p.have.size) p.have.grow(seq + 1);
      p.have.set(seq);
    }
    this.pump();
  }

  #recvRequest(hypha, body) {
    const wants = decodePairs(body);
    const missing = [];
    for (const { logId, seq } of wants) {
      const got = this.store.fetch(Buffer.from(logId).toString('hex'), seq);
      if (!got) { missing.push({ logId, seq }); continue; }
      try {
        hypha.send(encodeBlockMsg(got.cert, got.payload, got.authorPub));
        this.stats.served++;
        this.tel?.count('sync.served');
      } catch {
        missing.push({ logId, seq });
      }
    }
    // Answering "no" is not politeness. An unanswered request holds the requester's
    // reservation until its timeout expires, and that is time the swarm spends not
    // fetching a block somebody else could have supplied immediately.
    if (missing.length) {
      try { hypha.send(encodePairs(MSG.NOBLOCK, missing)); } catch { /* peer gone */ }
    }
  }

  #recvNoblock(peer, body) {
    for (const { logId, seq } of decodePairs(body)) {
      const l = this.logs.get(Buffer.from(logId).toString('hex'));
      if (!l) continue;
      this.#clearRequest(l, peer, seq);
      // They told us they don't have it. Believe them and stop asking.
      const p = l.peers.get(peer);
      if (p && seq < p.have.size && p.have.has(seq)) {
        p.have.bits[seq >> 3] &= ~(1 << (seq & 7));
        p.have.count--;
      }
      this.stats.noblock++;
    }
    this.tel?.count('sync.noblock');
    this.pump();
  }

  #recvBlock(peer, body) {
    const { authorPub, cert, payload } = decodeBlockMsg(body);
    this.stats.received++;
    if (cert.length < CERT_MIN) throw new WireError('block_cert_short');

    const res = this.store.insert(cert, payload, authorPub, peer.slice(0, 12));

    // Release the reservation whether or not the block was good. A peer that answers with
    // garbage must not be able to hold a block hostage by answering badly forever.
    const logKey = cert.subarray(4, 20).toString('hex');
    const l = this.logs.get(logKey);
    const seq = Number(cert.readBigUInt64LE(20));
    if (l) this.#clearRequest(l, peer, seq);

    if (!res.ok) {
      this.tel?.count(`sync.reject.${res.reason}`);
      this.pump();
      return;
    }
    if (!res.duplicate) {
      this.announce(cert.subarray(4, 20), seq);
      // Endgame may have asked several peers for this. Tell the losers to stop.
      if (l) this.#cancelOthers(l, peer, seq);
      this.#progress(logKey);
    }
    this.pump();
  }

  /** Endgame cleanup: we got it from someone, so nobody else needs to send it. */
  #cancelOthers(l, winner, seq) {
    for (const [peerHex, p] of l.peers) {
      if (peerHex === winner || !p.inflight.has(seq)) continue;
      this.#clearRequest(l, peerHex, seq);
      const h = this.mgr.hyphae.get(peerHex);
      if (h) {
        try { h.send(encodePairs(MSG.CANCEL, [{ logId: l.logId, seq }])); } catch { /* gone */ }
      }
      this.stats.cancelled++;
    }
  }

  #progress(logKey) {
    const r = this.store.replica(logKey);
    const l = this.logs.get(logKey);
    if (!r || !l) return;
    const total = this.#totalFor(l, r);
    this.emit('progress', { logId: r.logId, held: r.held, total });
    if (total > 0 && r.held >= total) {
      this.emit('complete', { logId: r.logId, blocks: r.held });
      this.tel?.event('sync.complete', { log: logKey.slice(0, 12), blocks: r.held });
    }
  }

  /** How long this log is, as far as anyone present knows. Grows; never shrinks. */
  #totalFor(l, replica) {
    let t = replica ? replica.head + 1 : 0;
    for (const p of l.peers.values()) if (p.have.size > t) t = p.have.size;
    return t;
  }

  // --- the pump -------------------------------------------------------------------

  #freeSlots(peer) {
    return Math.max(0, MAX_INFLIGHT_PER_PEER - (this.peerInflight.get(peer) || 0));
  }

  /** Expire requests that will never be answered, and give those blocks back. */
  #sweepDeadlines(now) {
    for (const l of this.logs.values()) {
      for (const [k, deadline] of l.deadlines) {
        if (deadline > now) continue;
        const i = k.lastIndexOf(':');
        const peer = k.slice(0, i);
        const seq = Number(k.slice(i + 1));
        this.#clearRequest(l, peer, seq);
        this.stats.timedOut++;
        this.tel?.count('sync.timeout');
      }
    }
  }

  /**
   * One scheduling round across every log.
   *
   * The `limit` passed to `plan()` is the exact number of requests this peer set can
   * absorb right now, because `plan()`'s contract is that every assignment it returns
   * WILL be issued. Asking for more than we will send strands blocks permanently, so the
   * budget is computed first and the plan is sized to it — never the other way round.
   */
  pump() {
    const now = process.hrtime.bigint();
    this.#sweepDeadlines(now);

    for (const l of this.logs.values()) {
      if (!l.peers.size) continue;
      const replica = this.store.replica(l.key);
      const total = this.#totalFor(l, replica);
      if (total <= 0) continue;

      // Our own have-set, sized to the longest log anyone knows about.
      const have = replica ? replica.bits : new Bitfield(total);
      if (have.size < total) have.grow(total);
      l.sched.total = total;

      // Hand each peer its REMAINING global budget as this log's capacity. maxInflight is
      // relative to the peer's current inflight in THIS log, so the scheduler's
      // `maxInflight - inflight.size` arithmetic yields exactly the global free slots.
      let budget = 0;
      for (const [peerHex, p] of l.peers) {
        const free = this.#freeSlots(peerHex);
        p.maxInflight = p.inflight.size + free;
        budget += free;
      }
      if (budget <= 0) continue;

      const plan = l.sched.plan(have, l.peers, l.inflightGlobal, null, budget);
      if (!plan.length) continue;

      // Group by peer so each gets one REQUEST frame instead of one per block. The peer
      // budget is charged HERE, at reservation time, not after a successful send: plan()
      // has already put these in the peer's inflight set, so a failure path that calls
      // #clearRequest must find a matching charge or the budget drifts down forever.
      const byPeer = new Map();
      for (const { peerId, index } of plan) {
        if (!byPeer.has(peerId)) byPeer.set(peerId, []);
        byPeer.get(peerId).push(index);
        this.peerInflight.set(peerId, (this.peerInflight.get(peerId) || 0) + 1);
      }
      const deadline = now + REQUEST_TIMEOUT_NS;
      for (const [peerHex, seqs] of byPeer) {
        const h = this.mgr.hyphae.get(peerHex);
        if (!h) {
          // Vanished between planning and sending. Give every block straight back.
          for (const seq of seqs) this.#clearRequest(l, peerHex, seq);
          continue;
        }
        try {
          h.send(encodePairs(MSG.REQUEST, seqs.map((seq) => ({ logId: l.logId, seq }))));
          for (const seq of seqs) l.deadlines.set(`${peerHex}:${seq}`, deadline);
          this.stats.requested += seqs.length;
          this.tel?.count('sync.requested', seqs.length);
        } catch {
          for (const seq of seqs) this.#clearRequest(l, peerHex, seq);
        }
      }
    }
  }
}
