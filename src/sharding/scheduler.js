// Rarest-first block scheduling — the mechanism the whole "gets faster as spores join"
// claim rests on. Adapted from BitTorrent, because BitTorrent solved this and inventing a
// worse version would be vanity.
//
// The core idea: a joiner does not pull the whole history from one seeder. It pulls
// different blocks from different peers simultaneously, and every peer that already has a
// block can serve it. Supply grows with peer count. That is where the speedup lives.
//
// Rarest-first matters because the failure mode of naive parallel fetch is everyone
// grabbing the same popular blocks while rare ones stay on a single seeder, so the swarm
// stalls at the end waiting on one machine. Fetching the scarcest block first keeps
// replica counts even and keeps every peer useful.
//
// ARCHITECTURE.md 3 is honest about the ceiling: within one Wi-Fi cell this saturates
// around N=5 because the air is a shared medium. This scheduler is what reaches that
// ceiling; it cannot exceed it, and nothing here pretends otherwise.

/** A peer's advertised block set, as a bitfield. Compact enough to gossip freely. */
export class Bitfield {
  constructor(size) {
    this.size = size;
    this.bits = new Uint8Array(Math.ceil(size / 8));
    this.count = 0;
  }
  has(i) {
    return (this.bits[i >> 3] & (1 << (i & 7))) !== 0;
  }
  set(i) {
    if (this.has(i)) return false;
    this.bits[i >> 3] |= 1 << (i & 7);
    this.count++;
    return true;
  }
  get complete() {
    return this.count === this.size;
  }
  /**
   * Widen to `size` bits, preserving what is set.
   *
   * A torrent knows its piece count up front; an append-only log does not. The set of
   * blocks a log has is discovered as peers advertise heads further out than ours, so the
   * bitfield has to grow underneath the scheduler without disturbing it. Shrinking is not
   * offered — a log only ever gets longer.
   */
  grow(size) {
    if (size <= this.size) return this;
    const bytes = Math.ceil(size / 8);
    if (bytes > this.bits.length) {
      const next = new Uint8Array(bytes);
      next.set(this.bits);
      this.bits = next;
    }
    this.size = size;
    return this;
  }
  static full(size) {
    const b = new Bitfield(size);
    b.bits.fill(0xff);
    b.count = size;
    return b;
  }
}

/**
 * Chooses which block to request from which peer.
 *
 * `peers` is a Map of peerId -> { have: Bitfield, inflight: Set, maxInflight }.
 * Returns a list of { peerId, index } assignments to issue right now.
 */
export class FetchScheduler {
  constructor(totalBlocks, { endgameThreshold = 0.97, maxDuplicate = 3, maxPerRound = 32 } = {}) {
    this.total = totalBlocks;
    this.endgameThreshold = endgameThreshold;
    this.maxDuplicate = maxDuplicate;
    this.maxPerRound = maxPerRound;
    // WORK COUNTERS, not performance counters. These exist so a test can assert that the
    // work done is proportional to what WE hold rather than to what a PEER claims — the
    // distinction six bugs in this repo have turned on. Wall-clock cannot express that:
    // the tablet is ~1.8x slower than the laptop, so a timing assertion would flake while
    // saying nothing about the invariant. See docs/METHOD.md.
    this.stats = {
      requests: 0, duplicates: 0, endgameRequests: 0,
      scanned: 0,     // block indices visited
      allocBytes: 0,  // bytes of index/bitfield allocation charged at the site
    };
  }

  /**
   * How many peers hold each block we still need. The rarity ranking.
   * O(blocks x peers) — correct but quadratic, so callers running many spores should
   * maintain replica counts incrementally and pass them in as `counts`.
   */
  rarity(have, peers) {
    const counts = new Int32Array(this.total).fill(-1);
    this.stats.allocBytes += this.total * 4;
    this.stats.scanned += this.total;
    for (let i = 0; i < this.total; i++) {
      if (have.has(i)) continue;
      let n = 0;
      for (const p of peers.values()) if (p.have.has(i)) n++;
      counts[i] = n;
    }
    return counts;
  }

  /**
   * Choose requests to issue now, rarest block first.
   *
   * Endgame: near the end a single slow peer sitting on the last block stalls the whole
   * fetch, so the remaining few are requested from several peers at once and the losers
   * cancelled. Wastes a little bandwidth, removes the long tail.
   *
   * `counts` may be supplied precomputed; otherwise it is derived from `peers`.
   *
   * `limit` MUST be the number of requests the caller will actually issue. Every
   * assignment returned is recorded in `inflightGlobal` and in the chosen peer's inflight
   * set, so an assignment the caller then discards leaves a phantom reservation that
   * blocks that block from ever being requested again. Asking for more than you will use
   * does not merely waste work — it strands blocks permanently.
   */
  /**
   * `floor` is where OUR replica starts. Below it we have decided to forget, and insert()
   * refuses anything we ask for down there — so asking is a request that can only ever be
   * answered with a block we will throw away, at one full block of airtime per attempt.
   */
  plan(have, peers, inflightGlobal, counts = null, limit = this.maxPerRound, floor = 0) {
    const assignments = [];
    if (have.complete || limit <= 0) return assignments;

    const rank = counts || this.rarity(have, peers);
    const endgame = have.count / this.total >= this.endgameThreshold;

    // candidate blocks we still need and somebody has, rarest first
    const wanted = [];
    this.stats.scanned += Math.max(0, this.total - floor);
    for (let i = floor; i < this.total; i++) {
      if (!have.has(i) && rank[i] > 0) wanted.push(i);
    }
    wanted.sort((a, b) => rank[a] - rank[b] || a - b);

    for (const index of wanted) {
      if (assignments.length >= limit) break;
      const already = inflightGlobal.get(index) || 0;
      // normally one request per block; in endgame, several, to kill the tail
      const allowed = endgame ? this.maxDuplicate : 1;
      if (already >= allowed) continue;

      // among peers holding it, prefer the one with the most free request slots —
      // a cheap proxy for "least busy", which keeps fast peers saturated
      let best = null;
      let bestFree = 0;
      for (const [peerId, p] of peers) {
        if (!p.have.has(index)) continue;
        if (p.inflight.has(index)) continue;
        const free = p.maxInflight - p.inflight.size;
        if (free > bestFree) {
          bestFree = free;
          best = peerId;
        }
      }
      if (!best) continue;

      assignments.push({ peerId: best, index });
      peers.get(best).inflight.add(index);
      inflightGlobal.set(index, already + 1);
      this.stats.requests++;
      if (already > 0) {
        this.stats.duplicates++;
        this.stats.endgameRequests++;
      }
    }
    return assignments;
  }
}
