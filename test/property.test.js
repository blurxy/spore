// Property tests: the same invariants, checked against thousands of generated worlds
// instead of the handful of cases somebody thought to write down.
//
// WHY THIS EXISTS, precisely. Over this project's review rounds, roughly one fix in three
// introduced a new bug, and every one of them had the same shape: a fix that added a PATH
// without adding the BOUND on that path. On-demand log creation, a one-way correction, a
// guard that ran on replica creation only. Each passed the example test written for it,
// because an example test asserts the case its author imagined, and the bug was always in
// the case they did not.
//
// The first invariant below — feed the same blocks in different orders, get the same
// state — would on its own have caught the log_id forgery, the fork divergence, and the
// timeout stranding. Those were the three worst bugs of the session and none of them had
// a failing test until somebody went looking.
//
// Everything is seeded. A failing shuffle with no reproducible seed is worthless, so the
// seed is printed on every failure.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { encodeBlock, logIdFor, TYPE, FLAG, encodeGrant, encodeRevoke } from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';
import { Syncer, MAX_INFLIGHT_PER_PEER } from '../src/sharding/sync.js';
import {
  decodeHave, decodePairs, decodeBlockMsg, decodeForkProof, msgType,
  encodePairs, encodeHave, MSG, MAX_SEQ, WireError,
} from '../src/sharding/wire.js';

// --- deterministic randomness --------------------------------------------------------

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (r, xs) => xs[Math.floor(r() * xs.length) % xs.length];

function shuffled(r, xs) {
  const a = xs.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function identity() {
  const kp = generateKeyPairSync('ed25519');
  const pub = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { kp, pub, logId: logIdFor(pub) };
}

// --- world generation ----------------------------------------------------------------

/**
 * Build a causally valid multi-log world, optionally with a planted fork.
 *
 * Blocks are built in a global order so a dep always points at something already built,
 * and every lamport is the derived value — otherwise nothing would link and the whole
 * test would pass vacuously while asserting nothing.
 */
function buildWorld(r, { logs = 3, blocks = 24, depChance = 0.35, forkAt = null, authority = false } = {}) {
  const ids = Array.from({ length: logs }, identity);
  const state = ids.map(() => ({ seq: 0, prevHash: Buffer.alloc(32), lastLamport: 0n }));
  const built = []; // { hash, lamport } for dep selection
  const out = [];

  // scope_id is only meaningful once there is a colony to be a member of.
  const scopeId = authority ? Buffer.alloc(16, 0xc0) : Buffer.alloc(16);

  const emit = (li, { type = TYPE.MESSAGE, payload, authRef = null, deps = [], depLamport = 0n }) => {
    const id = ids[li];
    const st = state[li];
    const lamport = (st.lastLamport > depLamport ? st.lastLamport : depLamport) + 1n;
    const { cert, blockHash } = encodeBlock(
      {
        type, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: st.seq, lamport, scopeId,
        prevHash: st.prevHash, authRef: authRef || Buffer.alloc(32), payload, deps,
      },
      id.kp.privateKey,
    );
    out.push({ cert, payload, authorPub: id.pub, logIdx: li, seq: st.seq });
    built.push({ hash: blockHash, lamport });
    st.prevHash = blockHash;
    st.lastLamport = lamport;
    st.seq += 1;
    return { hash: blockHash, lamport, seq: st.seq - 1 };
  };

  // Log 0 is the colony owner: genesis first, then one grant per member. Everything the
  // members write afterwards claims under its grant, so every shuffled arrival order has
  // to reach the same frontier through the authority rules, not just the chaining ones.
  const grants = [];
  if (authority) {
    emit(0, { type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
    for (let li = 1; li < logs; li++) {
      grants[li] = emit(0, {
        type: TYPE.ROLE_GRANT,
        payload: encodeGrant({ target: ids[li].logId, roleId: li }),
      }).hash;
    }
  }

  for (let i = 0; i < blocks; i++) {
    const li = Math.floor(r() * logs) % logs;

    let deps = [];
    let depLamport = 0n;
    if (built.length && r() < depChance) {
      const d = pick(r, built);
      deps = [d.hash];
      depLamport = d.lamport;
    }
    emit(li, {
      payload: Buffer.from(`log${li}:${state[li].seq}`),
      authRef: grants[li] || null,
      deps,
      depLamport,
    });
  }

  // A revocation lands somewhere in the middle of a member's history. Its pin is chosen
  // blind to what that member went on to write, which is the realistic case: the owner
  // revokes against the head they had, not the head that exists.
  if (authority && logs > 1) {
    const target = 1 + Math.floor(r() * (logs - 1));
    if (state[target].seq > 0) {
      const pinSeq = Math.floor(r() * state[target].seq);
      emit(0, {
        type: TYPE.ROLE_REVOKE,
        payload: encodeRevoke({ target: ids[target].logId, pinSeq, roleId: target }),
      });
    }
  }

  // A planted equivocation: the same author signs a second, different block at one seq.
  if (forkAt !== null) {
    const victim = out.find((b) => b.logIdx === 0 && b.seq === forkAt);
    if (victim) {
      const id = ids[0];
      const prev = out.find((b) => b.logIdx === 0 && b.seq === forkAt - 1);
      const payload = Buffer.from(`log0:${forkAt}:OTHER`);
      const { cert } = encodeBlock(
        {
          type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: forkAt,
          lamport: 1n + BigInt(forkAt), scopeId,
          prevHash: prev ? require_hash(prev) : Buffer.alloc(32), payload,
        },
        id.kp.privateKey,
      );
      out.push({ cert, payload, authorPub: id.pub, logIdx: 0, seq: forkAt, isFork: true });
    }
  }
  return { ids, blocks: out, scopeId };
}

// prevHash of an already-built block, recovered from its cert (offset 60, 32 bytes) by
// hashing the cert itself — the block hash IS hash256(cert), which encodeBlock returned.
import { hash256 } from '../src/substrate/store.js';
const require_hash = (b) => hash256(b.cert);

/** The comparable state of a substrate: what two honest replicas must agree on. */
function snapshot(s) {
  const out = [];
  for (const [key, r] of [...s.logs].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    out.push({
      key,
      linkedTo: r.linkedTo,
      forkedAt: r.forkedAt === Infinity ? -1 : r.forkedAt,
      held: [...r.blocks.keys()].sort((a, b) => a - b).join(','),
    });
  }
  return JSON.stringify(out);
}

// --- 1. convergence ------------------------------------------------------------------

test('property: replicas fed the same blocks in any order reach the same state', () => {
  // Everyone ends up with the same history no matter what order the mail arrived in.
  //
  // Same block SET every time — only the delivery order changes. Feeding different
  // subsets is a legitimately different test, and replicas that saw different things are
  // allowed to differ; conflating the two would make this pass for the wrong reason.
  //
  // Eviction is off (a large budget) because eviction is genuinely order-dependent: which
  // replica is holding the most bytes at a given moment decides what gets dropped. That
  // is by design, so it is measured separately below.
  for (let seed = 1; seed <= 60; seed++) {
    const r = rng(seed);
    const world = buildWorld(r, {
      logs: 1 + Math.floor(r() * 3),
      blocks: 12 + Math.floor(r() * 24),
      forkAt: r() < 0.4 ? 1 + Math.floor(r() * 4) : null,
      // Half the seeds carry a colony: genesis, grants, and a revocation whose pin lands
      // mid-history. Authority is the third thing that can stop a frontier, and it is the
      // only one that can stop it because of a block in SOMEBODY ELSE'S log — so it is the
      // one most likely to come out order-dependent.
      authority: r() < 0.5,
    });

    let reference = null;
    for (let k = 0; k < 4; k++) {
      const s = new Substrate({ maxBytes: 1 << 30 });
      for (const b of shuffled(rng(seed * 100 + k), world.blocks)) {
        s.insert(b.cert, b.payload, b.authorPub);
      }
      const snap = snapshot(s);
      if (reference === null) reference = snap;
      else assert.equal(snap, reference, `seed ${seed}, shuffle ${k}: replicas diverged`);
    }
  }
});

// --- 2. monotone frontier ------------------------------------------------------------

test('property: the verified frontier only ever moves forward, except behind a fork', () => {
  // "Verified up to here" must never slide backwards on its own. Three things now lean on
  // that: completion, eviction safety, and cross-log dep resolution. The single exception
  // is a fork retraction, which withdraws history we can no longer stand behind — and
  // when that happens the substrate says so out loud.
  for (let seed = 1; seed <= 40; seed++) {
    const r = rng(seed);
    const world = buildWorld(r, {
      logs: 2, blocks: 20 + Math.floor(r() * 20),
      forkAt: r() < 0.6 ? 1 + Math.floor(r() * 5) : null,
    });

    const s = new Substrate({ maxBytes: 1 << 30 });
    const last = new Map();
    let retractions = 0;
    s.on('retracted', () => { retractions++; });

    for (const b of shuffled(rng(seed * 7), world.blocks)) {
      const before = new Map([...s.logs].map(([k, rep]) => [k, rep.linkedTo]));
      const seen = retractions;
      s.insert(b.cert, b.payload, b.authorPub);
      for (const [k, rep] of s.logs) {
        const prior = before.has(k) ? before.get(k) : -1;
        if (rep.linkedTo < prior) {
          assert.ok(retractions > seen,
            `seed ${seed}: log ${k.slice(0, 8)} frontier fell ${prior} -> ${rep.linkedTo} with no retraction`);
        }
        last.set(k, rep.linkedTo);
      }
    }
  }
});

test('property: eviction never lowers the frontier, however tight the budget', () => {
  for (let seed = 1; seed <= 25; seed++) {
    const r = rng(seed);
    const world = buildWorld(r, { logs: 2, blocks: 30 });
    const each = world.blocks[0].cert.length + world.blocks[0].payload.length;

    const s = new Substrate({ maxBytes: each * (2 + Math.floor(r() * 8)) });
    let high = new Map();
    for (const b of shuffled(rng(seed * 13), world.blocks)) {
      s.insert(b.cert, b.payload, b.authorPub);
      for (const [k, rep] of s.logs) {
        const prev = high.get(k) ?? -1;
        assert.ok(rep.linkedTo >= prev,
          `seed ${seed}: eviction dropped the frontier ${prev} -> ${rep.linkedTo}`);
        high.set(k, rep.linkedTo);
        // and the frontier block itself must survive, or the log stalls forever
        if (rep.linkedTo >= 0) {
          assert.ok(rep.has(rep.linkedTo), `seed ${seed}: evicted the frontier block itself`);
        }
      }
    }
  }
});

// --- 3. decoder bounds ---------------------------------------------------------------

test('property: garbage at a decoder either parses or throws, and never allocates wildly', () => {
  // Every number arriving from a peer is an allocation request. Either the decoder
  // understands the bytes or it refuses them — it must never fall over, and it must never
  // hand a caller a number big enough to be used as a size.
  const decoders = [
    ['have', decodeHave],
    ['pairs', decodePairs],
    ['block', decodeBlockMsg],
    ['fork', decodeForkProof],
  ];
  for (let seed = 1; seed <= 400; seed++) {
    const r = rng(seed);
    const len = Math.floor(r() * 300);
    const buf = randomBytes(len);
    if (len) buf.writeUInt8(1 + Math.floor(r() * 7), 0);

    for (const [name, fn] of decoders) {
      let got = null;
      try {
        got = fn(buf);
      } catch (e) {
        assert.ok(e instanceof WireError || e instanceof RangeError,
          `seed ${seed} ${name}: threw ${e.constructor.name}: ${e.message}`);
        continue;
      }
      if (name === 'pairs' && Array.isArray(got)) {
        for (const p of got) {
          assert.ok(p.seq <= MAX_SEQ, `seed ${seed}: pairs yielded seq ${p.seq} above MAX_SEQ`);
        }
      }
      if (name === 'have' && Array.isArray(got)) {
        for (const h of got) {
          assert.ok(h.bitlen <= MAX_SEQ + 1, `seed ${seed}: have yielded bitlen ${h.bitlen}`);
        }
      }
    }
  }
});

test('property: an encoder never produces something its own decoder rejects', () => {
  for (let seed = 1; seed <= 200; seed++) {
    const r = rng(seed);
    const n = 1 + Math.floor(r() * 400);
    const pairs = Array.from({ length: n }, () => ({
      logId: randomBytes(16),
      seq: Math.floor(r() * MAX_SEQ),
    }));
    const back = decodePairs(encodePairs(MSG.HAVE_ADD, pairs));
    assert.ok(back.length <= pairs.length);
    for (let i = 0; i < back.length; i++) {
      assert.equal(back[i].seq, pairs[i].seq, `seed ${seed}: pair ${i} round-trip`);
      assert.ok(back[i].logId.equals(pairs[i].logId));
    }

    const entries = Array.from({ length: 1 + Math.floor(r() * 6) }, () => {
      const bitlen = Math.floor(r() * 500);
      return {
        logId: randomBytes(16), authorPub: randomBytes(32), bitlen,
        bits: randomBytes(Math.ceil(bitlen / 8)),
      };
    });
    const dec = decodeHave(encodeHave(entries).body);
    assert.ok(dec.length <= entries.length);
    for (let i = 0; i < dec.length; i++) assert.equal(dec[i].bitlen, entries[i].bitlen);
  }
});

// --- 4. reservation hygiene, over a fake transport -----------------------------------

/**
 * A drop-in HyphaManager with no sockets.
 *
 * Deliberately the same shape as the real one — same `hyphae` map, same 'hypha' /
 * 'message' events — rather than a fresh abstraction, so the Syncer cannot tell the
 * difference and the peer-lifecycle logic under test is the real code path. Hostility is
 * injected at the send() boundary, which is where a hostile peer actually lives: drop,
 * duplicate, reorder.
 *
 * It is blind to framing, coalescing and backpressure. Those are covered by the real
 * socket tests, and this session's nastiest transport bug lived exactly there — so this
 * is a test of the logic above the wire, and is not claimed to be more.
 */
class FakeHypha extends EventEmitter {
  constructor(peerId, net, from, to) {
    super();
    this.peerId = peerId;
    this.net = net;
    this.from = from;
    this.to = to;
    this.closed = false;
  }
  send(body) {
    if (this.closed) throw new Error('hypha closed');
    this.net.carry(this.from, this.to, Buffer.from(body));
  }
  close(reason = 'local') {
    if (this.closed) return;
    this.closed = true;
    this.emit('close', { reason });
  }
}

class FakeManager extends EventEmitter {
  constructor(id) {
    super();
    this.sporeId = id;
    this.hyphae = new Map();
  }
  adopt(h) {
    const key = Buffer.from(h.peerId).toString('hex');
    this.hyphae.set(key, h);
    h.on('close', () => { if (this.hyphae.get(key) === h) this.hyphae.delete(key); });
    h.on('message', (m) => this.emit('message', { hypha: h, payload: m }));
    this.emit('hypha', h);
  }
}

class FakeNet {
  constructor(r, { dropRate = 0, dupRate = 0 } = {}) {
    this.r = r;
    this.dropRate = dropRate;
    this.dupRate = dupRate;
    this.nodes = new Map();
    this.queue = [];
  }
  add(node) { this.nodes.set(node.key, node); }
  link(a, b) {
    const ha = new FakeHypha(b.id.pub, this, a.key, b.key);
    const hb = new FakeHypha(a.id.pub, this, b.key, a.key);
    a.pairs.set(b.key, ha);
    b.pairs.set(a.key, hb);
    a.mgr.adopt(ha);
    b.mgr.adopt(hb);
  }
  carry(from, to, body) {
    if (this.r() < this.dropRate) return;         // a lost frame
    this.queue.push({ to, from, body });
    if (this.r() < this.dupRate) this.queue.push({ to, from, body }); // a duplicated one
  }
  /** Deliver everything pending, in a shuffled order, until the network goes quiet. */
  /**
   * Deliver everything pending, in a shuffled order, until the network is genuinely quiet.
   *
   * Bounded by TIME, not by iterations. A dropped frame is recovered only when a request
   * deadline expires, and deadlines are real nanoseconds — twenty thousand idle pumps
   * finish faster than one millisecond, so a round counter would give up long before the
   * recovery it is waiting for could happen.
   */
  settle(budgetMs = 2000) {
    const start = process.hrtime.bigint();
    const budget = BigInt(budgetMs) * 1_000_000n;
    this.lastMsg = start;
    for (;;) {
      const now = process.hrtime.bigint();
      if (now - start > budget) return false;
      if (this.queue.length) {
        this.lastMsg = now;
        const i = Math.floor(this.r() * this.queue.length);
        const [msg] = this.queue.splice(i, 1);
        const node = this.nodes.get(msg.to);
        const h = node?.pairs.get(msg.from);
        if (!h || h.closed) continue;
        h.emit('message', msg.body);
        node.sync.pump();
        continue;
      }
      for (const n of this.nodes.values()) n.sync.pump();
      if (this.queue.length) continue;
      if (now - this.lastMsg > 8_000_000n) return true;
    }
  }
}

function fakeNode(net, key, opts = {}) {
  const id = identity();
  const store = new Substrate({ maxBytes: 1 << 30 });
  const mgr = new FakeManager(id.pub);
  const node = { key, id, store, mgr, pairs: new Map() };
  // A 1 ms patience so dropped frames are recovered inside the settle loop. The real
  // value is 8 s, and a suite that never reaches it never exercises the recovery at all.
  node.sync = new Syncer({
    substrate: store, hyphaManager: mgr, selfPub: id.pub,
    requestTimeoutNs: opts.timeoutNs ?? 1_000_000n,
  });
  if (opts.seed) for (const b of opts.seed) store.insert(b.cert, b.payload, b.authorPub);
  net.add(node);
  return node;
}

test('property: after a swarm settles, no reservation is still outstanding', () => {
  // When everyone has left the library, no book is still marked "someone is reading this".
  // A stranded reservation is the worst failure shape in the system: plan() refuses to
  // re-issue that block, the sync never finishes, and nothing reports an error at all.
  for (let seed = 1; seed <= 25; seed++) {
    const r = rng(seed);
    const world = buildWorld(r, { logs: 2, blocks: 20 + Math.floor(r() * 15) });
    const net = new FakeNet(r, { dropRate: r() * 0.15, dupRate: r() * 0.1 });

    const seeders = 1 + Math.floor(r() * 2);
    const nodes = [];
    for (let i = 0; i < seeders; i++) nodes.push(fakeNode(net, `s${i}`, { seed: world.blocks }));
    const joiner = fakeNode(net, 'j');
    nodes.push(joiner);
    for (const n of nodes) n.sync.start();
    for (let i = 0; i < seeders; i++) net.link(joiner, nodes[i]);

    net.settle();

    // Some peers may wither mid-transfer; releasing on wither is its own code path.
    if (r() < 0.5 && seeders > 1) {
      const victim = nodes[0];
      for (const h of victim.pairs.values()) h.close('gone');
      for (const n of nodes) {
        const h = n.pairs.get(victim.key);
        if (h) h.close('gone');
      }
      net.settle();
    }

    for (const l of joiner.sync.logs.values()) {
      assert.equal(l.inflightGlobal.size, 0,
        `seed ${seed}: ${l.inflightGlobal.size} reservations still held after the swarm settled`);
      for (const [p, st] of l.peers) {
        assert.equal(st.inflight.size, 0, `seed ${seed}: peer ${p.slice(0, 8)} still has requests out`);
      }
    }
    for (const [p, n] of joiner.sync.peerInflight) {
      assert.equal(n, 0, `seed ${seed}: peer ${p.slice(0, 8)} budget drifted to ${n}`);
      assert.ok(n <= MAX_INFLIGHT_PER_PEER);
    }
    for (const n of nodes) n.sync.stop();
  }
});

test('property: a lossy swarm still converges on whatever it managed to fetch', () => {
  for (let seed = 1; seed <= 20; seed++) {
    const r = rng(seed);
    const world = buildWorld(r, { logs: 1, blocks: 25 });
    const net = new FakeNet(r, { dropRate: 0, dupRate: r() * 0.2 });

    const a = fakeNode(net, 'a', { seed: world.blocks });
    const b = fakeNode(net, 'b');
    a.sync.start(); b.sync.start();
    net.link(b, a);
    assert.ok(net.settle(), `seed ${seed}: the network never went quiet`);

    const key = world.ids[0].logId.toString('hex');
    assert.equal(b.store.replica(key)?.linkedTo, 24,
      `seed ${seed}: joiner reached ${b.store.replica(key)?.linkedTo} of 24`);
    a.sync.stop(); b.sync.stop();
  }
});
