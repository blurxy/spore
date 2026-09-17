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
import {
  encodeBlock, decodeBlock, logIdFor, TYPE, FLAG, encodeGrant, encodeRevoke, colonyIdFor,
} from '../src/substrate/block.js';
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
  const cites = []; // { logIdx, seq, ref } — what each member block claimed under

  // scope_id is only meaningful once there is a colony to be a member of — and it is not
  // a constant. A colony names its founder, so the id has to be derived from log 0 at the
  // seq its genesis will occupy, or the genesis is ignored and every authority check in
  // this world stalls instead of deciding anything.
  const scopeId = authority ? colonyIdFor(ids[0].logId, 0) : Buffer.alloc(16);

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
      grants[li] = [emit(0, {
        type: TYPE.ROLE_GRANT,
        payload: encodeGrant({ target: ids[li].logId, roleId: li }),
      }).hash];
    }
  }

  /**
   * A burst of the owner's control statements about one member.
   *
   * Two independent choices, and the second one is what this generator was missing. The
   * PINS are chosen blind to each other, which it always did. The EMISSION ORDER is now
   * chosen blind to the pins, which it never did: the old version emitted the revocation
   * and then, maybe, a re-grant — so ownerSeq(revoke) < ownerSeq(grant) in every run it
   * could produce, on every seed.
   *
   * A grant and a revocation are entries in one ordered list sorted by boundary, with the
   * owner's log position breaking ties at EQUAL boundary. If write order and boundary
   * order never disagree, nothing here can tell the two apart, and a rule that used the
   * wrong one of them passes 102 tests and a property fuzzer. That is exactly what
   * happened: three review lenses found it and this file could not have, at any seed.
   *
   * So: statements are shuffled after their pins are picked. Divergence between the two
   * orderings is the whole point, not a rare accident.
   */
  const controlBurst = (target) => {
    if (!authority || target < 1 || target >= logs || state[target].seq === 0) return;
    const head = state[target].seq;
    const stmts = [];

    // The LAYERED shape, deliberately, because independent random pins essentially never
    // produce it. A revocation pinned at k has boundary k+1; only a grant pinned at exactly
    // k+1 shares that boundary, and it is the restore-at-the-same-boundary case that makes
    // anything above it observable at all. Without a restore, the revocation stops the
    // member at a low seq and every later verdict is hidden behind the contiguous
    // watermark — which is why a generator full of random revocations still saw nothing.
    const k = Math.floor(r() * (head + 1));
    stmts.push({ revoke: true, pinSeq: k });
    if (r() < 0.7) stmts.push({ revoke: false, pinSeq: k + 1 });          // restores at k+1
    if (r() < 0.7) stmts.push({ revoke: false, pinSeq: head + 1 + Math.floor(r() * 3) });
    for (let j = 0, n = Math.floor(r() * 2); j < n; j++) {
      stmts.push({ revoke: r() < 0.5, pinSeq: Math.floor(r() * (head + 2)) });
    }
    for (let k = stmts.length - 1; k > 0; k--) {
      const j = Math.floor(r() * (k + 1));
      const t = stmts[k]; stmts[k] = stmts[j]; stmts[j] = t;
    }
    for (const st of stmts) {
      if (st.revoke) {
        emit(0, {
          type: TYPE.ROLE_REVOKE,
          payload: encodeRevoke({ target: ids[target].logId, pinSeq: st.pinSeq, roleId: target }),
        });
      } else {
        grants[target].push(emit(0, {
          type: TYPE.ROLE_GRANT,
          payload: encodeGrant({ target: ids[target].logId, pinSeq: st.pinSeq, roleId: target }),
        }).hash);
      }
    }
  };

  for (let i = 0; i < blocks; i++) {
    const li = Math.floor(r() * logs) % logs;

    let deps = [];
    let depLamport = 0n;
    if (built.length && r() < depChance) {
      const d = pick(r, built);
      deps = [d.hash];
      depLamport = d.lamport;
    }
    // Cite ANY grant this member has ever been handed, not only the first. A member
    // holding an old grant's hash and still using it is the case R6 is about — and the
    // one the previous generator could not produce, because there was only ever one hash
    // to cite. Whether that old grant is still in force at this seq is precisely the
    // question #authCheck exists to answer.
    const mine = grants[li];
    const authRef = mine && mine.length ? mine[Math.floor(r() * mine.length)] : null;

    cites.push({
      logIdx: li,
      seq: state[li].seq,
      ref: authRef ? authRef.toString('hex') : null,
    });
    emit(li, {
      payload: Buffer.from(`log${li}:${state[li].seq}`),
      authRef,
      deps,
      depLamport,
    });

    // Control blocks land BETWEEN a member's blocks, not only after all of them. Emitting
    // them at the end meant no member block could ever cite a re-grant, so the supersede
    // path was unreachable however many seeds ran.
    if (authority && logs > 1 && r() < 0.08) {
      controlBurst(1 + Math.floor(r() * (logs - 1)));
    }
  }

  // One last burst after everything, so a member's whole history can be spoken about in
  // arrears. The owner revokes against the head they had, not the head that exists.
  if (authority && logs > 1) controlBurst(1 + Math.floor(r() * (logs - 1)));

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
  return { ids, blocks: out, scopeId, cites };
}

// prevHash of an already-built block, recovered from its cert (offset 60, 32 bytes) by
// hashing the cert itself — the block hash IS hash256(cert), which encodeBlock returned.
import { hash256 } from '../src/substrate/store.js';
const require_hash = (b) => hash256(b.cert);

/** The comparable state of a substrate: what two honest replicas must agree on. */
/**
 * The frontiers alone — no held set. Comparable across arrival orders even under a tight
 * budget, for the reason above: forgetting is meant to be invisible to derivation.
 */
function frontiers(s) {
  const out = [];
  for (const [key, r] of [...s.logs].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    out.push({
      key,
      chainTo: r.chainTo,
      orderedTo: r.orderedTo,
      linkedTo: r.linkedTo,
      forkedAt: r.forkedAt === Infinity ? -1 : r.forkedAt,
    });
  }
  return JSON.stringify(out);
}

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

    // A third of the seeds run under a budget tight enough that eviction actually bites.
    // The review found a fatal stall that this test was structurally unable to see: it ran
    // with eviction off, so a citer whose dep had been forgotten before it arrived never
    // occurred here. Eviction IS order-dependent in what a replica ends up HOLDING, which
    // is why it was excluded — but two replicas that hold the same set must still deliver
    // the same set, and that is what the snapshot compares.
    const tight = seed % 3 === 0;
    const each = world.blocks[0].cert.length + world.blocks[0].payload.length;

    let reference = null;
    const built = [];
    for (let k = 0; k < 4; k++) {
      const s = new Substrate({ maxBytes: tight ? each * 8 : 1 << 30 });
      for (const b of shuffled(rng(seed * 100 + k), world.blocks)) {
        s.insert(b.cert, b.payload, b.authorPub);
      }
      built.push(s);
      // LIVENESS, not just agreement. Two replicas that both stall identically agree
      // perfectly and are both wrong, and `snapshot` cannot tell the difference. A stall
      // is only legitimate when the dep genuinely cannot be ordered — never when the
      // substrate is already holding it, ordered, and simply stopped asking. That is what
      // a fixpoint loop counting only promotions did: a log whose every block was stopped
      // by a revocation still ORDERED them, reported no progress, and the loop exited
      // before the log citing them could resolve.
      for (const rep of s.logs.values()) {
        if (!rep.pendingDeps) continue;
        const stuck = rep.blocks.get(rep.orderedTo + 1);
        if (!stuck) continue; // waiting on a gap in the log itself, which is fine
        for (const dep of decodeBlock(stuck.cert).deps) {
          const at = s.resolveDep(dep);
          assert.ok(!at || !at.ordered,
            `seed ${seed}, shuffle ${k}: stalled on a dep this substrate has already ordered`);
        }
      }

      // Under a tight budget the HELD set legitimately differs between arrival orders —
      // which replica was fattest when the budget bit decides what it forgot, and that is
      // by design. So the snapshot is only compared where eviction is off. What is checked
      // in both cases is the liveness assertion above, which is the property the review's
      // fatal stall actually violated and which this test previously could not reach at
      // all, because it never ran with eviction on.
      // The sanity envelope eviction cannot legitimately break. Under a tight budget the
      // HELD set differs between arrival orders, so snapshots are not comparable — but a
      // replica must never claim to have delivered something it does not hold, and must
      // never reset below its own floor. Without this, tight seeds would assert liveness
      // and nothing else, and a frontier that ran past the blocks behind it would pass.
      for (const rep of s.logs.values()) {
        const top = rep.blocks.size ? Math.max(...rep.blocks.keys()) : -1;
        assert.ok(rep.linkedTo <= top,
          `seed ${seed}: linkedTo ${rep.linkedTo} is past the highest block held (${top})`);
        assert.ok(rep.orderedTo <= top,
          `seed ${seed}: orderedTo ${rep.orderedTo} is past the highest block held (${top})`);
        // NOT `linkedTo >= floor - 1`, which this used to assert and which is wrong —
        // wrong on principle, not merely in the way of a patch.
        //
        // It said "delivery below the floor is final". The substrate contradicts that in
        // two places of its own: the `retracted` event exists precisely to withdraw
        // delivery after the fact, and the V1 fix stops blocks retroactively. R4e's whole
        // point is that verdicts below the floor get re-asked — floorHash, floorLamport,
        // `lost` and now `claims` are the witnesses kept SO THAT they can be.
        //
        // It is also incompatible with convergence, which is the property this file is
        // about. A fresh replica facing a revocation at boundary B settles at
        // linkedTo = B - 1 forever. A replica that evicted past B has floor > B. For the
        // two to agree — and they must, they hold the same blocks — the tight one needs
        // linkedTo = B - 1, which is below floor - 1. The old assertion could only be
        // satisfied by dragging the floor down to B, which is what R7 originally did and
        // what cost ordering.
        //
        // The floor bounds ORDERING, which is what its witness serves: walk one chains
        // against floorHash at s === floor. Delivery is a sub-range of ordering by
        // construction, because walk two only ever visits what walk one ordered.
        assert.ok(rep.orderedTo >= rep.floor - 1,
          `seed ${seed}: orderedTo ${rep.orderedTo} is below the floor ${rep.floor}`);
        assert.ok(rep.linkedTo <= rep.orderedTo,
          `seed ${seed}: linkedTo ${rep.linkedTo} is above orderedTo ${rep.orderedTo}`);
      }

      // FRONTIERS ALWAYS, held sets only when eviction is off.
      //
      // Which blocks a replica HOLDS legitimately differs with arrival order under a tight
      // budget — which replica was fattest when the budget bit decides what it forgot, and
      // that is by design. The frontiers are a different matter: they are derived from the
      // blocks, the witnesses and the authority set, and every one of those is either held
      // or witnessed precisely so that forgetting does not change the answer.
      //
      // Skipping tight seeds entirely is why the tied-boundary divergence (auth.test.js,
      // scenario X) was invisible here: a tight budget is the ONLY condition under which
      // the eviction floor can climb past a revocation boundary at all.
      const snap = snapshot(s);
      if (tight) continue;
      if (reference === null) reference = snap;
      else assert.equal(snap, reference, `seed ${seed}, shuffle ${k}: replicas diverged`);
    }

    // FORK PROOFS TRAVEL, and modelling them is what makes "the same blocks" true.
    //
    // A fork at a seq a replica has already forgotten cannot be witnessed locally: the
    // contradicting block arrives, insert() refuses it below_floor, and nothing is left to
    // compare it against. So one replica ends at forkedAt 4 with its frontier withdrawn to
    // 3, and another — fed the identical blocks in a different order, having evicted past
    // 4 before the second one arrived — never learns there was a fork at all.
    //
    // That is a real and permanent property of forgetting, not a bug to fix in the store,
    // and the mesh already answers it: a proof is self-contained evidence anyone can verify,
    // sync.js replays every one it holds to every new hypha, and acceptForkProof takes them
    // from any relay. A replica that forgot the evidence learns from one that did not.
    //
    // Feeding only blocks therefore models LESS than a real replica receives. Exchanging
    // proofs before comparing is the honest model, and it is deliberately unconditional:
    // doing it only for tight seeds would make the harness agree with itself by choosing
    // when to be realistic.
    const proofs = [];
    for (const s of built) proofs.push(...s.knownForks());
    for (const s of built) {
      for (const f of proofs) s.acceptForkProof(f.certA, f.certB, f.authorPub);
    }

    // FRONTIERS ALWAYS, including tight seeds. Which blocks a replica HOLDS legitimately
    // differs with arrival order under a tight budget — which replica was fattest when the
    // budget bit decides what it forgot. The frontiers are a different matter: they are
    // derived from the blocks, the witnesses and the authority set, and every witness this
    // substrate keeps exists precisely so that forgetting does not change the answer.
    //
    // Skipping tight seeds is why the tied-boundary divergence (auth.test.js scenario X)
    // was invisible here — a tight budget is the only condition under which the eviction
    // floor can climb past a revocation boundary at all.
    let refFront = null;
    for (const s of built) {
      const front = frontiers(s);
      if (refFront === null) refFront = front;
      else assert.equal(front, refFront, `seed ${seed}: frontiers diverged`);
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
    // Authority on, budget tight. These two were only ever tested apart, and apart is
    // exactly where the interaction hides: the oldest block in the owner's log is its
    // COLONY_GENESIS, so the plain eviction rule feeds authority to the byte budget first.
    const world = buildWorld(r, { logs: 2, blocks: 30, authority: r() < 0.5 });
    const each = world.blocks[0].cert.length + world.blocks[0].payload.length;

    const s = new Substrate({ maxBytes: each * (2 + Math.floor(r() * 8)) });
    let high = new Map();
    let retractions = 0;
    s.on('retracted', () => { retractions++; });
    for (const b of shuffled(rng(seed * 13), world.blocks)) {
      const seen = retractions;
      s.insert(b.cert, b.payload, b.authorPub);
      for (const [k, rep] of s.logs) {
        const prev = high.get(k) ?? -1;
        // A frontier may fall for exactly one reason — history was withdrawn and the
        // substrate said so. EVICTION is never that reason: forgetting old blocks must
        // cost old blocks and nothing above them. Before authority existed this test could
        // assert plain monotonicity; now a revocation coming into reach is a real
        // retraction, so the exemption is the announcement, not the drop.
        assert.ok(rep.linkedTo >= prev || retractions > seen,
          `seed ${seed}: frontier fell ${prev} -> ${rep.linkedTo} with no retraction`);
        high.set(k, rep.linkedTo);
        // The frontier block must survive, or the log stalls forever — UNLESS the
        // frontier has fallen back to the floor boundary itself, which a retraction can
        // do. There, the block is gone by design and floorHash/floorLamport are what
        // relink() chains the next one against, so the log is not stalled at all.
        // Only ABOVE the floor. This used to exempt exactly `linkedTo === floor - 1`,
        // which was the previous invariant wearing a second coat: it assumed the only way
        // a frontier sits below what we hold is that it fell back to the floor boundary.
        // A delivery frontier can now sit anywhere below the floor, at a permanent stop
        // that a forgotten claim no longer passes.
        //
        // What relink actually needs held is the ORDERING frontier's block, because walk
        // one reads its lamport to chain the next one. A delivery frontier below the floor
        // is a permanent stop and nothing ever reads past it.
        if (rep.orderedTo >= rep.floor) {
          assert.ok(rep.has(rep.orderedTo), `seed ${seed}: evicted the ordering frontier block`);
        }
        if (rep.linkedTo >= rep.floor) {
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

// --- authority oracle -------------------------------------------------------------------

/**
 * Where SHOULD a member's frontier stop, read straight off the rule list.
 *
 * Deliberately naive: no sorted-list assumption, no early break, no sharing of code with
 * #authCheck. It re-derives "which statement governs seq N" by scanning everything that
 * reaches N and taking the maximum by (boundary, ownerSeq) — the ordering R6 defines.
 *
 * What this does and does not prove, stated plainly, because the distinction is the whole
 * reason this function exists:
 *
 *   The other properties in this file assert CONVERGENCE — replicas fed the same blocks in
 *   any order reach the same state. That cannot catch a deterministic logic error: when
 *   every replica computes the same wrong verdict, they agree perfectly and every seed
 *   passes. The supersession bug did exactly that, and no amount of shuffling or seeds
 *   could ever have found it. Agreement is not correctness.
 *
 *   This is a differential check against a second reading of the same rule list, so it
 *   catches a CONSUMER that diverges from the rule the PRODUCER built — which is what the
 *   bug was: #rebuildAuth's list was right, #authCheck read it by the wrong key. It does
 *   not independently validate the rule itself. If R6 is wrong, both readings are wrong
 *   together and this stays silent. It is a regression oracle, not a discovery oracle.
 */
function oracleFirstStop(rule, citations, upTo) {
  const stronger = (a, b) => a.boundary > b.boundary
    || (a.boundary === b.boundary && a.ownerSeq > b.ownerSeq);

  for (let seq = 0; seq <= upTo; seq++) {
    const ref = citations.get(seq);
    if (ref === undefined) return seq;   // no such block; the chain ended
    if (ref === null) continue;          // claims nothing — answered before any of this
    if (!rule || !rule.length) return seq;

    const reaching = rule.filter((e) => e.boundary <= seq);
    if (!reaching.length) return seq;    // the owner has said nothing that reaches here

    let gov = reaching[0];
    for (const e of reaching) if (stronger(e, gov)) gov = e;
    if (gov.kind === 'revoke') return seq;

    const cited = rule.find((e) => e.kind === 'grant' && e.hash === ref);
    if (!cited || cited.boundary > seq) return seq;
    for (const e of reaching) {
      if (e.kind === 'revoke' && stronger(e, cited)) return seq;
    }
  }
  return null; // nothing stops it
}

test('property: the delivery frontier matches an independent reading of the rule list', () => {
  // The test that would have caught the supersession bug, and the kind this file did not
  // have. Everything else here asks whether replicas AGREE. This asks whether they are
  // RIGHT — against a second, deliberately clumsy reading of the same authority rules.
  //
  // Only logs whose ordering is complete are checked: linkedTo is bounded by orderedTo as
  // well as by authority, and a frontier held back by an unresolved dep says nothing about
  // whether the authority verdict was correct.
  for (let seed = 1; seed <= 60; seed++) {
    const r = rng(seed);
    const w = buildWorld(r, { logs: 3, blocks: 30, depChance: 0.2, authority: true });

    const s = new Substrate();
    for (const b of shuffled(rng(seed * 7919), w.blocks)) {
      s.insert(b.cert, b.payload, b.authorPub);
    }

    const scope = w.scopeId.toString('hex');
    for (let li = 1; li < w.ids.length; li++) {
      const key = w.ids[li].logId.toString('hex');
      const rep = s.replica(key);
      if (!rep || rep.chainTo < 0) continue;
      if (rep.orderedTo !== rep.chainTo) continue; // ordering, not authority, is the limit

      const citations = new Map();
      for (const c of w.cites) if (c.logIdx === li) citations.set(c.seq, c.ref);

      const rule = s.auth.rule.get(`${key}|${scope}`) || [];
      const stop = oracleFirstStop(rule, citations, rep.chainTo);
      const expected = stop === null ? rep.chainTo : stop - 1;

      assert.equal(rep.linkedTo, expected,
        `seed ${seed}, log ${li}: frontier is ${rep.linkedTo}, the rule list says ${expected}`);
    }
  }
});
