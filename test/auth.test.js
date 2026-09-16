// CORRECTNESS.md [FATAL-V1] — the demoted moderator who comes back.
//
// "Founder/moderator M once held power P at a historical AUTH_SNAPSHOT S_old, then was
// superseded... Long after — whether M is malicious, or simply an honest client
// reconnecting after being offline — M publishes a new control block citing
// auth_ref = S_old and a naturally low lamport."
//
// Read that last clause carefully, because it kills the obvious fix. M's lamport is
// anchored to M's own frozen head, so M's new block sorts BEFORE the revocation in
// (lamport, log_id, seq). Any rule that compares the two blocks' lamports, or asks whether
// the revocation is "causally before" M's block, is a rule M wins: M chooses the lamport
// and M chooses what to cite. The tests below assert `B.lamport < R.lamport` in the test
// body on purpose — a version of this scenario written with the revoke first would go
// green against code that closes nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  encodeBlock, decodeBlock, logIdFor, TYPE, FLAG,
  encodeGrant, decodeGrant, encodeRevoke, decodeRevoke, colonyIdFor,
} from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';

function identity() {
  const kp = generateKeyPairSync('ed25519');
  const pub = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { kp, pub, logId: logIdFor(pub) };
}

/** A single-writer log builder: seq and prev_hash advance themselves, lamport is derived. */
function writer(id, scopeId) {
  let seq = 0;
  let prevHash = Buffer.alloc(32);
  let lamport = 0n;
  return {
    id,
    /** Append one block. `deps` raises lamport; `authRef` never does — that is the bug. */
    push({ type = TYPE.MESSAGE, payload = Buffer.alloc(0), authRef = null, deps = [], depLamports = [], scopeId: override = null } = {}) {
      let m = lamport;
      for (const d of depLamports) if (d > m) m = d;
      lamport = m + 1n;
      const { cert, blockHash } = encodeBlock(
        {
          type,
          flags: FLAG.PAYLOAD_INLINE,
          logId: id.logId,
          seq,
          lamport,
          scopeId: override || scopeId,
          prevHash,
          authRef: authRef || Buffer.alloc(32),
          payload,
          deps,
        },
        id.kp.privateKey,
      );
      const rec = { cert, payload, authorPub: id.pub, hash: blockHash, seq, lamport };
      prevHash = blockHash;
      seq += 1;
      return rec;
    },
    get seq() { return seq; },
    get lamport() { return lamport; },
  };
}

/**
 * The V1 world.
 *
 * Owner O writes COLONY_GENESIS, then ROLE_GRANT to M, then enough traffic to carry O's
 * lamport well past M's, then ROLE_REVOKE pinning M at M's head as O last saw it.
 * M writes ordinary blocks, goes quiet, and returns with a block citing the old grant.
 *
 * Owner control blocks carry auth_ref = 0. The owner acts AS the owner; there is no grant
 * to them and none is needed, which is also what keeps the resolution well-founded — the
 * owner's frontier can never be stopped by an authority rule, so the set of valid
 * revocations cannot shrink as frontiers move.
 */
function v1World({ pinBehind = 0, ownerTraffic = 8 } = {}) {
  const O = identity();
  const scopeId = colonyIdFor(O.logId, 0); // the colony names its founder
  const M = identity();
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const grant = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId, roleId: 1 }) });

  // M does ordinary work under the grant, citing it, then falls silent.
  const mBefore = [];
  for (let i = 0; i < 3; i++) {
    mBefore.push(mw.push({ payload: Buffer.from(`mod:${i}`), authRef: grant.hash }));
  }
  const pinSeq = mw.seq - 1 - pinBehind; // O's view of M's head

  // The colony keeps moving while M is away. This is what drives O's lamport above M's.
  const traffic = [];
  for (let i = 0; i < ownerTraffic; i++) traffic.push(ow.push({ payload: Buffer.from(`owner:${i}`) }));

  const revoke = ow.push({
    type: TYPE.ROLE_REVOKE,
    payload: encodeRevoke({ target: M.logId, pinSeq, roleId: 1 }),
  });

  // M returns. Anchored to M's own frozen head, citing the grant M no longer holds.
  const replay = mw.push({ payload: Buffer.from('i am still a moderator'), authRef: grant.hash });

  return { scopeId, O, M, ow, mw, genesis, grant, revoke, replay, mBefore, traffic, pinSeq };
}

const load = (s, blocks) => blocks.map((b) => s.insert(b.cert, b.payload, b.authorPub));

/** A second, different block signed at the same seq — the other half of a fork proof. */
function forkBlockAt(id, scopeId, seq, twin, text) {
  const d = decodeBlock(twin.cert);
  const { cert, blockHash } = encodeBlock(
    {
      type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq,
      lamport: d.lamport, scopeId, prevHash: d.prevHash, payload: Buffer.from(text),
    },
    id.kp.privateKey,
  );
  return { cert, payload: Buffer.from(text), authorPub: id.pub, hash: blockHash, seq };
}

test('V1: a revoked moderator cannot replay a stale auth_ref, even with a lower lamport', () => {
  const w = v1World();

  // The precondition that makes this test worth anything. If it ever stops holding, the
  // scenario has drifted into one that a lamport comparison would close for free.
  assert.ok(
    w.replay.lamport < w.revoke.lamport,
    `replay lamport ${w.replay.lamport} must be BELOW revoke lamport ${w.revoke.lamport}`,
  );

  const s = new Substrate();
  load(s, [w.genesis, w.grant, ...w.mBefore, ...w.traffic, w.revoke, w.replay]);

  const mr = s.replica(w.M.logId.toString('hex'));
  const or = s.replica(w.O.logId.toString('hex'));

  assert.equal(mr.linkedTo, w.pinSeq, `M's frontier must stop at the pin (${w.pinSeq})`);
  assert.ok(mr.has(w.replay.seq), 'the block is still HELD — append-only means never dropped');
  assert.equal(or.linkedTo, w.revoke.seq, "the owner's own log is untouched");
});

test('V1: the outcome does not depend on which arrived first', () => {
  const w = v1World();
  const all = [w.genesis, w.grant, ...w.mBefore, ...w.traffic, w.revoke, w.replay];

  const a = new Substrate();
  load(a, all);

  // The reverse order is the one that catches a check applied only on the way in: here the
  // replay block links first, on a substrate that has not yet met the revocation, and must
  // be withdrawn when it does.
  const b = new Substrate();
  load(b, [w.genesis, w.grant, ...w.mBefore, w.replay, ...w.traffic, w.revoke]);

  const key = w.M.logId.toString('hex');
  assert.equal(b.replica(key).linkedTo, w.pinSeq, 'late revocation must retract the replay');
  assert.equal(a.replica(key).linkedTo, b.replica(key).linkedTo);
  assert.equal(a.replica(w.O.logId.toString('hex')).linkedTo, b.replica(w.O.logId.toString('hex')).linkedTo);
});

test('V1: retraction is announced, not silent', () => {
  const w = v1World();
  const s = new Substrate();
  load(s, [w.genesis, w.grant, ...w.mBefore, w.replay]);

  const key = w.M.logId.toString('hex');
  assert.equal(s.replica(key).linkedTo, w.replay.seq, 'it links while nothing contradicts it');

  // design-substrate.md: soft_failed carries `wasApplied: true` when "the local user saw it
  // succeed and must be told it reverted." A frontier that quietly slides backwards leaves
  // a message on screen that the substrate no longer stands behind.
  const seen = [];
  s.on('retracted', (e) => seen.push(e));
  load(s, [...w.traffic, w.revoke]);

  assert.equal(s.replica(key).linkedTo, w.pinSeq);
  const mine = seen.filter((e) => e.logId.toString('hex') === key);
  assert.ok(mine.length, 'the retraction must be emitted');
  assert.ok(mine.some((e) => e.seqs.includes(w.replay.seq)), 'and must name the replayed block');
});

test('an unrevoked grant still works, and a revoke only reaches its own target', () => {
  const O = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const M = identity();
  const N = identity();
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);
  const nw = writer(N, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const gM = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });
  const gN = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: N.logId }) });
  const mBlocks = [0, 1].map((i) => mw.push({ payload: Buffer.from(`m${i}`), authRef: gM.hash }));
  const nBlocks = [0, 1].map((i) => nw.push({ payload: Buffer.from(`n${i}`), authRef: gN.hash }));
  const revokeM = ow.push({
    type: TYPE.ROLE_REVOKE,
    payload: encodeRevoke({ target: M.logId, pinSeq: 0 }),
  });

  const s = new Substrate();
  load(s, [genesis, gM, gN, ...mBlocks, ...nBlocks, revokeM]);

  assert.equal(s.replica(M.logId.toString('hex')).linkedTo, 0, 'M stops at the pin');
  assert.equal(s.replica(N.logId.toString('hex')).linkedTo, 1, 'N is untouched');
});

test('a revoke from someone who is not the colony owner has no power', () => {
  const O = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const M = identity();
  const X = identity(); // an ordinary member with opinions
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);
  const xw = writer(X, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const grant = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });
  const mBlocks = [0, 1, 2].map((i) => mw.push({ payload: Buffer.from(`m${i}`), authRef: grant.hash }));
  const forged = xw.push({
    type: TYPE.ROLE_REVOKE,
    payload: encodeRevoke({ target: M.logId, pinSeq: 0 }),
  });

  const s = new Substrate();
  load(s, [genesis, grant, ...mBlocks, forged]);

  assert.equal(s.replica(M.logId.toString('hex')).linkedTo, 2, 'M is unaffected');
  assert.equal(s.replica(X.logId.toString('hex')).linkedTo, 0, 'X is free to say it, to no effect');
});

test('a block citing a grant we do not hold STALLS; it does not link and does not stop', () => {
  const w = v1World();
  const s = new Substrate();
  // Everything except the grant the replay cites.
  load(s, [w.genesis, ...w.mBefore]);

  const key = w.M.logId.toString('hex');
  const mr = s.replica(key);
  assert.equal(mr.linkedTo, -1, 'nothing links while the cited grant is unknown');
  assert.ok(mr.pendingDeps, 'and it is recorded as waiting, not as broken');

  s.insert(w.grant.cert, w.grant.payload, w.grant.authorPub);
  assert.equal(s.replica(key).linkedTo, 2, 'the moment the grant arrives, the run promotes');
});

test('a block citing a grant issued to somebody else stops its own log', () => {
  const O = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const M = identity();
  const N = identity();
  const ow = writer(O, scopeId);
  const nw = writer(N, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const gM = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });
  const ok = nw.push({ payload: Buffer.from('fine') });
  const theft = nw.push({ payload: Buffer.from('borrowing this'), authRef: gM.hash });

  const s = new Substrate();
  load(s, [genesis, gM, ok, theft]);

  assert.equal(s.replica(N.logId.toString('hex')).linkedTo, 0, "N's log ends at the theft");
});

test('auth_ref = 0 is unaffected by any of this', () => {
  // Every SP1 MESSAGE claims nothing, so none of this machinery may touch the common path.
  const O = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const M = identity();
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const plain = [0, 1, 2, 3].map((i) => mw.push({ payload: Buffer.from(`hi ${i}`) }));
  const revoke = ow.push({
    type: TYPE.ROLE_REVOKE,
    payload: encodeRevoke({ target: M.logId, pinSeq: 0 }),
  });

  const s = new Substrate();
  load(s, [genesis, ...plain, revoke]);
  assert.equal(s.replica(M.logId.toString('hex')).linkedTo, 3, 'ordinary messages keep linking');
});

test('grant/revoke payloads round-trip and reject wrong lengths', () => {
  const target = Buffer.alloc(16, 0x7e);
  const g = encodeGrant({ target, pinSeq: 7, roleId: 9 });
  const r = encodeRevoke({ target, pinSeq: 2n ** 40n, roleId: 3 });

  assert.ok(decodeGrant(g).target.equals(target));
  assert.equal(decodeGrant(g).pinSeq, 7n);
  assert.equal(decodeGrant(g).roleId, 9);
  assert.equal(decodeRevoke(r).pinSeq, 2n ** 40n);
  assert.equal(decodeRevoke(r).roleId, 3);

  // The two payloads now share a layout, so length no longer tells them apart — and an
  // earlier version of this test leaned on exactly that. What distinguishes them is the
  // block TYPE at header offset 1, which is inside the signed region, so it is the author's
  // statement rather than the parser's guess. Length-sniffing was never the real defence;
  // it just happened to work while the two differed.
  assert.equal(g.length, r.length);
  assert.notEqual(TYPE.ROLE_GRANT, TYPE.ROLE_REVOKE);
  assert.throws(() => decodeGrant(Buffer.alloc(20)), /grant payload 20/);
  assert.throws(() => decodeRevoke(Buffer.alloc(20)), /revoke payload 20/);
  assert.throws(() => encodeGrant({ target: Buffer.alloc(8) }), /16 bytes/);
});

// --- the budget must not be able to launder a revocation -----------------------------

test('eviction cannot un-revoke, un-own, or un-grant a colony', () => {
  // forgetOldest() takes the oldest LINKED blocks first, and the oldest block in the
  // owner's log is COLONY_GENESIS. Drop it and nobody owns the colony; drop a ROLE_REVOKE
  // and the demoted moderator's blocks link again. A spore that has been running long
  // enough to hit its byte budget would quietly re-admit everyone it had ever removed,
  // and nothing in the substrate would report it.
  const w = v1World({ ownerTraffic: 40 });
  const all = [w.genesis, w.grant, ...w.mBefore, ...w.traffic, w.revoke, w.replay];

  // A budget far below what this world needs, so eviction runs hard.
  const each = all[0].cert.length + all[0].payload.length;
  const s = new Substrate({ maxBytes: each * 6 });
  load(s, all);

  const mr = s.replica(w.M.logId.toString('hex'));
  assert.ok(mr.linkedTo <= w.pinSeq, `M linked to ${mr.linkedTo}, past the pin ${w.pinSeq}`);
  assert.ok(s.auth.owners.size > 0, 'the colony must still have an owner');
  assert.ok(s.auth.revokes.size > 0, 'the revocation must still be in force');
});

// The review deleted a test here, and it was right to. "a frontier survives a
// recomputation that happens after eviction" never triggered one: it captured the
// frontier AFTER the ROLE_REVOKE had already been inserted — the only thing in the
// scenario that re-resolves anything — and then inserted a plain MESSAGE, which routes
// through the cheap local relink and never touches the owner's replica at all. The
// assertion compared the owner's frontier to itself with nothing happening in between and
// passed whether or not R4b's floor witness existed.
//
// I half-knew: when I falsified the floor witness earlier, this test did not fail, and I
// wrote the real one in sync.test.js ("a forgotten predecessor does not collapse the
// frontier on recompute") instead of removing this one. A test that cannot fail is worse
// than no test, because it reads like coverage.

test('a colony cannot be hijacked by minting a genesis block for its scope', () => {
  // scope_id has to be derived from the founder, or "who owns this colony" is decided by
  // a hash comparison between two blocks anyone can write — one cheap block from a fresh
  // identity wins the colony half the time, and then the real owner's grants stop working.
  const w = v1World();
  const X = identity();
  const xw = writer(X, w.scopeId);
  const hijack = xw.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('mine now') });

  const s = new Substrate();
  load(s, [w.genesis, w.grant, ...w.mBefore, hijack]);

  assert.equal(
    s.auth.owners.get(w.scopeId.toString('hex')),
    w.O.logId.toString('hex'),
    'the founder still owns the colony',
  );
  // The old tiebreak would have picked O about half the time too, so "O won" on its own
  // proves nothing. These two say X's block founded NOTHING: not a rival claim on O's
  // colony that lost a hash comparison, and not a colony of X's own either — it names a
  // scope it cannot derive, so it is malformed, not a founding of something else.
  assert.equal(s.auth.owners.size, 1, 'X created no colony at all');
  assert.equal(s.auth.owners.get(colonyIdFor(X.logId, 0).toString('hex')), undefined);
  assert.equal(s.replica(w.M.logId.toString('hex')).linkedTo, 2, 'and M is unaffected');
});

test('a grant in one colony does not authorise writes in another', () => {
  // Revocation pins carry a scope. If grants do not, the two are asymmetric: an owner of
  // two colonies who revokes someone from one has not revoked them from the other, yet
  // their grant in the first still authorises blocks in the second.
  //
  // Both colonies get a real, derived genesis from the same founder, so colony B has an
  // owner and the block is STOPPED on its merits — not stalled for want of one, which is
  // what an earlier version of this test was actually measuring.
  const O = identity();
  const M = identity();
  const A = colonyIdFor(O.logId, 0);
  const B = colonyIdFor(O.logId, 1);

  const ow = writer(O, A);
  const genA = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('A') });
  assert.equal(genA.seq, 0);
  // The same log founds the second colony at its next seq, so B's derived id is B.
  const genB = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('B'), scopeId: B });
  assert.equal(genB.seq, 1);
  const grantA = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });

  const mw = writer(M, B);
  const fine = mw.push({ payload: Buffer.from('no claim') });
  const reach = mw.push({ payload: Buffer.from('elsewhere'), authRef: grantA.hash });

  const s = new Substrate();
  load(s, [genA, genB, grantA, fine, reach]);

  assert.equal(s.auth.owners.get(A.toString('hex')), O.logId.toString('hex'), 'A is owned');
  assert.equal(s.auth.owners.get(B.toString('hex')), O.logId.toString('hex'), 'B is owned too');
  assert.equal(s.replica(M.logId.toString('hex')).linkedTo, fine.seq,
    'the unclaimed block links; the one reaching across colonies stops the log');
  assert.ok(reach.seq > fine.seq);
});

test('the byte budget is honoured even when the biggest logs are all authority', () => {
  // #trim picked the fattest replica, and on a null fall back to the fattest OTHER one —
  // then gave up. That predicate ("has a range") is not the one that matters ("has
  // something evictable in that range"). Now that control blocks are never dropped, two
  // founder logs at the top of the byte ordering are enough to end the scan while a third
  // replica sits there holding nothing but evictable messages.
  const founders = [identity(), identity()];
  const keep = [];
  for (const F of founders) {
    const scope = colonyIdFor(F.logId, 0);
    const fw = writer(F, scope);
    keep.push(fw.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('c') }));
    for (let i = 0; i < 24; i++) {
      keep.push(fw.push({
        type: TYPE.ROLE_GRANT,
        payload: encodeGrant({ target: Buffer.alloc(16, i + 1), roleId: i }),
      }));
    }
  }

  // One ordinary member, deliberately smaller than either founder log, holding nothing
  // but blocks the budget is allowed to take.
  const M = identity();
  const mw = writer(M, colonyIdFor(founders[0].logId, 0));
  const chatty = [];
  for (let i = 0; i < 12; i++) chatty.push(mw.push({ payload: Buffer.from(`msg ${i}`.padEnd(64, '.')) }));

  const s = new Substrate({ maxBytes: 8 * 1024 });
  load(s, [...keep, ...chatty]);

  // The budget is NOT satisfiable here and is not supposed to be: fifty retained control
  // blocks exceed it by themselves, and nothing bounds how many an owner may write. What
  // #trim must guarantee is the weaker, deliverable thing — that it left nothing evictable
  // behind. The old scan left twelve of the member's messages sitting there.
  for (const r of s.logs.values()) {
    for (let x = r.floor; x < r.linkedTo; x++) {
      const b = r.blocks.get(x);
      assert.ok(!b || KEEP.has(b.type),
        `log ${r.key.slice(0, 8)} still holds an evictable block at seq ${x}`);
    }
  }
  assert.ok(s.replica(M.logId.toString('hex')).forgotten > 0, 'the member log gave way');
  assert.equal(s.auth.owners.size, 2, 'and both colonies still have their owners');
  assert.ok(s.bytes > s.maxBytes, 'over budget, on authority alone, visibly');
});

// The types eviction may never drop, mirrored from the substrate so the test states the
// property rather than importing the implementation's opinion of it.
const KEEP = new Set([TYPE.COLONY_GENESIS, TYPE.ROLE_GRANT, TYPE.ROLE_REVOKE]);

test('a revocation does not un-link itself by stalling the log it lives in', () => {
  // The cycle: authority is read from the owner's LINKED blocks, but the owner's link
  // frontier can depend on a member's, because an owner who replies to a member cites
  // that member's block as an ordinary dep. So:
  //
  //   the revoke links -> M's block stops -> the owner's reply stalls on it as a dep ->
  //   the revoke is now above the owner's frontier and stops counting -> M's block links
  //   -> the owner's reply links -> the revoke links -> ...
  //
  // It converges identically on every replica, so the convergence property never sees it.
  // It just converges on the wrong thing: the owner's own log stranded at seq 1, with the
  // revocation it wrote sitting unlinked above it.
  const O = identity();
  const M = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const grant = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });

  const m0 = mw.push({ payload: Buffer.from('hello'), authRef: grant.hash });
  const m1 = mw.push({ payload: Buffer.from('again'), authRef: grant.hash });
  const m2 = mw.push({ payload: Buffer.from('and again'), authRef: grant.hash });

  // The owner replies to M. Nothing exotic — this is what deps are FOR.
  const reply = ow.push({
    payload: Buffer.from('noted'),
    deps: [m1.hash],
    depLamports: [m1.lamport],
  });
  const revoke = ow.push({
    type: TYPE.ROLE_REVOKE,
    payload: encodeRevoke({ target: M.logId, pinSeq: 0 }),
  });

  const s = new Substrate();
  load(s, [genesis, grant, m0, m1, m2, reply, revoke]);

  assert.equal(s.replica(M.logId.toString('hex')).linkedTo, 0,
    'M is revoked at pin 0, so only seq 0 survives');
  assert.equal(s.replica(O.logId.toString('hex')).linkedTo, revoke.seq,
    "the owner's own log must not be stranded by the revocation it wrote");
  assert.ok(s.auth.revokes.size > 0, 'and the revocation must still be in force');
  void m2;
});

// --- what the adversarial review found -----------------------------------------------

test('review: a fork below the eviction floor stops the log on every replica', () => {
  // Found by the review, confirmed with a repro, and it is one bug wearing two masks.
  //
  // #recordFork clamps chainTo and orderedTo down to the fork seq — and then
  // #resolveFrontiers resets every frontier to `floor - 1`, two lines later, undoing the
  // clamp whenever eviction had already carried the floor past the contradiction. The
  // other mask: #rebuildAuth trusts anything below the floor without ever asking whether
  // it is above a fork. So a replica that had evicted past a revocation kept honouring it
  // while a fresh replica, holding the same blocks and the same proof, did not.
  const O = identity();
  const M = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);

  const genesis = ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') });
  const early = [];
  for (let i = 0; i < 3; i++) early.push(ow.push({ payload: Buffer.from(`pre ${i}`.padEnd(60, '.')) }));

  // The author signs seq 4 twice. Only the first branch is ever inserted; the second
  // arrives later as a proof, the way a fork found by somebody else reaches us.
  const forkSeq = ow.seq;
  const branchA = ow.push({ payload: Buffer.from('branch A') });
  const branchB = forkBlockAt(O, scopeId, forkSeq, branchA, 'branch B');

  const grant = ow.push({ type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId }) });
  const mBlocks = [0, 1, 2].map((i) => mw.push({ payload: Buffer.from(`m${i}`), authRef: grant.hash }));
  const filler = [];
  for (let i = 0; i < 30; i++) filler.push(ow.push({ payload: Buffer.from(`fill ${i}`.padEnd(60, '.')) }));

  const all = [genesis, ...early, branchA, grant, ...mBlocks, ...filler];
  const each = all[0].cert.length + all[0].payload.length;

  // Replica FRESH holds everything. Replica TIGHT has evicted well past the fork.
  const fresh = new Substrate({ maxBytes: 1 << 30 });
  const tight = new Substrate({ maxBytes: each * 4 });
  load(fresh, all);
  load(tight, all);
  assert.ok(tight.replica(O.logId.toString('hex')).floor > forkSeq,
    'the test is pointless unless eviction carried the floor past the fork');

  for (const s of [fresh, tight]) {
    const got = s.acceptForkProof(branchA.cert, branchB.cert, O.pub);
    assert.equal(got.ok, true, got.reason);
  }

  const key = M.logId.toString('hex');
  assert.equal(fresh.auth.grants.size, 0, 'a grant above a fork is not a grant');
  assert.equal(
    tight.auth.grants.size, fresh.auth.grants.size,
    'and the replica that had evicted past the fork must agree',
  );
  assert.equal(tight.auth.owners.size, fresh.auth.owners.size, 'same for the colony itself');

  // Compared on AUTHORITY rather than on linkedTo. The two replicas ran different byte
  // budgets, so their floors differ, and linkedTo is reset to floor-1 — history already
  // delivered and forgotten stays delivered. Eviction is allowed to make those numbers
  // differ; what it is never allowed to do is make one replica enforce a grant the other
  // has thrown away, which is the bug this test exists for.
  assert.equal(fresh.replica(key).linkedTo, -1, 'nothing M wrote under that grant is delivered');
  const tr = tight.replica(key);
  assert.ok(tr.linkedTo < tr.floor,
    `M is linked to ${tr.linkedTo}, above its own floor ${tr.floor} — that is new delivery`);
});

test('review: a dep evicted before its citer ever arrived still resolves', () => {
  // The review's sharpest finding, and it falsifies a comment I wrote. depLamports was
  // introduced as a fallback for "we answered this once before the evidence went" — true
  // of a citer we already hold, false for one that turns up AFTER the eviction, which
  // never got the chance to answer it. That citer stalls forever on one replica and links
  // on another, from the same blocks, which is the fatal shape.
  const W = identity();
  const X = identity();
  const ww = writer(W, Buffer.alloc(16));
  const xw = writer(X, Buffer.alloc(16));

  const dep = ww.push({ payload: Buffer.from('cite me'.padEnd(60, '.')) });
  const flood = [];
  for (let i = 0; i < 30; i++) flood.push(ww.push({ payload: Buffer.from(`f${i}`.padEnd(60, '.')) }));
  const citer = xw.push({
    payload: Buffer.from('citing'),
    deps: [dep.hash],
    depLamports: [dep.lamport],
  });

  const each = dep.cert.length + dep.payload.length;
  const budget = each * 3;

  // A: the dep is forgotten before the citer is ever seen.
  const a = new Substrate({ maxBytes: budget });
  load(a, [dep, ...flood]);
  load(a, [citer]);

  // B: the citer arrives while the dep is still held, and the flood evicts it afterwards.
  const b = new Substrate({ maxBytes: budget });
  load(b, [dep, citer, ...flood]);

  const key = X.logId.toString('hex');
  assert.equal(a.replica(key).linkedTo, b.replica(key).linkedTo,
    'the same blocks must deliver the same way whichever order they arrived in');
  assert.equal(b.replica(key).linkedTo, 0, 'and the citer is deliverable: its dep was real');
});

test('review: a stranger cannot make a spore rebuild its whole authority on demand', () => {
  // Any block whose WIRE TYPE is a control type forced a full substrate-wide auth rebuild
  // plus a reset-and-rewalk of every frontier — before anything asked whether the author
  // had any authority at all. One free identity, one open hypha, and the cost is O(held)
  // BLAKE2b hashes per forged block. The bound is not a smaller scan, it is refusing to
  // rewalk when nothing actually changed, which only the colony owner can cause.
  const O = identity();
  const X = identity(); // no standing whatsoever
  const scopeId = colonyIdFor(O.logId, 0);
  const ow = writer(O, scopeId);
  const xw = writer(X, scopeId);

  const setup = [ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') })];
  for (let i = 0; i < 40; i++) setup.push(ow.push({ payload: Buffer.from(`real ${i}`) }));

  const tel = {
    n: 0,
    count(name) { if (name === 'substrate.resolved') this.n += 1; },
    gauge() {}, event() {}, rateOf() { return 0; }, get() { return 0; },
  };
  const s = new Substrate({ telemetry: tel, maxBytes: 1 << 30 });
  load(s, setup);

  const after = tel.n;
  for (let i = 0; i < 200; i++) {
    const junk = xw.push({
      type: TYPE.ROLE_REVOKE,
      payload: encodeRevoke({ target: O.logId, pinSeq: 0 }),
    });
    s.insert(junk.cert, junk.payload, X.pub);
  }
  assert.equal(tel.n, after,
    `${tel.n - after} full re-resolutions bought by a stranger writing blocks in their own log`);
  assert.equal(s.replica(O.logId.toString('hex')).linkedTo, 40, 'and the owner is unharmed');
});

// --- re-grant ------------------------------------------------------------------------
//
// GRANT and REVOKE both name a BOUNDARY in the target's log: a grant governs from its pin,
// a revocation from its pin + 1. Whichever has the largest boundary at or below a block's
// seq governs that block, ties going to the later block in the owner's own log. One rule,
// one lookup, and it subsumes the pin scan it replaces.

function colony({ ownerTraffic = 0 } = {}) {
  const O = identity();
  const M = identity();
  const scopeId = colonyIdFor(O.logId, 0);
  const ow = writer(O, scopeId);
  const mw = writer(M, scopeId);
  const blocks = [ow.push({ type: TYPE.COLONY_GENESIS, payload: Buffer.from('colony') })];
  for (let i = 0; i < ownerTraffic; i++) blocks.push(ow.push({ payload: Buffer.from(`o${i}`) }));
  const grant = (pinSeq) => ow.push({
    type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: M.logId, pinSeq }),
  });
  const revoke = (pinSeq) => ow.push({
    type: TYPE.ROLE_REVOKE, payload: encodeRevoke({ target: M.logId, pinSeq }),
  });
  return { O, M, scopeId, ow, mw, blocks, grant, revoke };
}

test('re-grant: an owner can let someone back in, going forward', () => {
  // The member is revoked at pin 2, writes NOTHING while out, and is re-granted from 3.
  // Writing nothing is not a detail of the test, it is the whole shape of the feature —
  // see the next test for why.
  const c = colony();
  const g1 = c.grant(0);
  const early = [0, 1, 2].map(() => c.mw.push({ payload: Buffer.from('before'), authRef: g1.hash }));
  const rev = c.revoke(2);   // boundary 3
  const g2 = c.grant(3);     // boundary 3, written later in the owner's log, so it wins
  const back = [3, 4].map(() => c.mw.push({ payload: Buffer.from('back'), authRef: g2.hash }));

  const s = new Substrate();
  load(s, [...c.blocks, g1, ...early, rev, g2, ...back]);

  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 4,
    'the frontier reaches the blocks written under the new grant');
  assert.equal(early.length, 3);
  assert.equal(back[1].seq, 4);
});

test('re-grant: a member who wrote while revoked is out for good, and that is the chain', () => {
  // The limitation, stated rather than discovered later. linkedTo is a CONTIGUOUS
  // watermark over a single-writer chain, so a block that stops the frontier stops
  // everything above it forever — no later grant can reach past a hole, because a hole in
  // a hash chain is not a thing that can exist.
  //
  // So re-grant lifts a revocation for a member who stayed quiet while out. A member who
  // kept writing has ended their own log at the first block they wrote without authority.
  // Their remedy is a new identity, which is a new log, which is honest: the old log
  // really does contain blocks nobody authorised.
  const c = colony();
  const g1 = c.grant(0);
  const early = [0, 1, 2].map(() => c.mw.push({ payload: Buffer.from('before'), authRef: g1.hash }));
  const rev = c.revoke(2);
  const defiant = c.mw.push({ payload: Buffer.from('anyway'), authRef: g1.hash }); // seq 3
  const g2 = c.grant(4);
  const after = c.mw.push({ payload: Buffer.from('forgiven?'), authRef: g2.hash }); // seq 4

  const s = new Substrate();
  load(s, [...c.blocks, g1, ...early, rev, defiant, g2, after]);

  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 2,
    'the log still ends at the block written without authority');
  assert.equal(defiant.seq, 3);
  assert.equal(after.seq, 4);
  assert.equal(early.length, 3);
});

test('re-grant: a pin of 0 after a revocation does NOT bless the replay', () => {
  // The security property, and the reason the boundary rule is one lookup rather than two
  // rules. An owner who revoked at k and then re-grants from 0 has blessed nothing above k:
  // the revocation's boundary k+1 is still the largest one at or below k+1, so it still
  // governs and still stops. Lifting the stop has to be said out loud, with a pin >= k+1.
  const w = v1World();
  const forgiving = w.ow.push({
    type: TYPE.ROLE_GRANT, payload: encodeGrant({ target: w.M.logId, pinSeq: 0 }),
  });

  const s = new Substrate();
  load(s, [w.genesis, w.grant, ...w.mBefore, ...w.traffic, w.revoke, forgiving, w.replay]);

  assert.equal(s.replica(w.M.logId.toString('hex')).linkedTo, w.pinSeq,
    'the replayed block is still stopped; a sweeping re-grant is not a pardon for it');
});

test('re-grant: an older grant still in force is fine; a superseded one is not', () => {
  // auth_ref names the authority a block acts under, and the check is whether that
  // authority REACHES this block — covering the seq, and not cut off by a revocation that
  // reaches it too. It is deliberately not "cite the newest grant": an owner writing a
  // second, broader grant would then retroactively invalidate everything delivered under
  // the first, and an owner being generous must not break the past.
  const c = colony();
  const g1 = c.grant(0);
  const underOld = [0, 1].map(() => c.mw.push({ payload: Buffer.from('fine'), authRef: g1.hash }));
  const g2 = c.grant(2);
  const stillOld = c.mw.push({ payload: Buffer.from('old papers'), authRef: g1.hash }); // seq 2

  const s = new Substrate();
  load(s, [...c.blocks, g1, ...underOld, g2, stillOld]);
  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 2,
    'g1 was never revoked, so it still authorises');

  // Now the same shape with a revocation in between — that one does cut it off.
  const c2 = colony();
  const h1 = c2.grant(0);
  const ok2 = [0, 1].map(() => c2.mw.push({ payload: Buffer.from('fine'), authRef: h1.hash }));
  const cut = c2.revoke(1);   // boundary 2, later in the owner's log than h1
  const stale = c2.mw.push({ payload: Buffer.from('stale'), authRef: h1.hash }); // seq 2

  const s2 = new Substrate();
  load(s2, [...c2.blocks, h1, ...ok2, cut, stale]);
  assert.equal(s2.replica(c2.M.logId.toString('hex')).linkedTo, 1,
    'the revocation superseded the grant this block cites');
  assert.equal(stale.seq, 2);
});

test('re-grant: nothing is authorised in a range the owner has not spoken about', () => {
  // A member writing under a grant that begins at seq 4 has said nothing about seqs 0-3.
  // That is a STALL, not a STOP: the owner may yet speak, and deciding against them now
  // would make the answer depend on what has arrived rather than on what is true.
  const c = colony();
  const g = c.grant(4);
  const tooEarly = c.mw.push({ payload: Buffer.from('jumping the gun'), authRef: g.hash });

  const s = new Substrate();
  load(s, [...c.blocks, g, tooEarly]);

  const mr = s.replica(c.M.logId.toString('hex'));
  assert.equal(mr.linkedTo, -1, 'nothing links');
  assert.ok(mr.pendingDeps, 'and it is recorded as waiting, not as decided against');
});

test('re-grant: a restored member must cite the new grant, not the revoked one', () => {
  // The case that falsification found missing. Governing alone does not catch it: after
  // revoke-then-re-grant the entry governing the member's next seq is the NEW grant, so
  // the block is in an authorised range — but it cites the grant the revocation cut off.
  //
  // If that were allowed, a revocation would mean nothing to anyone who kept a copy of the
  // old grant's hash, which is everyone: it is a block, it replicates. Being let back in
  // has to be acted on under the authority that let you back in.
  const c = colony();
  const g1 = c.grant(0);
  const before = [0, 1].map(() => c.mw.push({ payload: Buffer.from('ok'), authRef: g1.hash }));
  const rev = c.revoke(1);   // boundary 2, ownerSeq after g1
  const g2 = c.grant(2);     // boundary 2, ownerSeq after the revocation — back in from 2
  const stale = c.mw.push({ payload: Buffer.from('old papers'), authRef: g1.hash }); // seq 2

  const s = new Substrate();
  load(s, [...c.blocks, g1, ...before, rev, g2, stale]);
  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 1,
    'seq 2 is inside the re-granted range, but it cites the grant that was revoked');

  // The same block, citing the new grant, is fine.
  const d = colony();
  const h1 = d.grant(0);
  const okBefore = [0, 1].map(() => d.mw.push({ payload: Buffer.from('ok'), authRef: h1.hash }));
  const cut = d.revoke(1);
  const h2 = d.grant(2);
  const proper = d.mw.push({ payload: Buffer.from('new papers'), authRef: h2.hash });

  const s2 = new Substrate();
  load(s2, [...d.blocks, h1, ...okBefore, cut, h2, proper]);
  assert.equal(s2.replica(d.M.logId.toString('hex')).linkedTo, 2, 'restored, and acting like it');
  assert.equal(proper.seq, 2);
  assert.equal(okBefore.length, 2);
  assert.ok(stale.seq === 2 && rev.seq < g2.seq);
});

// ---------------------------------------------------------------------------------------
// Review round 2 found these. One root cause, three directions, and it is the bug the
// re-grant commit itself introduced: #authCheck answers "which statement governs this seq"
// by BOUNDARY, then answers "was the cited grant superseded" by OWNER-LOG WRITE ORDER.
// R6 says there is exactly one rule so that the two can never disagree. They disagreed.
//
// The reason no existing test caught it, and the reason the property fuzzer could not:
// test/property.test.js always emits the revocation BEFORE the optional re-grant, so
// ownerSeq(revoke) < ownerSeq(grant) in every run it can generate. Boundary order and
// owner-log order therefore never diverge there, and divergence is what both bugs need.
// More seeds would not have found this. A different generator would.
// ---------------------------------------------------------------------------------------

test('re-grant: a revocation that reaches lower than the grant does not supersede it', () => {
  // FALSE STOP. The owner grants from seq 5, then writes a revocation pinned at 1 — later
  // in their own log, but reaching a range that ENDS before the grant's range begins. The
  // two statements do not overlap at all, so the revocation has nothing to say about seq 5.
  //
  // Ordering by write position alone says "the revoke is the owner's newer word, so it
  // wins". That is the wrong question: newer about WHAT? A revocation is a statement about
  // a range, and this one's range stops at seq 1.
  const c = colony();
  const g1 = c.grant(5);    // boundary 5,  ownerSeq 1
  const rev = c.revoke(1);  // boundary 2,  ownerSeq 2 — written later, reaches lower
  const early = [0, 1, 2, 3, 4].map((i) => c.mw.push({ payload: Buffer.from(`q${i}`) }));
  const under = c.mw.push({ payload: Buffer.from('granted from five'), authRef: g1.hash });

  const s = new Substrate();
  load(s, [...c.blocks, g1, rev, ...early, under]);

  assert.equal(under.seq, 5, 'the block sits exactly at the grant boundary');
  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 5,
    'the grant governs seq 5 and no revocation reaches it; the block must deliver');
  assert.equal(early.length, 5);
});

test('re-grant: a grant the owner cut off cannot be cited, even if written after the cut', () => {
  // FALSE OK, the mirror image. The owner revokes first (boundary 3), THEN writes a grant
  // pinned at 0 — a grant that is newer in the log but whose range was already carved out
  // by the revocation above it — and finally the real restoring grant at boundary 4.
  //
  // A member citing that middle grant at seq 4 is citing authority the owner's own
  // revocation had already withdrawn. Comparing write order lets it through, because the
  // revocation was written FIRST and so has the lower ownerSeq.
  const c = colony();
  const rev = c.revoke(2);  // boundary 3,  ownerSeq 1 — written first
  const g1 = c.grant(0);    // boundary 0,  ownerSeq 2 — newer in the log, older in range
  const g2 = c.grant(4);    // boundary 4,  ownerSeq 3 — the actual restoring grant
  const early = [0, 1, 2, 3].map((i) => c.mw.push({ payload: Buffer.from(`e${i}`) }));
  const stale = c.mw.push({ payload: Buffer.from('old papers'), authRef: g1.hash });

  const s = new Substrate();
  load(s, [...c.blocks, rev, g1, g2, ...early, stale]);

  assert.equal(stale.seq, 4, 'seq 4 is governed by g2, the restoring grant');
  assert.equal(s.replica(c.M.logId.toString('hex')).linkedTo, 3,
    'but it cites g1, which the revocation cut off — a revocation must not be citable past');
  assert.notEqual(g2.hash.toString('hex'), g1.hash.toString('hex'));
});

test('re-grant: a spent revocation does not reach forward past the grants that replaced it', () => {
  // The layered case, and the one with real teeth: FOUR overlapping statements where
  // boundary order and owner-log order disagree in the middle.
  //
  //   g0      boundary 0   ownerSeq 1     covers the member from the start
  //   gFuture boundary 10  ownerSeq 2     covers seq 10 onward
  //   rEarly  boundary 3   ownerSeq 3     cuts at seq 3 — and is itself replaced below
  //   gMid    boundary 3   ownerSeq 4     restores at seq 3, same boundary, later word
  //
  // rEarly has the second-highest ownerSeq of the lot, so under write-order comparison it
  // supersedes gFuture — a grant whose range starts seven seqs ABOVE where rEarly's ends,
  // and which rEarly could not possibly have been speaking about. The member's entire log
  // from seq 10 up is stranded permanently, on every replica, deterministically.
  const c = colony();
  const g0 = c.grant(0);
  const gFuture = c.grant(10);
  const rEarly = c.revoke(2);  // boundary 3
  const gMid = c.grant(3);     // boundary 3, later in the owner's log — so it wins the tie

  const m = [];
  for (let i = 0; i < 3; i++) m.push(c.mw.push({ payload: Buffer.from(`a${i}`), authRef: g0.hash }));
  for (let i = 3; i < 10; i++) m.push(c.mw.push({ payload: Buffer.from(`b${i}`), authRef: gMid.hash }));
  for (let i = 10; i < 16; i++) m.push(c.mw.push({ payload: Buffer.from(`c${i}`), authRef: gFuture.hash }));

  const s = new Substrate();
  load(s, [...c.blocks, g0, gFuture, rEarly, gMid, ...m]);

  const mr = s.replica(c.M.logId.toString('hex'));
  assert.equal(m[m.length - 1].seq, 15);
  assert.equal(mr.chainTo, 15, 'the chain itself is intact — this is purely an authority question');
  assert.equal(mr.linkedTo, 15,
    'a revocation spent at seq 3 has nothing to say about a grant that begins at seq 10');
});

test('review: an eviction floor cannot outrank a revocation boundary', () => {
  // R4e says the floor can never outrank a FORK — #recordFork brings it down with the
  // contradiction, because a fork means nothing at or above it can be chain-verified. The
  // same sentence is true of a revocation and was never written, so:
  //
  //   Order A  member's blocks link under the grant, the budget evicts them, floor climbs
  //            past the revocation's boundary, THEN the revocation arrives. #resolveFrontiers
  //            resets every frontier to floor - 1 — but floor is already above the boundary,
  //            so the rewalk begins above everything the revocation was about and nothing
  //            revoked is ever re-examined.
  //   Order B  authority resolves first, the walk hits the boundary honestly, frontier stops.
  //
  // Same blocks, same revocation held by both (AUTHORITY is KEEP_FOREVER, so neither can
  // evict it), permanently different answers. That is the one thing this substrate exists
  // to rule out.
  //
  // The existing property harness cannot see this: it skips the cross-replica snapshot
  // comparison whenever the budget is tight (test/property.test.js, `if (tight) continue`),
  // which is the only condition under which the floor can climb past a boundary at all.
  const build = () => {
    const c = colony();
    const g = c.grant(0);
    const m = [];
    for (let i = 0; i < 10; i++) m.push(c.mw.push({ payload: Buffer.from(`m${i}`), authRef: g.hash }));
    const rev = c.revoke(3); // boundary 4 — seq 3 is the last seq it leaves alone
    return { c, g, m, rev };
  };

  const width = build().m[0].cert.length + 8;

  // A: the member is delivered and evicted before the owner's word ever shows up.
  const a = build();
  const sa = new Substrate({ maxBytes: width * 3 });
  load(sa, [...a.m, ...a.c.blocks, a.g, a.rev]);

  // B: the owner's word arrives first.
  const b = build();
  const sb = new Substrate({ maxBytes: width * 3 });
  load(sb, [...b.c.blocks, b.g, b.rev, ...b.m]);

  const la = sa.replica(a.c.M.logId.toString('hex')).linkedTo;
  const lb = sb.replica(b.c.M.logId.toString('hex')).linkedTo;

  assert.equal(la, lb,
    `arrival order decided the frontier: ${la} when the revocation arrived last, ${lb} when it arrived first`);
  assert.equal(la, 3, 'and the honest answer is the revocation boundary minus one');
});

test('review: clamping the floor to a revocation costs ordering — characterised, not desired', () => {
  // THIS TEST ASSERTS CURRENT BEHAVIOUR, NOT CORRECT BEHAVIOUR. It exists so the cost is a
  // fact in the suite rather than a paragraph someone has to find, and so that anyone who
  // fixes it gets a failure pointing straight at ARCHITECTURE.md R7.
  //
  // The floor governs chain-verification and ORDERING as well as delivery. Bringing it down
  // to a revocation boundary is therefore a bigger hammer than the problem: seq 9 below is
  // held and chain-verified, and stops being orderable purely because the blocks between it
  // and the lowered floor were already evicted. Other logs' deps resolve against orderedTo,
  // so a log that did nothing wrong can stall on this.
  //
  // The obvious alternative was built and rejected: bounding linkedTo alone drives it below
  // floor - 1, and forgetOldest iterates [floor, linkedTo), so a revoked log stops being
  // evictable at all. Two rules genuinely conflict once the floor climbs past a boundary,
  // and the real fix is a deterministic eviction floor — an SP2 storage question, not a
  // patch to #resolveFrontiers.
  const c = colony();
  const g = c.grant(0);
  const m = [];
  for (let i = 0; i < 10; i++) m.push(c.mw.push({ payload: Buffer.from(`m${i}`), authRef: g.hash }));
  const rev = c.revoke(3); // boundary 4

  const width = m[0].cert.length + 8;
  const s = new Substrate({ maxBytes: width * 3 });
  load(s, [...m, ...c.blocks, g, rev]);

  const r = s.replica(c.M.logId.toString('hex'));
  assert.equal(r.linkedTo, 3, 'delivery is correct: the revocation boundary minus one');
  assert.ok(r.blocks.has(9), 'seq 9 is still held');
  assert.equal(r.chainTo, 9, 'and still chain-verified');
  assert.equal(r.orderedTo, 3,
    'but not orderable — THE COST. If this now reads 9, the ordering problem has been '
    + 'fixed and ARCHITECTURE.md R7 should lose its residual paragraph.');
});
