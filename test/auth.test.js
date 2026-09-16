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
  encodeBlock, logIdFor, TYPE, FLAG,
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
  const g = encodeGrant({ target, roleId: 9 });
  const r = encodeRevoke({ target, pinSeq: 2n ** 40n, roleId: 3 });
  assert.equal(g.length, 20);
  assert.equal(r.length, 28);

  assert.ok(decodeGrant(g).target.equals(target));
  assert.equal(decodeGrant(g).roleId, 9);
  assert.equal(decodeRevoke(r).pinSeq, 2n ** 40n);
  assert.equal(decodeRevoke(r).roleId, 3);

  // A length check is the whole of the parser's defence here, so it is the whole of the
  // test: a revoke read as a grant would silently take pin_seq's low bytes as a role id.
  assert.throws(() => decodeRevoke(g), /revoke payload 20/);
  assert.throws(() => decodeGrant(r), /grant payload 28/);
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

test('a frontier survives a recomputation that happens after eviction', () => {
  // relink() resets to `floor - 1` and walks up, so the first block it looks at needs the
  // hash and lamport of its predecessor — which eviction has just deleted. Nothing
  // exercised that before, because a full recomputation only ran on a fork and the
  // eviction tests never forked. Authority made recomputation common.
  const w = v1World({ ownerTraffic: 30 });
  const all = [w.genesis, w.grant, ...w.mBefore, ...w.traffic, w.revoke];
  const each = all[0].cert.length + all[0].payload.length;

  const s = new Substrate({ maxBytes: each * 8 });
  load(s, all);
  const or = s.replica(w.O.logId.toString('hex'));
  const before = or.linkedTo;
  assert.ok(or.floor > 0, 'the test is pointless unless eviction actually ran');

  // Any control block linking re-resolves every frontier from the floor up.
  load(s, [w.replay]);
  assert.equal(s.replica(w.O.logId.toString('hex')).linkedTo, before,
    "the owner's frontier must not collapse just because old history was forgotten");
});

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
