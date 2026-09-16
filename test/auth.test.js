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
  encodeGrant, decodeGrant, encodeRevoke, decodeRevoke,
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
    push({ type = TYPE.MESSAGE, payload = Buffer.alloc(0), authRef = null, deps = [], depLamports = [] } = {}) {
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
          scopeId,
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
  const scopeId = Buffer.alloc(16, 0xc0);
  const O = identity();
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
  const scopeId = Buffer.alloc(16, 0xc0);
  const O = identity();
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
  const scopeId = Buffer.alloc(16, 0xc0);
  const O = identity();
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
  const scopeId = Buffer.alloc(16, 0xc0);
  const O = identity();
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
  const scopeId = Buffer.alloc(16, 0xc0);
  const O = identity();
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
