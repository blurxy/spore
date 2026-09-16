import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  encodeBlock, decodeBlock, verifyBlock, order, deriveLamport, newLogId,
  TYPE, FLAG, HEADER_LEN, SIG_LEN,
} from '../src/substrate/block.js';

test('block: hash chain verifies, tampering is caught, wall clock is never recorded', () => {
  const kp = generateKeyPairSync('ed25519');
  const logId = newLogId();
  const payload = Buffer.from('mycelium remembers');

  const { cert, blockHash } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId, seq: 1, lamport: 2, payload },
    kp.privateKey,
  );

  assert.equal(cert.length, HEADER_LEN + SIG_LEN, 'zero-dep cert is 260 bytes');
  assert.equal(blockHash.length, 32);

  const good = verifyBlock(cert, kp.publicKey, payload);
  assert.ok(good.ok, `expected valid, got ${good.reason}`);
  assert.equal(good.block.type, TYPE.MESSAGE);
  assert.equal(good.block.seq, 1n);
  assert.equal(good.block.lamport, 2n);

  // wall_ms at offset 36 must be zero: off-web has no NTP, so nothing may depend on clocks
  assert.equal(cert.readBigUInt64LE(36), 0n, 'wall_ms must never be populated');

  // a flipped bit anywhere in the signed region must fail
  const tampered = Buffer.from(cert);
  tampered[100] ^= 0xff;
  assert.equal(verifyBlock(tampered, kp.publicKey, payload).ok, false);

  // signature covers payload_hash, so a substituted payload is caught
  assert.equal(
    verifyBlock(cert, kp.publicKey, Buffer.from('lies')).reason,
    'payload_len_mismatch',
  );
  const sameLen = Buffer.from('mycelium forgets..').subarray(0, payload.length);
  assert.equal(verifyBlock(cert, kp.publicKey, sameLen).reason, 'payload_hash_mismatch');

  // a different key must not verify
  const other = generateKeyPairSync('ed25519');
  assert.equal(verifyBlock(cert, other.publicKey, payload).ok, false);

  // deps round-trip and change the cert length predictably
  const deps = [Buffer.alloc(32, 7), Buffer.alloc(32, 9)];
  const withDeps = encodeBlock(
    { type: TYPE.MESSAGE, logId, seq: 2, lamport: 3, payload, deps },
    kp.privateKey,
  );
  assert.equal(withDeps.cert.length, HEADER_LEN + 2 * 32 + SIG_LEN);
  const d = decodeBlock(withDeps.cert);
  assert.equal(d.depCount, 2);
  assert.ok(d.deps[1].equals(deps[1]));
  assert.ok(verifyBlock(withDeps.cert, kp.publicKey, payload).ok);
});

test('block: ORDER is a total order and lamport is derived, not asserted', () => {
  const mk = (l, lid, s) => ({ lamport: BigInt(l), logId: Buffer.alloc(16, lid), seq: BigInt(s) });

  // lamport dominates, then log_id lexicographically, then seq
  const sorted = [mk(2, 2, 1), mk(1, 9, 1), mk(2, 1, 5), mk(2, 1, 2)].sort(order);
  assert.deepEqual(
    sorted.map((b) => `${b.lamport}:${b.logId[0]}:${b.seq}`),
    ['1:9:1', '2:1:2', '2:1:5', '2:2:1'],
  );

  // total: no two distinct blocks compare equal, and it is antisymmetric
  const all = [mk(1, 1, 1), mk(1, 1, 2), mk(1, 2, 1), mk(2, 1, 1)];
  for (const a of all) {
    for (const b of all) {
      const ab = order(a, b);
      if (a === b) assert.equal(ab, 0);
      else {
        assert.notEqual(ab, 0, 'distinct blocks must never tie');
        assert.equal(Math.sign(ab), -Math.sign(order(b, a)), 'must be antisymmetric');
      }
    }
  }

  // derived lamport: 1 + max(own previous, every dep)
  assert.equal(deriveLamport(5, [9, 3]), 10n);
  assert.equal(deriveLamport(9, []), 10n);
  assert.equal(deriveLamport(0, []), 1n, 'genesis IDENTITY block sits at lamport 1');
});
