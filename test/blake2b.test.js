import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { Blake2b, blake2b256, blake2b, BLOCK_BYTES } from '../src/substrate/blake2b.js';

// Oracle test. Node's native blake2b512 is a trusted implementation; if ours agrees with
// it at nn=64 across every awkward input shape, the compression function, block handling,
// counter and finalization are all correct. nn=32 is the same machinery with one changed
// parameter word, so agreement at 64 is what earns trust at 256.
test('blake2b: matches Node native blake2b512 byte-for-byte', () => {
  const native = (b) => createHash('blake2b512').update(b).digest();
  const ours = (b) => blake2b(64, b);

  // empty, and every length around the 128-byte block boundary where off-by-ones live
  const lengths = [
    0, 1, 2, 63, 64, 65, 127, 128, 129, 130, 255, 256, 257, 383, 384, 385, 1000, 4096,
  ];
  for (const n of lengths) {
    const b = randomBytes(n);
    assert.ok(ours(b).equals(native(b)), `mismatch at length ${n}`);
  }

  // fuzz
  for (let i = 0; i < 200; i++) {
    const b = randomBytes(Math.floor(Math.random() * 600));
    assert.ok(ours(b).equals(native(b)), `fuzz mismatch at length ${b.length}`);
  }

  // streaming in arbitrary chunks must equal hashing in one go
  for (const total of [200, 300, 1000]) {
    const b = randomBytes(total);
    const h = new Blake2b(64);
    let off = 0;
    while (off < b.length) {
      const take = 1 + Math.floor(Math.random() * 97);
      h.update(b.subarray(off, off + take));
      off += take;
    }
    assert.ok(h.digest().equals(native(b)), `streaming mismatch at ${total}`);
  }
});

test('blake2b: reproduces the published BLAKE2b-256 vectors', () => {
  // These are the values truncation gets WRONG, which is the entire reason this file exists.
  assert.equal(
    blake2b256(Buffer.alloc(0)).toString('hex'),
    '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
    'BLAKE2b-256 of the empty string',
  );
  assert.equal(
    blake2b256(Buffer.from('abc')).toString('hex'),
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319',
    'BLAKE2b-256 of "abc"',
  );
});

test('blake2b: real 256 differs from truncated 512 — the bug this replaces', () => {
  for (const s of ['', 'abc', 'the mycelium remembers']) {
    const b = Buffer.from(s);
    const real = blake2b256(b);
    const truncated = createHash('blake2b512').update(b).digest().subarray(0, 32);
    assert.equal(real.length, 32);
    assert.ok(
      !real.equals(truncated),
      `real BLAKE2b-256 must differ from truncated-512 for ${JSON.stringify(s)} — if these `
      + 'ever match, the digest length is not reaching the IV and parameterization is broken',
    );
  }
});

test('blake2b: digest length is parameterized, guarded, and single-use', () => {
  for (const n of [1, 16, 20, 32, 48, 64]) assert.equal(blake2b(n, Buffer.from('x')).length, n);

  // differing only in requested length must produce unrelated output, not a prefix
  const a = blake2b(32, Buffer.from('same input'));
  const b = blake2b(64, Buffer.from('same input'));
  assert.ok(!b.subarray(0, 32).equals(a), 'shorter digest must not be a prefix of the longer');

  assert.throws(() => new Blake2b(0));
  assert.throws(() => new Blake2b(65));
  assert.throws(() => new Blake2b(32, randomBytes(65)));

  const h = new Blake2b(32);
  h.update(Buffer.from('once'));
  h.digest();
  assert.throws(() => h.digest(), /finalized/);
  assert.throws(() => h.update(Buffer.from('more')), /finalized/);
});

test('blake2b: throughput is adequate for block certs', () => {
  const cert = randomBytes(260); // a real zero-dep block certificate
  const t0 = process.hrtime.bigint();
  const N = 2000;
  for (let i = 0; i < N; i++) blake2b256(cert);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const perSec = Math.round(N / (ms / 1000));
  console.log(`      blake2b256: ${perSec.toLocaleString()} certs/sec (${(ms / N).toFixed(3)} ms each)`);
  assert.ok(perSec > 2000, `too slow for the substrate: ${perSec}/sec`);
});
