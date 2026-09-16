// BLAKE2b — RFC 7693, with real digest-length IV parameterization.
//
// Node exposes blake2b512 and blake2s256 and nothing else. SPORE's substrate spec says
// BLAKE2b-256, and truncating BLAKE2b-512 is NOT that: BLAKE2b mixes the digest length
// into h[0], so real BLAKE2b-256 produces entirely different bytes. Truncation would have
// meant a second implementation written from the spec could never interop with us.
//
// So this is the real thing. Every block hash in the system depends on it, which makes a
// subtle bug here silent substrate corruption rather than a visible failure — so it is
// validated two ways in test/blake2b.test.js:
//
//   1. At nn=64 it must match Node's NATIVE blake2b512 byte-for-byte over hundreds of
//      random inputs and every awkward length around the 128-byte block boundary. Node's
//      implementation is the oracle; if we agree with it at 64 the machinery is right.
//   2. At nn=32 it must reproduce the published BLAKE2b-256 vectors.
//
// Implemented on BigInt. Deliberately: the 32-bit-pair decomposition is roughly 5x faster
// and vastly easier to get subtly wrong, and a wrong hash here is unrecoverable. Measured
// throughput is in the test output; block certs are 260 bytes, so this is not the hot path
// it looks like. Revisit only with the oracle test in place to catch a bad optimization.

const MASK = (1n << 64n) - 1n;

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const add = (a, b) => (a + b) & MASK;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK;

export const BLOCK_BYTES = 128;
export const MAX_DIGEST = 64;

export class Blake2b {
  /**
   * @param {number} digestLength 1..64 — mixed into h[0], which is the whole point
   * @param {Buffer|null} key optional MAC key, up to 64 bytes
   */
  constructor(digestLength = 32, key = null) {
    if (!Number.isInteger(digestLength) || digestLength < 1 || digestLength > MAX_DIGEST) {
      throw new Error(`digestLength must be 1..64, got ${digestLength}`);
    }
    const kk = key ? key.length : 0;
    if (kk > 64) throw new Error('key must be <= 64 bytes');

    this.nn = digestLength;
    this.h = IV.slice();
    // Parameter block word 0: digest_length | key_length<<8 | fanout<<16 | depth<<24.
    // Sequential mode is fanout=1, depth=1 => 0x01010000.
    this.h[0] ^= BigInt(0x01010000 ^ (kk << 8) ^ digestLength);

    this.t = 0n;            // bytes compressed so far
    this.buf = Buffer.alloc(BLOCK_BYTES);
    this.buflen = 0;
    this.finished = false;

    if (kk > 0) {
      // A keyed hash begins with the key padded to a full block.
      const block = Buffer.alloc(BLOCK_BYTES);
      key.copy(block, 0);
      block.copy(this.buf, 0);
      this.buflen = BLOCK_BYTES;
    }
  }

  #compress(block, offset, last) {
    const m = new Array(16);
    for (let i = 0; i < 16; i++) m[i] = block.readBigUInt64LE(offset + i * 8);

    const v = new Array(16);
    for (let i = 0; i < 8; i++) v[i] = this.h[i];
    for (let i = 0; i < 8; i++) v[i + 8] = IV[i];

    v[12] ^= this.t & MASK;
    v[13] ^= (this.t >> 64n) & MASK;
    if (last) v[14] ^= MASK;

    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r];
      // G applied to columns, then diagonals
      const G = (a, b, c, d, x, y) => {
        v[a] = add(add(v[a], v[b]), x);
        v[d] = rotr(v[d] ^ v[a], 32n);
        v[c] = add(v[c], v[d]);
        v[b] = rotr(v[b] ^ v[c], 24n);
        v[a] = add(add(v[a], v[b]), y);
        v[d] = rotr(v[d] ^ v[a], 16n);
        v[c] = add(v[c], v[d]);
        v[b] = rotr(v[b] ^ v[c], 63n);
      };
      G(0, 4, 8, 12, m[s[0]], m[s[1]]);
      G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]);
      G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]);
      G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]);
      G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (let i = 0; i < 8; i++) this.h[i] ^= v[i] ^ v[i + 8];
  }

  update(data) {
    if (this.finished) throw new Error('digest already finalized');
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    let off = 0;

    while (off < buf.length) {
      // Only compress a full buffer when more input is known to follow: BLAKE2b must
      // know which block is last, and the last block is finalized, never compressed here.
      if (this.buflen === BLOCK_BYTES) {
        this.t += BigInt(BLOCK_BYTES);
        this.#compress(this.buf, 0, false);
        this.buflen = 0;
      }
      const take = Math.min(BLOCK_BYTES - this.buflen, buf.length - off);
      buf.copy(this.buf, this.buflen, off, off + take);
      this.buflen += take;
      off += take;
    }
    return this;
  }

  digest() {
    if (this.finished) throw new Error('digest already finalized');
    this.finished = true;
    this.t += BigInt(this.buflen);
    this.buf.fill(0, this.buflen);
    this.#compress(this.buf, 0, true);

    const out = Buffer.alloc(64);
    for (let i = 0; i < 8; i++) out.writeBigUInt64LE(this.h[i], i * 8);
    return out.subarray(0, this.nn);
  }
}

/** BLAKE2b-256 over the concatenation of its arguments. The substrate's hash. */
export function blake2b256(...parts) {
  const h = new Blake2b(32);
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Arbitrary digest length, for the few places that want something other than 256. */
export function blake2b(digestLength, ...parts) {
  const h = new Blake2b(digestLength);
  for (const p of parts) h.update(p);
  return h.digest();
}
