// BLAKE2b — RFC 7693, with real digest-length IV parameterization.
//
// Node exposes blake2b512 and blake2s256 and nothing else. SPORE's substrate spec says
// BLAKE2b-256, and truncating BLAKE2b-512 is NOT that: BLAKE2b mixes the digest length
// into h[0], so real BLAKE2b-256 produces entirely different bytes. Truncation would have
// meant a second implementation written from the spec could never interop with us.
//
// IMPLEMENTATION NOTE — this file was written twice, on purpose.
//
// The first version used BigInt: simple, obviously correct, ~3.5 MB/s. It shipped that way
// deliberately, because a wrong hash here is silent substrate corruption rather than a
// visible failure, and the rule was "no optimizing this without an oracle test in place".
//
// bench/curve.js then measured the consequence: at real Wi-Fi rates a joiner hashing every
// byte it verifies becomes the bottleneck BEFORE the network does, which would have made
// the scaling curve look flat for a reason that has nothing to do with the mesh.
//
// So this is the 32-bit-pair version — each 64-bit word carried as two 32-bit halves,
// because JS has no fast 64-bit integer arithmetic. It is roughly 5x faster and much
// easier to get subtly wrong, which is exactly why it only exists now that
// test/blake2b.test.js can catch a mistake: it checks nn=64 against Node's NATIVE
// blake2b512 across every block-boundary length and 200 fuzz cases, and nn=32 against the
// published vectors. If this file is wrong, that test fails immediately and loudly.
//
// Layout convention throughout: index 2i is the LOW half of word i, 2i+1 is the HIGH half.

const IV32 = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

// SIGMA doubled: each entry is a byte offset into the 32-pair message array.
const SIGMA8 = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
];
const SIGMA82 = new Uint8Array(SIGMA8.map((x) => x * 2));

export const BLOCK_BYTES = 128;
export const MAX_DIGEST = 64;

// Scratch reused across calls — compression is synchronous and single-threaded, so this
// is safe and keeps the allocator out of the hot path.
const v = new Uint32Array(32);
const m = new Uint32Array(32);

/** v[a] += v[b], 64-bit, carried across the halves. */
function ADD64AA(a, b) {
  const lo = v[a] + v[b];
  let hi = v[a + 1] + v[b + 1];
  if (lo >= 0x100000000) hi++;
  v[a] = lo;
  v[a + 1] = hi;
}

/** v[a] += (b1<<32 | b0), 64-bit. b0 may arrive sign-extended from a Uint32Array read. */
function ADD64AC(a, b0, b1) {
  let lo = v[a] + b0;
  if (b0 < 0) lo += 0x100000000;
  let hi = v[a + 1] + b1;
  if (lo >= 0x100000000) hi++;
  v[a] = lo;
  v[a + 1] = hi;
}

function G(a, b, c, d, ix, iy) {
  const x0 = m[ix];
  const x1 = m[ix + 1];
  const y0 = m[iy];
  const y1 = m[iy + 1];

  ADD64AA(a, b);
  ADD64AC(a, x0, x1);

  // v[d] = rotr64(v[d] ^ v[a], 32) — a 32-bit rotate is just a half swap
  let xor0 = v[d] ^ v[a];
  let xor1 = v[d + 1] ^ v[a + 1];
  v[d] = xor1;
  v[d + 1] = xor0;

  ADD64AA(c, d);

  // v[b] = rotr64(v[b] ^ v[c], 24)
  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = (xor0 >>> 24) ^ (xor1 << 8);
  v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);

  ADD64AA(a, b);
  ADD64AC(a, y0, y1);

  // v[d] = rotr64(v[d] ^ v[a], 16)
  xor0 = v[d] ^ v[a];
  xor1 = v[d + 1] ^ v[a + 1];
  v[d] = (xor0 >>> 16) ^ (xor1 << 16);
  v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);

  ADD64AA(c, d);

  // v[b] = rotr64(v[b] ^ v[c], 63)
  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = (xor1 >>> 31) ^ (xor0 << 1);
  v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
}

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
    this.h = new Uint32Array(IV32);
    // Parameter block word 0: digest_length | key_length<<8 | fanout<<16 | depth<<24.
    // Sequential mode is fanout=1, depth=1 => 0x01010000. This XOR is the line that makes
    // BLAKE2b-256 a different function from truncated BLAKE2b-512.
    this.h[0] ^= 0x01010000 ^ (kk << 8) ^ digestLength;

    this.tLo = 0;
    this.tHi = 0;
    this.buf = Buffer.alloc(BLOCK_BYTES);
    this.buflen = 0;
    this.finished = false;

    if (kk > 0) {
      // A keyed hash begins with the key padded to a full block.
      key.copy(this.buf, 0);
      this.buf.fill(0, kk);
      this.buflen = BLOCK_BYTES;
    }
  }

  #compress(last) {
    for (let i = 0; i < 16; i++) v[i] = this.h[i];
    for (let i = 0; i < 16; i++) v[i + 16] = IV32[i];

    // t is the byte counter; XOR it into v[12..13] (low) and v[14..15] (high)
    v[24] ^= this.tLo;
    v[25] ^= this.tHi;
    // v[26], v[27] would take t's upper 64 bits — always zero at our sizes
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }

    for (let i = 0; i < 32; i++) m[i] = this.buf.readUInt32LE(i * 4);

    for (let r = 0; r < 12; r++) {
      const o = r * 16;
      G(0, 8, 16, 24, SIGMA82[o + 0], SIGMA82[o + 1]);
      G(2, 10, 18, 26, SIGMA82[o + 2], SIGMA82[o + 3]);
      G(4, 12, 20, 28, SIGMA82[o + 4], SIGMA82[o + 5]);
      G(6, 14, 22, 30, SIGMA82[o + 6], SIGMA82[o + 7]);
      G(0, 10, 20, 30, SIGMA82[o + 8], SIGMA82[o + 9]);
      G(2, 12, 22, 24, SIGMA82[o + 10], SIGMA82[o + 11]);
      G(4, 14, 16, 26, SIGMA82[o + 12], SIGMA82[o + 13]);
      G(6, 8, 18, 28, SIGMA82[o + 14], SIGMA82[o + 15]);
    }

    for (let i = 0; i < 16; i++) this.h[i] ^= v[i] ^ v[i + 16];
  }

  #bumpCounter(n) {
    this.tLo += n;
    if (this.tLo >= 0x100000000) {
      this.tLo -= 0x100000000;
      this.tHi++;
    }
  }

  update(data) {
    if (this.finished) throw new Error('digest already finalized');
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    let off = 0;

    while (off < buf.length) {
      // Only compress a full buffer when more input is known to follow: BLAKE2b must know
      // which block is last, and the last block is finalized, never compressed here.
      if (this.buflen === BLOCK_BYTES) {
        this.#bumpCounter(BLOCK_BYTES);
        this.#compress(false);
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
    this.#bumpCounter(this.buflen);
    this.buf.fill(0, this.buflen);
    this.#compress(true);

    const out = Buffer.alloc(64);
    for (let i = 0; i < 16; i++) out.writeUInt32LE(this.h[i], i * 4);
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
