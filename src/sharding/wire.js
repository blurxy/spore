// Sync protocol messages. What actually crosses a hypha once it is authenticated.
//
// Every frame is a one-byte type followed by a body. The type byte is INSIDE the AEAD
// sealed region, so an observer on the LAN cannot tell a block request from a block or
// from a HAVE — they see equal-looking ciphertext of similar size. That is not a
// confidentiality claim for SP1 (the payloads inside are plaintext to any colony member
// and the banner says so), it just avoids handing a passive observer free structure.
//
// Seven messages. Five are obvious; NOBLOCK is the one that looks optional and is not,
// and FORK_PROOF is the one that keeps the substrate converging.
//
//   HAVE      here is everything I hold, per log, as a bitfield
//   HAVE_ADD  I have just acquired (log, seq) — cache-on-fetch, announced
//   REQUEST   send me these
//   BLOCK     here is one
//   CANCEL    never mind, somebody beat you (endgame)
//   NOBLOCK   I do not have that after all
//   FORK_PROOF this author signed two different blocks at one seq, and here are both
//
// HAVE_ADD is where swarm supply growth becomes real rather than theoretical. A joiner
// that fetches a block is instantly a source for it, but only if the rest of the swarm
// is told. Without HAVE_ADD, every joiner would keep pulling from the original seeder,
// supply would stay flat at one, and the measured curve would be a straight line.
//
// NOBLOCK exists because the scheduler reserves a block the moment it assigns it. If a
// peer is asked for something it turns out not to have, silence would leave that
// reservation standing until a timeout, and under `plan()`'s documented contract a
// stranded reservation blocks that index from ever being requested again. An explicit
// "no" releases it in one round trip instead of one timeout.
//
// FORK_PROOF carries the two certificates an author signed at the same seq. Without it, a
// spore that only ever meets one branch keeps a longer linked frontier than everyone who
// met both, and never learns why. The substrate's answer to a fork is deterministic only
// if every replica knows the fork exists.

import { MAX_FRAME } from '../transport/tcp.js';

export const MSG = {
  HAVE: 0x01,
  HAVE_ADD: 0x02,
  REQUEST: 0x03,
  BLOCK: 0x04,
  CANCEL: 0x05,
  NOBLOCK: 0x06,
  FORK_PROOF: 0x07,
};

// The transport frame budget, minus what the hypha spends wrapping us: 8 bytes of
// cleartext associated data and a 16-byte Poly1305 tag. Everything here checks against
// this rather than MAX_FRAME, because overshooting is a hypha-fatal AEAD-size error and
// not something to discover in production.
export const AEAD_OVERHEAD = 8 + 16;
export const MAX_BODY = MAX_FRAME - AEAD_OVERHEAD;

const LOG_ID = 16;
const PUB = 32;
const PAIR = LOG_ID + 4; // (log_id, seq)

/**
 * The largest seq that may arrive on the wire. 2^24 = 16,777,216 blocks in one log.
 *
 * seq is a u32, and a receiver sizes a bitfield from it — so without this bound a peer
 * sends 23 well-formed bytes claiming a block at 4,294,967,295 and the receiver allocates
 * a 512 MB Uint8Array. On a phone that is not a slowdown, it is the process.
 *
 * The bound lives in the DECODER rather than at each use site, because there is no
 * correct thing for a caller to do with a number this large and only one place to forget
 * the check. 16M blocks at the 32 KB the harness uses is half a terabyte in one log; a
 * log that long has other problems first, and the bitfield costs 2 MB.
 */
// 2^20 - 1, not 2^24 - 1, and the difference is 480 MB.
//
// A peer's advertised set is a Bitfield sized from the seq it claims (sync.js #recvHaveAdd:
// `new Bitfield(seq + 1)`), which allocates ceil(size/8). At 0xffffff that is 2 MB per log,
// and MAX_LOGS is 256 — so ONE ~5 KB HAVE_ADD frame carrying 256 (logId, 0xffffff) pairs
// allocated 512 MB. No signature is involved on that path: the pairs are bare, and this cap
// was the only thing standing in front of the allocation.
//
// The original comment justified 2^24 per log and never multiplied by the log cap. That is
// this codebase's recurring shape once more — a bound that is correct about the quantity it
// names and silent about the one that matters.
//
// 2^20 gives 128 KB per log and still allows a million blocks in one log — which at ~320
// bytes each is 335 MB of content, far past any phone's budget.
//
// AND THE SAME MISTAKE AGAIN, ONE LEVEL UP. The first version of this comment said "32 MB
// across the cap". That is 128 KB x MAX_LOGS, and the allocation in #recvHaveAdd is per
// (log, PEER) — so it is 32 MB x the number of connected hyphae, and nothing caps that
// number. I multiplied by the log cap and not by the peer cap, having just written a commit
// message about a comment that multiplied by neither.
//
// So this constant does NOT bound the advertised-set allocation. It bounds one peer's share
// of it. The real bound has to come from OUR frontier rather than from a limit on what a peer
// may claim, because the multiplier is a quantity we do not control. Recorded in
// docs/RESULTS-2026-09-17.md; the fix is a window above linkedTo, not a smaller MAX_SEQ.
export const MAX_SEQ = 0xfffff;

export class WireError extends Error {
  constructor(code) { super(code); this.code = code; }
}

/** HAVE: [{ logId, authorPub, bitlen, bits }] */
export function encodeHave(entries) {
  const parts = [];
  const head = Buffer.alloc(3);
  head.writeUInt8(MSG.HAVE, 0);
  head.writeUInt16LE(entries.length, 1);
  parts.push(head);
  let total = head.length;
  const used = [];
  for (const e of entries) {
    const nbytes = Math.ceil(e.bitlen / 8);
    const h = Buffer.alloc(LOG_ID + PUB + 4);
    e.logId.copy(h, 0);
    e.authorPub.copy(h, LOG_ID);
    h.writeUInt32LE(e.bitlen, LOG_ID + PUB);
    // A HAVE that does not fit is truncated by LOGS, never by bits: a short bitfield
    // would claim we lack blocks we hold, and the peer would believe it. Dropping whole
    // logs understates coverage too, but only for logs the next HAVE can still carry.
    if (total + h.length + nbytes > MAX_BODY) break;
    parts.push(h, Buffer.from(e.bits.subarray(0, nbytes)));
    total += h.length + nbytes;
    used.push(e);
  }
  if (used.length !== entries.length) head.writeUInt16LE(used.length, 1);
  return { body: Buffer.concat(parts), sent: used.length, dropped: entries.length - used.length };
}

export function decodeHave(body) {
  if (body.length < 3) throw new WireError('have_short');
  const n = body.readUInt16LE(1);
  const out = [];
  let o = 3;
  for (let i = 0; i < n; i++) {
    if (o + LOG_ID + PUB + 4 > body.length) throw new WireError('have_truncated');
    const logId = body.subarray(o, o + LOG_ID);
    const authorPub = body.subarray(o + LOG_ID, o + LOG_ID + PUB);
    const bitlen = body.readUInt32LE(o + LOG_ID + PUB);
    // Same reason as MAX_SEQ: bitlen sizes an allocation on the receiving side.
    if (bitlen > MAX_SEQ + 1) throw new WireError('bitlen_out_of_range');
    o += LOG_ID + PUB + 4;
    const nbytes = Math.ceil(bitlen / 8);
    if (o + nbytes > body.length) throw new WireError('have_bits_truncated');
    out.push({ logId, authorPub, bitlen, bits: body.subarray(o, o + nbytes) });
    o += nbytes;
  }
  return out;
}

/** HAVE_ADD / REQUEST / CANCEL / NOBLOCK all carry the same thing: a list of (log, seq). */
export function encodePairs(type, pairs) {
  const max = Math.floor((MAX_BODY - 3) / PAIR);
  const use = pairs.length > max ? pairs.slice(0, max) : pairs;
  const b = Buffer.alloc(3 + use.length * PAIR);
  b.writeUInt8(type, 0);
  b.writeUInt16LE(use.length, 1);
  use.forEach((p, i) => {
    const o = 3 + i * PAIR;
    p.logId.copy(b, o);
    b.writeUInt32LE(p.seq, o + LOG_ID);
  });
  return b;
}

export function decodePairs(body) {
  if (body.length < 3) throw new WireError('pairs_short');
  const n = body.readUInt16LE(1);
  if (3 + n * PAIR > body.length) throw new WireError('pairs_truncated');
  const out = [];
  for (let i = 0; i < n; i++) {
    const o = 3 + i * PAIR;
    const seq = body.readUInt32LE(o + LOG_ID);
    if (seq > MAX_SEQ) throw new WireError('seq_out_of_range');
    out.push({ logId: body.subarray(o, o + LOG_ID), seq });
  }
  return out;
}

/**
 * BLOCK: the author key travels with the block.
 *
 * It has to. The receiver verifies the signature under this key and then checks the key
 * against the log_id inside the signed header — so shipping it costs 32 bytes and buys
 * the ability to relay a third party's blocks without ever having met them. Handing over
 * the wrong key does not let anything through; it just fails both checks.
 */
export function encodeBlockMsg(cert, payload, authorPub) {
  const total = 1 + 3 + PUB + 4 + 4 + cert.length + payload.length;
  if (total > MAX_BODY) throw new WireError('block_oversize');
  const b = Buffer.alloc(total);
  b.writeUInt8(MSG.BLOCK, 0);
  authorPub.copy(b, 4);
  b.writeUInt32LE(cert.length, 4 + PUB);
  b.writeUInt32LE(payload.length, 8 + PUB);
  cert.copy(b, 12 + PUB);
  payload.copy(b, 12 + PUB + cert.length);
  return b;
}

export function decodeBlockMsg(body) {
  const HEAD = 12 + PUB;
  if (body.length < HEAD) throw new WireError('block_short');
  const authorPub = body.subarray(4, 4 + PUB);
  const certLen = body.readUInt32LE(4 + PUB);
  const payLen = body.readUInt32LE(8 + PUB);
  if (HEAD + certLen + payLen !== body.length) throw new WireError('block_length_mismatch');
  return {
    authorPub,
    cert: body.subarray(HEAD, HEAD + certLen),
    payload: body.subarray(HEAD + certLen, HEAD + certLen + payLen),
  };
}

/** Does a block of this size fit a single frame? Callers must ask before appending. */
export function blockFits(certLen, payloadLen) {
  return 1 + 3 + PUB + 4 + 4 + certLen + payloadLen <= MAX_BODY;
}

/**
 * FORK_PROOF: two certificates that cannot both be honest.
 *
 * Self-authenticating in the strongest sense available here — both signatures verify under
 * a key that must hash to the log_id they claim, so the receiver needs no trust in whoever
 * forwarded it. There is exactly one entity that can manufacture one of these, and it is
 * the author, about themselves, once per fork.
 */
export function encodeForkProof(certA, certB, authorPub) {
  const total = 1 + 3 + PUB + 4 + 4 + certA.length + certB.length;
  if (total > MAX_BODY) throw new WireError('fork_proof_oversize');
  const b = Buffer.alloc(total);
  b.writeUInt8(MSG.FORK_PROOF, 0);
  authorPub.copy(b, 4);
  b.writeUInt32LE(certA.length, 4 + PUB);
  b.writeUInt32LE(certB.length, 8 + PUB);
  certA.copy(b, 12 + PUB);
  certB.copy(b, 12 + PUB + certA.length);
  return b;
}

export function decodeForkProof(body) {
  const HEAD = 12 + PUB;
  if (body.length < HEAD) throw new WireError('fork_proof_short');
  const authorPub = body.subarray(4, 4 + PUB);
  const aLen = body.readUInt32LE(4 + PUB);
  const bLen = body.readUInt32LE(8 + PUB);
  if (HEAD + aLen + bLen !== body.length) throw new WireError('fork_proof_length_mismatch');
  return {
    authorPub,
    certA: body.subarray(HEAD, HEAD + aLen),
    certB: body.subarray(HEAD + aLen, HEAD + aLen + bLen),
  };
}

export function msgType(body) {
  if (!body.length) throw new WireError('empty');
  return body.readUInt8(0);
}
