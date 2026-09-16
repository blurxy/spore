// Sync protocol messages. What actually crosses a hypha once it is authenticated.
//
// Every frame is a one-byte type followed by a body. The type byte is INSIDE the AEAD
// sealed region, so an observer on the LAN cannot tell a block request from a block or
// from a HAVE — they see equal-looking ciphertext of similar size. That is not a
// confidentiality claim for SP1 (the payloads inside are plaintext to any colony member
// and the banner says so), it just avoids handing a passive observer free structure.
//
// Six messages. Five are obvious; NOBLOCK is the one that looks optional and is not.
//
//   HAVE      here is everything I hold, per log, as a bitfield
//   HAVE_ADD  I have just acquired (log, seq) — cache-on-fetch, announced
//   REQUEST   send me these
//   BLOCK     here is one
//   CANCEL    never mind, somebody beat you (endgame)
//   NOBLOCK   I do not have that after all
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

import { MAX_FRAME } from '../transport/tcp.js';

export const MSG = {
  HAVE: 0x01,
  HAVE_ADD: 0x02,
  REQUEST: 0x03,
  BLOCK: 0x04,
  CANCEL: 0x05,
  NOBLOCK: 0x06,
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
    out.push({ logId: body.subarray(o, o + LOG_ID), seq: body.readUInt32LE(o + LOG_ID) });
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

export function msgType(body) {
  if (!body.length) throw new WireError('empty');
  return body.readUInt8(0);
}
