// Block certificate — the unit of truth in the substrate.
//
// 196-byte fixed header + deps + 64-byte signature, exactly per design-substrate.md.
// The signature covers payload_hash, not the payload, so a 40MB video block is still a
// 260-byte cert that SHARDING can fetch and verify independently of its bytes.

import { sign as edSign, verify as edVerify, randomBytes } from 'node:crypto';
import { blake2b256 } from './blake2b.js';

export const HEADER_LEN = 196;
export const SIG_LEN = 64;
export const DEP_LEN = 32;

// Real BLAKE2b-256 exactly as design-substrate.md specifies — not blake2b512 truncated.
// Node ships no parameterized-output BLAKE2b, so src/substrate/blake2b.js implements
// RFC 7693 properly, with the digest length mixed into h[0] where it belongs. That
// distinction is not cosmetic: truncated-512 and real-256 produce entirely different
// bytes, so getting this wrong would have silently guaranteed that no second SPORE
// implementation written from the spec could ever interop with this one.
export const hash256 = blake2b256;

export const TYPE = {
  IDENTITY: 0x01,
  DEVICE_LINK: 0x02,
  COLONY_GENESIS: 0x10,
  FRUITING_CREATE: 0x11,
  MEMBER_JOIN: 0x20,
  MEMBER_LEAVE: 0x21,
  MEMBER_INVITE: 0x22,
  MEMBER_BAN: 0x23,
  ROLE_GRANT: 0x24,
  ROLE_REVOKE: 0x25,
  POWER_SET: 0x26,
  AUTH_SNAPSHOT: 0x30,
  MESSAGE: 0x40,
  EDIT: 0x41,
  DELETE: 0x42,
};

export const FLAG = {
  PAYLOAD_INLINE: 1 << 0,
  ENCRYPTED: 1 << 1,
  BATCH: 1 << 2,
  SNAPSHOT_ANCHOR: 1 << 3,
  REDACTED: 1 << 4,
  AUTH_CONTROL: 1 << 5,
};

const ZERO16 = Buffer.alloc(16);
const ZERO32 = Buffer.alloc(32);

/**
 * A colony names its own founder, the same way a log names its own writer.
 *
 * Without this, "who owns colony C" is decided by comparing two blocks that anyone can
 * write. A fresh identity mints COLONY_GENESIS with scope_id = C — it chains, its lamport
 * derives, it claims no authority, so it links — and roughly half the time its block hash
 * sorts below the real founder's and it takes the colony: its revocations start counting
 * and the founder's grants stop, because the grants no longer come from "the owner". One
 * cheap block, whole colony locked out, every spore agreeing.
 *
 * Deriving the id closes it by construction rather than by arbitration. The shape follows
 * design-substrate.md's own `fruiting_id = BLAKE2b(colony_id || creator_log_id || seq)`,
 * minus the parent a colony does not have. Two genesis blocks for one scope now require
 * one founder to have signed both at one seq, which is equivocation, and the log already
 * ends at a fork.
 */
export function colonyIdFor(founderLogId, seq) {
  const b = Buffer.alloc(24);
  founderLogId.copy(b, 0);
  b.writeBigUInt64LE(BigInt(seq), 16);
  return hash256(b).subarray(0, 16);
}

/**
 * ROLE_GRANT / ROLE_REVOKE payloads.
 *
 * design-app.md gives the op as ROLE_GRANT/REVOKE(member, role_id). REVOKE carries one
 * field beyond that — `pin_seq`, the revoker's view of the target log's head — and the
 * reason it is a SEQ and not a lamport is the whole of §1.19's fix.
 *
 * The attack (CORRECTNESS.md V1) is a moderator who was demoted while offline and comes
 * back citing the grant they used to hold, with "a naturally low lamport" — their counter
 * is anchored to their own frozen head, so their new block sorts BEFORE the revoke in
 * (lamport, log_id, seq) and gets auth-checked against history from before the demotion.
 * Every compliant spore computes the identical wrong answer.
 *
 * So anything that compares the two blocks' lamports is already lost: the attacker picks
 * theirs, and picks it low. A seq pin does not care. The target's log is single-writer and
 * its seqs are monotone, so EVERY block the target writes after the revoker saw them is at
 * a seq above the pin, no matter what lamport it claims. Writing below the pin is not an
 * evasion, it is an equivocation, and the log already ends at a fork.
 *
 * The cost, stated plainly rather than fixed: if the revoker's pin lags the target's real
 * head, blocks the target wrote in between are stopped too. The revoker is saying "out, as
 * of what I had seen," and that is deterministic over-revocation, identical on every spore.
 *
 * GRANT CARRIES A PIN TOO, and the two become one rule rather than two. Each control block
 * names a BOUNDARY in the target's log — a GRANT governs from `pin_seq`, a REVOKE from
 * `pin_seq + 1` — and the block that governs any given seq is the one with the largest
 * boundary at or below it, ties going to the later block in the owner's own log.
 *
 * That single lookup is what makes re-grant possible without reopening V1. An owner who
 * revoked at `k` and then re-grants at pin 0 has NOT blessed the replay at `k+1`: the
 * revocation's boundary `k+1` is still the largest one at or below `k+1`, so it still
 * governs and still stops. To lift the stop the owner must say so explicitly, with a pin
 * at or above `k+1`, and then the tie-break hands it to the later block. The intent has to
 * be written down; it cannot be arrived at by accident.
 *
 * An earlier design computed a GRANT's effective boundary as `max(pin_seq, k+1)` over
 * every preceding revocation. That is subsumed by "largest boundary wins" and having both
 * would have meant two rules that can disagree.
 */
export const GRANT_LEN = 28;
export const REVOKE_LEN = 28;

export function encodeGrant({ target, pinSeq = 0, roleId = 0 }) {
  if (target.length !== 16) throw new Error(`target must be 16 bytes, got ${target.length}`);
  const p = Buffer.alloc(GRANT_LEN);
  target.copy(p, 0);
  p.writeBigUInt64LE(BigInt(pinSeq), 16);
  p.writeUInt32LE(roleId, 24);
  return p;
}

export function decodeGrant(payload) {
  if (payload.length !== GRANT_LEN) throw new Error(`grant payload ${payload.length}, want ${GRANT_LEN}`);
  return {
    target: payload.subarray(0, 16),
    pinSeq: payload.readBigUInt64LE(16),
    roleId: payload.readUInt32LE(24),
  };
}

export function encodeRevoke({ target, pinSeq, roleId = 0 }) {
  if (target.length !== 16) throw new Error(`target must be 16 bytes, got ${target.length}`);
  const p = Buffer.alloc(REVOKE_LEN);
  target.copy(p, 0);
  p.writeBigUInt64LE(BigInt(pinSeq), 16);
  p.writeUInt32LE(roleId, 24);
  return p;
}

export function decodeRevoke(payload) {
  if (payload.length !== REVOKE_LEN) throw new Error(`revoke payload ${payload.length}, want ${REVOKE_LEN}`);
  return {
    target: payload.subarray(0, 16),
    pinSeq: payload.readBigUInt64LE(16),
    roleId: payload.readUInt32LE(24),
  };
}

/**
 * Encode a block certificate. Returns { cert, blockHash, payloadHash }.
 * Signature is ed25519 over hash256(header || deps), so signing cost is independent
 * of dep count and of payload size.
 */
export function encodeBlock(fields, privateKey) {
  const {
    type,
    flags = 0,
    logId,
    seq,
    lamport,
    scopeId = ZERO16,
    prevHash = ZERO32,
    mmrRoot = ZERO32,
    authRef = ZERO32,
    payload = Buffer.alloc(0),
    deps = [],
  } = fields;

  if (logId.length !== 16) throw new Error(`logId must be 16 bytes, got ${logId.length}`);
  if (deps.some((d) => d.length !== DEP_LEN)) throw new Error('each dep must be 32 bytes');

  const h = Buffer.alloc(HEADER_LEN);
  h.writeUInt8(0x01, 0);
  h.writeUInt8(type, 1);
  h.writeUInt16LE(flags, 2);
  logId.copy(h, 4);
  h.writeBigUInt64LE(BigInt(seq), 20);
  h.writeBigUInt64LE(BigInt(lamport), 28);
  // wall_ms (offset 36) stays ZERO. Advisory-only per spec, and ARCHITECTURE.md 1.2
  // removed all wall-clock dependence — off-web has no NTP, so we never even record it.
  h.writeBigUInt64LE(0n, 36);
  scopeId.copy(h, 44);
  prevHash.copy(h, 60);
  mmrRoot.copy(h, 92);
  authRef.copy(h, 124);
  hash256(payload).copy(h, 156);
  h.writeUInt32LE(payload.length, 188);
  h.writeUInt16LE(deps.length, 192);
  h.writeUInt16LE(0, 194);

  const depBytes = deps.length ? Buffer.concat(deps) : Buffer.alloc(0);
  const signed = Buffer.concat([h, depBytes]);
  const sig = edSign(null, hash256(signed), privateKey);
  if (sig.length !== SIG_LEN) throw new Error(`unexpected sig length ${sig.length}`);

  const cert = Buffer.concat([signed, sig]);
  return { cert, blockHash: hash256(cert), payloadHash: h.subarray(156, 188) };
}

export function decodeBlock(cert) {
  if (cert.length < HEADER_LEN + SIG_LEN) throw new Error('cert too short');
  if (cert.readUInt8(0) !== 0x01) throw new Error(`unsupported block ver ${cert.readUInt8(0)}`);
  const depCount = cert.readUInt16LE(192);
  const want = HEADER_LEN + depCount * DEP_LEN + SIG_LEN;
  if (cert.length !== want) throw new Error(`cert length ${cert.length}, expected ${want}`);

  const deps = [];
  for (let i = 0; i < depCount; i++) {
    const o = HEADER_LEN + i * DEP_LEN;
    deps.push(cert.subarray(o, o + DEP_LEN));
  }
  return {
    ver: cert.readUInt8(0),
    type: cert.readUInt8(1),
    flags: cert.readUInt16LE(2),
    logId: cert.subarray(4, 20),
    seq: cert.readBigUInt64LE(20),
    lamport: cert.readBigUInt64LE(28),
    scopeId: cert.subarray(44, 60),
    prevHash: cert.subarray(60, 92),
    mmrRoot: cert.subarray(92, 124),
    authRef: cert.subarray(124, 156),
    payloadHash: cert.subarray(156, 188),
    payloadLen: cert.readUInt32LE(188),
    depCount,
    deps,
    sig: cert.subarray(want - SIG_LEN),
    signedRegion: cert.subarray(0, want - SIG_LEN),
    blockHash: hash256(cert),
  };
}

/** Verify signature and, when the payload is supplied, that it matches payload_hash. */
export function verifyBlock(cert, publicKey, payload = null) {
  let b;
  try {
    b = decodeBlock(cert);
  } catch (e) {
    return { ok: false, reason: `decode: ${e.message}` };
  }
  if (!edVerify(null, hash256(b.signedRegion), publicKey, b.sig)) {
    return { ok: false, reason: 'bad_signature' };
  }
  if (payload !== null) {
    if (payload.length !== b.payloadLen) return { ok: false, reason: 'payload_len_mismatch' };
    if (!hash256(payload).equals(b.payloadHash)) return { ok: false, reason: 'payload_hash_mismatch' };
  }
  return { ok: true, block: b };
}

/**
 * ORDER(B) = (lamport, log_id lexicographic, seq).
 * Total, because (log_id, seq) is globally unique. A pure function of block fields, so
 * every spore computes the same order with no clock and no coordinator.
 */
export function order(a, b) {
  if (a.lamport !== b.lamport) return a.lamport < b.lamport ? -1 : 1;
  const c = Buffer.compare(a.logId, b.logId);
  if (c !== 0) return c;
  if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1;
  return 0;
}

/**
 * Lamport is DERIVED, never asserted: 1 + max(own previous, all deps).
 * A spore recomputes this and rejects a block whose field disagrees, which closes the
 * lamport-inflation attack — you cannot declare lamport = 2^60 and pin yourself atop
 * history forever.
 */
export function deriveLamport(prevLamport, depLamports = []) {
  let m = BigInt(prevLamport);
  for (const d of depLamports) if (BigInt(d) > m) m = BigInt(d);
  return m + 1n;
}

/**
 * A log announces its own writer.
 *
 * Logs are single-writer, so every block in a log must be signed by the same key. But
 * until block transfer existed, nothing had to prove WHICH key: a spore only ever received
 * blocks from their author across an authenticated hypha, so "the key the handshake proved"
 * was always the right answer.
 *
 * Replication breaks that. Fetching Alice's blocks from Bob means verifying a signature
 * against a key Bob hands us, and a random 16-byte log_id gives us no way to know it is
 * the right one — Bob could serve blocks he signed himself and call them Alice's log.
 *
 * So the log_id IS the author, truncated: log_id = hash256(author_pub)[0..16]. It sits in
 * the header at offset 4, inside the signed region, in every block. Verification becomes
 * two checks that together are unforgeable: the signature verifies under the supplied key,
 * AND that key hashes to the log_id the block claims. Claiming another spore's log now
 * requires a 128-bit preimage on their public key.
 *
 * 16 bytes rather than the full 32 because the header field is 16 bytes and widening it
 * would cost 16 bytes on every block forever to buy collision resistance nothing needs —
 * the second check already pins the exact key.
 */
export function logIdFor(authorPubRaw) {
  if (authorPubRaw.length !== 32) throw new Error(`author pub must be 32 bytes, got ${authorPubRaw.length}`);
  return hash256(authorPubRaw).subarray(0, 16);
}

/** True if `authorPubRaw` is the writer this log_id names. */
export function logIdMatches(logId, authorPubRaw) {
  return logId.length === 16 && logIdFor(authorPubRaw).equals(logId);
}

/** Random log id. Test/scratch use only — a real log is named by its author. */
export function newLogId() {
  return randomBytes(16);
}
