// Steganographic invites — the trick that started this project, turned into a mechanism.
//
// SPORE has no server, so there is no join link to host and no directory to look a colony
// up in. An invite has to travel out-of-band, through whatever channel two people already
// share. That is an awkward requirement with an elegant answer.
//
// elder-plinius/FRV1T hides 27KB of prompt inside a single blueberry emoji using Unicode
// variation selectors: codepoints that carry no width, no glyph, and no meaning of their
// own, but survive copy-paste because they are legitimately part of the text. We decoded
// that file at the start of this project. Here we use the same encoding to carry a colony
// invite inside any innocuous sentence.
//
//   "hey are we still on for friday"      <- what a human sees
//   "hey are we still on for friday󠅘󠄐..."  <- what is actually there
//
// The invite rides SMS, email, a chat app, a screenshot's alt text, a commit message —
// anything that moves UTF-8. Off-web invites for an off-web mesh.
//
// SECURITY, STATED PLAINLY: this is ENCODING, not encryption. Anyone who knows to look
// can extract it, and any tool that strips non-printing characters destroys it. It hides
// an invite from a casual reader, not from an adversary, and it is not a confidentiality
// mechanism. The invite's own signature is what makes it unforgeable.

import { gzipSync, gunzipSync } from 'node:zlib';
import { sign as edSign, verify as edVerify } from 'node:crypto';
import { blake2b256 } from '../substrate/blake2b.js';
import { edPub } from '../session/noise.js';

// byte 0..15   -> U+FE00..U+FE0F   (VS1-16)
// byte 16..255 -> U+E0100..U+E01EF (VS17-256)
const LOW_BASE = 0xfe00;
const HIGH_BASE = 0xe0100;

/** Encode arbitrary bytes as zero-width variation selectors. */
export function bytesToSelectors(buf) {
  let out = '';
  for (const b of buf) {
    out += String.fromCodePoint(b < 16 ? LOW_BASE + b : HIGH_BASE + (b - 16));
  }
  return out;
}

/** Recover bytes from a string, ignoring every visible character. */
export function selectorsToBytes(text) {
  const out = [];
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if (c >= LOW_BASE && c <= LOW_BASE + 15) out.push(c - LOW_BASE);
    else if (c >= HIGH_BASE && c <= HIGH_BASE + 239) out.push(c - HIGH_BASE + 16);
  }
  return Buffer.from(out);
}

/** Strip any hidden payload, leaving only what a human sees. */
export function visibleOnly(text) {
  let out = '';
  for (const ch of text) {
    const c = ch.codePointAt(0);
    const hidden = (c >= LOW_BASE && c <= LOW_BASE + 15) || (c >= HIGH_BASE && c <= HIGH_BASE + 239);
    if (!hidden) out += ch;
  }
  return out;
}

const MAGIC = Buffer.from('SPOR', 'ascii');
const INVITE_VERSION = 1;
const CTX = Buffer.concat([Buffer.from('SPORE-INVITE-v1', 'utf8'), Buffer.from([0])]);

/**
 * Build a signed colony invite and hide it inside `cover` text.
 *
 * There is no expiry field, deliberately. ARCHITECTURE.md 1.2: off-web means no NTP, so
 * two spores cannot agree what time it is and a timestamp-based TTL would fail for
 * reasons neither side could diagnose. Invites are burned causally instead — the colony
 * log records the redemption, and that record is what stops reuse.
 */
export function mintInvite({ colonyId, colonyName = '', inviterId, inviterPrivate, nonce }, cover = '') {
  if (colonyId.length !== 16) throw new Error('colonyId must be 16 bytes');
  if (inviterId.length !== 32) throw new Error('inviterId must be 32 bytes');
  if (!nonce || nonce.length !== 16) throw new Error('nonce must be 16 bytes');

  const name = Buffer.from(String(colonyName).slice(0, 48), 'utf8');
  const body = Buffer.concat([
    MAGIC,
    Buffer.from([INVITE_VERSION]),
    colonyId,
    inviterId,
    nonce,
    Buffer.from([name.length]),
    name,
  ]);
  const sig = edSign(null, blake2b256(CTX, body), inviterPrivate);
  const packed = gzipSync(Buffer.concat([body, sig]), { level: 9 });

  return {
    text: cover + bytesToSelectors(packed),
    bytes: packed.length,
    coverLength: cover.length,
  };
}

/**
 * Extract and verify an invite from text. Returns { ok, invite } or { ok:false, reason }.
 * Everything here arrives from outside, so nothing is trusted until the signature checks.
 */
export function readInvite(text) {
  let packed;
  try {
    packed = selectorsToBytes(text);
  } catch {
    return { ok: false, reason: 'undecodable' };
  }
  if (packed.length === 0) return { ok: false, reason: 'no_payload' };

  let raw;
  try {
    raw = gunzipSync(packed);
  } catch {
    return { ok: false, reason: 'bad_container' };
  }

  // 4 magic + 1 ver + 16 colony + 32 inviter + 16 nonce + 1 namelen + 64 sig
  if (raw.length < 134) return { ok: false, reason: 'too_short' };
  if (!raw.subarray(0, 4).equals(MAGIC)) return { ok: false, reason: 'bad_magic' };
  if (raw.readUInt8(4) !== INVITE_VERSION) return { ok: false, reason: 'bad_version' };

  const colonyId = raw.subarray(5, 21);
  const inviterId = raw.subarray(21, 53);
  const nonce = raw.subarray(53, 69);
  const nameLen = raw.readUInt8(69);
  if (raw.length !== 70 + nameLen + 64) return { ok: false, reason: 'length_mismatch' };
  const colonyName = raw.subarray(70, 70 + nameLen).toString('utf8');
  const body = raw.subarray(0, 70 + nameLen);
  const sig = raw.subarray(70 + nameLen);

  let ok = false;
  try {
    ok = edVerify(null, blake2b256(CTX, body), edPub(inviterId), sig);
  } catch {
    ok = false;
  }
  if (!ok) return { ok: false, reason: 'bad_signature' };

  return {
    ok: true,
    invite: {
      colonyId,
      colonyName,
      inviterId,
      nonce,
      // the id the colony log burns on redemption, so an invite cannot be replayed
      burnId: blake2b256(colonyId, nonce),
    },
  };
}

/** Does this text carry a hidden payload at all? Cheap check before attempting a read. */
export function carriesPayload(text) {
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if ((c >= LOW_BASE && c <= LOW_BASE + 15) || (c >= HIGH_BASE && c <= HIGH_BASE + 239)) return true;
  }
  return false;
}
