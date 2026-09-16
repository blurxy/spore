// Noise_XX_25519_ChaChaPoly_BLAKE2b — the handshake that turns a raw duplex into a hypha.
//
// Spec-exact Noise on Node stdlib alone. The enabling trick, verified independently
// before this was written: Noise's HKDF(ck, ikm, n) is bit-identical to
//   crypto.hkdfSync('blake2b512', ikm, ck, EMPTY_INFO, 64 * n)
// because Noise's chain with an empty info string IS RFC5869 Expand. So there is no
// hand-rolled HMAC anywhere in this file, which removes the single most likely place
// for a subtle, silent, catastrophic crypto bug.
//
// XX is forced on us and is the right choice: a bare hotspot has no directory, and
// BEACON announcements are spoofable and stale, so zero prior knowledge is the only
// honest assumption. XX gives mutual auth, forward secrecy from `ee`, and hides the
// initiator's static from passive observers.
//
// Identity binding (libp2p-noise style, strengthened): ed25519 is NEVER used for DH.
// A separate X25519 static is bound to the ed25519 identity by a long-lived link_sig,
// and each session is authenticated by a bind_sig over the transcript hash. The point
// is that the ed25519 key is the sole per-session authenticator — compromise of the
// X25519 static alone yields neither impersonation nor decryption.

import {
  createHash, createPrivateKey, createPublicKey, createCipheriv, createDecipheriv,
  diffieHellman, generateKeyPairSync, hkdfSync, sign as edSign, verify as edVerify,
  timingSafeEqual,
} from 'node:crypto';

export const PROTOCOL = 'Noise_XX_25519_ChaChaPoly_BLAKE2b';
export const HASHLEN = 64;
export const DHLEN = 32;
export const TAGLEN = 16;

const EMPTY = Buffer.alloc(0);
const WIRE_VERSION = 1;
const SUITE_ID = 1;

// not_after is permanently saturated. ARCHITECTURE.md 1.2: off-web means no NTP, so two
// spores cannot agree what time it is, and a clock-based validity window would make the
// handshake fail for reasons neither side can diagnose. Revocation is causal, not temporal.
export const NOT_AFTER_NEVER = 0xffffffff;

// --- DER wrapping, so raw 32-byte keys become Node KeyObjects -----------------
const X_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const X_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

const xPub = (raw) => createPublicKey({ key: Buffer.concat([X_SPKI, raw]), format: 'der', type: 'spki' });
const xPriv = (raw) => createPrivateKey({ key: Buffer.concat([X_PKCS8, raw]), format: 'der', type: 'pkcs8' });
export const edPub = (raw) => createPublicKey({ key: Buffer.concat([ED_SPKI, raw]), format: 'der', type: 'spki' });

export const rawPub = (ko) => ko.export({ format: 'der', type: 'spki' }).subarray(-32);
export const rawPriv = (ko) => ko.export({ format: 'der', type: 'pkcs8' }).subarray(-32);

export function generateStatic() {
  const kp = generateKeyPairSync('x25519');
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, raw: rawPub(kp.publicKey) };
}

/** Rebuild an X25519 keypair from a raw 32-byte private key — used to replay test vectors. */
export function staticFromRaw(rawPrivate) {
  const privateKey = xPriv(rawPrivate);
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey, raw: rawPub(publicKey) };
}

function dh(privateKey, peerRaw) {
  const secret = diffieHellman({ privateKey, publicKey: xPub(peerRaw) });
  // All-zero output means a low-order point was supplied. Noise says abort; we abort.
  if (secret.every((b) => b === 0)) throw new NoiseError('low_order_point');
  return secret;
}

export class NoiseError extends Error {
  constructor(code) {
    super(`noise: ${code}`);
    this.code = code;
  }
}

const hash = (...parts) => {
  const h = createHash('blake2b512');
  for (const p of parts) h.update(p);
  return h.digest();
};

/** Noise HKDF(ck, ikm, n) — see the file header for why this is stdlib-only. */
function hkdf(ck, ikm, n) {
  const out = Buffer.from(hkdfSync('blake2b512', ikm, ck, EMPTY, HASHLEN * n));
  const parts = [];
  for (let i = 0; i < n; i++) parts.push(out.subarray(i * HASHLEN, (i + 1) * HASHLEN));
  return parts;
}

/** ChaCha20-Poly1305 nonce: 4 zero bytes then the little-endian 64-bit counter. */
function nonceOf(n) {
  const b = Buffer.alloc(12);
  b.writeBigUInt64LE(n, 4);
  return b;
}

function aeadEncrypt(k, n, ad, pt) {
  const c = createCipheriv('chacha20-poly1305', k, nonceOf(n), { authTagLength: TAGLEN });
  c.setAAD(ad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}

function aeadDecrypt(k, n, ad, ct) {
  if (ct.length < TAGLEN) throw new NoiseError('aead_fail');
  const body = ct.subarray(0, ct.length - TAGLEN);
  const d = createDecipheriv('chacha20-poly1305', k, nonceOf(n), { authTagLength: TAGLEN });
  d.setAAD(ad, { plaintextLength: body.length });
  d.setAuthTag(ct.subarray(ct.length - TAGLEN));
  try {
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    throw new NoiseError('aead_fail');
  }
}

class SymmetricState {
  constructor(protocolName, prologue) {
    const pn = Buffer.from(protocolName, 'utf8');
    this.h = pn.length <= HASHLEN ? Buffer.concat([pn, Buffer.alloc(HASHLEN - pn.length)]) : hash(pn);
    this.ck = Buffer.from(this.h);
    this.k = null;
    this.n = 0n;
    this.mixHash(prologue);
  }
  mixHash(data) {
    this.h = hash(this.h, data);
  }
  mixKey(ikm) {
    const [ck, temp] = hkdf(this.ck, ikm, 2);
    this.ck = ck;
    this.k = temp.subarray(0, 32);
    this.n = 0n;
  }
  encryptAndHash(pt) {
    const ct = this.k ? aeadEncrypt(this.k, this.n++, this.h, pt) : pt;
    this.mixHash(ct);
    return ct;
  }
  decryptAndHash(ct) {
    const pt = this.k ? aeadDecrypt(this.k, this.n++, this.h, ct) : ct;
    this.mixHash(ct);
    return pt;
  }
  split() {
    const [t1, t2] = hkdf(this.ck, EMPTY, 2);
    return [t1.subarray(0, 32), t2.subarray(0, 32)];
  }
}

// --- identity binding --------------------------------------------------------

const LINK_CTX = Buffer.concat([Buffer.from('SPORE-LINK-v1', 'utf8'), Buffer.from([0])]);
const BIND_CTX = Buffer.concat([Buffer.from('SPORE-BIND-v1', 'utf8'), Buffer.from([0])]);
const SAS_CTX = Buffer.concat([Buffer.from('SPORE-SAS-v1', 'utf8'), Buffer.from([0])]);

/**
 * The link certificate binds an X25519 static to an ed25519 identity. Long-lived and
 * freely gossipable — it proves "this DH key belongs to that spore", nothing more.
 */
export function makeLinkSig(idPrivate, idPubRaw, staticPubRaw, notAfter = NOT_AFTER_NEVER) {
  const na = Buffer.alloc(4);
  na.writeUInt32LE(notAfter);
  return edSign(null, Buffer.concat([LINK_CTX, idPubRaw, staticPubRaw, na]), idPrivate);
}

function verifyLinkSig(idPubRaw, staticPubRaw, notAfter, sig) {
  const na = Buffer.alloc(4);
  na.writeUInt32LE(notAfter);
  try {
    return edVerify(null, Buffer.concat([LINK_CTX, idPubRaw, staticPubRaw, na]), edPub(idPubRaw), sig);
  } catch {
    return false;
  }
}

// payload: id_pub(32) | not_after(4) | link_sig(64) | bind_sig(64)
const AUTH_PAYLOAD_LEN = 32 + 4 + 64 + 64;

function buildAuthPayload(idPubRaw, idPrivate, staticPubRaw, transcriptH, notAfter) {
  const na = Buffer.alloc(4);
  na.writeUInt32LE(notAfter);
  return Buffer.concat([
    idPubRaw,
    na,
    makeLinkSig(idPrivate, idPubRaw, staticPubRaw, notAfter),
    edSign(null, Buffer.concat([BIND_CTX, transcriptH]), idPrivate),
  ]);
}

function openAuthPayload(payload, peerStaticRaw, transcriptH) {
  if (payload.length !== AUTH_PAYLOAD_LEN) throw new NoiseError('bad_auth_payload');
  const idPubRaw = payload.subarray(0, 32);
  const notAfter = payload.readUInt32LE(32);
  const linkSig = payload.subarray(36, 100);
  const bindSig = payload.subarray(100, 164);

  if (!verifyLinkSig(idPubRaw, peerStaticRaw, notAfter, linkSig)) throw new NoiseError('bad_link_sig');
  let ok = false;
  try {
    ok = edVerify(null, Buffer.concat([BIND_CTX, transcriptH]), edPub(idPubRaw), bindSig);
  } catch {
    ok = false;
  }
  if (!ok) throw new NoiseError('bad_bind_sig');
  return { idPubRaw, notAfter };
}

/** prologue = 0x53 | wire_version | suite_u16 — MixHashed before msg1, so no downgrade. */
export function prologue(wireVersion = WIRE_VERSION, suite = SUITE_ID) {
  const p = Buffer.alloc(4);
  p.writeUInt8(0x53, 0);
  p.writeUInt8(wireVersion, 1);
  p.writeUInt16LE(suite, 2);
  return p;
}

/**
 * A completed hypha: per-direction keys and counters.
 * Separate key AND counter per direction is what makes reflection attacks inert.
 */
export class CipherPair {
  constructor(sendKey, recvKey, hyphaId) {
    this.sendKey = sendKey;
    this.recvKey = recvKey;
    this.hyphaId = hyphaId;
    this.sendN = 0n;
    this.recvN = 0n;
  }
  /** 4 bytes of the transcript hash — the short authentication string, ZRTP-style. */
  get sas() {
    return hash(SAS_CTX, this.hyphaId).subarray(0, 4);
  }
  encrypt(ad, pt) {
    return aeadEncrypt(this.sendKey, this.sendN++, ad, pt);
  }
  decrypt(ad, ct) {
    return aeadDecrypt(this.recvKey, this.recvN++, ad, ct);
  }
}

/**
 * PURE Noise XX, with no SPORE policy in it at all — arbitrary payloads, and injectable
 * ephemerals so published test vectors can be replayed exactly.
 *
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 *
 * This is deliberately separate from SPORE's identity binding. design-crypto.md named
 * hand-written Noise as "where this design most plausibly fails"; keeping the raw pattern
 * isolated is what lets test/noise-vectors.test.js check it against the official
 * Cacophony vectors byte-for-byte, which is the only real evidence that it is correct.
 */
export class NoiseXX {
  constructor({ initiator, s, e = null, pro = prologue() }) {
    this.initiator = initiator;
    this.s = s;
    this.fixedE = e;
    this.ss = new SymmetricState(PROTOCOL, pro);
    this.e = null;
    this.re = null;
    this.rs = null;
    this.step = 0;
    this.done = false;
  }

  #ephemeral() {
    this.e = this.fixedE || generateStatic();
    return this.e;
  }

  get handshakeHash() { return this.ss.h; }

  writeMessage(payload = EMPTY) {
    if (this.initiator && this.step === 0) {
      const e = this.#ephemeral();
      this.ss.mixHash(e.raw);
      const out = Buffer.concat([e.raw, this.ss.encryptAndHash(payload)]);
      this.step = 1;
      return out;
    }
    if (!this.initiator && this.step === 1) {
      const e = this.#ephemeral();
      this.ss.mixHash(e.raw);
      this.ss.mixKey(dh(e.privateKey, this.re));                    // ee
      const encS = this.ss.encryptAndHash(rawPub(this.s.publicKey)); // s
      this.ss.mixKey(dh(this.s.privateKey, this.re));               // es
      const out = Buffer.concat([e.raw, encS, this.ss.encryptAndHash(payload)]);
      this.step = 2;
      return out;
    }
    if (this.initiator && this.step === 2) {
      const encS = this.ss.encryptAndHash(rawPub(this.s.publicKey)); // s
      this.ss.mixKey(dh(this.s.privateKey, this.re));               // se
      const out = Buffer.concat([encS, this.ss.encryptAndHash(payload)]);
      this.step = 3;
      this.done = true;
      return out;
    }
    throw new NoiseError('out_of_turn_write');
  }

  /** Returns { payload, hBefore } — hBefore is the transcript as it stood pre-decrypt. */
  readMessage(msg) {
    if (!this.initiator && this.step === 0) {
      if (msg.length < DHLEN) throw new NoiseError('short_msg1');
      this.re = msg.subarray(0, DHLEN);
      this.ss.mixHash(this.re);
      const hBefore = this.ss.h;
      const payload = this.ss.decryptAndHash(msg.subarray(DHLEN));
      this.step = 1;
      return { payload, hBefore };
    }
    if (this.initiator && this.step === 1) {
      if (msg.length < DHLEN + DHLEN + TAGLEN) throw new NoiseError('short_msg2');
      this.re = msg.subarray(0, DHLEN);
      this.ss.mixHash(this.re);
      this.ss.mixKey(dh(this.e.privateKey, this.re));                              // ee
      this.rs = this.ss.decryptAndHash(msg.subarray(DHLEN, DHLEN + DHLEN + TAGLEN)); // s
      this.ss.mixKey(dh(this.e.privateKey, this.rs));                              // es
      const hBefore = this.ss.h;
      const payload = this.ss.decryptAndHash(msg.subarray(DHLEN + DHLEN + TAGLEN));
      this.step = 2;
      return { payload, hBefore };
    }
    if (!this.initiator && this.step === 2) {
      if (msg.length < DHLEN + TAGLEN) throw new NoiseError('short_msg3');
      this.rs = this.ss.decryptAndHash(msg.subarray(0, DHLEN + TAGLEN)); // s
      this.ss.mixKey(dh(this.e.privateKey, this.rs));                    // se
      const hBefore = this.ss.h;
      const payload = this.ss.decryptAndHash(msg.subarray(DHLEN + TAGLEN));
      this.step = 3;
      this.done = true;
      return { payload, hBefore };
    }
    throw new NoiseError('out_of_turn_read');
  }

  split() {
    if (!this.done) throw new NoiseError('incomplete');
    const [t1, t2] = this.ss.split();
    return this.initiator ? [t1, t2] : [t2, t1]; // [send, recv]
  }
}

/**
 * SPORE's handshake: pure Noise XX plus the identity binding that makes the ed25519 key
 * the sole per-session authenticator.
 *
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 */
export class Handshake {
  constructor({ initiator, staticKeys, idPublicRaw, idPrivate, notAfter = NOT_AFTER_NEVER, pro = prologue() }) {
    this.initiator = initiator;
    this.s = staticKeys;
    this.idPublicRaw = idPublicRaw;
    this.idPrivate = idPrivate;
    this.notAfter = notAfter;
    this.ss = new SymmetricState(PROTOCOL, pro);
    this.e = null;
    this.re = null;
    this.rs = null;
    this.peerId = null;
    this.step = 0;
    this.done = false;
  }

  /** 0..1 — how far the handshake really is. The hypha in the UI grows on this value. */
  get progress() {
    return this.done ? 1 : this.step / 3;
  }

  writeMessage() {
    if (this.initiator && this.step === 0) {
      this.e = generateStatic();
      this.ss.mixHash(this.e.raw);
      const out = Buffer.concat([this.e.raw, this.ss.encryptAndHash(EMPTY)]);
      this.step = 1;
      return out;
    }
    if (!this.initiator && this.step === 1) {
      this.e = generateStatic();
      this.ss.mixHash(this.e.raw);
      this.ss.mixKey(dh(this.e.privateKey, this.re)); // ee
      const encS = this.ss.encryptAndHash(rawPub(this.s.publicKey)); // s
      this.ss.mixKey(dh(this.s.privateKey, this.re)); // es
      const auth = buildAuthPayload(this.idPublicRaw, this.idPrivate, rawPub(this.s.publicKey), this.ss.h, this.notAfter);
      const out = Buffer.concat([this.e.raw, encS, this.ss.encryptAndHash(auth)]);
      this.step = 2;
      return out;
    }
    if (this.initiator && this.step === 2) {
      const encS = this.ss.encryptAndHash(rawPub(this.s.publicKey)); // s
      this.ss.mixKey(dh(this.s.privateKey, this.re)); // se
      const auth = buildAuthPayload(this.idPublicRaw, this.idPrivate, rawPub(this.s.publicKey), this.ss.h, this.notAfter);
      const out = Buffer.concat([encS, this.ss.encryptAndHash(auth)]);
      this.step = 3;
      this.done = true;
      return out;
    }
    throw new NoiseError('out_of_turn_write');
  }

  readMessage(msg) {
    if (!this.initiator && this.step === 0) {
      if (msg.length < DHLEN) throw new NoiseError('short_msg1');
      this.re = msg.subarray(0, DHLEN);
      this.ss.mixHash(this.re);
      this.ss.decryptAndHash(msg.subarray(DHLEN));
      this.step = 1;
      return EMPTY;
    }
    if (this.initiator && this.step === 1) {
      if (msg.length < DHLEN + DHLEN + TAGLEN) throw new NoiseError('short_msg2');
      this.re = msg.subarray(0, DHLEN);
      this.ss.mixHash(this.re);
      this.ss.mixKey(dh(this.e.privateKey, this.re)); // ee
      this.rs = this.ss.decryptAndHash(msg.subarray(DHLEN, DHLEN + DHLEN + TAGLEN)); // s
      this.ss.mixKey(dh(this.e.privateKey, this.rs)); // es
      const hBefore = this.ss.h;
      const auth = this.ss.decryptAndHash(msg.subarray(DHLEN + DHLEN + TAGLEN));
      this.peerId = openAuthPayload(auth, this.rs, hBefore).idPubRaw;
      this.step = 2;
      return auth;
    }
    if (!this.initiator && this.step === 2) {
      if (msg.length < DHLEN + TAGLEN) throw new NoiseError('short_msg3');
      this.rs = this.ss.decryptAndHash(msg.subarray(0, DHLEN + TAGLEN)); // s
      this.ss.mixKey(dh(this.e.privateKey, this.rs)); // se
      const hBefore = this.ss.h;
      const auth = this.ss.decryptAndHash(msg.subarray(DHLEN + TAGLEN));
      this.peerId = openAuthPayload(auth, this.rs, hBefore).idPubRaw;
      this.step = 3;
      this.done = true;
      return auth;
    }
    throw new NoiseError('out_of_turn_read');
  }

  /** hypha_id is the final transcript hash — the channel binding for later join proofs. */
  finish() {
    if (!this.done) throw new NoiseError('incomplete');
    const [t1, t2] = this.ss.split();
    const hyphaId = this.ss.h;
    return this.initiator ? new CipherPair(t1, t2, hyphaId) : new CipherPair(t2, t1, hyphaId);
  }
}

/** Constant-time compare, for SAS confirmation and id checks. */
export function eq(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}
