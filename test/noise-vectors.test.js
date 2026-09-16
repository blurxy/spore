// The test design-crypto.md said the build must have or "this layer is unverified".
//
// Every other noise test proves SPORE talks to SPORE. This one proves SPORE talks to
// NOISE: it replays the official Cacophony vector for Noise_XX_25519_ChaChaPoly_BLAKE2b
// with the vector's own fixed keys and asserts our wire bytes, transcript hash and
// transport keys match the published values exactly.
//
// Vectors: https://github.com/mcginty/snow/blob/main/tests/vectors/cacophony.txt
// Vendored to test/fixtures/ so the suite never needs the network — SPORE is off-web and
// its own test suite should be too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createCipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { NoiseXX, staticFromRaw } from '../src/session/noise.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, 'fixtures', 'noise-xx-25519-chachapoly-blake2b.json');

const hex = (s) => Buffer.from(s, 'hex');

test('noise: reproduces the official Cacophony XX_25519_ChaChaPoly_BLAKE2b vector', (t) => {
  if (!existsSync(FIXTURE)) {
    t.skip(`fixture missing: ${FIXTURE}`);
    return;
  }
  const v = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  assert.equal(v.protocol_name, 'Noise_XX_25519_ChaChaPoly_BLAKE2b');

  const pro = hex(v.init_prologue || '');
  assert.ok(Buffer.from(v.resp_prologue || '', 'hex').equals(pro), 'prologues must match');

  const init = new NoiseXX({
    initiator: true,
    s: staticFromRaw(hex(v.init_static)),
    e: staticFromRaw(hex(v.init_ephemeral)),
    pro,
  });
  const resp = new NoiseXX({
    initiator: false,
    s: staticFromRaw(hex(v.resp_static)),
    e: staticFromRaw(hex(v.resp_ephemeral)),
    pro,
  });

  // --- the three handshake messages, byte for byte against the published values
  const hs = v.messages.slice(0, 3);

  const m0 = init.writeMessage(hex(hs[0].payload));
  assert.equal(m0.toString('hex'), hs[0].ciphertext, 'handshake message 1 must match exactly');
  assert.equal(resp.readMessage(m0).payload.toString('hex'), hs[0].payload);

  const m1 = resp.writeMessage(hex(hs[1].payload));
  assert.equal(m1.toString('hex'), hs[1].ciphertext, 'handshake message 2 must match exactly');
  assert.equal(init.readMessage(m1).payload.toString('hex'), hs[1].payload);

  const m2 = init.writeMessage(hex(hs[2].payload));
  assert.equal(m2.toString('hex'), hs[2].ciphertext, 'handshake message 3 must match exactly');
  assert.equal(resp.readMessage(m2).payload.toString('hex'), hs[2].payload);

  // --- the transcript hash, which is SPORE's channel binding and bind_sig input
  if (v.handshake_hash) {
    assert.equal(
      init.handshakeHash.toString('hex'), v.handshake_hash,
      'handshake_hash must match the published value — bind_sig and hypha_id depend on it',
    );
    assert.equal(resp.handshakeHash.toString('hex'), v.handshake_hash);
  }

  // --- Split(): the transport keys, verified by reproducing the vector's own transport
  //     messages rather than merely checking the two sides agree with each other
  const [iSend, iRecv] = init.split();
  const [rSend, rRecv] = resp.split();
  assert.ok(iSend.equals(rRecv), 'initiator send == responder recv');
  assert.ok(iRecv.equals(rSend), 'responder send == initiator recv');

  const seal = (key, n, pt) => {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(BigInt(n), 4);
    const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    c.setAAD(Buffer.alloc(0), { plaintextLength: pt.length });
    return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  };

  // Messages keep alternating across the handshake/transport boundary: 0,2,4... come
  // from the initiator and 1,3,5... from the responder. XX has three handshake messages,
  // so the FIRST transport message (index 3) is the responder's, not the initiator's.
  let iN = 0;
  let rN = 0;
  for (let k = 3; k < v.messages.length; k++) {
    const msg = v.messages[k];
    const fromInitiator = k % 2 === 0;
    const key = fromInitiator ? iSend : rSend;
    const n = fromInitiator ? iN++ : rN++;
    assert.equal(
      seal(key, n, hex(msg.payload)).toString('hex'), msg.ciphertext,
      `transport message ${k - 3} must match the published ciphertext`,
    );
  }
});
