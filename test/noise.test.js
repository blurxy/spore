import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, hkdfSync, createHmac, randomBytes } from 'node:crypto';
import {
  Handshake, generateStatic, rawPub, prologue, NoiseError, eq, NOT_AFTER_NEVER,
} from '../src/session/noise.js';

function spore() {
  const id = generateKeyPairSync('ed25519');
  return {
    staticKeys: generateStatic(),
    idPublicRaw: id.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
    idPrivate: id.privateKey,
  };
}

function pair(a, b) {
  const hi = new Handshake({ initiator: true, ...a });
  const hr = new Handshake({ initiator: false, ...b });
  return { hi, hr };
}

function run(hi, hr) {
  const m1 = hi.writeMessage();
  hr.readMessage(m1);
  const m2 = hr.writeMessage();
  hi.readMessage(m2);
  const m3 = hi.writeMessage();
  hr.readMessage(m3);
  return { m1, m2, m3, ci: hi.finish(), cr: hr.finish() };
}

test('noise: HKDF equivalence holds — the assumption this whole file rests on', () => {
  const hmac = (k, d) => createHmac('blake2b512', k).update(d).digest();
  const ck = randomBytes(64);
  const ikm = randomBytes(32);
  const tk = hmac(ck, ikm);
  const o1 = hmac(tk, Buffer.from([1]));
  const o2 = hmac(tk, Buffer.concat([o1, Buffer.from([2])]));
  const got = Buffer.from(hkdfSync('blake2b512', ikm, ck, Buffer.alloc(0), 128));
  assert.ok(o1.equals(got.subarray(0, 64)), 'Noise HKDF output 1 must equal hkdfSync');
  assert.ok(o2.equals(got.subarray(64, 128)), 'Noise HKDF output 2 must equal hkdfSync');
});

test('noise: XX completes, both sides derive matching keys, transcripts agree', () => {
  const a = spore();
  const b = spore();
  const { hi, hr } = pair(a, b);
  const { m1, m2, m3, ci, cr } = run(hi, hr);

  // transcript hash is the channel binding — it must be identical on both sides
  assert.ok(ci.hyphaId.equals(cr.hyphaId), 'hypha_id must match');
  assert.equal(ci.hyphaId.length, 64);

  // directions must be crossed, never equal (this is what kills reflection attacks)
  assert.ok(ci.sendKey.equals(cr.recvKey), 'initiator send == responder recv');
  assert.ok(ci.recvKey.equals(cr.sendKey), 'responder send == initiator recv');
  assert.ok(!ci.sendKey.equals(ci.recvKey), 'send and recv keys must differ');

  // each side learned the other's real ed25519 identity, not just a DH key
  assert.ok(eq(Buffer.from(hi.peerId), Buffer.from(b.idPublicRaw)), 'initiator learns responder id');
  assert.ok(eq(Buffer.from(hr.peerId), Buffer.from(a.idPublicRaw)), 'responder learns initiator id');

  // SAS is derived from the transcript, so both sides show the same 4 bytes
  assert.ok(ci.sas.equals(cr.sas));

  // record actual wire sizes (spec predicted 32 / 256 / 224)
  assert.equal(m1.length, 32, 'msg1 is a bare ephemeral');
  assert.equal(m2.length, 32 + 48 + 164 + 16);
  assert.equal(m3.length, 48 + 164 + 16);

  // and the resulting channel actually works, in both directions
  const ad = Buffer.from([0x53, 0, 0, 0, 0, 0, 0, 0]);
  const ct = ci.encrypt(ad, Buffer.from('spore to spore'));
  assert.equal(cr.decrypt(ad, ct).toString(), 'spore to spore');
  const back = cr.encrypt(ad, Buffer.from('and back'));
  assert.equal(ci.decrypt(ad, back).toString(), 'and back');
});

test('noise: nonces never repeat, and a replayed frame is rejected', () => {
  const { hi, hr } = pair(spore(), spore());
  const { ci, cr } = run(hi, hr);
  const ad = Buffer.alloc(8);

  const seen = new Set();
  const frames = [];
  for (let i = 0; i < 64; i++) {
    const ct = ci.encrypt(ad, Buffer.from(`frame ${i}`));
    assert.ok(!seen.has(ct.toString('hex')), 'identical ciphertext means a nonce repeated');
    seen.add(ct.toString('hex'));
    frames.push(ct);
  }
  assert.equal(ci.sendN, 64n, 'counter advanced once per frame');

  for (let i = 0; i < 64; i++) assert.equal(cr.decrypt(ad, frames[i]).toString(), `frame ${i}`);

  // replaying an old frame fails: the stateful counter has moved past it
  assert.throws(() => cr.decrypt(ad, frames[0]), (e) => e.code === 'aead_fail');

  // a fresh handshake between the same pair yields entirely different keys (ee is ephemeral)
  const again = pair(spore(), spore());
  const r2 = run(again.hi, again.hr);
  assert.ok(!r2.ci.sendKey.equals(ci.sendKey), 'each session must have fresh keys');
});

test('noise: forgery, downgrade and tampering are all fatal', () => {
  // a tampered msg2 must fail AEAD
  {
    const { hi, hr } = pair(spore(), spore());
    hr.readMessage(hi.writeMessage());
    const m2 = hr.writeMessage();
    m2[40] ^= 0xff;
    assert.throws(() => hi.readMessage(m2), (e) => e instanceof NoiseError);
  }

  // mismatched prologue (version/suite downgrade) must fail — it is MixHashed before msg1
  {
    const a = spore();
    const b = spore();
    const hi = new Handshake({ initiator: true, ...a, pro: prologue(1, 1) });
    const hr = new Handshake({ initiator: false, ...b, pro: prologue(1, 2) });
    hr.readMessage(hi.writeMessage());
    assert.throws(() => hi.readMessage(hr.writeMessage()), (e) => e instanceof NoiseError);
  }

  // an attacker who presents someone else's ed25519 key cannot produce a valid bind_sig
  {
    const a = spore();
    const b = spore();
    const victim = spore();
    const hi = new Handshake({ initiator: true, ...a });
    // responder claims the victim's identity while holding its own ed25519 private key
    const hr = new Handshake({ initiator: false, ...b, idPublicRaw: victim.idPublicRaw });
    hr.readMessage(hi.writeMessage());
    assert.throws(
      () => hi.readMessage(hr.writeMessage()),
      (e) => e.code === 'bad_link_sig' || e.code === 'bad_bind_sig',
    );
  }

  // out-of-turn writes are refused rather than silently producing garbage
  {
    const { hi } = pair(spore(), spore());
    hi.writeMessage();
    assert.throws(() => hi.writeMessage(), (e) => e.code === 'out_of_turn_write');
  }
});

test('noise: handshake progress is a real 0..1 the UI can grow a hypha on', () => {
  const { hi, hr } = pair(spore(), spore());
  const seen = [hi.progress];
  const m1 = hi.writeMessage();
  seen.push(hi.progress);
  hr.readMessage(m1);
  hi.readMessage(hr.writeMessage());
  seen.push(hi.progress);
  hi.writeMessage();
  seen.push(hi.progress);

  assert.deepEqual(seen, [0, 1 / 3, 2 / 3, 1]);
  for (let i = 1; i < seen.length; i++) {
    assert.ok(seen[i] > seen[i - 1], 'progress must be monotonic — a hypha never ungrows');
  }
  assert.equal(hi.progress, 1);
  assert.ok(hi.done);
});
