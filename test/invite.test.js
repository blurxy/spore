import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  mintInvite, readInvite, visibleOnly, carriesPayload, bytesToSelectors, selectorsToBytes,
} from '../src/app/invite.js';

function inviter() {
  const kp = generateKeyPairSync('ed25519');
  return { kp, id: kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32) };
}

const COVER = 'hey are we still on for friday';

function mint(over = {}) {
  const inv = over.inviter || inviter();
  return {
    inv,
    ...mintInvite({
      colonyId: over.colonyId || randomBytes(16),
      colonyName: over.colonyName ?? 'the basement',
      inviterId: inv.id,
      inviterPrivate: inv.kp.privateKey,
      nonce: over.nonce || randomBytes(16),
    }, over.cover ?? COVER),
  };
}

test('invite: hides inside innocuous text and survives the round trip', () => {
  const colonyId = randomBytes(16);
  const { inv, text, bytes } = mint({ colonyId, colonyName: 'the basement' });

  // a human sees only the cover text
  assert.equal(visibleOnly(text), COVER);
  assert.ok(text.length > COVER.length, 'payload must actually be present');
  assert.ok(carriesPayload(text));
  assert.ok(!carriesPayload(COVER));

  const r = readInvite(text);
  assert.ok(r.ok, r.reason);
  assert.ok(r.invite.colonyId.equals(colonyId));
  assert.equal(r.invite.colonyName, 'the basement');
  assert.ok(r.invite.inviterId.equals(inv.id));
  assert.equal(r.invite.burnId.length, 32);

  console.log(`      ${bytes} B hidden behind ${COVER.length} visible chars`);
});

test('invite: survives the things text actually goes through', () => {
  const { text } = mint();

  // pasted into a sentence, quoted, wrapped in markdown, surrounded by emoji
  const mangles = [
    (t) => `> ${t}`,
    (t) => `someone said: "${t}" earlier`,
    (t) => `**${t}**`,
    (t) => `🫐 ${t} 🫐`,
    (t) => `${t}\n\n--\nsent from my phone`,
    (t) => t.normalize('NFC'),
    (t) => t.normalize('NFD'),
    (t) => `${t} ${t}`.slice(0, t.length), // truncated back to itself
  ];
  for (const m of mangles) {
    const r = readInvite(m(text));
    assert.ok(r.ok, `should survive: ${m.toString().slice(0, 40)} -> ${r.reason}`);
  }

  // it is also carried by a completely empty cover
  assert.ok(readInvite(mint({ cover: '' }).text).ok);
});

test('invite: is destroyed by anything that strips non-printing characters', () => {
  const { text } = mint();

  // this is the honest limitation, asserted rather than hoped for
  assert.equal(readInvite(visibleOnly(text)).ok, false);
  assert.equal(readInvite(text.replace(/[︀-️]/gu, '')).ok, false);
  assert.equal(readInvite(COVER).reason, 'no_payload');
  assert.equal(readInvite('').reason, 'no_payload');
});

test('invite: forgery is rejected — encoding hides, the signature is what protects', () => {
  const { inv, text } = mint();

  // an attacker who re-encodes a mutated body cannot produce a valid signature
  const raw = selectorsToBytes(text);
  const tampered = Buffer.from(raw);
  tampered[tampered.length - 1] ^= 0xff;
  assert.equal(readInvite(COVER + bytesToSelectors(tampered)).ok, false);

  // garbage that is not a valid container
  assert.equal(readInvite(COVER + bytesToSelectors(randomBytes(200))).reason, 'bad_container');

  // a different colony's invite signed by the wrong key
  const other = inviter();
  const forged = mintInvite({
    colonyId: randomBytes(16),
    colonyName: 'not yours',
    inviterId: inv.id,              // claims to be the real inviter
    inviterPrivate: other.kp.privateKey, // but signs with a different key
    nonce: randomBytes(16),
  }, COVER);
  assert.equal(readInvite(forged.text).reason, 'bad_signature');
});

test('invite: burnId is deterministic per invite and unique across invites', () => {
  const colonyId = randomBytes(16);
  const nonce = randomBytes(16);
  const inv = inviter();

  const a = readInvite(mint({ inviter: inv, colonyId, nonce }).text);
  const b = readInvite(mint({ inviter: inv, colonyId, nonce, cover: 'different cover' }).text);
  assert.ok(a.invite.burnId.equals(b.invite.burnId), 'same colony+nonce burns the same id');

  const c = readInvite(mint({ inviter: inv, colonyId, nonce: randomBytes(16) }).text);
  assert.ok(!a.invite.burnId.equals(c.invite.burnId), 'a fresh nonce is a distinct invite');
});

test('invite: the selector codec round-trips every byte value', () => {
  const all = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.ok(selectorsToBytes(bytesToSelectors(all)).equals(all), 'all 256 byte values');

  for (let i = 0; i < 50; i++) {
    const b = randomBytes(1 + Math.floor(Math.random() * 500));
    assert.ok(selectorsToBytes(bytesToSelectors(b)).equals(b));
  }
  assert.equal(selectorsToBytes(bytesToSelectors(Buffer.alloc(0))).length, 0);
});
