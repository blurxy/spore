import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { HyphaManager, dialAllowed, FrameReader, frame, MAX_FRAME } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, verifyBlock, newLogId, TYPE, FLAG } from '../src/substrate/block.js';
import { Telemetry } from '../src/telemetry/bus.js';

function spore(port) {
  const id = generateKeyPairSync('ed25519');
  const idPublicRaw = id.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const tel = new Telemetry();
  return {
    id,
    idPublicRaw,
    tel,
    mgr: new HyphaManager({
      sporeId: idPublicRaw,
      staticKeys: generateStatic(),
      idPublicRaw,
      idPrivate: id.privateKey,
      telemetry: tel,
      port,
    }),
  };
}

test('hypha: two spores handshake over real sockets and exchange a signed block', async () => {
  const a = spore(47501);
  const b = spore(47502);
  await a.mgr.listen();
  await b.mgr.listen();

  const progress = [];
  b.tel.on('hypha.handshake.progress', (p) => progress.push(p.progress));

  const established = new Promise((res) => a.mgr.once('hypha', res));
  const hypha = await b.mgr.dial({ sporeId: a.idPublicRaw, addrs: ['127.0.0.1'], tcpPort: 47501 });
  assert.ok(hypha, 'dial must produce a hypha');
  const peerSide = await established;

  // both sides authenticated the other's real ed25519 identity
  assert.ok(Buffer.from(hypha.peerId).equals(a.idPublicRaw));
  assert.ok(Buffer.from(peerSide.peerId).equals(b.idPublicRaw));

  // same transcript, same short authentication string
  assert.ok(hypha.hyphaId.equals(peerSide.hyphaId));
  assert.ok(hypha.sas.equals(peerSide.sas));

  // handshake progress really was observed advancing — this is what the UI grows on
  assert.ok(progress.length >= 2, `expected progress events, got ${progress.length}`);
  assert.equal(progress.at(-1), 1);
  for (let i = 1; i < progress.length; i++) assert.ok(progress[i] >= progress[i - 1]);

  // now send a real signed block across the encrypted hypha
  const logId = newLogId();
  const payload = Buffer.from('the mycelium found itself');
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId, seq: 1, lamport: 1, payload },
    b.id.privateKey,
  );

  const got = new Promise((res) => peerSide.once('message', res));
  hypha.send(Buffer.concat([cert, payload]));
  const received = await got;

  // the receiver verifies it against the identity the handshake proved, not a claim in the frame
  const certLen = cert.length;
  const v = verifyBlock(
    received.subarray(0, certLen),
    b.id.publicKey,
    received.subarray(certLen),
  );
  assert.ok(v.ok, `block must verify: ${v.reason}`);
  assert.equal(received.subarray(certLen).toString(), 'the mycelium found itself');
  assert.equal(v.block.lamport, 1n);

  await a.mgr.stop();
  await b.mgr.stop();
});

test('hypha: dialing anything outside the LAN allowlist is refused', () => {
  for (const h of ['192.168.1.9', '10.0.0.4', '172.16.5.5', '127.0.0.1', '169.254.1.1']) {
    assert.equal(dialAllowed(h).ok, true, h);
  }
  // public internet
  for (const h of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
    assert.equal(dialAllowed(h).ok, false, h);
  }
  // Tailscale CGNAT — deliberately excluded per ARCHITECTURE 1.3
  for (const h of ['100.85.132.85', '100.64.0.1', '100.127.255.254']) {
    assert.equal(dialAllowed(h).ok, false, `${h} must be refused: it is the tunnel loophole`);
  }
  // but genuine public 100.x outside CGNAT is also refused, as it should be
  assert.equal(dialAllowed('100.200.0.1').ok, false);
});

test('hypha: framing preserves message boundaries and refuses oversize', () => {
  const out = [];
  let err = null;
  const r = new FrameReader((f) => out.push(f.toString()), (e) => { err = e; });

  // three messages arriving as one chunk
  r.push(Buffer.concat([frame(Buffer.from('one')), frame(Buffer.from('two')), frame(Buffer.from('three'))]));
  assert.deepEqual(out, ['one', 'two', 'three']);

  // one message arriving byte by byte
  out.length = 0;
  const f = frame(Buffer.from('dribbled'));
  for (const byte of f) r.push(Buffer.from([byte]));
  assert.deepEqual(out, ['dribbled']);

  // an oversize length prefix is refused BEFORE allocating
  const evil = Buffer.alloc(4);
  evil.writeUInt32LE(MAX_FRAME + 1);
  r.push(evil);
  assert.ok(err, 'oversize frame must error rather than allocate');
});
