import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  encodeHello, decodeHello, classify, broadcastFor, lanInterfaces, TYPE, FLAG, MAX_HELLO,
} from '../src/transport/beacon.js';

const id = generateKeyPairSync('ed25519');
const sporeId = id.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const networkKey = Buffer.from('spore-test-network');

const mk = (over = {}) => encodeHello({
  sporeId, bootId: randomBytes(8), announceSeq: 3, tcpPort: 47475,
  addrs: ['192.168.12.5'], nick: 'probe', networkKey, idPrivate: id.privateKey, ...over,
});

test('beacon: a valid HELLO round-trips every field', () => {
  const pkt = mk();
  assert.ok(pkt.length <= MAX_HELLO, 'must never fragment on a 1280-MTU path');

  const r = decodeHello(pkt, networkKey);
  assert.ok(r.ok, r.reason);
  assert.ok(r.hello.sporeId.equals(sporeId));
  assert.equal(r.hello.type, TYPE.HELLO);
  assert.equal(r.hello.flags, FLAG.DIALABLE_LAN);
  assert.equal(r.hello.announceSeq, 3);
  assert.equal(r.hello.tcpPort, 47475);
  assert.equal(r.hello.nick, 'probe');
  assert.deepEqual(r.hello.addrs, ['192.168.12.5']);
  assert.equal(r.hello.bootId.length, 8);
});

test('beacon: the staged gate rejects junk before it costs a signature verify', () => {
  const pkt = mk();

  assert.equal(decodeHello(Buffer.alloc(10), networkKey).reason, 'too_short');
  const badMagic = Buffer.from(pkt); badMagic.write('XXXX', 0);
  assert.equal(decodeHello(badMagic, networkKey).reason, 'bad_magic');
  const badVer = Buffer.from(pkt); badVer.writeUInt8(99, 4);
  assert.equal(decodeHello(badVer, networkKey).reason, 'bad_version');
  const badType = Buffer.from(pkt); badType.writeUInt8(0x77, 5);
  assert.equal(decodeHello(badType, networkKey).reason, 'bad_type');

  // wrong network key fails at the cheap proof tag, never reaching ed25519
  assert.equal(decodeHello(pkt, Buffer.from('other-network')).reason, 'bad_proof_tag');

  // tamper inside the signed region but keep the proof tag valid -> caught by signature
  const forged = Buffer.from(mk({ nick: 'evil' }));
  pkt.subarray(pkt.length - 64).copy(forged, forged.length - 64);
  assert.equal(decodeHello(forged, networkKey).ok, false);

  // truncation is caught rather than read out of bounds
  assert.equal(decodeHello(pkt.subarray(0, pkt.length - 1), networkKey).ok, false);
});

test('beacon: tunnel interfaces are refused so off-web is code, not a comment', () => {
  // the exact adapters the probe found on this machine
  assert.equal(classify('Tailscale', { family: 'IPv4', address: '100.85.132.85', internal: false }), 'tunnel');
  assert.equal(classify('Ethernet', { family: 'IPv4', address: '192.168.12.5', internal: false }), 'lan');

  // by name, whatever address it carries
  for (const n of ['tun0', 'utun3', 'wg0', 'tailscale0', 'ztabc123', 'nordlynx']) {
    assert.equal(classify(n, { family: 'IPv4', address: '10.0.0.1', internal: false }), 'tunnel', n);
  }
  // and by CGNAT range, whatever it is named — belt and braces
  assert.equal(classify('Ethernet 2', { family: 'IPv4', address: '100.100.0.1', internal: false }), 'tunnel');
  assert.equal(classify('lo', { family: 'IPv4', address: '127.0.0.1', internal: true }), 'loopback');

  // genuine LAN ranges still pass
  for (const a of ['192.168.1.1', '10.1.2.3', '172.16.0.9', '100.200.0.1']) {
    assert.equal(classify('eth0', { family: 'IPv4', address: a, internal: false }), 'lan', a);
  }

  // whatever this machine has, nothing tunnel-class survives enumeration
  for (const i of lanInterfaces()) assert.equal(i.cls, 'lan');
});

test('beacon: subnet-directed broadcast is computed correctly', () => {
  assert.equal(broadcastFor({ address: '192.168.12.5', netmask: '255.255.255.0' }), '192.168.12.255');
  assert.equal(broadcastFor({ address: '192.168.43.17', netmask: '255.255.255.0' }), '192.168.43.255');
  assert.equal(broadcastFor({ address: '172.20.10.3', netmask: '255.255.255.240' }), '172.20.10.15');
  assert.equal(broadcastFor({ address: '10.0.0.5', netmask: '255.0.0.0' }), '10.255.255.255');
});
