#!/usr/bin/env node
// SPORE — an off-web mycelial mesh.
//
//   node bin/spore.js                    grow a spore
//   node bin/spore.js --nick alice       ...with a name
//   node bin/spore.js --headless         no TUI, log lines only (for two-terminal tests)
//   node bin/spore.js --port 47600       move the hypha listener
//
// Zero dependencies. No internet. No bootstrap node. If you are the only one running
// it, the whole network is your machine, and that is a correct network.

import { generateKeyPairSync, createHash } from 'node:crypto';
import { Telemetry } from '../src/telemetry/bus.js';
import { Beacon, HYPHA_PORT } from '../src/transport/beacon.js';
import { HyphaManager } from '../src/transport/tcp.js';
import { generateStatic, edPub } from '../src/session/noise.js';
import { encodeBlock, verifyBlock, newLogId, deriveLamport, TYPE, FLAG } from '../src/substrate/block.js';
import { Screen } from '../src/ui/canvas.js';
import { MyceliumView, PAL } from '../src/ui/mycelium.js';

const argv = process.argv.slice(2);
const flag = (n, d = null) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? (argv[i + 1]?.startsWith('--') ? true : argv[i + 1] ?? true) : d;
};
const has = (n) => argv.includes(`--${n}`);

const NICK = String(flag('nick', `spore-${process.pid}`));
const PORT = Number(flag('port', HYPHA_PORT));
const HEADLESS = has('headless') || !process.stdout.isTTY;

// The network key scopes a mesh. Everyone who shares it can find each other; it is not
// a secret and provides no confidentiality — it is a cheap pre-signature junk filter.
const NETWORK_KEY = createHash('blake2b512').update(String(flag('net', 'spore-default'))).digest();

const tel = new Telemetry();
tel.trackRate('hypha.bytes');
tel.trackRate('beacon.sent');

const idKeys = generateKeyPairSync('ed25519');
const sporeId = idKeys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const staticKeys = generateStatic();
const logId = newLogId();
let seq = 0n;
let lamport = 0n;

const beacon = new Beacon({
  sporeId, idPrivate: idKeys.privateKey, networkKey: NETWORK_KEY,
  nick: NICK, telemetry: tel, tcpPort: PORT,
});
const mgr = new HyphaManager({
  sporeId, staticKeys, idPublicRaw: sporeId, idPrivate: idKeys.privateKey,
  telemetry: tel, port: PORT,
});

const view = new MyceliumView(tel, { nick: NICK, sporeId: sporeId.toString('hex') });

// --- the substrate: append a signed block, broadcast cert + payload ---------------
function say(text) {
  const payload = Buffer.from(text, 'utf8');
  seq += 1n;
  lamport = deriveLamport(lamport, []);
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId, seq, lamport, payload },
    idKeys.privateKey,
  );
  const wire = Buffer.concat([cert, payload]);
  const n = mgr.broadcast(wire);
  tel.count('hypha.bytes', wire.length * Math.max(1, n));
  tel.event('substrate.appended', { seq: Number(seq), lamport: Number(lamport), toPeers: n, text });
  view.message(NICK, text);
  return n;
}

mgr.on('message', ({ hypha, payload }) => {
  tel.count('hypha.bytes', payload.length);
  // Everything a peer sends is untrusted until the signature says otherwise, and we
  // verify against the identity the HANDSHAKE proved — never against a claim in the frame.
  const CERT_LEN = 196 + 64;
  if (payload.length < CERT_LEN) return;
  const cert = payload.subarray(0, CERT_LEN);
  const body = payload.subarray(CERT_LEN);

  const v = verifyBlock(cert, edPub(Buffer.from(hypha.peerId)), body);
  if (!v.ok) {
    tel.count(`substrate.reject.${v.reason.split(':')[0]}`);
    view.log('REJECT', v.reason, PAL.alarm);
    return;
  }
  lamport = deriveLamport(lamport, [v.block.lamport]);
  const who = Buffer.from(hypha.peerId).toString('hex').slice(0, 6);
  tel.event('substrate.verified', {
    from: who,
    seq: Number(v.block.seq),
    lamport: Number(v.block.lamport),
    text: body.toString('utf8').slice(0, 60),
  });
  view.message(who, body.toString('utf8').slice(0, 200));
});

// --- discovery -> dial ------------------------------------------------------------
beacon.on('peer', (peer) => {
  // Deterministic: only the lower spore_id dials, so we never race ourselves.
  if (mgr.shouldDial(peer.sporeId)) mgr.dial(peer);
});

// --- run --------------------------------------------------------------------------
const screen = HEADLESS ? null : new Screen(process.stdout);
let raf = null;

async function main() {
  await mgr.listen();
  await beacon.start();

  if (HEADLESS) {
    tel.on('telemetry', ({ kind, payload }) => {
      const brief = kind === 'hypha.handshake.progress'
        ? `progress ${(payload.progress * 100) | 0}%`
        : JSON.stringify(payload ?? {}, (k, v) => (Buffer.isBuffer(v) ? v.toString('hex').slice(0, 12) : v)).slice(0, 120);
      console.log(`${String(tel.ms() | 0).padStart(7)}ms  ${kind.padEnd(28)} ${brief}`);
    });
    console.log(`SPORE ${sporeId.toString('hex').slice(0, 16)} "${NICK}" on :${PORT}`);
    console.log('MESSAGES ARE NOT ENCRYPTED — SP1 has no content confidentiality.');
    setInterval(() => say(`${NICK} pulse`), 5000);
  } else {
    screen.enter();
    const loop = () => {
      view.step();
      screen.paint((cv) => view.draw(cv));
      raf = setTimeout(loop, 33); // 30fps; probe 3 says we have ~66x headroom at 60
    };
    loop();

    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    let line = '';
    process.stdin.on('data', (b) => {
      const s = b.toString();
      if (s === '\u0003' || s === '\u0004') return shutdown();
      if (s === '\r' || s === '\n') {
        if (line.trim()) say(line.trim());
        line = '';
      } else if (s === '\u007f') line = line.slice(0, -1);
      else if (s >= ' ') line += s;
    });
  }
}

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearTimeout(raf);
  if (screen) {
    const s = screen.stats;
    screen.exit();
    console.log(`\nframes ${s.frames} · ${s.msPerFrame.toFixed(3)} ms/frame · ${s.bytesPerFrame} B/frame`);
  }
  await beacon.stop();
  await mgr.stop();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

main().catch((e) => {
  if (screen) screen.exit();
  console.error('spore failed to germinate:', e);
  process.exit(1);
});
