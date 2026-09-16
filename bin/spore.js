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
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, logIdFor, deriveLamport, TYPE, FLAG } from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';
import { Syncer } from '../src/sharding/sync.js';
import { blockFits } from '../src/sharding/wire.js';
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

// The log is NAMED BY ITS AUTHOR: log_id = hash256(spore_id)[0..16]. Not a random id.
// Once blocks travel through third parties, a log has to carry proof of who may write it,
// and this binding is that proof — it lives inside the signed header of every block.
const logId = logIdFor(sporeId);
let seq = 0n;
let lamport = 0n;
let prevHash = Buffer.alloc(32);

const beacon = new Beacon({
  sporeId, idPrivate: idKeys.privateKey, networkKey: NETWORK_KEY,
  nick: NICK, telemetry: tel, tcpPort: PORT,
});
const mgr = new HyphaManager({
  sporeId, staticKeys, idPublicRaw: sporeId, idPrivate: idKeys.privateKey,
  telemetry: tel, port: PORT,
});

const substrate = new Substrate({ telemetry: tel });
const sync = new Syncer({ substrate, hyphaManager: mgr, telemetry: tel, selfPub: sporeId, selfLogId: logId });

const view = new MyceliumView(tel, { nick: NICK, sporeId: sporeId.toString('hex') });

// --- the substrate: append a signed block, push it, let the syncer serve it ---------
//
// Two paths now, and they are deliberately different. `say()` PUSHES: a live message goes
// straight to every hypha, unscheduled, because latency is what matters and there is
// nothing to schedule. The Syncer PULLS: history is fetched rarest-first from whoever has
// it, because throughput is what matters and there is a lot to schedule. Conflating them
// would make live chat wait behind a backlog, which is the wrong trade in both directions.
function say(text) {
  const payload = Buffer.from(text, 'utf8');
  seq += 1n;
  lamport = deriveLamport(lamport, []);
  const { cert, blockHash } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId, seq, lamport, prevHash, payload },
    idKeys.privateKey,
  );
  if (!blockFits(cert.length, payload.length)) {
    view.log('TOO BIG', 'message exceeds one frame', PAL.alarm);
    seq -= 1n;
    return 0;
  }
  prevHash = blockHash;

  // Into our own substrate first. We are a replica of our own log like any other, and
  // serving it to peers goes through exactly the same path theirs does.
  const res = substrate.insert(cert, payload, sporeId, 'self');
  if (!res.ok) {
    view.log('REJECT', `own block: ${res.reason}`, PAL.alarm);
    return 0;
  }

  const n = sync.push(cert, payload);
  sync.announce(logId, Number(seq));
  tel.count('hypha.bytes', (cert.length + payload.length) * Math.max(1, n));
  tel.event('substrate.appended', { seq: Number(seq), lamport: Number(lamport), toPeers: n, text });
  view.lamport = Number(lamport);
  view.message(NICK, text);
  return n;
}

mgr.on('message', ({ payload }) => tel.count('hypha.bytes', payload.length));

// Every accepted block, however it arrived — pushed live or pulled from a backlog. The
// substrate has already verified the signature against the key the LOG ID names, not
// against whoever handed it over, so a block relayed by a stranger is worth exactly as
// much as one from its author.
substrate.on('block', ({ logId: lid, seq: s, block, payload, from }) => {
  if (lid.equals(logId)) return; // our own, already shown by say()
  lamport = deriveLamport(lamport, [block.lamport]);
  view.lamport = Number(lamport);
  const who = lid.toString('hex').slice(0, 6);
  tel.event('substrate.verified', { from, log: who, seq: s, lamport: Number(block.lamport) });
  if (block.type === TYPE.MESSAGE) view.message(who, payload.toString('utf8').slice(0, 200));
});

substrate.on('equivocation', ({ logId: lid, seq: s }) => {
  // The author signed two different blocks at one seq. Both signatures are valid, so this
  // is not a network fault — it is that spore contradicting itself, and it is permanent.
  view.log('FORKED', `${lid.toString('hex').slice(0, 6)} signed twice at seq ${s}`, PAL.alarm);
});

sync.on('complete', ({ logId: lid, blocks }) => {
  view.log('GRAFTED', `${lid.toString('hex').slice(0, 6)} · ${blocks} blocks`, PAL.core);
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
  sync.start();

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
  sync.stop();
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
