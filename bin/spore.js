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
import { Glass } from '../src/ui/glass.js';

const argv = process.argv.slice(2);
const flag = (n, d = null) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? (argv[i + 1]?.startsWith('--') ? true : argv[i + 1] ?? true) : d;
};
const has = (n) => argv.includes(`--${n}`);

const NICK = String(flag('nick', `spore-${process.pid}`));
const PORT = Number(flag('port', HYPHA_PORT));
const HEADLESS = has('headless') || !process.stdout.isTTY;
// --glass opens the same view in a browser on this device, for the hardware the mesh is
// actually for. Off unless asked: it is a second surface, and a surface that is not
// running cannot be got at. Loopback only, read-only — see src/ui/glass.js.
const GLASS = has('glass') ? Number(flag('glass', 7777)) || 7777 : 0;

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
// -1 so the first append is seq 0. A log's genesis is seq 0 by definition — relink()
// looks for it there and stops dead if it is missing, which meant a spore's own log never
// linked at all and its messages never reached the ordered-delivery path. Unit tests could
// not see this: they build chains from 0 directly and never go through say().
let seq = -1n;
let ownPrev = 0n;   // lamport of OUR last block — the only input we may assert from
let lamport = 0n;   // local causal clock, for display; never stamped into a block
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
/**
 * The most recent thing we have seen from somebody else, as a citable dep.
 *
 * Only LINKED blocks qualify. That is stricter than it strictly needs to be — a receiver
 * derives lamport from a dep's ORDERED position, and a block stopped on authority is still
 * ordered — but citing something the receiver has not delivered would put a dep in our log
 * on a block their user never saw. Held-but-unordered is genuinely unusable: its lamport
 * has not been validated, so citing it stalls our block at every receiver until it is.
 */
function latestForeignDep() {
  let best = null;
  for (const r of substrate.logs.values()) {
    if (r.logId.equals(logId) || r.linkedTo < 0) continue;
    const b = r.get(r.linkedTo);
    if (b && (!best || b.lamport > best.lamport)) best = { hash: b.hash, lamport: b.lamport };
  }
  return best;
}

function say(text) {
  const payload = Buffer.from(text, 'utf8');
  seq += 1n;

  // Lamport must be DERIVABLE BY THE RECEIVER, not merely correct here. The rule is
  // 1 + max(own previous, all deps), so anything that raised our clock has to be cited —
  // otherwise a peer recomputing the value gets a different number, and under the new
  // link-time check their frontier stops at our block. Absorbing other spores' lamports
  // into a local counter and stamping THAT was the old behaviour, and it was unverifiable
  // by construction: it asserted a number nobody else could reproduce.
  const dep = latestForeignDep();
  const cite = dep && dep.lamport >= ownPrev ? dep : null;
  const deps = cite ? [cite.hash] : [];
  const lam = deriveLamport(ownPrev, cite ? [cite.lamport] : []);

  const { cert, blockHash } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId, seq, lamport: lam, prevHash, payload, deps },
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

  ownPrev = lam;
  if (lam > lamport) lamport = lam;
  const n = sync.push(cert, payload);
  sync.announce(logId, Number(seq));
  tel.count('hypha.bytes', (cert.length + payload.length) * Math.max(1, n));
  tel.event('substrate.appended', { seq: Number(seq), lamport: Number(lam), deps: deps.length, toPeers: n, text });
  view.lamport = Number(lamport);
  view.message(NICK, text);
  return n;
}

mgr.on('message', ({ payload }) => tel.count('hypha.bytes', payload.length));

// Two different questions, answered in two different places.
//
// HAVE WE SEEN IT? — 'block'. Fires the moment a block is accepted, in whatever order it
// arrived, because a signature is self-contained. Causality advances here: we have
// observed that block, so our lamport must account for it even if the blocks before it
// are still in flight.
substrate.on('block', ({ logId: lid, seq: s, block, from }) => {
  if (lid.equals(logId)) return; // our own
  tel.event('substrate.verified', { from, log: lid.toString('hex').slice(0, 6), seq: s, lamport: Number(block.lamport) });
});

// CAN WE READ IT IN ORDER? — 'linked'. Rarest-first deliberately fetches out of order, so
// showing messages as they land would scramble a backlog on screen. The linked frontier
// only advances along prev_hash from seq 0, so this fires in log order, in runs, as gaps
// close. The design note says scheduling reads `held` and ordered delivery reads `linked`;
// this is the line where the interface actually obeys it.
substrate.on('linked', ({ logId: lid, seqs }) => {
  const rep = substrate.replica(lid.toString('hex'));
  // The causal clock advances on VALIDATED blocks only. It used to advance on every held
  // block, using a lamport nothing had checked — so one peer asserting 2^60 dragged every
  // spore that merely RECEIVED it to 2^60, forever. That is the inflation attack the spec
  // claimed was closed.
  for (const s of seqs) {
    const b = rep?.get(s);
    if (b && b.lamport > lamport) lamport = b.lamport;
  }
  view.lamport = Number(lamport);
  if (lid.equals(logId)) return; // our own, already shown by say()
  const who = lid.toString('hex').slice(0, 6);
  for (const s of seqs) {
    const b = rep?.get(s);
    if (b && b.type === TYPE.MESSAGE) view.message(who, b.payload.toString('utf8').slice(0, 200));
  }
});

substrate.on('equivocation', ({ logId: lid, seq: s }) => {
  // The author signed two different blocks at one seq. Both signatures are valid, so this
  // is not a network fault — it is that spore contradicting itself, and it is permanent.
  // The log stops here for everyone who knows, which is why the proof gets passed on.
  view.log('FORKED', `${lid.toString('hex').slice(0, 6)} signed twice at seq ${s} · log ends`, PAL.alarm);
});

// History we had accepted and can no longer stand behind. Saying so is the point: we
// linked those blocks in good faith, then got proof the author was writing more than one
// past. An interface that cannot show a retraction is one you cannot trust when it shows
// nothing.
substrate.on('retracted', ({ logId: lid, seqs }) => {
  view.log('RETRACTED', `${lid.toString('hex').slice(0, 6)} · seq ${seqs[0]}–${seqs.at(-1)} withdrawn`, PAL.alarm);
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
const glass = GLASS ? new Glass(tel, { nick: NICK, sporeId: sporeId.toString('hex'), port: GLASS }) : null;
let raf = null;

async function main() {
  await mgr.listen();
  await beacon.start();
  sync.start();
  if (glass) {
    const at = await glass.listen();
    // Printed even in the TUI, where it scrolls past above the alt-screen — the address is
    // the only way to find it and a UI you cannot find is not shipped.
    console.log(`GLASS ${at}`);
  }

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
  if (glass) await glass.stop();
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
