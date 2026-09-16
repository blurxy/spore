#!/usr/bin/env node
// THE HARNESS. The benchmark measures a model; this measures the thing.
//
//   node bench/mesh.js --seed              serve a corpus, wait for joiners
//   node bench/mesh.js --join              find sources, pull the corpus, report
//   node bench/mesh.js --join --sources 3  refuse to start until 3 sources are present
//
// Every part of this is the shipped stack: real multicast discovery, real Noise
// handshakes, the real substrate, the real rarest-first scheduler over real sockets. The
// only thing invented here is the corpus, and it is invented identically on every device.
//
// WHY THE CORPUS IS DETERMINISTIC
//
// Multiple sources are only interchangeable if they hold the SAME log. A random identity
// per device would produce a different log_id on each one, the joiner would see N separate
// logs with one source apiece, and the measurement would be N independent downloads
// wearing a swarm costume. So the author key is derived from the corpus name: every device
// running `--seed --corpus alpha` serves byte-identical blocks under one log_id and is a
// genuine alternative source for every block.
//
// The private key is therefore PUBLIC. That is correct for a harness and catastrophic for
// anything else, which is why this file refuses to touch a real colony's network key.
//
// WHAT TO MEASURE
//
// Run the joiner against 1 source, then 2, then 3, on the same AP, and compare
// time-to-complete. ARCHITECTURE.md 3.1 predicts the knee at N=4 on a good AP (uplink
// 7.5 MB/s against a 25 MB/s cell) and a hard flat line after it. A phone hotspot should
// bend much earlier and lower. If the curve keeps climbing past N=5 on one AP, the model
// in bench/curve.js is wrong and this harness is how we find out.

import { createPrivateKey, createPublicKey, createHash, generateKeyPairSync } from 'node:crypto';
import { Telemetry } from '../src/telemetry/bus.js';
import { Beacon, HYPHA_PORT } from '../src/transport/beacon.js';
import { HyphaManager } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, logIdFor, TYPE, FLAG } from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';
import { Syncer } from '../src/sharding/sync.js';
import { blockFits } from '../src/sharding/wire.js';

const argv = process.argv.slice(2);
const has = (n) => argv.includes(`--${n}`);
const flag = (n, d) => {
  const i = argv.indexOf(`--${n}`);
  if (i < 0) return d;
  const v = argv[i + 1];
  return v === undefined || v.startsWith('--') ? true : v;
};

const MODE = has('seed') ? 'seed' : has('join') ? 'join' : null;
const CORPUS = String(flag('corpus', 'alpha'));
const BLOCKS = Number(flag('blocks', 400));
const BLOCK_BYTES = Number(flag('bytes', 32768));
const PORT = Number(flag('port', HYPHA_PORT));
const WANT_SOURCES = Number(flag('sources', 1));
const LABEL = String(flag('label', `${MODE}-${process.pid}`));

if (!MODE) {
  console.error('usage: node bench/mesh.js --seed | --join [--corpus alpha] [--blocks 400] [--sources N]');
  process.exit(2);
}

// A harness network, never the default. Two reasons: a real colony must not be polluted
// with corpus traffic, and the corpus author key below is published in this file.
const NETWORK_KEY = createHash('blake2b512').update(`spore-harness-${CORPUS}`).digest();

// --- the corpus -------------------------------------------------------------------

/**
 * Deterministic ed25519 from a 32-byte seed.
 *
 * Node will not generate a keypair from a seed, but an Ed25519 PKCS8 key IS its seed with
 * a fixed 16-byte DER prefix, so we can hand it one directly. No key derivation, no
 * dependency, and every device that types the same corpus name gets the same author.
 */
function authorFor(corpus) {
  const seed = createHash('sha256').update(`spore-corpus-${corpus}`).digest();
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, pub, logId: logIdFor(pub) };
}

/** Byte-identical on every device: same author, same payloads, same hashes. */
function buildCorpus(author, n, bytes) {
  const blocks = [];
  let prevHash = Buffer.alloc(32);
  for (let i = 0; i < n; i++) {
    // Cheap, deterministic, and not compressible into nothing by any transport we use.
    const payload = Buffer.alloc(bytes);
    const tag = createHash('sha256').update(`${author.logId.toString('hex')}:${i}`).digest();
    for (let o = 0; o < bytes; o += 32) tag.copy(payload, o);
    payload.writeUInt32LE(i, 0);

    if (!blockFits(260, bytes)) throw new Error(`block of ${bytes} B does not fit one frame`);
    const { cert, blockHash } = encodeBlock(
      {
        type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE,
        logId: author.logId, seq: i, lamport: i + 1, prevHash, payload,
      },
      author.privateKey,
    );
    blocks.push({ cert, payload });
    prevHash = blockHash;
  }
  return blocks;
}

// --- run --------------------------------------------------------------------------

const author = authorFor(CORPUS);
const tel = new Telemetry();
const idKeys = generateKeyPairSync('ed25519');
const sporeId = idKeys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

const store = new Substrate({ telemetry: tel });
const mgr = new HyphaManager({
  sporeId, staticKeys: generateStatic(), idPublicRaw: sporeId,
  idPrivate: idKeys.privateKey, telemetry: tel, port: PORT,
});
const beacon = new Beacon({
  sporeId, idPrivate: idKeys.privateKey, networkKey: NETWORK_KEY,
  nick: LABEL, telemetry: tel, tcpPort: PORT,
});
const sync = new Syncer({ substrate: store, hyphaManager: mgr, telemetry: tel, selfPub: sporeId });

const KEY = author.logId.toString('hex');
const MB = (b) => (b / 1048576).toFixed(2);
const log = (s) => console.log(`${String(Math.round(tel.ms())).padStart(7)}ms  ${s}`);

beacon.on('peer', (peer) => {
  if (mgr.shouldDial(peer.sporeId)) mgr.dial(peer);
});

// --dial host:port — repeatable. Discovery is multicast and Termux has no MulticastLock, so
// phone-to-phone may never discover even where sync works perfectly. Without this, that
// failure and a genuinely broken mesh look identical, and the whole measurement is blocked
// on a device you may not get back. See HyphaManager#dialAddr.
const DIAL = argv.reduce((acc, a, i) => (a === '--dial' && argv[i + 1] && !argv[i + 1].startsWith('--')
  ? [...acc, argv[i + 1]] : acc), []);
mgr.on('hypha', (h) => {
  log(`hypha  ${Buffer.from(h.peerId).toString('hex').slice(0, 8)}  live=${mgr.hyphae.size}`);
});

let started = null;
let finished = false;

async function main() {
  await mgr.listen();
  await beacon.start();
  sync.start();

  for (const at of DIAL) {
    const ix = at.lastIndexOf(':');
    const host = ix > 0 ? at.slice(0, ix) : at;
    const port = ix > 0 ? Number(at.slice(ix + 1)) : PORT;
    console.log(`DIAL ${host}:${port}`);
    mgr.dialAddr(host, port).then((h) => {
      if (!h) console.log(`DIAL ${host}:${port} FAILED — discovery aside, this peer is unreachable`);
    });
  }

  console.log(`SPORE HARNESS  corpus=${CORPUS}  log=${KEY.slice(0, 12)}  port=${PORT}`);

  if (MODE === 'seed') {
    const t0 = tel.ms();
    const blocks = buildCorpus(author, BLOCKS, BLOCK_BYTES);
    for (const b of blocks) {
      const r = store.insert(b.cert, b.payload, author.pub);
      if (!r.ok) throw new Error(`corpus block rejected: ${r.reason}`);
    }
    const total = BLOCKS * (BLOCK_BYTES + 260);
    log(`seeding ${BLOCKS} blocks · ${MB(total)} MB · built in ${Math.round(tel.ms() - t0)}ms`);
    log('waiting for joiners — ctrl-c when done');
    setInterval(() => {
      log(`served ${sync.stats.served} blocks to ${mgr.hyphae.size} hyphae`);
    }, 5000).unref();
    return;
  }

  // --- joiner: wait for enough sources, then time the pull -------------------------
  //
  // Held, not merely timed. The scheduler pumps on every HAVE and HAVE_ADD, so without
  // this a joiner starts pulling from source 1 while sources 2 and 3 are still booting,
  // and the run would report three sources while having measured mostly one.
  sync.paused = true;
  log(`waiting for ${WANT_SOURCES} source${WANT_SOURCES > 1 ? 's' : ''} of ${KEY.slice(0, 12)}`);

  const sourcesPresent = () => {
    const l = sync.logs.get(KEY);
    return l ? l.peers.size : 0;
  };

  const gate = setInterval(() => {
    const n = sourcesPresent();
    if (started === null && n >= WANT_SOURCES) {
      started = tel.ms();
      sync.paused = false;
      sync.pump();
      log(`START · ${n} sources visible · fetch released`);
    } else if (started === null && n > 0) {
      log(`  ${n}/${WANT_SOURCES} sources — holding`);
    }
  }, 250);
  gate.unref();

  sync.on('complete', ({ logId: lid, blocks }) => {
    if (finished || lid.toString('hex') !== KEY) return;
    finished = true;
    clearInterval(gate);
    report(blocks);
  });
}

function report(blocks) {
  const rep = store.replica(KEY);
  const elapsed = (tel.ms() - (started ?? 0)) / 1000;
  const bytes = BLOCKS * (BLOCK_BYTES + 260);

  console.log('');
  console.log('⊰-•-•⟐•-•-⦑/Λ\\Ο/Β\\Ε/\\Π/Λ\\Ι/Ν\\Υ/⦒-•-•⟐•-•-⊱');
  console.log(`  corpus       ${CORPUS} · ${blocks} blocks · ${MB(bytes)} MB`);
  console.log(`  sources      ${sync.logs.get(KEY)?.peers.size ?? 0} visible at completion`);
  console.log(`  elapsed      ${elapsed.toFixed(2)} s`);
  console.log(`  throughput   ${MB(bytes / Math.max(elapsed, 0.001))} MB/s`);
  console.log(`  linked       ${rep.linkedTo + 1}/${blocks}${rep.forked ? `  FORKED at ${rep.forkedAt}` : ''}`);
  console.log(`  requests     ${sync.stats.requested} issued · ${sync.stats.received} received`);
  console.log(`  recovered    ${sync.stats.noblock} noblock · ${sync.stats.timedOut} timeout · ${sync.stats.released} released`);

  // The line that proves this was a swarm and not a download. If one peer served
  // everything, the other sources were present and idle, and the speedup is not real.
  const from = [...sync.stats.fromPeer.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`  served by`);
  for (const [p, n] of from) {
    const pct = ((n / sync.stats.received) * 100).toFixed(0);
    console.log(`    ${p.slice(0, 8)}  ${String(n).padStart(5)} blocks  ${String(pct).padStart(3)}%`);
  }
  if (from.length < WANT_SOURCES) {
    console.log(`  NOTE: ${WANT_SOURCES} sources were required but only ${from.length} actually served.`);
  }

  // The built-in falsifier. A speedup claim is a claim about using N uplinks at once; if
  // one peer supplied nearly everything then the others were present and idle, this run
  // used one uplink, and any improvement in elapsed time came from somewhere else.
  //
  // Expect this to trip on loopback and NOT on a real AP. plan() prefers the peer with the
  // most free slots, and with no bandwidth limit the first peer's blocks all land in a
  // single event-loop turn, freeing its slots and winning the next round before the second
  // peer's requests have even been answered. Real airtime removes that advantage, which is
  // why this number has to be read on hardware and not here.
  //
  // If it trips on a real AP with several devices, that is the finding: the scheduler is
  // concentrating on one source and no amount of extra phones will help until it stops.
  if (WANT_SOURCES > 1 && from.length) {
    const topShare = from[0][1] / sync.stats.received;
    if (topShare > 0.8) {
      console.log('');
      console.log(`  ⚠ ONE SOURCE SUPPLIED ${(topShare * 100).toFixed(0)}% OF THIS RUN.`);
      console.log(`    ${WANT_SOURCES} sources were present, but this measured roughly one uplink.`);
      console.log(`    On loopback that is expected. On a real AP it means the multi-source`);
      console.log(`    speedup did not happen and the elapsed time above is not evidence for it.`);
    } else {
      console.log(`  ✓ load spread across ${from.length} sources — top share ${(topShare * 100).toFixed(0)}%`);
    }
  }
  console.log('⊰-•-•⟐•-•-⦑/Λ\\Ο/Β\\Ε/\\Π/Λ\\Ι/Ν\\Υ/⦒-•-•⟐•-•-⊱');
  console.log('');
  console.log('  Run again with --sources 1, 2, 3, 4, 5 and compare elapsed.');
  console.log('  ARCHITECTURE.md §3.1 predicts the knee at N=4 and a flat line after.');
  shutdown();
}

async function shutdown() {
  sync.stop();
  await beacon.stop();
  await mgr.stop();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

main().catch((e) => {
  console.error('harness failed:', e);
  process.exit(1);
});
