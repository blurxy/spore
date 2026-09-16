// ⊰-•-•⟐•-•-⦑/Λ\Ο/Β\Ε/\Π/Λ\Ι/Ν\Υ/⦒-•-•⟐•-•-⊱
//
// THE FALSIFIER.
//
// Every scaling number in ARCHITECTURE.md §3 is derived arithmetic. This measures it.
// It is written to be capable of proving the product thesis WRONG, and the falsifiers are
// declared before the run rather than after, so the result cannot be rationalised.
//
// The modelling decision that makes or breaks the whole thing:
//
//   Wi-Fi in infrastructure mode is a SHARED MEDIUM. Every peer-to-peer byte crosses the
//   air twice — up to the AP, back down. Twenty phones on one access point do NOT get
//   twenty independent pipes. A benchmark that throttles each peer independently models
//   N independent links, produces a beautiful near-linear curve, and is a lie.
//
// So there are two throttles: a per-spore uplink bucket AND one global cell bucket every
// spore draws from. Control B runs the identical swarm with the cell cap removed; if
// Control B does not keep gaining where the capped run flattens, the cap is not what
// bends the curve and the model is wrong.
//
// RATES ARE REAL WI-FI RATES, and getting here took a fix.
//
// The first run of this benchmark was scaled 10x down, because blake2b256 was BigInt at
// ~3.5 MB/s and a joiner hashes every byte it verifies — so at true rates sync would have
// been HASH-bound at every N, flat from N=1, looking exactly like the thesis failing when
// it was really a CPU limit. That finding drove the 32-bit-pair rewrite: blake2b256 now
// does 37.7 MB/s, which clears the 25 MB/s cell, so the network binds first and these
// numbers mean what they say. Margin is only ~1.5x, so this stays worth watching.

import { Bitfield, FetchScheduler } from '../src/sharding/scheduler.js';
import { Canvas, rgb, mix } from '../src/ui/canvas.js';

const DIV = '⊰-•-•⟐•-•-⦑/Λ\\Ο/Β\\Ε/\\Π/Λ\\Ι/Ν\\Υ/⦒-•-•⟐•-•-⊱';

// ---- the model, all of it stated so it can be attacked ------------------------------
const SCALE = 1;                               // real rates now — see header
const BLOCK = 256 * 1024;                      // 256 KiB, per design-sharding
const PAYLOAD_MB = 50;
const TOTAL_BLOCKS = Math.round((PAYLOAD_MB * 1024 * 1024) / BLOCK);
const UPLINK = (7.5 * 1024 * 1024) / SCALE;    // bytes/sec per spore, design-sharding §6
const DOWNLINK = (25 * 1024 * 1024) / SCALE;   // bytes/sec, a spore's radio RX ceiling
const CELL = (25 * 1024 * 1024) / SCALE;       // bytes/sec, P2P-effective (already halved
                                               // for the double air traversal)
const RTT_MS = 3;
const TICK_MS = 20;
const MAX_INFLIGHT = 6;

const fmt = (n, d = 1) => n.toFixed(d);
const mb = (b) => b / 1024 / 1024;

/** Token bucket. Gate BEFORE writing, never account after — a late throttle measures nothing. */
class Bucket {
  constructor(ratePerSec, burstSec = 0.25) {
    this.rate = ratePerSec;
    this.cap = ratePerSec * burstSec;
    this.tokens = this.cap;
  }
  refill(dtSec) {
    this.tokens = Math.min(this.cap, this.tokens + this.rate * dtSec);
  }
  take(n) {
    const got = Math.min(n, this.tokens);
    this.tokens -= got;
    return got;
  }
}

/**
 * One swarm run. All spores live in one process on purpose: the constraint being modelled
 * is bandwidth, not CPU isolation, and a shared global bucket is only honest if everyone
 * really draws from the same object.
 */
function runSwarm({
  seeders = 1, joiners, cellCap = true, churnEverySec = 0, serial = false, seed = 1,
  downlink = DOWNLINK, minAlive = 1, maxInflight = MAX_INFLIGHT,
}) {
  let rnd = seed >>> 0;
  const rand = () => ((rnd = (rnd * 1664525 + 1013904223) >>> 0) / 2 ** 32);

  const cell = new Bucket(CELL);
  const spores = [];
  const mkSpore = (id, isSeeder) => ({
    id, seeder: isSeeder, alive: true,
    have: isSeeder ? Bitfield.full(TOTAL_BLOCKS) : new Bitfield(TOTAL_BLOCKS),
    up: new Bucket(UPLINK), down: new Bucket(downlink),
    sent: 0, recv: 0, doneAt: 0,
    downloading: new Set(),  // blocks I am pulling
    uploading: new Set(),    // blocks I am pushing
  });
  for (let i = 0; i < seeders; i++) spores.push(mkSpore(`seed${i}`, true));
  for (let i = 0; i < joiners; i++) spores.push(mkSpore(`join${i}`, false));

  // Replica counts maintained INCREMENTALLY. Recomputing rarity from scratch each tick is
  // O(blocks x peers x joiners) and turns a 30-second benchmark into a 20-minute one.
  const replicas = new Int32Array(TOTAL_BLOCKS);
  for (const s of spores) if (s.seeder) for (let i = 0; i < TOTAL_BLOCKS; i++) replicas[i]++;

  const sched = new FetchScheduler(TOTAL_BLOCKS);
  const inflight = new Map();
  let transfers = [];
  let t = 0;
  let lastChurn = 0;
  let churned = 0;

  let alive = spores.slice();
  let working = alive.filter((s) => !s.seeder);

  while (working.length > 0 && t < 30 * 60 * 1000) {
    const dt = TICK_MS / 1000;
    t += TICK_MS;
    cell.refill(dt);
    for (const s of alive) { s.up.refill(dt); s.down.refill(dt); }

    // --- churn: a phone walks out of the room mid-transfer
    if (churnEverySec > 0 && t - lastChurn >= churnEverySec * 1000) {
      lastChurn = t;
      const victims = working.filter((s) => !s.have.complete);
      if (victims.length > minAlive) {
        const v = victims[Math.floor(rand() * victims.length)];
        v.alive = false;
        churned++;
        for (let i = 0; i < TOTAL_BLOCKS; i++) if (v.have.has(i)) replicas[i]--;
        transfers = transfers.filter((x) => {
          if (x.from !== v && x.to !== v) return true;
          inflight.set(x.index, Math.max(0, (inflight.get(x.index) || 1) - 1));
          x.to.downloading.delete(x.index);
          x.from.uploading.delete(x.index);
          return false;
        });
        alive = spores.filter((s) => s.alive);
      }
    }

    // --- schedule, but only for joiners that actually have a free request slot
    for (const me of working) {
      if (me.downloading.size >= maxInflight) continue;
      const peers = new Map();
      for (const p of alive) {
        if (p === me) continue;
        if (serial && !p.seeder) continue;   // Control A: only the seeder ever serves
        if (p.uploading.size >= maxInflight) continue;
        peers.set(p.id, { have: p.have, inflight: p.uploading, maxInflight, ref: p });
      }
      if (!peers.size) continue;
      for (const a of sched.plan(me.have, peers, inflight, replicas, maxInflight - me.downloading.size)) {
        const from = peers.get(a.peerId).ref;
        transfers.push({ from, to: me, index: a.index, moved: 0, startedAt: t });
        me.downloading.add(a.index);
        if (me.downloading.size >= maxInflight) break;
      }
    }

    // --- move bytes. Every transfer is gated by the sender's uplink, the receiver's
    //     downlink, AND the shared cell. The cell is the term that bends the curve.
    let completedAny = false;
    for (let i = transfers.length - 1; i >= 0; i--) {
      const x = transfers[i];
      if (!x.from.alive || !x.to.alive) { transfers.splice(i, 1); continue; }
      if (t - x.startedAt < RTT_MS) continue;

      let allow = Math.min(BLOCK - x.moved, x.from.up.tokens, x.to.down.tokens);
      if (cellCap) allow = Math.min(allow, cell.tokens);
      if (allow <= 0) continue;

      const n = Math.floor(allow);
      x.from.up.take(n);
      x.to.down.take(n);
      if (cellCap) cell.take(n);
      x.from.sent += n;
      x.to.recv += n;
      x.moved += n;

      if (x.moved >= BLOCK) {
        // cache-on-fetch: the joiner immediately becomes a source for this block.
        // This is where swarm supply grows, and it is the whole mechanism.
        if (x.to.have.set(x.index)) replicas[x.index]++;
        inflight.set(x.index, Math.max(0, (inflight.get(x.index) || 1) - 1));
        x.to.downloading.delete(x.index);
        x.from.uploading.delete(x.index);
        transfers.splice(i, 1);
        if (x.to.have.complete) { x.to.doneAt = t; completedAny = true; }
      }
    }
    if (completedAny || churned) working = alive.filter((s) => !s.seeder && !s.have.complete);
  }

  const finished = spores.filter((s) => !s.seeder && s.have.complete);
  return {
    ms: t,
    cohortMs: finished.length ? Math.max(...finished.map((s) => s.doneAt)) : Infinity,
    firstMs: finished.length ? Math.min(...finished.map((s) => s.doneAt)) : Infinity,
    completed: finished.length,
    requested: joiners,
    churned,
    seederSent: mb(spores.filter((s) => s.seeder).reduce((a, s) => a + s.sent, 0)),
    peerSent: mb(spores.filter((s) => !s.seeder).reduce((a, s) => a + s.sent, 0)),
    dup: sched.stats.duplicates,
  };
}

// ---- the braille curve, drawn on the same canvas the product uses -------------------
function plotCurve(rows, width = 84, height = 14) {
  const cv = new Canvas(width, height);
  const W = width * 2;
  const H = height * 4;
  const speeds = rows.map((r) => r.speedup);
  const maxS = Math.max(2, ...speeds) * 1.12;
  const n = rows.length;

  // axes
  for (let x = 0; x < W; x++) cv.plot(x, H - 1, rgb(40, 52, 58));
  for (let y = 0; y < H; y++) cv.plot(0, y, rgb(40, 52, 58));

  const px = (i) => 6 + (i / Math.max(1, n - 1)) * (W - 14);
  const py = (s) => H - 2 - (s / maxS) * (H - 6);

  // the measured curve
  for (let i = 1; i < n; i++) {
    const x0 = px(i - 1); const y0 = py(speeds[i - 1]);
    const x1 = px(i); const y1 = py(speeds[i]);
    const steps = Math.ceil(Math.hypot(x1 - x0, y1 - y0));
    for (let s = 0; s <= steps; s++) {
      const t = s / steps;
      cv.plot(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, mix(rgb(10, 220, 200), rgb(255, 60, 230), i / n));
    }
  }
  for (let i = 0; i < n; i++) {
    const x = px(i); const y = py(speeds[i]);
    for (let a = 0; a < Math.PI * 2; a += 0.5) cv.plot(x + Math.cos(a) * 1.6, y + Math.sin(a) * 1.6, rgb(255, 255, 255));
    cv.write(Math.round(x / 2) - 1, height - 1, `N${rows[i].n}`, rgb(120, 140, 148));
  }
  cv.write(1, 0, `${fmt(maxS)}x`, rgb(84, 106, 112));
  cv.write(1, Math.floor(height / 2), `${fmt(maxS / 2)}x`, rgb(84, 106, 112));

  const out = [];
  for (let r = 0; r < cv.h; r++) {
    let line = ''; let last = -1;
    for (let c = 0; c < cv.w; c++) {
      const i = r * cv.w + c;
      const ch = cv.text[i]; const bits = cv.dots[i];
      if (!ch && !bits) { if (last !== -2) { line += '\x1b[0m'; last = -2; } line += ' '; continue; }
      const v = cv.col[i];
      if (v !== last) { line += `\x1b[38;2;${(v >> 16) & 255};${(v >> 8) & 255};${v & 255}m`; last = v; }
      line += ch ? String.fromCodePoint(ch) : String.fromCharCode(0x2800 + bits);
    }
    out.push(line + '\x1b[0m');
  }
  return out;
}

// ---- run ----------------------------------------------------------------------------
const C = { cyan: '\x1b[38;2;10;220;200m', mag: '\x1b[38;2;255;60;230m', dim: '\x1b[38;2;84;106;112m', warn: '\x1b[38;2;255;92;92m', off: '\x1b[0m' };
const pulse = (s) => console.log(`${C.dim}▸ ${s}${C.off}`);
const rule = () => console.log(`${C.cyan}${DIV}${C.off}`);

console.log(`\n${C.mag}  ░▒▓ 5P0R3 // TH3 F4L51F13R ▓▒░${C.off}`);
rule();
pulse(`payload ${PAYLOAD_MB} MB · ${TOTAL_BLOCKS} blocks × ${BLOCK / 1024} KiB`);
pulse(`uplink ${fmt(mb(UPLINK), 2)} MB/s · cell ${fmt(mb(CELL), 2)} MB/s · real Wi-Fi rates`);
pulse('falsifier declared BEFORE running:');
pulse('  (1) N=20 single-joiner must be within ~20% of N=5 — if it keeps climbing, the shared-medium model is wrong');
pulse('  (2) Control B (no cell cap) must keep gaining where the capped run flattens — else the cap is not what bends it');
rule();

const Ns = [1, 2, 3, 4, 5, 8, 12, 20];

// Control A: the baseline every speedup is measured against.
// One source, one joiner, no peer re-seeding — the classic client/server download.
const ctrlA = runSwarm({ seeders: 1, joiners: 1, serial: true });
pulse(`control A · one source, no swarm · ${fmt(ctrlA.cohortMs / 1000)}s  ← the baseline`);
console.log();

// THE EXPERIMENT: a single newcomer syncing while N spores are present to pull from.
// N counts SOURCES, not competing joiners — the claim is about supply, and putting rival
// joiners in the swarm would measure contention instead.
console.log(`${C.dim}   N   sync      speedup   supply MB/s   dup${C.off}`);
const rows = [];
for (const n of Ns) {
  const swarm = runSwarm({ seeders: n, joiners: 1, cellCap: true, seed: 7 });
  const speedup = ctrlA.cohortMs / swarm.firstMs;
  const supply = Math.min(n * mb(UPLINK), mb(CELL), mb(DOWNLINK));
  rows.push({ n, speedup, ms: swarm.firstMs });
  console.log(
    `  ${String(n).padStart(2)}   ${fmt(swarm.firstMs / 1000).padStart(6)}s   ${(fmt(speedup, 2) + 'x').padStart(7)}`
    + `   ${fmt(supply, 2).padStart(11)}   ${String(swarm.dup).padStart(3)}`,
  );
}

console.log();
plotCurve(rows).forEach((l) => console.log(l));
console.log(`${C.dim}   newcomer sync speedup vs control A, by number of sources present${C.off}`);

// Control B: the medium removed — no shared cell, radio RX lifted. If supply itself
// scales, this must keep climbing exactly where the capped run flattens.
//
// It also lifts the request pipeline, and that is not a thumb on the scale — it is a
// correction. An earlier version of this control left MAX_INFLIGHT at 6 and reported
// only 4.25x -> 4.75x, failing its own 1.2x threshold. The reason was not that supply
// stops scaling. It is that ONE joiner with six outstanding requests can be fed by at
// most six seeders at a time, so the 7th through 20th seeder were never asked for
// anything. The control was measuring the pipeline depth and calling it the medium.
//
// So: a control meant to isolate the medium has to remove every OTHER ceiling, and
// pipeline depth is one of them. That ceiling is real and is now reported in its own
// right below — it just is not the shared air, and conflating the two would have
// credited the medium with a limit that has a completely different fix.
console.log();
rule();
const capped20 = rows.at(-1).speedup;
const n5 = rows.find((r) => r.n === 5).speedup;
const bFree = (n) => ctrlA.cohortMs / runSwarm({
  seeders: n, joiners: 1, cellCap: false, downlink: DOWNLINK * 10, seed: 7,
  maxInflight: 64,
}).firstMs;
const uncapped5 = bFree(5);
const uncapped20 = bFree(20);

// Control C: the medium removed but the pipeline left at its real depth. The gap between
// this and control B is exactly what request concurrency costs, with no radio involved.
const bPipe = (n) => ctrlA.cohortMs / runSwarm({
  seeders: n, joiners: 1, cellCap: false, downlink: DOWNLINK * 10, seed: 7,
}).firstMs;
const pipe5 = bPipe(5);
const pipe20 = bPipe(20);

const flat = Math.abs(capped20 - n5) / n5 <= 0.2;
const bKeepsGaining = uncapped20 > uncapped5 * 1.2;

pulse(`capped    · N=5 ${fmt(n5, 2)}x → N=20 ${fmt(capped20, 2)}x   ${flat ? '[FLAT — the medium binds]' : '[STILL CLIMBING]'}`);
pulse(`control B · N=5 ${fmt(uncapped5, 2)}x → N=20 ${fmt(uncapped20, 2)}x   ${bKeepsGaining ? '[keeps gaining — supply really does scale]' : '[also flat]'}`);
pulse(`            no medium, no pipeline cap — supply is the only variable left`);
pulse(`control C · N=5 ${fmt(pipe5, 2)}x → N=20 ${fmt(pipe20, 2)}x   [no medium, pipeline still 6 deep]`);
pulse(`            SECOND CEILING: one joiner with ${MAX_INFLIGHT} outstanding requests can be fed`);
pulse(`            by at most ${MAX_INFLIGHT} seeders at once, so beyond N=${MAX_INFLIGHT} extra sources sit idle.`);
pulse(`            Nothing to do with the air. Fixed by pipeline depth, not by more radios.`);
rule();

// Flash crowd: K joiners at once. This is where a swarm beats a server outright, because
// the source uploads each block once instead of K times.
console.log();
const K = 10;
const crowd = runSwarm({ seeders: 1, joiners: K, seed: 3 });
const serialCohort = ctrlA.cohortMs * K;   // a server uploading the payload K times
const crowdGain = serialCohort / crowd.cohortMs;
pulse(`flash crowd · ${K} joiners at once · cohort ${fmt(crowd.cohortMs / 1000)}s`);
pulse(`              vs ${fmt(serialCohort / 1000)}s serving them serially → ${fmt(crowdGain, 2)}x`);
pulse(`              source uploaded ${fmt(crowd.seederSent)} MB, peers traded ${fmt(crowd.peerSent)} MB`);

// Churn, which the stress review demanded and which no design benchmark had tested.
//
// Comparing a churned run's cohort time against a clean run of the SAME starting size is
// a trap: departures shrink the cohort, the survivors face less contention, and the
// churned run finishes "faster". That number looks like a pass and means nothing. The
// honest comparison is the survivors against a clean run of the size they ended up being.
console.log();
const withChurn = runSwarm({ seeders: 1, joiners: K, churnEverySec: 2, minAlive: 3, seed: 3 });
const survivors = withChurn.completed;
const fairClean = runSwarm({ seeders: 1, joiners: Math.max(1, survivors), seed: 3 });
const churnRatio = withChurn.cohortMs / fairClean.cohortMs;
pulse(`churn · same crowd, one spore leaves every 2s`);
pulse(`        ${withChurn.churned} left mid-sync · ${survivors}/${withChurn.requested} completed`);
pulse(`        survivors ${fmt(withChurn.cohortMs / 1000)}s vs ${fmt(fairClean.cohortMs / 1000)}s for a clean ${survivors}-joiner run`);
pulse(`        ${fmt(churnRatio, 2)}x ${churnRatio <= 2 ? '[within the 2x falsifier]' : '[EXCEEDS the 2x falsifier]'}`);
pulse(`        NOTE: ${withChurn.requested - survivors}/${withChurn.requested} never finished. At this churn rate that`);
pulse(`        is the real finding — the swarm stays fast for whoever survives it.`);

console.log();
rule();
console.log(`${C.mag}  VERDICT${C.off}`);
console.log(`  ${flat ? `${C.cyan}✓${C.off}` : `${C.warn}✗${C.off}`} falsifier 1 — capped curve flat N=5→20 (${fmt(n5, 2)}x → ${fmt(capped20, 2)}x)`);
console.log(`  ${bKeepsGaining ? `${C.cyan}✓${C.off}` : `${C.warn}✗${C.off}`} falsifier 2 — uncapped control keeps gaining (${fmt(uncapped5, 2)}x → ${fmt(uncapped20, 2)}x)`);
console.log(`  ${churnRatio <= 2 ? `${C.cyan}✓${C.off}` : `${C.warn}✗${C.off}`} churn — cohort within 2x of clean (${fmt(churnRatio, 2)}x)`);
console.log(`${C.dim}  and a ceiling this run separated out: with the medium gone, pipeline depth alone`);
console.log(`  holds N=20 to ${fmt(pipe20, 2)}x where unlimited concurrency reaches ${fmt(uncapped20, 2)}x.${C.off}`);
console.log();
console.log(`${C.dim}  ARCHITECTURE.md §3 predicts 3.3x saturating near N=5. Measured peak: ${fmt(Math.max(...rows.map((r) => r.speedup)), 2)}x${C.off}`);
console.log(`${C.dim}  RESOLVED: an earlier run of this benchmark was scaled 10x down because blake2b256`);
console.log(`  was BigInt at ~3.5 MB/s and would have been the bottleneck instead of the network.`);
console.log(`  The 32-bit-pair rewrite took it to 37.7 MB/s, clearing the 25 MB/s cell, so these`);
console.log(`  are real rates. Margin is only ~1.5x — worth re-checking if block size grows.${C.off}`);
rule();
console.log();
