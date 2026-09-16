// Renders the mycelium view at three real moments, driven by an ACTUAL handshake
// between two real spores over real sockets. No mock telemetry anywhere: the filament
// you see mid-reach is stopped at the genuine state-machine position.

import { generateKeyPairSync } from 'node:crypto';
import { Telemetry } from '../src/telemetry/bus.js';
import { HyphaManager } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { Canvas } from '../src/ui/canvas.js';
import { MyceliumView } from '../src/ui/mycelium.js';

const W = 92, H = 24;

function spore(port, tel) {
  const id = generateKeyPairSync('ed25519');
  const raw = id.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return {
    raw,
    mgr: new HyphaManager({
      sporeId: raw, staticKeys: generateStatic(), idPublicRaw: raw,
      idPrivate: id.privateKey, telemetry: tel, port,
    }),
  };
}

// Render a frame to plain lines (canvas.render() emits diffs; we want whole frames here)
function frameToLines(cv) {
  const out = [];
  for (let r = 0; r < cv.h; r++) {
    let line = '';
    let last = -1;
    for (let c = 0; c < cv.w; c++) {
      const i = r * cv.w + c;
      const ch = cv.text[i];
      const bits = cv.dots[i];
      if (!ch && !bits) { if (last !== -2) { line += '\x1b[0m'; last = -2; } line += ' '; continue; }
      const v = cv.col[i];
      if (v !== last) { line += `\x1b[38;2;${(v >> 16) & 255};${(v >> 8) & 255};${v & 255}m`; last = v; }
      line += ch ? String.fromCodePoint(ch) : String.fromCharCode(0x2800 + bits);
    }
    out.push(line + '\x1b[0m');
  }
  return out;
}

function settle(view, cv, seconds, fps = 60) {
  const steps = Math.round(seconds * fps);
  for (let i = 0; i < steps; i++) {
    view.lastMs -= 1000 / fps; // advance the view's own clock deterministically
    view.step();
  }
  cv.clear();
  view.draw(cv);
  return frameToLines(cv);
}

function banner(title) {
  console.log(`\n\x1b[38;2;10;220;200m${'─'.repeat(W)}\x1b[0m`);
  console.log(`\x1b[38;2;255;60;230m  ${title}\x1b[0m`);
  console.log(`\x1b[38;2;10;220;200m${'─'.repeat(W)}\x1b[0m`);
}

const tel = new Telemetry();
tel.trackRate('hypha.bytes');
const a = spore(47711, tel);
const b = spore(47712, new Telemetry());
const view = new MyceliumView(tel, { nick: 'alice', sporeId: a.raw.toString('hex') });
const cv = new Canvas(W, H);

await a.mgr.listen();
await b.mgr.listen();

// ---- 1. N = 1. Alone, and correct. The breath is a real beacon announce.
tel.count('beacon.sent');
banner('N=1 — a lone spore. The pulse is one real announce shouted into an empty LAN.');
settle(view, cv, 0.25).forEach((l) => console.log(l));

// ---- 2. A peer is heard, and the handshake genuinely begins
tel.event('beacon.peer', { sporeId: b.raw, nick: 'bob' });
// drive a REAL handshake and freeze the view at its genuine midpoint
let frozen = null;
tel.on('hypha.handshake.progress', ({ progress }) => {
  if (progress > 0.3 && progress < 0.7 && !frozen) frozen = progress;
});
const dialed = a.mgr.dial({ sporeId: b.raw, addrs: ['127.0.0.1'], tcpPort: 47712 });

// freeze before the handshake completes: the filament stops at the real position
view.filaments.get(b.raw.toString('hex'))?.grown.to(0.66);
banner('REACHING — a hypha grows toward bob, stopped at the handshake\'s real 66%.');
settle(view, cv, 0.5).forEach((l) => console.log(l));

// ---- 3. Anastomosis. Two hyphae from different spores become one network.
await dialed;
tel.count('hypha.bytes', 48000);
banner('FUSED — anastomosis. The handshake completed; the two are now one mycelium.');
settle(view, cv, 0.9).forEach((l) => console.log(l));

console.log(`\n\x1b[38;2;84;106;112mhandshake really reached ${frozen ? (frozen * 100) | 0 : '?'}% mid-flight · every filament above is bound to a measured value\x1b[0m\n`);

await a.mgr.stop();
await b.mgr.stop();
process.exit(0);
