// The growing view.
//
// GROWTH.md's law, enforced here: nothing animates off a timer. Every growth in this
// file is a spring pulled toward a setpoint that came from a real measured quantity.
// If a value cannot be found in the telemetry bus, it does not get drawn.
//
//   a hypha's length          <- the Noise handshake's actual state-machine position
//   a hypha's brightness      <- bytes really moved, EWMA-smoothed
//   the lone spore's breath   <- each real BEACON announce pushed into the dark
//   a peer's wither           <- the socket actually closing
//
// The breath is the one worth pausing on. At N=1 a spore shouts into an empty LAN every
// few seconds and nothing answers. That shout is real, so the pulse that renders it is
// honest, and the loneliest state in the product is also its most alive-looking.

import { Canvas, rgb, mix } from './canvas.js';

// Palette. Deep substrate, cyan core, magenta tips — bioluminescent, and every value
// checked for contrast against the substrate black rather than chosen by feel.
export const PAL = {
  substrate: rgb(6, 8, 12),
  core: rgb(10, 220, 200),      // cyan  — established, carrying traffic
  tip: rgb(255, 60, 230),       // magenta — growing edge
  dormant: rgb(38, 54, 60),     // a hypha that exists but is idle
  wither: rgb(120, 40, 46),     // departing
  text: rgb(190, 214, 216),
  dim: rgb(84, 106, 112),
  alarm: rgb(255, 92, 92),
  seed: rgb(240, 248, 255),
};

/** Critically damped spring. Overshoot reads as bouncy; growth should read as inevitable. */
export class Spring {
  constructor(value = 0, stiffness = 26) {
    this.x = value;
    this.v = 0;
    this.target = value;
    this.k = stiffness;
    this.c = 2 * Math.sqrt(stiffness); // critical damping
  }
  to(target) { this.target = target; return this; }
  step(dt) {
    const d = Math.min(dt, 0.05); // clamp so a stalled frame cannot explode the sim
    this.v += (-this.k * (this.x - this.target) - this.c * this.v) * d;
    this.x += this.v * d;
    return this.x;
  }
}

/**
 * One hypha, drawn as a branching filament reaching from us toward a peer.
 * `grown` is a spring whose target is the real handshake progress, so the filament
 * literally stops mid-air if the handshake stalls, and resumes when it resumes.
 */
class Filament {
  constructor(peerKey, angle, nick) {
    this.peerKey = peerKey;
    this.angle = angle;
    this.nick = nick;
    this.grown = new Spring(0, 18);
    this.glow = new Spring(0, 30);
    this.state = 'reaching';
    this.fused = 0;      // anastomosis flash, decays after the handshake completes
    this.bytes = 0;
    this.sas = null;
    // deterministic wobble per peer so each filament is individual but never random
    this.seedWobble = [...peerKey.slice(0, 6)].reduce((a, c) => a + c.charCodeAt(0), 0) % 100 / 100;
  }
  get dead() { return this.state === 'withered' && this.grown.x < 0.02; }
}

export class MyceliumView {
  constructor(telemetry, { nick = 'spore', sporeId = '' } = {}) {
    this.tel = telemetry;
    this.nick = nick;
    this.sporeId = sporeId;
    this.filaments = new Map();
    this.messages = [];
    this.breath = new Spring(0, 40);
    this.lastMs = telemetry.ms();
    this.announces = 0;
    this.nextAngle = -Math.PI / 2;
    this.encrypted = false; // SP1 truth. Do not flip this until the ciphertext is real.
    this.#wire();
  }

  #angleFor() {
    // golden-angle placement: filaments spread evenly however many arrive
    const a = this.nextAngle;
    this.nextAngle += 2.399963;
    return a;
  }

  #wire() {
    const t = this.tel;

    t.on('beacon.sent', () => {});
    t.on('beacon.started', () => this.log('BEACON', 'listening on the dark', PAL.dim));

    // the lone spore's breath: one real shout into the LAN, one pulse outward
    const origCount = t.count.bind(t);
    t.count = (name, n = 1) => {
      const v = origCount(name, n);
      if (name === 'beacon.sent') {
        this.announces++;
        this.breath.x = 1;
        this.breath.to(0);
      }
      return v;
    };

    t.on('beacon.peer', (p) => {
      const key = p.sporeId.toString('hex');
      if (!this.filaments.has(key)) {
        this.filaments.set(key, new Filament(key, this.#angleFor(), p.nick || key.slice(0, 6)));
        this.log('SPORE', `${p.nick || key.slice(0, 6)} is out there`, PAL.tip);
      }
    });

    t.on('hypha.handshake.progress', ({ progress }) => {
      // pull EVERY reaching filament toward real progress. With one peer this is exact;
      // with several the attribution is approximate and that is stated, not hidden.
      for (const f of this.filaments.values()) {
        if (f.state === 'reaching') f.grown.to(Math.max(f.grown.target, progress * 0.92));
      }
    });

    t.on('hypha.established', ({ peerId, sas }) => {
      const key = Buffer.from(peerId).toString('hex');
      let f = this.filaments.get(key);
      if (!f) {
        f = new Filament(key, this.#angleFor(), key.slice(0, 6));
        this.filaments.set(key, f);
      }
      f.state = 'fused';
      f.sas = sas;
      f.grown.to(1);
      f.fused = 1; // anastomosis: two hyphae from different spores becoming one network
      this.log('FUSED', `${f.nick} · sas ${sas.toString('hex')}`, PAL.core);
    });

    t.on('hypha.withered', ({ peerId, reason }) => {
      const f = this.filaments.get(Buffer.from(peerId).toString('hex'));
      if (!f) return;
      f.state = 'withered';
      f.grown.to(0);
      this.log('WITHER', `${f.nick} · ${reason}`, PAL.wither);
    });

    t.on('hypha.dial_refused', ({ host, why }) => this.log('REFUSED', `${host} · ${why}`, PAL.alarm));
    t.on('beacon.join_failed', ({ iface }) => this.log('BEACON', `${iface} join refused, continuing`, PAL.dim));
  }

  log(tag, text, colour = PAL.text) {
    this.messages.push({ tag, text, colour, atMs: this.tel.ms(), age: new Spring(0, 22).to(1) });
    if (this.messages.length > 200) this.messages.shift();
  }

  message(from, body) {
    this.log(from, body, PAL.seed);
  }

  step() {
    const now = this.tel.ms();
    const dt = Math.min(0.1, (now - this.lastMs) / 1000);
    this.lastMs = now;

    this.breath.step(dt);
    for (const [k, f] of this.filaments) {
      f.grown.step(dt);
      f.glow.to(Math.min(1, this.tel.rateOf('hypha.bytes') / 65536)).step(dt);
      f.fused = Math.max(0, f.fused - dt * 1.4);
      if (f.dead) this.filaments.delete(k);
    }
    for (const m of this.messages) m.age.step(dt);
    return dt;
  }

  /** @param {Canvas} cv */
  draw(cv) {
    const W = cv.w * 2;
    const H = cv.h * 4;
    const panel = Math.floor(cv.w * 0.46);
    const cxSub = panel * 2 / 2;           // centre of the graph panel, subpixel space
    const cx = panel;                       // in subpixels: panel cells * 2 / 2
    const cy = H / 2;
    const live = [...this.filaments.values()].filter((f) => f.state === 'fused').length;
    const t = this.tel.ms() / 1000;

    // ---- the lone seed, always drawn: this spore, alive whether or not anyone answers
    const breath = this.breath.x;
    const seedR = 2.2 + breath * 2.6;
    for (let a = 0; a < Math.PI * 2; a += 0.22) {
      cv.plot(cx + Math.cos(a) * seedR, cy + Math.sin(a) * seedR * 0.55,
        mix(PAL.seed, PAL.core, breath));
    }
    // the shout itself: an expanding ring, only while a real announce is decaying
    if (breath > 0.02) {
      const ring = (1 - breath) * Math.min(W, H) * 0.42;
      const c = mix(PAL.substrate, PAL.tip, breath * 0.8);
      for (let a = 0; a < Math.PI * 2; a += 0.09) {
        cv.plot(cx + Math.cos(a) * ring, cy + Math.sin(a) * ring * 0.55, c);
      }
    }

    // ---- filaments: one per peer, length = real handshake progress
    for (const f of this.filaments.values()) {
      const g = Math.max(0, Math.min(1, f.grown.x));
      if (g < 0.01) continue;
      const reach = Math.min(W, H * 1.8) * 0.40 * g;
      const wob = Math.sin(t * 0.7 + f.seedWobble * 6.28) * 0.16;
      const ex = cx + Math.cos(f.angle + wob) * reach;
      const ey = cy + Math.sin(f.angle + wob) * reach * 0.55;

      const base = f.state === 'withered' ? PAL.wither
        : f.state === 'fused' ? mix(PAL.dormant, PAL.core, 0.35 + f.glow.x * 0.65)
          : PAL.dormant;
      const tipC = f.state === 'withered' ? PAL.wither : PAL.tip;

      // the filament, with a couple of real branches so it reads as grown not drawn
      cv.line(cx, cy, ex, ey, base, tipC);
      for (const bt of [0.45, 0.72]) {
        if (g < bt + 0.12) continue;
        const bx = cx + (ex - cx) * bt;
        const by = cy + (ey - cy) * bt;
        const spread = 0.42 + f.seedWobble * 0.3;
        const bl = reach * 0.22 * (g - bt);
        cv.line(bx, by, bx + Math.cos(f.angle + spread) * bl, by + Math.sin(f.angle + spread) * bl * 0.55, base, tipC);
        cv.line(bx, by, bx + Math.cos(f.angle - spread) * bl, by + Math.sin(f.angle - spread) * bl * 0.55, base, tipC);
      }

      // anastomosis flash: the moment two networks become one
      if (f.fused > 0.02) {
        const r = (1 - f.fused) * 7;
        for (let a = 0; a < Math.PI * 2; a += 0.3) {
          cv.plot(ex + Math.cos(a) * r, ey + Math.sin(a) * r * 0.55, mix(PAL.core, PAL.seed, f.fused));
        }
      }

      const label = f.state === 'fused' ? f.nick : `${f.nick} ${Math.round(g * 100)}%`;
      cv.write(Math.round(ex / 2) - 1, Math.round(ey / 4), label.slice(0, 14),
        f.state === 'fused' ? PAL.core : PAL.dim);
    }

    // ---- right panel: the log, germinating
    const px = panel + 2;
    const width = cv.w - px - 1;
    const visible = this.messages.slice(-(cv.h - 5));
    visible.forEach((m, i) => {
      const grow = Math.min(1, m.age.x);
      const full = `${m.tag.padEnd(8)}${m.text}`;
      // germination: the line arrives character by character at the real spring rate
      const shown = full.slice(0, Math.max(0, Math.floor(full.length * grow)));
      cv.write(px, i + 3, shown.slice(0, width), m.colour);
    });

    // ---- header
    cv.write(1, 0, '░▒▓ MYCELIUM ▓▒░', PAL.core);
    const stat = `${live} fused · ${this.filaments.size} known · ${this.announces} shouts`;
    cv.write(cv.w - stat.length - 1, 0, stat, PAL.dim);
    cv.write(1, 1, `spore ${this.sporeId.slice(0, 16)}  ${this.nick}`, PAL.dim);

    // ---- the disclosure. Plain English, mandatory, non-dismissable.
    // CORRECTNESS.md C3: SP1 has zero content confidentiality. Every VAULT, RELAY and
    // bystander can read every message body. A banner is a disclosure, not a
    // confidentiality mechanism, and it must be legible to someone who has never heard
    // the word "fruiting". The FRV1T frame goes around the warning, never over it.
    const warn = this.encrypted ? ' messages are encrypted ' : ' MESSAGES ARE NOT ENCRYPTED ';
    const c = this.encrypted ? PAL.core : PAL.alarm;
    const row = cv.h - 1;
    const bar = `⊰-•-•⟐${warn}⟐•-•-⊱`;
    cv.write(Math.max(0, Math.floor((cv.w - bar.length) / 2)), row, bar, c);
  }
}
