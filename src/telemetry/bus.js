// The single source of truth every growth animation reads from.
//
// GROWTH.md's law: nothing animates off a timer. A hypha grows because a handshake
// really progressed; a thread brightens because bytes really moved. This module is
// where "really" is defined, so if a value cannot be found here it may not be drawn.

import { EventEmitter } from 'node:events';

/** Exponentially weighted moving average. Network telemetry is spiky; screens are not. */
export class Ewma {
  constructor(alpha = 0.2, initial = 0) {
    this.alpha = alpha;
    this.value = initial;
    this.primed = false;
  }
  push(x) {
    this.value = this.primed ? this.alpha * x + (1 - this.alpha) * this.value : x;
    this.primed = true;
    return this.value;
  }
}

/**
 * A rate meter over a monotonically increasing counter.
 * Returns units/second, smoothed. Used for hypha throughput.
 */
export class Rate {
  constructor(alpha = 0.3) {
    this.ewma = new Ewma(alpha);
    this.last = 0;
    this.lastAt = null;
  }
  observe(total, nowNs) {
    if (this.lastAt !== null) {
      const dt = Number(nowNs - this.lastAt) / 1e9;
      if (dt > 0) this.ewma.push((total - this.last) / dt);
    }
    this.last = total;
    this.lastAt = nowNs;
    return this.ewma.value;
  }
}

/**
 * Compresses a value spanning many orders of magnitude into 0..1 for screen space.
 * asinh, not log: it is defined at zero and near-linear for small values, so an idle
 * hypha reads as genuinely idle rather than as negative infinity.
 */
export function compress(x, scale = 1e5) {
  return Math.min(1, Math.asinh(Math.max(0, x) / scale) / Math.asinh(1e9 / scale));
}

export class Telemetry extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(64);
    this.counters = new Map();
    this.gauges = new Map();
    this.rates = new Map();
    this.startNs = process.hrtime.bigint();
  }

  /** Monotonic nanoseconds since this spore woke. Never wall-clock — off-web has no NTP. */
  now() {
    return process.hrtime.bigint() - this.startNs;
  }

  /** ms since wake, as a float. For animation phase only, never for ordering or auth. */
  ms() {
    return Number(this.now()) / 1e6;
  }

  count(name, n = 1) {
    const v = (this.counters.get(name) || 0) + n;
    this.counters.set(name, v);
    const r = this.rates.get(name);
    if (r) r.observe(v, this.now());
    return v;
  }

  gauge(name, v) {
    this.gauges.set(name, v);
    return v;
  }

  /** Mark a counter as rate-tracked, so `rateOf` returns units/sec. */
  trackRate(name, alpha = 0.3) {
    if (!this.rates.has(name)) this.rates.set(name, new Rate(alpha));
    return this;
  }

  rateOf(name) {
    const r = this.rates.get(name);
    return r ? r.ewma.value : 0;
  }

  get(name) {
    return this.counters.get(name) ?? this.gauges.get(name) ?? 0;
  }

  /**
   * Emit a semantic event. The UI listens to these to start growths.
   * Events are facts about what happened, never instructions about what to draw.
   */
  event(kind, payload = {}) {
    this.emit('telemetry', { kind, payload, atMs: this.ms() });
    this.emit(kind, payload);
    return this;
  }

  snapshot() {
    return {
      counters: Object.fromEntries(this.counters),
      gauges: Object.fromEntries(this.gauges),
      rates: Object.fromEntries([...this.rates].map(([k, r]) => [k, r.ewma.value])),
    };
  }
}

export const telemetry = new Telemetry();
export default telemetry;
