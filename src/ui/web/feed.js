// The telemetry bus, as seen from a page.
//
// MyceliumView asks its telemetry for four things — on(), count(), ms(), rateOf() — and
// nothing else. So the browser does not need the real bus, it needs something that answers
// those four honestly from an event stream, and then the SAME view class runs in both
// places with no branch inside it.
//
// HOLD-LAST-VALUE (GROWTH.md §3.1) is the rule this file exists to keep. A rate arrives as
// a measured sample; between samples it is HELD, never interpolated toward where it looks
// like it is heading. Interpolating a measured quantity is fabrication, and it is the most
// tempting fabrication in a renderer because it looks smoother.
//
// FAIL-LOUD (§3.3) is the other. rateOf() for a row nobody has ever sent returns null, not
// zero — a zero is a plausible lie and would draw a calm, idle mesh over a dead feed. The
// caller renders U+2298 instead.

export class Feed {
  constructor() {
    this.handlers = new Map();
    this.rates = new Map();
    this.counters = new Map();
    this.t0 = now();
    this.connected = false;
    this.lastMessageMs = null;
  }

  on(kind, fn) {
    const list = this.handlers.get(kind) || [];
    list.push(fn);
    this.handlers.set(kind, list);
    return this;
  }

  emit(kind, payload) {
    for (const fn of this.handlers.get(kind) || []) fn(payload);
  }

  /**
   * Present because MyceliumView WRAPS it — the lone spore's breath is driven by
   * intercepting count('beacon.sent'), not by a timer. Keeping the same seam here means
   * that mechanism works in the page without a second code path for it.
   */
  count(name, n = 1) {
    const v = (this.counters.get(name) || 0) + n;
    this.counters.set(name, v);
    return v;
  }

  ms() { return now() - this.t0; }

  /** Last MEASURED sample, held. null when the row has never been reported. */
  rateOf(name) {
    const r = this.rates.get(name);
    return r === undefined ? null : r;
  }

  get(name) { return this.counters.get(name) ?? null; }

  /** One frame off the wire. Shape is fixed by glass.js; anything else is ignored. */
  absorb(frame) {
    this.lastMessageMs = this.ms();
    if (frame.rates) for (const [k, v] of Object.entries(frame.rates)) this.rates.set(k, v);
    if (frame.counters) for (const [k, v] of Object.entries(frame.counters)) this.counters.set(k, v);
    if (frame.bumps) for (const name of frame.bumps) this.count(name);
    if (frame.kind) this.emit(frame.kind, frame.payload || {});
  }

  /**
   * Connect to the stream. Loopback only — the page is served by the spore on this device
   * and talks to nothing else, so the URL is relative and there is no host to get wrong.
   */
  connect(path = 'events') {
    const src = new EventSource(path);
    src.onopen = () => { this.connected = true; this.emit('feed.open', {}); };
    src.onerror = () => { this.connected = false; this.emit('feed.down', {}); };
    src.onmessage = (e) => {
      let frame;
      try { frame = JSON.parse(e.data); } catch { return; } // a torn frame is not an event
      this.absorb(frame);
    };
    this.source = src;
    return this;
  }
}

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
