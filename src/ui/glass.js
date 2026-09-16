// Glass: the mycelium, seen from a phone.
//
// R3 settled that the hardware target is phones and that the braille subpixel renderer
// does not map to a touchscreen, so the same view needs a canvas path. This is that path,
// and it is deliberately the smallest thing that can be one: an HTTP server bound to
// loopback, a stream of telemetry frames, and the SAME MyceliumView running in the page.
//
// WHY LOOPBACK AND NOTHING ELSE. A spore holds a mesh identity and other people's traffic.
// A debug UI that binds 0.0.0.0 is a second, unauthenticated way into all of it, and it
// would be the easiest thing in this repo to attack because it speaks HTTP and every tool
// on earth speaks HTTP. So: bind 127.0.0.1, and CHECK THE PEER ADDRESS ON EVERY REQUEST
// rather than trusting the bind. The bind is a request to the OS; the check is a fact.
// On Android in particular, interface and routing configuration is not something this
// process gets to assume.
//
// WHY NOTHING IS FETCHED. The page loads no fonts, no CDN, no analytics — not as a
// preference but because a spore is off-web by construction and a UI that phones home is
// a contradiction, not a convenience. test/glass.test.js asserts it rather than trusting
// this comment.
//
// WHAT IS NOT HERE. No control surface: nothing in the page can write a block, send a
// message, or change a setting. It reads. A read-only viewer needs no authentication
// beyond being on the device; the moment it can act, it does, and that is a different
// design with a different threat model.

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { MAX_WRITE_BUFFER } from '../transport/tcp.js';

export const MAX_CLIENTS = 4;
export const KEEPALIVE_MS = 15_000;

/**
 * The telemetry rows and events the page actually consumes.
 *
 * Enumerated, not forwarded wholesale. Telemetry payloads carry Buffers — spore ids, SAS
 * digests — and JSON.stringify turns a Buffer into `{type:'Buffer',data:[...]}`, which is
 * both wrong and larger than the thing it replaces. More to the point, forwarding
 * everything means every future telemetry row silently becomes part of a wire format and
 * part of what a page can see.
 */
const EVENTS = [
  ['beacon.started', () => ({})],
  ['beacon.peer', (p) => ({ sporeId: hex(p.sporeId), nick: p.nick || '' })],
  ['beacon.join_failed', (p) => ({ iface: String(p.iface ?? '') })],
  ['hypha.handshake.progress', (p) => ({ progress: num(p.progress) })],
  ['hypha.established', (p) => ({ peerId: hex(p.peerId), sas: hex(p.sas) })],
  ['hypha.closed', (p) => ({ peerId: hex(p.peerId), reason: String(p.reason ?? '') })],
  ['hypha.dial_refused', (p) => ({ host: String(p.host ?? ''), why: String(p.why ?? '') })],
];

const RATES = ['hypha.bytes'];
const COUNTERS = ['beacon.sent', 'substrate.blocks', 'hypha.established'];

const hex = (b) => (typeof b === 'string' ? b
  : b && b.length ? Buffer.from(b).toString('hex') : '');
const num = (x) => (Number.isFinite(x) ? x : 0);

/** Loopback, and only loopback. IPv4, IPv6, and the v4-mapped-in-v6 form Node may hand us. */
export function isLoopback(addr) {
  if (!addr) return false;
  const a = addr.replace(/^::ffff:/, '');
  return a === '127.0.0.1' || a === '::1' || a.startsWith('127.');
}

export class Glass {
  constructor(telemetry, { nick = 'spore', sporeId = '', port = 7777 } = {}) {
    this.tel = telemetry;
    this.nick = nick;
    this.sporeId = sporeId;
    this.port = port;
    this.clients = new Set();
    this.refused = 0;
    this.server = createServer((req, res) => this.#route(req, res));
    this.#wire();
  }

  #wire() {
    for (const [kind, shape] of EVENTS) {
      this.tel.on(kind, (payload = {}) => {
        let body;
        try { body = shape(payload); } catch { return; } // a malformed row is not a frame
        this.#broadcast({ kind, payload: body, ...this.#sample() });
      });
    }
    // beacon.sent is a COUNTER, not an event — MyceliumView drives the lone spore's breath
    // by intercepting count(), so the page needs the bump itself, not a rate.
    this.lastSent = 0;
    this.pulse = setInterval(() => {
      const sent = this.tel.get('beacon.sent') ?? 0;
      const bumps = [];
      for (let i = this.lastSent; i < sent; i++) bumps.push('beacon.sent');
      this.lastSent = sent;
      if (bumps.length || this.clients.size) this.#broadcast({ bumps, ...this.#sample() });
    }, 250);
    this.pulse.unref?.();
  }

  #sample() {
    // Omitted rather than zeroed when never measured. §3.3: the page renders U+2298 for a
    // row it has never seen, and a zero here would replace that with a calm lie — an idle
    // mesh drawn over a feed that has told us nothing. Asking `hasRate` rather than
    // testing the value is the whole distinction: a genuinely quiet row reports 0 and
    // should be drawn as 0.
    const rates = {};
    for (const r of RATES) {
      if (!this.tel.hasRate?.(r)) continue;
      const v = this.tel.rateOf(r);
      if (Number.isFinite(v)) rates[r] = v;
    }
    const counters = {};
    for (const c of COUNTERS) {
      if (!this.tel.hasCounter?.(c)) continue;
      const v = this.tel.get(c);
      if (Number.isFinite(v)) counters[c] = v;
    }
    return { rates, counters };
  }

  #broadcast(frame) {
    if (!this.clients.size) return;
    const line = `data: ${JSON.stringify(frame)}\n\n`;
    for (const res of this.clients) {
      // The same rule as Hypha.send, for the same reason: a client that stops reading is a
      // queue it controls for free, and TCP will never drain on its own. Node's docs are
      // explicit that writing a socket which is not draining is remotely exploitable.
      if (res.socket && res.socket.writableLength > MAX_WRITE_BUFFER) {
        this.#drop(res, 'not_draining');
        continue;
      }
      res.write(line);
    }
  }

  #drop(res, why) {
    this.clients.delete(res);
    this.tel.count?.(`glass.dropped.${why}`);
    try { res.end(); } catch { /* already gone */ }
    res.socket?.destroy();
  }

  #route(req, res) {
    if (!isLoopback(req.socket?.remoteAddress)) {
      this.refused += 1;
      this.tel.count?.('glass.refused');
      res.writeHead(403, { 'content-type': 'text/plain' });
      return res.end('glass is loopback only\n');
    }
    const path = (req.url || '/').split('?')[0];
    if (path === '/events') return this.#stream(req, res);
    const asset = ASSETS[path] || (path === '/' ? ASSETS['/index.html'] : null);
    if (!asset) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('no\n');
    }
    res.writeHead(200, {
      'content-type': asset.type,
      'cache-control': 'no-store',
      // The page loads nothing from anywhere. Said to the browser as well as to the
      // reader, so a mistake in the HTML is refused rather than silently working.
      'content-security-policy':
        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
      'x-content-type-options': 'nosniff',
    });
    res.end(asset.body(this));
  }

  #stream(req, res) {
    if (this.clients.size >= MAX_CLIENTS) {
      res.writeHead(503, { 'content-type': 'text/plain' });
      return res.end('too many viewers\n');
    }
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    });
    res.socket?.setNoDelay?.(true);
    this.clients.add(res);
    res.write(`data: ${JSON.stringify(this.#sample())}\n\n`);

    const ka = setInterval(() => {
      if (!this.clients.has(res)) return clearInterval(ka);
      res.write(': keepalive\n\n');
    }, KEEPALIVE_MS);
    ka.unref?.();

    const gone = () => { clearInterval(ka); this.clients.delete(res); };
    req.on('close', gone);
    req.on('error', gone);
    res.on('error', gone);
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      // The host is half the protection and the per-request check is the other half.
      this.server.listen(this.port, '127.0.0.1', () => {
        this.port = this.server.address().port;
        resolve(`http://127.0.0.1:${this.port}/`);
      });
    });
  }

  async stop() {
    clearInterval(this.pulse);
    for (const res of [...this.clients]) this.#drop(res, 'shutdown');
    await new Promise((r) => this.server.close(r));
  }
}

// --- served assets ---------------------------------------------------------------------
//
// Everything is same-origin and relative. No scheme, no host, no protocol-relative `//`
// anywhere — that is the property test/glass.test.js checks, by parsing these strings
// rather than by reading this paragraph.

const PAGE = (g) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>spore · ${escapeHtml(g.nick)}</title>
<style>
  html,body{margin:0;height:100%;background:#06080c;color:#bed6d8;
    font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overscroll-behavior:none}
  #m{position:fixed;inset:0}
  noscript{display:block;padding:2rem;line-height:1.6}
</style>
</head><body>
<div id="m" data-nick="${escapeHtml(g.nick)}" data-spore="${escapeHtml(g.sporeId)}"></div>
<noscript>This view draws the mesh as it grows, which needs scripting. The terminal UI shows the same thing.</noscript>
<script type="module" src="./ui/web/main.js"></script>
</body></html>
`;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const JS = 'text/javascript; charset=utf-8';
export const MODULE_ROUTES = [
  ['/ui/web/main.js', 'web/main.js'],
  ['/ui/web/boot.js', 'web/boot.js'],
  ['/ui/web/feed.js', 'web/feed.js'],
  ['/ui/web/paint.js', 'web/paint.js'],
  ['/ui/mycelium.js', 'mycelium.js'],
  ['/ui/palette.js', 'palette.js'],
];

const ASSETS = {
  '/index.html': { type: 'text/html; charset=utf-8', body: PAGE },
};
for (const [route, file] of MODULE_ROUTES) {
  ASSETS[route] = { type: JS, body: () => readModule(file) };
}

// Read once, from disk, at first request. These are the SAME files Node imports — not a
// copy, not a bundle — so there is exactly one MyceliumView in the project and no build
// step that could let the terminal's and the browser's drift apart.
//
// The routes mirror the source tree for the same reason, which means every relative import
// inside the modules already resolves without rewriting: web/boot.js asking for
// '../mycelium.js' lands on /ui/mycelium.js because that is where it is.
const cache = new Map();
function readModule(rel) {
  if (!cache.has(rel)) cache.set(rel, readFileSync(new URL(rel, import.meta.url), 'utf8'));
  return cache.get(rel);
}
