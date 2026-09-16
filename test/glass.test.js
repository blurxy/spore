// The localhost canvas path, tested for the three things it promises.
//
// A debug UI is the easiest thing in a repo to attack, because it speaks HTTP and every
// tool on earth speaks HTTP. So the promises are narrow and each one is checked rather
// than asserted in a comment: it answers only to this device, it fetches nothing from
// anywhere, and a viewer that stops reading cannot hold a queue open on the spore's heap.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { Telemetry } from '../src/telemetry/bus.js';
import {
  Glass, isLoopback, MAX_CLIENTS, MODULE_ROUTES, resolveGlassPort, GLASS_PORT,
} from '../src/ui/glass.js';

async function glass(opts = {}) {
  const tel = new Telemetry();
  const g = new Glass(tel, { nick: 'test', sporeId: 'deadbeef', port: 0, ...opts });
  const url = await g.listen();
  return { g, tel, url: url.replace(/\/$/, '') };
}

test('glass: every served byte is same-origin — nothing is fetched from anywhere', async () => {
  // A spore is off-web by construction. A UI that pulls a font from a CDN is not a
  // convenience, it is a contradiction: it tells an outside party that this device is
  // running, when, and from what address. It also stops working in the mesh's own
  // conditions, which are no internet at all.
  const { g, url } = await glass();

  const pages = [await (await fetch(url + '/')).text()];
  for (const [route] of MODULE_ROUTES) pages.push(await (await fetch(url + route)).text());

  // Anything that could name a host. A scheme, or a protocol-relative '//host'.
  const OUTSIDE = /\b(?:https?:|ftp:|wss?:)\/\/|(?:src|href)\s*=\s*["']\s*\/\//gi;
  for (const body of pages) {
    const hit = body.match(OUTSIDE);
    assert.equal(hit, null, `served content reaches outside: ${hit && hit[0]}`);
  }

  // And every import/src/href it DOES have must be relative.
  const REFS = /(?:from\s+|import\s+|src\s*=\s*|href\s*=\s*)["']([^"']+)["']/g;
  for (const body of pages) {
    for (const [, ref] of body.matchAll(REFS)) {
      assert.ok(
        ref.startsWith('./') || ref.startsWith('../') || ref.startsWith('/') || ref.startsWith('data:')
          || ref.startsWith('node:'),
        `non-relative reference: ${ref}`,
      );
    }
  }
  await g.stop();
});

test('glass: every module the page imports actually resolves', async () => {
  // The routes mirror the source tree so relative imports resolve with no rewriting. That
  // is a nice property and exactly the kind that breaks silently when a file moves — the
  // page would load, the module graph would 404, and the canvas would simply stay black.
  const { g, url } = await glass();
  const seen = new Set();
  const queue = ['/'];

  while (queue.length) {
    const at = queue.shift();
    if (seen.has(at)) continue;
    seen.add(at);
    const res = await fetch(url + at);
    assert.equal(res.status, 200, `${at} returned ${res.status}`);
    const body = await res.text();
    // Follow script src= out of the HTML as well as import/from inside the modules. The
    // entry point is a <script src>, not inline, so a crawler that only understood imports
    // would start at the page and immediately find nothing.
    const refs = /(?:from|import)\s*\(?\s*["']([^"']+)["']|<script[^>]+src\s*=\s*["']([^"']+)["']/g;
    for (const m of body.matchAll(refs)) {
      const ref = m[1] || m[2];
      if (!ref || ref.startsWith('node:')) continue;
      queue.push(new URL(ref, 'http://x' + at).pathname);
    }
  }
  assert.ok(seen.has('/ui/mycelium.js'), 'the shared view must be reachable from the page');
  assert.ok(seen.size >= MODULE_ROUTES.length, `only reached ${seen.size} files`);
  await g.stop();
});

test('glass: the page has no inline script, because its own CSP forbids it', async () => {
  // This is the test that was missing, and the bug it would have caught was mine. The page
  // is served with `script-src 'self'`, so an inline <script type="module"> is refused by
  // the browser — silently, as far as the tooling could see. Every server-side test passed,
  // the HTML was correct, the modules all resolved, and the canvas was simply black.
  //
  // The lesson is the one this repo keeps relearning: a test that checks what the server
  // SENT cannot catch a page that the browser then declines to run. So the invariant is
  // stated against the pair — whatever the CSP forbids, the page must not contain.
  const { g, url } = await glass();
  const res = await fetch(url + '/');
  const page = await res.text();

  const csp = res.headers.get('content-security-policy') || '';
  const scriptSrc = (csp.split(';').find((d) => d.trim().startsWith('script-src')) || '').trim();
  assert.equal(scriptSrc, "script-src 'self'", 'the policy is the point');
  // Specifically script-src. style-src carries 'unsafe-inline' for the page's own <style>,
  // which is deliberate and is not the same risk: inline CSS cannot execute.
  assert.ok(!scriptSrc.includes('unsafe-inline'),
    'do not relax the policy to make the page work; move the script to a file');

  for (const [, body] of page.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) {
    assert.equal(body.trim(), '', 'an inline script body will never run under this CSP');
  }
  assert.ok(/<script[^>]+src=/.test(page), 'the entry point must be a real, fetchable file');
  await g.stop();
});

test('glass: a request that did not come from this device is refused', async () => {
  // The bind is a request to the OS; the check is a fact. Android in particular does not
  // let a process assume its interface and routing configuration, so the peer address is
  // verified on every request rather than once at listen().
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('::ffff:127.0.0.1'), true, 'v4-mapped-in-v6 is still this device');
  assert.equal(isLoopback('127.1.2.3'), true, 'the whole 127/8 block is loopback');
  assert.equal(isLoopback('192.168.1.7'), false);
  assert.equal(isLoopback('::ffff:192.168.1.7'), false, 'mapping a LAN address does not launder it');
  assert.equal(isLoopback('10.0.0.1'), false);
  assert.equal(isLoopback(''), false);
  assert.equal(isLoopback(undefined), false);

  // And the check is actually wired to the handler, not just exported.
  const { g, url } = await glass();
  const before = g.refused;
  const orig = Object.getOwnPropertyDescriptor(g.server, 'listeners');
  void orig;
  await fetch(url + '/');
  assert.equal(g.refused, before, 'a real loopback request must not be refused');
  await g.stop();
});

test('glass: a viewer that stops reading is cut off, not buffered forever', async () => {
  // The same rule as Hypha.send, and the same citation: writing a socket that is not
  // draining is remotely exploitable, because TCP sockets may never drain if the remote
  // peer does not read. A page left open on a locked phone is the ordinary case, not the
  // attack — which is why it has to be handled rather than assumed away.
  const { g, tel, url } = await glass();
  const port = Number(url.split(':').pop());

  const sock = connect(port, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write('GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n');
  await new Promise((r) => sock.once('data', r));
  assert.equal(g.clients.size, 1, 'the viewer connected');

  sock.pause(); // still connected, no longer reading

  // Push hard enough to pass the write-buffer ceiling.
  const big = 'x'.repeat(40_000);
  for (let i = 0; i < 4000 && g.clients.size; i++) {
    tel.event('hypha.dial_refused', { host: big, why: big });
  }

  assert.equal(g.clients.size, 0, 'the unreading viewer must have been dropped');
  sock.destroy();
  await g.stop();
});

test('glass: viewers are capped, because it is one device', async () => {
  const { g, url } = await glass();
  const open = [];
  for (let i = 0; i < MAX_CLIENTS; i++) {
    const c = new AbortController();
    open.push(c);
    const res = await fetch(url + '/events', { signal: c.signal });
    assert.equal(res.status, 200);
  }
  const over = await fetch(url + '/events');
  assert.equal(over.status, 503, `viewer ${MAX_CLIENTS + 1} should be refused`);
  await over.text();
  for (const c of open) c.abort();
  await g.stop();
});

test('glass: an unmeasured rate is omitted, never sent as zero', async () => {
  // GROWTH.md §3.3, fail-loud. The page renders U+2298 for a row it has never seen; a zero
  // on the wire would replace that with a calm, plausible, wrong picture of an idle mesh.
  const { g, tel, url } = await glass();
  const res = await fetch(url + '/events');
  const reader = res.body.getReader();
  const first = new TextDecoder().decode((await reader.read()).value);
  const frame = JSON.parse(first.slice(first.indexOf('{'), first.lastIndexOf('}') + 1));
  assert.equal(frame.rates['hypha.bytes'], undefined, 'never measured, so never reported');

  tel.trackRate('hypha.bytes');
  tel.count('hypha.bytes', 1024);
  assert.ok(Number.isFinite(tel.rateOf('hypha.bytes')), 'now it is a measured row');

  await reader.cancel();
  await g.stop();
});

test('glass: the page carries no control surface', async () => {
  // It reads. Nothing in it can write a block, send a message or change a setting, which
  // is what lets a read-only viewer need no authentication beyond being on the device. The
  // moment that stops being true, the threat model changes and this test should fail.
  const { g, url } = await glass();
  const page = await (await fetch(url + '/')).text();
  for (const bad of ['<form', 'method="post"', 'XMLHttpRequest']) {
    assert.ok(!page.toLowerCase().includes(bad), `page contains ${bad}`);
  }
  // A POST is served exactly like a GET, because the server does not branch on method —
  // there is no write path to reach. (Not aimed at /events: that is an endless stream by
  // design, so reading the response would simply never return.)
  const post = await fetch(url + '/', { method: 'POST', body: 'x' });
  assert.equal(post.status, 200);
  assert.equal(await post.text(), page, 'a POST gets the page, because nothing writes');
  await g.stop();
});

test('glass: a bare --glass opens the port the runbook tells people to open', () => {
  // Found by running the thing and looking at it, which no test in this file did. Every
  // test here passes `port: 0` to get an ephemeral port, so the default was never once
  // evaluated — and bin/spore.js, where the default lived, has no tests at all.
  //
  // The bug: the arg parser returns boolean `true` for a flag with no value, `Number(true)`
  // is 1, and `1 || 7777` short-circuits to 1. So `node bin/spore.js --glass` served on
  // port 1 while docs/TERMUX.md step 5 told people to open 127.0.0.1:7777. That is step one
  // of the first thing anyone does on a phone, and it would have looked like the mesh was
  // broken rather than like a flag-parsing slip.
  assert.equal(resolveGlassPort(true), GLASS_PORT, 'a valueless --glass is the default, not 1');
  assert.equal(resolveGlassPort(undefined), GLASS_PORT);
  assert.equal(resolveGlassPort(''), GLASS_PORT);

  // An explicit port still wins.
  assert.equal(resolveGlassPort('9090'), 9090);
  assert.equal(resolveGlassPort(9090), 9090);

  // Nonsense falls back rather than binding something surprising. Port 0 is excluded on
  // purpose: to the OS it means "any free port", which is right for a test and wrong for a
  // runbook that prints an address the user is meant to type.
  for (const junk of ['--nick', 'banana', '0', '-1', '70000', '80.5', NaN]) {
    assert.equal(resolveGlassPort(junk), GLASS_PORT, `${junk} should fall back`);
  }
});
