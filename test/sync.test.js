import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { HyphaManager } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, logIdFor, newLogId, TYPE, FLAG } from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';
import { Syncer } from '../src/sharding/sync.js';
import { Telemetry } from '../src/telemetry/bus.js';
import {
  MSG, encodeHave, decodeHave, encodePairs, decodePairs,
  encodeBlockMsg, decodeBlockMsg, MAX_BODY,
} from '../src/sharding/wire.js';

// --- helpers ------------------------------------------------------------------------

function identity() {
  const kp = generateKeyPairSync('ed25519');
  const pub = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { kp, pub, logId: logIdFor(pub) };
}

/** A real hash-chained log: n blocks, each committing the previous block's hash. */
function chain(id, n, prefix = 'block') {
  const out = [];
  let prevHash = Buffer.alloc(32);
  for (let i = 0; i < n; i++) {
    const payload = Buffer.from(`${prefix} ${i}`);
    const { cert, blockHash } = encodeBlock(
      {
        type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE,
        logId: id.logId, seq: i, lamport: i + 1, prevHash, payload,
      },
      id.kp.privateKey,
    );
    out.push({ cert, payload });
    prevHash = blockHash;
  }
  return out;
}

function spore(port, { seedFrom = null, seedCount = 0 } = {}) {
  const id = identity();
  const tel = new Telemetry();
  const store = new Substrate({ telemetry: tel });
  const mgr = new HyphaManager({
    sporeId: id.pub, staticKeys: generateStatic(),
    idPublicRaw: id.pub, idPrivate: id.kp.privateKey, telemetry: tel, port,
  });
  const sync = new Syncer({ substrate: store, hyphaManager: mgr, telemetry: tel, selfPub: id.pub });
  if (seedFrom) {
    const blocks = seedCount ? seedFrom.blocks.slice(0, seedCount) : seedFrom.blocks;
    for (const b of blocks) {
      const r = store.insert(b.cert, b.payload, seedFrom.id.pub);
      assert.ok(r.ok, `seeding must succeed: ${r.reason}`);
    }
  }
  return { id, tel, store, mgr, sync, port };
}

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll until `fn()` is true or the budget runs out. Returns whether it became true. */
async function until(fn, budgetMs = 6000) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await settle(15);
  }
  return fn();
}

// --- wire codec ---------------------------------------------------------------------

test('wire: HAVE round-trips log id, author and bitfield exactly', () => {
  const a = identity();
  const b = identity();
  const bits = Uint8Array.from([0b10110101, 0b00000011]);
  const { body, dropped } = encodeHave([
    { logId: a.logId, authorPub: a.pub, bitlen: 10, bits },
    { logId: b.logId, authorPub: b.pub, bitlen: 1, bits: Uint8Array.from([1]) },
  ]);
  assert.equal(dropped, 0);
  const back = decodeHave(body);
  assert.equal(back.length, 2);
  assert.ok(back[0].logId.equals(a.logId));
  assert.ok(back[0].authorPub.equals(a.pub));
  assert.equal(back[0].bitlen, 10);
  assert.deepEqual([...back[0].bits], [...bits]);
  assert.ok(back[1].authorPub.equals(b.pub));
});

test('wire: pair lists round-trip and are capped to one frame, never overflowing it', () => {
  const id = identity();
  const pairs = Array.from({ length: 5000 }, (_, i) => ({ logId: id.logId, seq: i }));
  const body = encodePairs(MSG.REQUEST, pairs);
  assert.ok(body.length <= MAX_BODY, `${body.length} must fit ${MAX_BODY}`);
  const back = decodePairs(body);
  assert.ok(back.length > 0 && back.length < pairs.length, 'must truncate, not drop or overflow');
  assert.equal(back[0].seq, 0);
  assert.equal(back.at(-1).seq, back.length - 1);
  assert.ok(back[7].logId.equals(id.logId));
});

test('wire: BLOCK carries the author key alongside the cert', () => {
  const id = identity();
  const [b0] = chain(id, 1);
  const msg = encodeBlockMsg(b0.cert, b0.payload, id.pub);
  const back = decodeBlockMsg(msg);
  assert.ok(back.cert.equals(b0.cert));
  assert.ok(back.payload.equals(b0.payload));
  assert.ok(back.authorPub.equals(id.pub));
});

// --- store --------------------------------------------------------------------------

test('store: a block verifies alone, so blocks may arrive in any order', () => {
  const id = identity();
  const blocks = chain(id, 6);
  const s = new Substrate();

  // deliberately backwards — this is the property parallel fetch depends on
  for (let i = 5; i >= 0; i--) {
    const r = s.insert(blocks[i].cert, blocks[i].payload, id.pub);
    assert.ok(r.ok, `seq ${i}: ${r.reason}`);
  }
  const rep = s.replica(id.logId.toString('hex'));
  assert.equal(rep.held, 6);
  assert.equal(rep.linkedTo, 5, 'the chain must link all the way once the gaps close');
});

test('store: the linked frontier stops at a gap and resumes when it is filled', () => {
  const id = identity();
  const blocks = chain(id, 5);
  const s = new Substrate();
  const linked = [];
  s.on('linked', ({ seqs }) => linked.push(...seqs));

  for (const i of [0, 1, 3, 4]) s.insert(blocks[i].cert, blocks[i].payload, id.pub);
  const rep = s.replica(id.logId.toString('hex'));
  assert.equal(rep.held, 4);
  assert.equal(rep.linkedTo, 1, 'cannot link past a missing block');

  s.insert(blocks[2].cert, blocks[2].payload, id.pub);
  assert.equal(rep.linkedTo, 4, 'filling the gap promotes the whole run at once');
  assert.deepEqual(linked, [0, 1, 2, 3, 4]);
});

test('store: a log cannot be claimed by a key it does not name', () => {
  const alice = identity();
  const mallory = identity();
  const [b0] = chain(alice, 1);
  const s = new Substrate();

  // Mallory relays Alice's block but names himself as the author.
  const r = s.insert(b0.cert, b0.payload, mallory.pub);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad_signature', 'his key does not verify her signature');

  // And a block Mallory signed into a log id he does not own is refused on the binding.
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, logId: alice.logId, seq: 0, lamport: 1, payload: Buffer.alloc(0) },
    mallory.kp.privateKey,
  );
  const r2 = s.insert(cert, Buffer.alloc(0), mallory.pub);
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'log_author_mismatch');
});

test('store: an author signing two blocks at one seq is detected, not silently accepted', () => {
  const id = identity();
  const s = new Substrate();
  const mk = (text) => encodeBlock(
    { type: TYPE.MESSAGE, logId: id.logId, seq: 3, lamport: 4, payload: Buffer.from(text) },
    id.kp.privateKey,
  );
  const a = mk('what I told you');
  const b = mk('what I told them');

  assert.ok(s.insert(a.cert, Buffer.from('what I told you'), id.pub).ok);
  const seen = [];
  s.on('equivocation', (e) => seen.push(e));
  const r = s.insert(b.cert, Buffer.from('what I told them'), id.pub);

  assert.equal(r.ok, false);
  assert.equal(r.reason, 'equivocation');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].seq, 3);
  assert.ok(!seen[0].kept.equals(seen[0].rejected), 'two genuinely different blocks');
});

test('store: a random log id has no author and is refused', () => {
  const id = identity();
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, logId: newLogId(), seq: 0, lamport: 1, payload: Buffer.alloc(0) },
    id.kp.privateKey,
  );
  assert.equal(s_insert(cert, id.pub).reason, 'log_author_mismatch');
  function s_insert(c, pub) { return new Substrate().insert(c, Buffer.alloc(0), pub); }
});

// --- real transfer over real sockets -------------------------------------------------

test('sync: a joiner pulls a whole backlog over real hyphae and links every block', async () => {
  const author = identity();
  const blocks = chain(author, 40, 'history');

  const seeder = spore(47610, { seedFrom: { id: author, blocks } });
  const joiner = spore(47611);
  await seeder.mgr.listen();
  await joiner.mgr.listen();
  seeder.sync.start();
  joiner.sync.start();

  const done = new Promise((res) => joiner.sync.once('complete', res));
  await joiner.mgr.dial({ sporeId: seeder.id.pub, addrs: ['127.0.0.1'], tcpPort: 47610 });
  await done;

  const rep = joiner.store.replica(author.logId.toString('hex'));
  assert.equal(rep.held, 40, 'every block arrived');
  assert.equal(rep.linkedTo, 39, 'and the chain links end to end');
  assert.equal(rep.get(17).payload.toString(), 'history 17');
  assert.ok(rep.authorPub.equals(author.pub), 'the log is bound to its real author');

  // No stranded reservations. This is the failure mode that does not announce itself.
  for (const l of joiner.sync.logs.values()) {
    assert.equal(l.inflightGlobal.size, 0, 'every reservation was released');
    for (const p of l.peers.values()) assert.equal(p.inflight.size, 0);
  }
  assert.equal(joiner.sync.stats.timedOut, 0, 'nothing had to be recovered by timeout');
  assert.ok(joiner.sync.stats.requested >= 40);

  seeder.sync.stop(); joiner.sync.stop();
  await seeder.mgr.stop(); await joiner.mgr.stop();
});

test('sync: a joiner pulls from two partial seeders, neither of which holds the whole log', async () => {
  const author = identity();
  const blocks = chain(author, 30, 'split');

  // Deliberately disjoint: evens on one, odds on the other. Neither can finish the job
  // alone, so completing at all proves blocks came from both.
  const evens = blocks.filter((_, i) => i % 2 === 0);
  const odds = blocks.filter((_, i) => i % 2 === 1);

  const a = spore(47620, { seedFrom: { id: author, blocks: evens } });
  const b = spore(47621, { seedFrom: { id: author, blocks: odds } });
  const joiner = spore(47622);
  for (const s of [a, b, joiner]) await s.mgr.listen();
  for (const s of [a, b, joiner]) s.sync.start();

  const done = new Promise((res) => joiner.sync.once('complete', res));
  await joiner.mgr.dial({ sporeId: a.id.pub, addrs: ['127.0.0.1'], tcpPort: 47620 });
  await joiner.mgr.dial({ sporeId: b.id.pub, addrs: ['127.0.0.1'], tcpPort: 47621 });
  await done;

  const rep = joiner.store.replica(author.logId.toString('hex'));
  assert.equal(rep.held, 30);
  assert.equal(rep.linkedTo, 29);

  // Both seeders were actually used, so this really was a parallel fetch.
  assert.ok(a.sync.stats.served > 0, 'seeder A served nothing');
  assert.ok(b.sync.stats.served > 0, 'seeder B served nothing');

  for (const s of [a, b, joiner]) { s.sync.stop(); await s.mgr.stop(); }
});

test('sync: cache-on-fetch — a joiner becomes a source before it has finished', async () => {
  const author = identity();
  const blocks = chain(author, 24, 'supply');

  const seeder = spore(47630, { seedFrom: { id: author, blocks } });
  const first = spore(47631);
  const second = spore(47632);
  for (const s of [seeder, first, second]) await s.mgr.listen();
  for (const s of [seeder, first, second]) s.sync.start();

  // `first` fetches from the seeder; `second` is attached ONLY to `first`, never to the
  // seeder. If HAVE_ADD did not exist, `second` would sit at zero forever — the entire
  // supply-growth claim in one assertion.
  await first.mgr.dial({ sporeId: seeder.id.pub, addrs: ['127.0.0.1'], tcpPort: 47630 });
  await second.mgr.dial({ sporeId: first.id.pub, addrs: ['127.0.0.1'], tcpPort: 47631 });

  const key = author.logId.toString('hex');
  const ok = await until(() => (second.store.replica(key)?.held || 0) === 24);
  assert.ok(ok, `second only reached ${second.store.replica(key)?.held || 0}/24 blocks`);
  assert.ok(first.sync.stats.served > 0, 'the middle spore must have re-served what it fetched');
  assert.equal(second.store.replica(key).linkedTo, 23);

  for (const s of [seeder, first, second]) { s.sync.stop(); await s.mgr.stop(); }
});

test('sync: a peer that withers mid-transfer strands nothing', async () => {
  const author = identity();
  const blocks = chain(author, 60, 'churn');

  const dying = spore(47640, { seedFrom: { id: author, blocks } });
  const stable = spore(47641, { seedFrom: { id: author, blocks } });
  const joiner = spore(47642);
  for (const s of [dying, stable, joiner]) await s.mgr.listen();
  for (const s of [dying, stable, joiner]) s.sync.start();

  await joiner.mgr.dial({ sporeId: dying.id.pub, addrs: ['127.0.0.1'], tcpPort: 47640 });
  // Kill the first seeder the moment anything is in flight, so reservations are open.
  await until(() => joiner.sync.stats.requested > 0, 3000);
  await dying.mgr.stop();
  dying.sync.stop();

  await joiner.mgr.dial({ sporeId: stable.id.pub, addrs: ['127.0.0.1'], tcpPort: 47641 });
  const key = author.logId.toString('hex');
  const ok = await until(() => (joiner.store.replica(key)?.held || 0) === 60, 10000);
  assert.ok(ok, `stalled at ${joiner.store.replica(key)?.held || 0}/60 — reservations stranded`);
  assert.equal(joiner.store.replica(key).linkedTo, 59);

  for (const l of joiner.sync.logs.values()) {
    assert.equal(l.inflightGlobal.size, 0);
  }

  stable.sync.stop(); joiner.sync.stop();
  await stable.mgr.stop(); await joiner.mgr.stop();
});
