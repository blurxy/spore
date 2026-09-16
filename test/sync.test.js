import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { HyphaManager, MAX_WRITE_BUFFER } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, logIdFor, newLogId, TYPE, FLAG } from '../src/substrate/block.js';
import { Substrate } from '../src/substrate/store.js';
import { Syncer } from '../src/sharding/sync.js';
import { Telemetry } from '../src/telemetry/bus.js';
import {
  MSG, encodeHave, decodeHave, encodePairs, decodePairs,
  encodeBlockMsg, decodeBlockMsg, MAX_BODY, MAX_SEQ, WireError,
} from '../src/sharding/wire.js';
import { MAX_LOGS } from '../src/sharding/sync.js';

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

test('wire: a seq above MAX_SEQ is refused before anything is sized from it', () => {
  // seq arrives as a raw u32. Sizing an allocation from it means a 23-byte frame can ask
  // for a 512 MB Uint8Array — on a phone that is the process. The bound has to sit in the
  // decoder, before any caller can be tempted to trust the number.
  const id = identity();
  const body = Buffer.alloc(3 + 20);
  body.writeUInt8(MSG.HAVE_ADD, 0);
  body.writeUInt16LE(1, 1);
  id.logId.copy(body, 3);
  body.writeUInt32LE(0xffffffff, 19);

  assert.throws(() => decodePairs(body), (e) => e instanceof WireError && e.code === 'seq_out_of_range');

  // and the boundary is exactly where it says it is
  const ok = Buffer.from(body);
  ok.writeUInt32LE(MAX_SEQ, 19);
  assert.equal(decodePairs(ok)[0].seq, MAX_SEQ, 'MAX_SEQ itself is legal');
  const bad = Buffer.from(body);
  bad.writeUInt32LE(MAX_SEQ + 1, 19);
  assert.throws(() => decodePairs(bad), /seq_out_of_range/);
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

test('store: a block that asserts its lamport instead of deriving it stops the log', () => {
  // The inflation attack the spec says is closed. It was not: nothing anywhere compared
  // the lamport field to 1 + max(own previous, deps), so a peer could declare 2^60 and
  // pin every receiving spore's clock there forever.
  const id = identity();
  const s = new Substrate();
  let prevHash = Buffer.alloc(32);
  const mk = (seq, lamport) => {
    const payload = Buffer.from(`b${seq}`);
    const r = encodeBlock(
      { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq, lamport, prevHash, payload },
      id.kp.privateKey,
    );
    prevHash = r.blockHash;
    return { cert: r.cert, payload };
  };

  const b0 = mk(0, 1n);
  const b1 = mk(1, 1n << 60n);   // the lie
  const b2 = mk(2, (1n << 60n) + 1n); // self-consistent with the lie

  for (const b of [b0, b1, b2]) assert.ok(s.insert(b.cert, b.payload, id.pub).ok, 'all are signed correctly');

  const rep = s.replica(id.logId.toString('hex'));
  assert.equal(rep.held, 3, 'they are authentic, so they are held');
  assert.equal(rep.linkedTo, 0, 'but the chain stops at the first asserted lamport');
});

test('store: lamport is derived across logs, and a dep must LINK before it counts', () => {
  // The first dep-carrying blocks in this project. Until now depCount was always 0, so
  // this path had never run: a block whose lamport depends on another LOG's block.
  const alice = identity();
  const bob = identity();

  const aPayload = Buffer.from('alice 0');
  const a0 = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: alice.logId, seq: 0, lamport: 1n, payload: aPayload },
    alice.kp.privateKey,
  );
  const aPayload1 = Buffer.from('alice 1');
  const a1 = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: alice.logId, seq: 1, lamport: 2n,
      prevHash: a0.blockHash, payload: aPayload1 },
    alice.kp.privateKey,
  );

  // Bob's genesis cites Alice's second block: lamport = 1 + max(0, 2) = 3.
  const bPayload = Buffer.from('bob 0');
  const b0 = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: bob.logId, seq: 0, lamport: 3n,
      payload: bPayload, deps: [a1.blockHash] },
    bob.kp.privateKey,
  );

  const s = new Substrate();
  assert.ok(s.insert(b0.cert, bPayload, bob.pub).ok, 'held immediately — the signature is self-contained');
  const rb = s.replica(bob.logId.toString('hex'));
  assert.equal(rb.linkedTo, -1, 'but it cannot link: the dep is not here yet');

  s.insert(a1.cert, aPayload1, alice.pub);
  assert.equal(rb.linkedTo, -1, 'still not: alice seq 1 is held but not LINKED, so its lamport is unverified');

  s.insert(a0.cert, aPayload, alice.pub);
  assert.equal(s.replica(alice.logId.toString('hex')).linkedTo, 1, 'alice links end to end');
  assert.equal(rb.linkedTo, 0, 'and linking HER log unblocks HIS — one pass would have missed this');
});

test('store: a cross-log lamport that does not match the dep is refused', () => {
  const alice = identity();
  const bob = identity();
  const aP = Buffer.from('alice 0');
  const a0 = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: alice.logId, seq: 0, lamport: 1n, payload: aP },
    alice.kp.privateKey,
  );
  // cites a block with lamport 1, so the only legal value is 2. Claims 9.
  const bP = Buffer.from('bob 0');
  const b0 = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: bob.logId, seq: 0, lamport: 9n,
      payload: bP, deps: [a0.blockHash] },
    bob.kp.privateKey,
  );

  const s = new Substrate();
  s.insert(a0.cert, aP, alice.pub);
  s.insert(b0.cert, bP, bob.pub);
  assert.equal(s.replica(alice.logId.toString('hex')).linkedTo, 0);
  assert.equal(s.replica(bob.logId.toString('hex')).linkedTo, -1, 'the inflated cross-log claim never links');
});

test('store: a log cannot be claimed by a key it does not name', () => {
  const alice = identity();
  const mallory = identity();
  const [b0] = chain(alice, 1);
  const s = new Substrate();

  // Mallory relays Alice's block but names himself as the author. The log_id binding is
  // now checked BEFORE the signature — which key may sign is a property of the log, not
  // something the message gets to assert — so this is refused on the binding.
  const r = s.insert(b0.cert, b0.payload, mallory.pub);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'log_author_mismatch', 'his key does not name her log');

  // And a block Mallory signed into a log id he does not own is refused on the binding.
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, logId: alice.logId, seq: 0, lamport: 1, payload: Buffer.alloc(0) },
    mallory.kp.privateKey,
  );
  const r2 = s.insert(cert, Buffer.alloc(0), mallory.pub);
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'log_author_mismatch');
});

test('store: a log ALREADY KNOWN cannot be written by anyone but its author', () => {
  // The test above used a fresh Substrate, so the replica did not exist and the binding
  // check ran on creation. That is the only path it ever ran on. Once a replica exists —
  // i.e. always, after the first block — a second author could write into it freely.
  // A log_id binding that stops applying after block zero is not a binding.
  const alice = identity();
  const mallory = identity();
  const s = new Substrate();

  const g = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: alice.logId, seq: 0,
      lamport: 1, payload: Buffer.from('alice here') },
    alice.kp.privateKey,
  );
  assert.ok(s.insert(g.cert, Buffer.from('alice here'), alice.pub).ok, 'genesis creates the replica');

  // Mallory signs a block claiming ALICE's log id, under HIS OWN key, chained correctly
  // onto her genesis. The signature is real — it is just not hers.
  const evil = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: alice.logId, seq: 1,
      lamport: 2, prevHash: g.blockHash, payload: Buffer.from('ALICE SAID THIS') },
    mallory.kp.privateKey,
  );
  const r = s.insert(evil.cert, Buffer.from('ALICE SAID THIS'), mallory.pub);

  assert.equal(r.ok, false, 'forging into an existing log must be refused');
  const rep = s.replica(alice.logId.toString('hex'));
  assert.equal(rep.has(1), false, 'and the forged block must not be stored');
  assert.equal(rep.linkedTo, 0, 'and above all must not reach the linked chain');
  assert.ok(rep.authorPub.equals(alice.pub), 'the replica still names alice');
});

test('store: knowing the real author key does not help a forger either', () => {
  // Alice's public key is public. A forger supplies it honestly and signs with their own
  // private key — so the fix cannot be "check the supplied key binds to the log id".
  // Once a replica exists, its stored key is the only one that may verify anything.
  const alice = identity();
  const mallory = identity();
  const s = new Substrate();
  const [g] = chain(alice, 1);
  assert.ok(s.insert(g.cert, g.payload, alice.pub).ok);

  const evil = encodeBlock(
    { type: TYPE.MESSAGE, logId: alice.logId, seq: 1, lamport: 2, payload: Buffer.alloc(0) },
    mallory.kp.privateKey,
  );
  const r = s.insert(evil.cert, Buffer.alloc(0), alice.pub); // claims alice, signed by mallory
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad_signature');
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
  assert.ok(!seen[0].a.equals(seen[0].b), 'two genuinely different blocks');
  assert.ok(seen[0].certA && seen[0].certB, 'the proof must carry the certs, not just hashes');
});

/** A log that forks at `at`: one chain, plus a second block signed at the same seq. */
function forkedChain(id, n, at) {
  const main = chain(id, n, 'main');
  let prevHash = Buffer.alloc(32);
  for (let i = 0; i < at; i++) {
    prevHash = encodeBlock(
      { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: i,
        lamport: i + 1, prevHash, payload: Buffer.from(`main ${i}`) },
      id.kp.privateKey,
    ).blockHash;
  }
  const payload = Buffer.from(`OTHER ${at}`);
  const { cert } = encodeBlock(
    { type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: at,
      lamport: at + 1, prevHash, payload },
    id.kp.privateKey,
  );
  return { main, other: { cert, payload } };
}

test('store: two spores that meet the branches in opposite orders still agree', () => {
  // The convergence property, stated as a test because keep-the-first-seen fails it
  // silently. X meets the main branch first, Y meets the other first. Under any rule that
  // depends on arrival order they end up holding different logs under the same log_id,
  // forever, and nothing reports an error.
  const id = identity();
  const { main, other } = forkedChain(id, 8, 4);

  const X = new Substrate();
  for (const b of main) X.insert(b.cert, b.payload, id.pub);
  X.insert(other.cert, other.payload, id.pub);

  const Y = new Substrate();
  Y.insert(other.cert, other.payload, id.pub);
  for (const b of main) Y.insert(b.cert, b.payload, id.pub);

  const rx = X.replica(id.logId.toString('hex'));
  const ry = Y.replica(id.logId.toString('hex'));

  assert.equal(rx.forkedAt, 4);
  assert.equal(ry.forkedAt, 4);
  assert.equal(rx.linkedTo, 3, 'the frontier stops below the contradiction');
  assert.equal(ry.linkedTo, ry.linkedTo);
  assert.equal(rx.linkedTo, ry.linkedTo, 'both agree despite opposite arrival order');
});

test('store: history linked past a fork is retracted when the fork turns up late', () => {
  const id = identity();
  const { main, other } = forkedChain(id, 8, 4);
  const s = new Substrate();
  const retracted = [];
  s.on('retracted', (e) => retracted.push(...e.seqs));

  for (const b of main) s.insert(b.cert, b.payload, id.pub);
  const rep = s.replica(id.logId.toString('hex'));
  assert.equal(rep.linkedTo, 7, 'the whole chain links while only one branch is known');

  s.insert(other.cert, other.payload, id.pub);
  assert.equal(rep.linkedTo, 3, 'and is withdrawn below the fork once it is known');
  assert.deepEqual(retracted, [4, 5, 6, 7]);
});

test('store: a fork proof convinces a spore that only ever saw one branch', () => {
  const id = identity();
  const { main, other } = forkedChain(id, 8, 4);

  const witness = new Substrate();
  for (const b of main) witness.insert(b.cert, b.payload, id.pub);
  let proof = null;
  witness.on('equivocation', (e) => { proof = e; });
  witness.insert(other.cert, other.payload, id.pub);
  assert.ok(proof, 'the witness must be able to produce a proof');

  // This spore has seen only the main branch and has no reason to doubt it.
  const naive = new Substrate();
  for (const b of main) naive.insert(b.cert, b.payload, id.pub);
  const rep = naive.replica(id.logId.toString('hex'));
  assert.equal(rep.linkedTo, 7);

  const res = naive.acceptForkProof(proof.certA, proof.certB, id.pub);
  assert.ok(res.ok, res.reason);
  assert.equal(rep.linkedTo, 3, 'the proof alone is enough — no trust in the messenger');
  assert.equal(naive.acceptForkProof(proof.certA, proof.certB, id.pub).duplicate, true);
});

test('store: a fork proof that does not prove a fork is refused', () => {
  const id = identity();
  const stranger = identity();
  const blocks = chain(id, 3);
  const s = new Substrate();

  assert.equal(s.acceptForkProof(blocks[0].cert, blocks[0].cert, id.pub).reason, 'proof_same_block');
  assert.equal(s.acceptForkProof(blocks[0].cert, blocks[1].cert, id.pub).reason, 'proof_different_seq');

  // A stranger cannot open a log they do not name, so the binding refuses before any
  // signature is considered. (This used to report proof_bad_signature, because the
  // signature was checked under the key the CALLER supplied — the same inversion that
  // let forged blocks into other people's logs.)
  const { main, other } = forkedChain(id, 4, 2);
  const fresh = new Substrate();
  assert.equal(fresh.acceptForkProof(main[2].cert, other.cert, stranger.pub).reason, 'log_author_mismatch');
});

test('store: a real fork proof is accepted no matter who relays it', () => {
  // The flip side of the binding: once the log is known, its own stored key decides.
  // A proof is a claim about an author contradicting themselves, and it verifies on its
  // own terms — so the messenger's identity is irrelevant and may be anyone's.
  const id = identity();
  const stranger = identity();
  const { main, other } = forkedChain(id, 6, 3);

  const s = new Substrate();
  for (const b of main) s.insert(b.cert, b.payload, id.pub);
  assert.equal(s.replica(id.logId.toString('hex')).linkedTo, 5);

  const res = s.acceptForkProof(main[3].cert, other.cert, stranger.pub);
  assert.ok(res.ok, `a valid proof must stand on its own: ${res.reason}`);
  assert.equal(s.replica(id.logId.toString('hex')).linkedTo, 2, 'and still stops the log');
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

test('sync: a hostile HAVE_ADD cannot make a spore allocate, and kills the hypha', async () => {
  const victim = spore(47670);
  const hostile = spore(47671);
  for (const s of [victim, hostile]) await s.mgr.listen();
  victim.sync.start();

  const h = await hostile.mgr.dial({ sporeId: victim.id.pub, addrs: ['127.0.0.1'], tcpPort: 47670 });
  assert.ok(h, 'dial must succeed');

  const before = process.memoryUsage().heapTotal;
  const closed = new Promise((res) => h.once('close', res));

  // One 23-byte frame claiming a block at seq 2^32-1. Well-formed by every length check;
  // the only thing wrong with it is the number.
  const body = Buffer.alloc(23);
  body.writeUInt8(MSG.HAVE_ADD, 0);
  body.writeUInt16LE(1, 1);
  Buffer.alloc(16, 0xab).copy(body, 3);
  body.writeUInt32LE(0xffffffff, 19);
  h.send(body);

  await closed; // a protocol violation from an authenticated peer ends the hypha
  const grew = (process.memoryUsage().heapTotal - before) / 1048576;
  assert.ok(grew < 64, `victim heap grew ${grew.toFixed(1)} MB from a 23-byte frame`);
  assert.equal(victim.sync.logs.size, 0, 'and no state was created for the claimed log');

  victim.sync.stop();
  await victim.mgr.stop(); await hostile.mgr.stop();
});

test('sync: a log flood is capped rather than tracked forever', async () => {
  const victim = spore(47672);
  const hostile = spore(47673);
  for (const s of [victim, hostile]) await s.mgr.listen();
  victim.sync.start();

  const h = await hostile.mgr.dial({ sporeId: victim.id.pub, addrs: ['127.0.0.1'], tcpPort: 47672 });

  // Nothing authorises a log into existence — any peer can name one. Unbounded, that is
  // a memory leak with a wire interface, and it also overflows the u16 log count in HAVE.
  const pairs = [];
  for (let i = 0; i < MAX_LOGS + 200; i++) {
    const logId = Buffer.alloc(16);
    logId.writeUInt32LE(i, 0);
    pairs.push({ logId, seq: 0 });
  }
  h.send(encodePairs(MSG.HAVE_ADD, pairs));

  await until(() => victim.sync.logs.size >= MAX_LOGS, 4000);
  await settle(200);
  assert.ok(victim.sync.logs.size <= MAX_LOGS, `tracked ${victim.sync.logs.size} logs, cap is ${MAX_LOGS}`);

  victim.sync.stop();
  await victim.mgr.stop(); await hostile.mgr.stop();
});

test('hypha: a peer that stops reading gets cut off instead of buffered forever', async () => {
  // Node's own docs: "Writing a socket that is not draining may lead to a remotely
  // exploitable vulnerability, since TCP sockets may never drain if the remote peer does
  // not read the data." The attacker does not need to flood us — one request for a large
  // range, then simply never read the answer. Capping what we serve per request does not
  // help, because they control how fast we drain, not how much we send.
  const a = spore(47680);
  const b = spore(47681);
  await a.mgr.listen();
  await b.mgr.listen();

  const established = new Promise((res) => a.mgr.once('hypha', res));
  const out = await b.mgr.dial({ sporeId: a.id.pub, addrs: ['127.0.0.1'], tcpPort: 47680 });
  const inbound = await established;

  // The receiver goes silent at the socket level: still connected, no longer reading.
  inbound.socket.pause();

  const blob = Buffer.alloc(60000, 0x5a);
  let reason = null;
  out.once('close', ({ reason: r }) => { reason = r; });

  let sent = 0;
  let threw = false;
  for (let i = 0; i < 2000 && !threw; i++) {
    try { out.send(blob); sent++; } catch { threw = true; }
  }

  assert.ok(threw, `sender queued ${sent} frames without ever refusing`);
  assert.equal(reason, 'peer_not_draining');
  assert.ok(out.socket.writableLength < MAX_WRITE_BUFFER * 4,
    `buffer reached ${out.socket.writableLength} bytes`);

  await a.mgr.stop(); await b.mgr.stop();
});

test('hypha: a dial that fails leaves no socket behind', async () => {
  const a = spore(47682);
  await a.mgr.listen();

  // 47683 is inside the allowlist and has nothing listening. Every beacon-discovered peer
  // that is firewalled, asleep, or gone takes this path, and on a phone mesh that is the
  // common case rather than the edge — one leaked handle each, permanently.
  for (let i = 0; i < 5; i++) {
    const h = await a.mgr.dial({ sporeId: identity().pub, addrs: ['127.0.0.1'], tcpPort: 47683 });
    assert.equal(h, null, 'the dial must fail');
  }
  await settle(50);
  assert.equal(a.mgr.sockets.size, 0, `leaked ${a.mgr.sockets.size} sockets`);

  await a.mgr.stop();
});

test('sync: a forked log does not report itself complete', async () => {
  // #totalFor clamps total to forkedAt, but `held` counted every block ever accepted —
  // including ones above the fork that can never link. So a forked log could announce
  // completion while holding nothing readable past the contradiction.
  const author = identity();
  const { main, other } = forkedChain(author, 12, 5);

  const s = spore(47684, { seedFrom: { id: author, blocks: main } });
  await s.mgr.listen();
  s.sync.start();

  const key = author.logId.toString('hex');
  s.store.insert(other.cert, other.payload, author.pub);
  const rep = s.store.replica(key);
  assert.equal(rep.forkedAt, 5);
  // The losing branch is kept as proof, not as a block, so held is the 12 main blocks.
  assert.equal(rep.held, 12, 'it still HOLDS everything, including the unusable tail');
  assert.equal(rep.countBelow(5), 5, 'but only five blocks are below the fork');

  s.sync.stop();
  await s.mgr.stop();
});

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

test('sync: a spore that connects while empty is still discoverable as a source', async () => {
  const author = identity();
  const blocks = chain(author, 24, 'relay');

  const seeder = spore(47650, { seedFrom: { id: author, blocks } });
  const middle = spore(47651);
  const tail = spore(47652);
  for (const s of [seeder, middle, tail]) await s.mgr.listen();
  for (const s of [seeder, middle, tail]) s.sync.start();

  // The ordering that matters: `tail` attaches to `middle` while `middle` holds NOTHING,
  // so `middle` has no full HAVE to send. Everything `tail` ever learns about `middle`
  // must therefore arrive by HAVE_ADD. If HAVE_ADD is treated as a refinement of a HAVE
  // that was never sent, `middle` is invisible as a source forever and `tail` sits at
  // zero — which is the "gets faster as people join" claim failing in exactly the case
  // it is meant for: everyone arriving at once with nothing.
  await tail.mgr.dial({ sporeId: middle.id.pub, addrs: ['127.0.0.1'], tcpPort: 47651 });
  assert.equal(middle.store.size, 0, 'middle must still be empty when tail attaches');
  await settle(60);
  assert.equal(tail.store.size, 0, 'nothing to learn yet');

  // Only now does the middle spore get anything to pass on.
  await middle.mgr.dial({ sporeId: seeder.id.pub, addrs: ['127.0.0.1'], tcpPort: 47650 });

  const key = author.logId.toString('hex');
  const ok = await until(() => (tail.store.replica(key)?.held || 0) === 24, 8000);
  assert.ok(ok, `tail reached ${tail.store.replica(key)?.held || 0}/24 — middle was never seen as a source`);
  assert.equal(tail.store.replica(key).linkedTo, 23);
  assert.ok(middle.sync.stats.served > 0, 'middle must have re-served what it fetched');

  for (const s of [seeder, middle, tail]) { s.sync.stop(); await s.mgr.stop(); }
});

test('sync: a fork proof reaches a spore that connects long after the fork was found', async () => {
  const author = identity();
  const { main, other } = forkedChain(author, 12, 6);

  // The witness finds the fork ALONE, before any hypha exists. Its broadcast goes to
  // nobody, and the once-per-fork guard means it is never broadcast again. If proofs are
  // not replayed at connect time, `naive` links all the way to 11 and stays there.
  const witness = spore(47660, { seedFrom: { id: author, blocks: main } });
  witness.store.insert(other.cert, other.payload, author.pub);
  const naive = spore(47661, { seedFrom: { id: author, blocks: main } });

  for (const s of [witness, naive]) await s.mgr.listen();
  for (const s of [witness, naive]) s.sync.start();

  const key = author.logId.toString('hex');
  assert.equal(witness.store.replica(key).forkedAt, 6);
  assert.equal(naive.store.replica(key).linkedTo, 11, 'naive has no reason to doubt yet');

  await naive.mgr.dial({ sporeId: witness.id.pub, addrs: ['127.0.0.1'], tcpPort: 47660 });

  const ok = await until(() => naive.store.replica(key).forkedAt === 6, 6000);
  assert.ok(ok, 'the proof never arrived');
  assert.equal(naive.store.replica(key).linkedTo, 5, 'and history above the fork is withdrawn');

  for (const s of [witness, naive]) { s.sync.stop(); await s.mgr.stop(); }
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
