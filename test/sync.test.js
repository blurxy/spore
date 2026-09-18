import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { HyphaManager, MAX_WRITE_BUFFER } from '../src/transport/tcp.js';
import { generateStatic } from '../src/session/noise.js';
import { encodeBlock, decodeBlock, logIdFor, newLogId, TYPE, FLAG } from '../src/substrate/block.js';
import { Substrate, LOST_CAP } from '../src/substrate/store.js';
import { Syncer } from '../src/sharding/sync.js';
import { Telemetry } from '../src/telemetry/bus.js';
import { FetchScheduler, Bitfield } from '../src/sharding/scheduler.js';
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

test('store: a block seq above MAX_SEQ is refused, not sized into a Bitfield', () => {
  // The sibling of the test above, and the hole it left. MAX_SEQ exists, in wire.js's own
  // words, so that a peer cannot send a handful of well-formed bytes claiming a block at
  // 4,294,967,295 and have the receiver allocate a 512 MB Uint8Array — "on a phone that is
  // not a slowdown, it is the process."
  //
  // That bound was enforced on decodePairs and decodeHave, which carry a bare seq in the
  // envelope. It was never enforced on BLOCK, where the seq lives inside the signed cert
  // and so never passes through decodePairs at all — the one message type that actually
  // sizes LogReplica#bits, and the highest-volume one on the wire.
  //
  // The check belongs in insert() rather than in decodeBlockMsg because insert() is the
  // single funnel: every block reaches it, whether from a hypha, a disk replay, or a test.
  const id = identity();
  const seq = 5_000_000_000; // ~300x MAX_SEQ; ceil((seq+1)/8) is a ~596 MB request
  const { cert } = encodeBlock(
    {
      type: TYPE.MESSAGE,
      flags: FLAG.PAYLOAD_INLINE,
      logId: id.logId,
      seq,
      lamport: 1n,
      prevHash: Buffer.alloc(32),
      payload: Buffer.alloc(0),
    },
    id.kp.privateKey,
  );

  const store = new Substrate();
  const res = store.insert(cert, Buffer.alloc(0), id.pub);
  assert.equal(res.ok, false, `seq ${seq} is ${Math.round(seq / MAX_SEQ)}x MAX_SEQ and must be refused`);
  assert.equal(res.reason, 'seq_range');
  assert.equal(store.logs.size, 0, 'and no replica is created for it');

  // The boundary itself stays legal — the bound is a ceiling, not an off-by-one.
  assert.ok(Number.isSafeInteger(MAX_SEQ));
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

test('store: a forgotten predecessor does not collapse the frontier on recompute', () => {
  // relink() restarts at `floor` and asks for the hash and lamport of the block before it
  // — which eviction has just deleted. Nothing exercised that before: a full recompute
  // only ran on a fork, and the eviction tests never forked. Measured on the broken code,
  // a 20-block log evicted to floor 15 kept linkedTo 19 right up until something forced a
  // recompute, then fell to 14 and promoted nothing, permanently. Forgetting old history
  // is supposed to cost old history, not the frontier above it.
  const quiet = identity();
  const noisy = identity();
  const blocks = chain(quiet, 20, 'x'.repeat(40));
  const each = blocks[0].cert.length + blocks[0].payload.length;

  const s = new Substrate({ maxBytes: each * 5 });
  for (const b of blocks) s.insert(b.cert, b.payload, quiet.pub);

  const r = s.replica(quiet.logId.toString('hex'));
  assert.ok(r.floor > 0, 'the test is pointless unless eviction actually ran');
  const before = r.linkedTo;
  assert.equal(before, 19);

  // An equivocation anywhere re-resolves every frontier in the substrate, this one too.
  const { main, other } = forkedChain(noisy, 6, 3);
  for (const b of main) s.insert(b.cert, b.payload, noisy.pub);
  s.insert(other.cert, other.payload, noisy.pub);

  assert.equal(s.replica(quiet.logId.toString('hex')).linkedTo, before,
    'an unrelated fork must not cost this log the history it still holds');
  assert.equal(s.replica(noisy.logId.toString('hex')).forkedAt, 3, 'and the fork is real');
});

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

test('store: a substrate under budget pressure forgets, and stays usable', () => {
  // Before this the substrate grew forever — every block ever seen, plus a hash index
  // entry each. Tests run for seconds and the harness moves 400 blocks, so nothing we
  // measure could see it. It would have surfaced as a phone dying after a day.
  const id = identity();
  const blocks = chain(id, 60, 'bulk');
  const per = blocks[0].cert.length + blocks[0].payload.length;
  const s = new Substrate({ maxBytes: per * 20 });

  for (const b of blocks) assert.ok(s.insert(b.cert, b.payload, id.pub).ok);

  const rep = s.replica(id.logId.toString('hex'));
  assert.ok(s.bytes <= per * 20, `held ${s.bytes} bytes against a ${per * 20} budget`);
  assert.ok(rep.forgotten > 0, 'something must actually have been dropped');

  // The frontier is a watermark over validated history and must not move backwards.
  assert.equal(rep.linkedTo, 59, 'the log is still fully linked');
  // The block AT the frontier survives: relink() reads its hash and lamport to check the
  // next one, so dropping it would stall the log forever.
  assert.ok(rep.has(59), 'the frontier block itself is never evicted');
  assert.equal(rep.has(0), false, 'but the oldest verified history is gone');

  // And we no longer advertise what we cannot serve.
  const adv = s.advertise()[0];
  assert.equal(adv.bits[0] & 1, 0, 'the forgotten block is no longer in our HAVE');
  assert.equal(s.fetch(id.logId.toString('hex'), 0), null, 'and fetching it returns nothing');
});

test('store: unlinked blocks are never evicted, because they are why the frontier moves', () => {
  const id = identity();
  const blocks = chain(id, 30, 'gap');
  const per = blocks[0].cert.length + blocks[0].payload.length;
  const s = new Substrate({ maxBytes: per * 5 });

  // Everything except genesis, so nothing can ever link.
  for (let i = 1; i < 30; i++) s.insert(blocks[i].cert, blocks[i].payload, id.pub);
  const rep = s.replica(id.logId.toString('hex'));
  assert.equal(rep.linkedTo, -1);
  assert.equal(rep.forgotten, 0, 'a substrate of unlinked blocks cannot shrink');
  assert.ok(s.bytes > per * 5, 'and it is honest about being over budget rather than dropping them');

  s.insert(blocks[0].cert, blocks[0].payload, id.pub);
  assert.equal(rep.linkedTo, 29, 'the gap closes and the whole run links');
  assert.ok(rep.forgotten > 0, 'and only then is there anything safe to forget');
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

test('store: a block below the eviction floor is refused, not silently re-admitted', () => {
  // The byte-budget leak is the small half of this. insert() looks for a fork with
  // `prior = r.blocks.get(seq)`, and for a seq that was EVICTED that returns undefined —
  // indistinguishable from a seq never seen. So a replayed block is admitted as brand new:
  // bytes counted, HAVE bit set, and forgetOldest iterates [floor, linkedTo) so it can
  // never be evicted again.
  //
  // The large half is that nothing below the floor is ever re-walked, so the lamport the
  // author signed is taken on trust, and `resolveDep` reports `ordered: true` for it
  // because orderedTo >= floor - 1 always holds. And since `prior` is undefined, a
  // DIFFERENT block at that seq is not detected as equivocation either. So any identity
  // can plant an arbitrary lamport at any seq the victim has forgotten — and advertise()
  // publishes the cleared HAVE bit, which tells them exactly which seqs qualify.
  //
  // Deliberately plain eviction: no revocation, so this never touches the floor clamp from
  // ARCHITECTURE.md R7. That clamp is under review and a test that depended on it would be
  // measuring the wrong thing.
  const id = identity();
  const blocks = chain(id, 12);

  const width = blocks[0].cert.length + 8;
  const s = new Substrate({ maxBytes: width * 4 });
  for (const b of blocks) s.insert(b.cert, b.payload, id.pub);

  const r = s.replica(id.logId.toString('hex'));
  assert.ok(r.floor > 0, `the budget must actually have bitten (floor ${r.floor})`);
  assert.ok(!r.blocks.has(0), 'seq 0 was forgotten');
  const bytesBefore = s.bytes;
  const linkedBefore = r.linkedTo;

  // 1. An honest replay of a block we deliberately forgot.
  const replay = s.insert(blocks[0].cert, blocks[0].payload, id.pub);
  assert.equal(replay.ok, false, 'a block below the floor must not be re-admitted');
  assert.equal(s.bytes, bytesBefore, 'and must not be counted against the budget');
  assert.ok(!r.blocks.has(0), 'and must not be held again');

  // 2. The same seq, a different block, an invented lamport. This is the attack: it is not
  //    a duplicate, it is not detected as a fork, and nothing would ever re-derive it.
  const { cert: forged } = encodeBlock(
    {
      type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE,
      logId: id.logId, seq: 0, lamport: 999_999, prevHash: Buffer.alloc(32),
      payload: Buffer.from('forged'),
    },
    id.kp.privateKey,
  );
  const inject = s.insert(forged, Buffer.from('forged'), id.pub);
  assert.equal(inject.ok, false, 'a forged lamport below the floor must not be accepted');
  assert.equal(s.bytes, bytesBefore, 'and must cost nothing');
  assert.equal(r.linkedTo, linkedBefore, 'and must not move the frontier');

  // 3. The budget still holds, which is what test "the byte budget is honoured" asserts and
  //    what the leak defeated: every replay used to add bytes with nothing left to evict.
  assert.ok(s.bytes <= s.maxBytes, `over budget: ${s.bytes} > ${s.maxBytes}`);
});

/** Two different blocks the same author signed at one seq — a real equivocation. */
function twoAt(id, seq) {
  const mk = (text) => encodeBlock(
    {
      type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq,
      lamport: seq + 1, prevHash: Buffer.alloc(32), payload: Buffer.from(text),
    },
    id.kp.privateKey,
  ).cert;
  return [mk(`a${seq}`), mk(`b${seq}`)];
}

test('store: one fork proof per log, and a proof above the contradiction is free', () => {
  // A log that forked at seq 3 has ENDED at 3. A proof at seq 7 says nothing further: it
  // cannot end the log harder, and it cannot be the proof anyone needs. So keeping every
  // proof was storing unbounded evidence of one fact.
  //
  // `forks` had no cap at all — contrast `lost`, capped at LOST_CAP with oldest-out — and
  // held TWO FULL CERTIFICATES per entry while its own comment said "block hashes", an 8x
  // undercount that is presumably why nobody looked. #trim and forgetOldest only ever touch
  // r.blocks and r.bytes, so maxBytes gave zero protection however tight it was set.
  //
  // The CPU half was worse. #recordFork forced #resolveFrontiers(true), and `force` exists
  // precisely to bypass the R4f short-circuit that refuses to rewalk when derived authority
  // is unchanged. Proofs sent in DESCENDING seq order make every one of them lower forkedAt,
  // so every one bought a full substrate-wide rewalk — R4f's DoS, reopened one function
  // over, through acceptForkProof, which sync.js accepts with no rate limit from anyone.
  const id = identity();
  const blocks = chain(id, 6);
  const tel = new Telemetry();
  const s = new Substrate({ telemetry: tel });
  for (const b of blocks) s.insert(b.cert, b.payload, id.pub);

  const r = s.replica(id.logId.toString('hex'));
  assert.equal(r.chainTo, 5, 'the log is real before anyone attacks it');

  // Descending, and every one above anything held. Each lowers forkedAt, so the old code
  // treated each as `lowered` and forced a rewalk — though nothing could possibly move.
  const resolvesBefore = tel.counters.get('substrate.resolved') || 0;
  for (let seq = 2000; seq > 1970; seq--) {
    const [a, b] = twoAt(id, seq);
    assert.ok(s.acceptForkProof(a, b, id.pub).ok, `proof at ${seq} should be accepted`);
  }

  assert.equal(r.forks.size, 1, 'one proof per log — the lowest, which is the only one that ends it');
  assert.equal(tel.counters.get('substrate.resolved') || 0, resolvesBefore,
    'and no rewalk, because not one frontier could have moved');
  assert.equal(s.knownForks().length, 1, 'and only that one is offered to peers');

  // The real thing still works: a fork BELOW what we hold must retract history.
  const [lowA, lowB] = twoAt(id, 2);
  assert.ok(s.acceptForkProof(lowA, lowB, id.pub).ok);
  assert.equal(r.forkedAt, 2, 'the lower contradiction wins');
  assert.equal(r.chainTo, 1, 'and the chain ends there');
  assert.equal(r.forks.size, 1, 'still one proof, now the lower one');
  assert.equal(s.knownForks()[0].seq, 2, 'and it is the one worth relaying');
  assert.ok((tel.counters.get('substrate.resolved') || 0) > resolvesBefore,
    'THAT one is worth a rewalk — the gate must not have blocked real work');

  // Re-offering a proof at or above a known contradiction is a duplicate, not new work.
  const [dupA, dupB] = twoAt(id, 9);
  assert.equal(s.acceptForkProof(dupA, dupB, id.pub).duplicate, true);
  assert.equal(r.forks.size, 1);
});

test('store: the forgotten-lamport witness is capped, oldest out', () => {
  // `lost` remembers hash -> lamport for blocks this replica evicted, so a citer that
  // arrives AFTER its dep was forgotten can still be ordered (R4e). It is the one map in
  // LogReplica with an explicit cap, and the cap had zero coverage: delete the four lines
  // that enforce it and the whole suite still passed, because nothing here ever caused
  // anywhere near LOST_CAP evictions in one replica.
  //
  // That is the shape this repo keeps getting caught by — a bound that is real in the code
  // today and would be silently removable tomorrow. `lost` is independent of maxBytes and
  // has no other backstop: #trim and forgetOldest bound r.blocks and r.bytes, not this.
  const id = identity();
  const n = LOST_CAP + 200;
  const blocks = chain(id, n);

  // A budget that holds only a handful, so almost every block is evicted as it links.
  const width = blocks[0].cert.length + 8;
  const s = new Substrate({ maxBytes: width * 8 });
  for (const b of blocks) s.insert(b.cert, b.payload, id.pub);

  const r = s.replica(id.logId.toString('hex'));
  assert.ok(r.forgotten > LOST_CAP, `the cap must actually be exercised (forgot ${r.forgotten})`);
  assert.ok(r.lost.size <= LOST_CAP, `lost grew past its cap: ${r.lost.size} > ${LOST_CAP}`);

  // Oldest out, not newest: the witness that survives is the one most likely to still be
  // cited. A recently forgotten block is remembered; the very first one is not.
  const hashOf = (b) => {
    const d = decodeBlock(b.cert);
    return d.blockHash.toString('hex');
  };
  assert.ok(!r.lost.has(hashOf(blocks[0])), 'the oldest witness was dropped');
  assert.ok(r.lost.has(hashOf(blocks[n - 20])), 'a recent one was kept');
});

test('store: a block naming more deps than there are logs is refused', () => {
  // dep_count is a u16 and was capped nowhere. MAX_BODY bounds it to ~2036 deps on the wire,
  // which is still a ~64 KB CERT — and a cert is not a payload, so the retention shape check
  // does not see it. Typed ROLE_GRANT with a well-formed 28-byte payload, it is real
  // authority by every test the substrate applies, and unevictable at 224x the cost R4b
  // budgets for.
  //
  // The bound is principled rather than arbitrary, which is the only kind worth adding: deps
  // name logs whose head this block advanced past, and a spore tracks at most MAX_LOGS logs
  // (store.js says "one number, one meaning"). A block claiming more deps than there are
  // logs to depend on is claiming something that cannot be true.
  //
  // Same funnel and same argument as MAX_SEQ: enforce where the field SIZES something, at
  // insert(), ahead of ensure(), because a bound checked on one transport is a bound the
  // next transport silently loses.
  const id = identity();
  const deps = Array.from({ length: MAX_LOGS + 1 }, (_, i) => {
    const b = Buffer.alloc(32);
    b.writeUInt32LE(i + 1, 0);
    return b;
  });
  const { cert } = encodeBlock(
    {
      type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: 0,
      lamport: 1n, prevHash: Buffer.alloc(32), payload: Buffer.alloc(0), deps,
    },
    id.kp.privateKey,
  );

  const store = new Substrate();
  const res = store.insert(cert, Buffer.alloc(0), id.pub);
  assert.equal(res.ok, false, `${MAX_LOGS + 1} deps must be refused`);
  assert.equal(res.reason, 'dep_count');
  assert.equal(store.logs.size, 0, 'and no replica is created for it');

  // The bound itself is legal — a ceiling, not an off-by-one.
  const okDeps = deps.slice(0, MAX_LOGS);
  const { cert: okCert } = encodeBlock(
    {
      type: TYPE.MESSAGE, flags: FLAG.PAYLOAD_INLINE, logId: id.logId, seq: 0,
      lamport: 1n, prevHash: Buffer.alloc(32), payload: Buffer.alloc(0), deps: okDeps,
    },
    id.kp.privateKey,
  );
  const s2 = new Substrate();
  assert.notEqual(s2.insert(okCert, Buffer.alloc(0), id.pub).reason, 'dep_count',
    'exactly MAX_LOGS deps is legal');
});

test('wire: the advertised-set allocation is bounded across ALL logs, not just one', () => {
  // The bound that was missing. A peer HAVE_ADD carries bare (logId, seq) pairs and sync.js
  // sizes a Bitfield straight from the seq claimed — ceil(size/8) bytes, and no signature is
  // involved on that path. MAX_SEQ was the only thing standing in front of it, and it had
  // been justified PER LOG: 2 MB each sounded tolerable, and nobody multiplied by MAX_LOGS.
  // One ~5 KB frame carrying 256 maximal pairs demanded 512 MB.
  //
  // So the invariant is the PRODUCT, and it is asserted as the product. Raise MAX_SEQ again
  // and this fails, which is the point — the previous bound was correct about the quantity it
  // named and silent about the one that mattered.
  const perLog = Math.ceil((MAX_SEQ + 1) / 8);
  const worst = perLog * MAX_LOGS;
  assert.ok(
    worst <= 64 * 1024 * 1024,
    `worst-case advertised-set allocation is ${Math.round(worst / 1048576)} MB `
    + `(${perLog} B/log x ${MAX_LOGS} logs) — one unsigned frame can demand all of it`,
  );

  // And the cap is not in the way of anything real: a million blocks in one log is still
  // expressible, which at ~320 bytes each is already past any phone's storage budget.
  assert.ok(MAX_SEQ >= (1 << 20) - 1, 'a log must still hold ~1M blocks');

  // WHERE THE RESIDUAL LIVES NOW, updated when the window landed rather than left to point
  // at a function that is no longer the problem.
  //
  // #recvHaveAdd used to allocate per (log, PEER) straight from a claimed seq, so the worst
  // case was this figure times an uncapped hypha count. It is now capped at 8x the fetch
  // window above our own frontier, and the cost oracle asserts the invariant directly.
  //
  // What is still unbounded is #recvHave: it allocates from `bitlen`, but decodeHave refuses
  // a frame that does not actually carry ceil(bitlen/8) bytes, so that allocation is 1:1
  // with bytes the peer paid for and is bounded per frame by MAX_BODY. The residual is
  // RETAINED bits across peers — roughly MAX_LOGS x MAX_BODY per peer — and the fix is a
  // per-peer advertised-bytes budget, not a smaller MAX_SEQ. Deliberately not clamped: a
  // joiner that learns bits only to a cap stalls until the 10 s refresh, which would pause
  // the harness every couple of windows.
  assert.ok(MAX_SEQ > 0, 'residual documented above — see #recvHave, not #recvHaveAdd');
});

test('sharding: the scheduler never asks for a block below our own floor', () => {
  // Half of a request livelock, and the half that can be tested precisely.
  //
  // A replica that evicted [0, floor) clears those HAVE bits. A peer with a bigger budget —
  // or one that simply has not trimmed yet, which the property tests say is legitimate —
  // still advertises them. plan() iterated from index 0 and saw "we do not have it, they do",
  // so it asked. insert() then refused with below_floor, #recvBlock released the reservation
  // and called pump(), the peer's bit was still set, and plan() asked again.
  //
  // That is one full block over the air per RTT, per evicted seq, for as long as both sides
  // stay connected — and it is reachable by two entirely honest peers. It burns exactly the
  // airtime the §3.1 experiment is trying to measure, and the harness cannot see it because
  // the seeder never evicts.
  const total = 20;
  const sched = new FetchScheduler(total);

  // We hold nothing, but we have forgotten everything below 10.
  const have = new Bitfield(total);
  const floor = 10;

  // One peer who has the lot.
  const peerHave = new Bitfield(total);
  for (let i = 0; i < total; i++) peerHave.set(i);
  const peers = new Map([['deadbeef', { have: peerHave, inflight: new Set(), maxInflight: 32 }]]);

  const plan = sched.plan(have, peers, new Map(), null, 32, floor);

  assert.ok(plan.length > 0, 'it should still want the blocks above the floor');
  const below = plan.filter((a) => a.index < floor);
  assert.deepEqual(below, [],
    `asked for ${below.length} block(s) below the floor — every one of those is a request `
    + 'that can only be answered with a block insert() will refuse');
  assert.equal(plan.length, total - floor, 'and it should want all of the ones above it');
});

/** One HAVE_ADD frame claiming `n` distinct logs, each at `seq`. Well-formed throughout. */
function haveAddFrame(n, seq, saltByte) {
  const body = Buffer.alloc(3 + n * 20);
  body.writeUInt8(MSG.HAVE_ADD, 0);
  body.writeUInt16LE(n, 1);
  for (let i = 0; i < n; i++) {
    const at = 3 + i * 20;
    Buffer.alloc(16, saltByte).copy(body, at);
    body.writeUInt16LE(i, at); // distinct log ids, same salt
    body.writeUInt32LE(seq, at + 16);
  }
  return body;
}

test('sync: work is proportional to what WE hold, not to what a peer CLAIMS', {
  // EXPECTED TO FAIL until the window bound lands (ARCHITECTURE R10).
  //
  // Measured on the code as it stands, across runs: roughly 600x to 750x more counted work
  // when three peers claim MAX_SEQ than when they claim head 1000. Absolute figures swing a
  // lot between runs — 8.7 MiB vs 6.3 GiB on one, 55 MiB vs 32 GiB on another — because the
  // total depends on how many pump() cycles land inside the wait window, and each cycle is
  // itself slow at MAX_SEQ. The RATIO is the stable quantity and the ratio is what this
  // asserts. Quote the ratio, not the gigabytes.
  //
  // Marked todo rather than deleted or weakened, because the whole point of this test is to
  // be RED before the fix and green after. A test written after the fix is written to match
  // the fix; that is how R7's clamp shipped twice and was wrong twice.
}, async () => {
  // THE COST ORACLE. Six bugs in this repo have turned on one distinction: a quantity sized
  // by a number the peer chooses, rather than by one we hold. forks, KEEP_FOREVER, MAX_SEQ,
  // dep_count, rarity(), and MAX_SEQ again. Each time the bound was placed on the number and
  // never on the product — see docs/METHOD.md.
  //
  // So this asserts the INVARIANT rather than a threshold: drive identical victim state
  // twice, once with peers claiming a modest head and once with them claiming MAX_SEQ, and
  // require the work done to be within a constant factor. A threshold would need a number
  // nobody has justified yet; an invariance test needs only that the bound EXIST.
  //
  // Counted work, never wall-clock. The tablet is ~1.8x slower than this laptop, so a timing
  // assertion would flake while saying nothing about the property. Nor heapTotal, which is
  // GC noise — the existing hostile-HAVE_ADD test uses it because it only needs to catch a
  // 512 MB spike, and that is a different question from this one.
  const LOGS = 12;

  const run = async (claimedSeq, basePort) => {
    const victim = spore(basePort);
    const hostiles = [spore(basePort + 1), spore(basePort + 2), spore(basePort + 3)];
    for (const sp of [victim, ...hostiles]) await sp.mgr.listen();
    victim.sync.start();

    let salt = 0x40;
    for (const hostile of hostiles) {
      const h = await hostile.mgr.dial({ sporeId: victim.id.pub, addrs: ['127.0.0.1'], tcpPort: basePort });
      assert.ok(h, 'dial must succeed');
      h.send(haveAddFrame(LOGS, claimedSeq, salt));
      // NOBLOCK naming the same pairs. #recvNoblock forgets any pair, asked-for or not, and
      // that is what turned a one-off cost into a per-pump one.
      const nb = haveAddFrame(LOGS, claimedSeq, salt);
      nb.writeUInt8(MSG.NOBLOCK, 0);
      h.send(nb);
      salt += 1;
    }

    // Let the frames land and a few pump() cycles run.
    await new Promise((r) => setTimeout(r, 120));

    const work = victim.sync.stats.allocBytes
      + [...victim.sync.logs.values()].reduce((a, l) => a + l.sched.stats.allocBytes + l.sched.stats.scanned * 4, 0);

    victim.sync.stop();
    for (const sp of [victim, ...hostiles]) await sp.mgr.stop();
    return work;
  };

  const modest = await run(1000, 47780);
  const maximal = await run(MAX_SEQ, 47790);

  // Within a constant factor. Generous on purpose: the point is that it does not scale WITH
  // the claimed number, and MAX_SEQ/1000 is a ratio of ~1048x.
  assert.ok(
    maximal <= modest * 8 + (1 << 20),
    `work scaled with the peer's claim: ${(modest / 1024).toFixed(0)} KiB at head 1000 versus `
    + `${(maximal / 1048576).toFixed(1)} MiB at MAX_SEQ — a ${(MAX_SEQ / 1000).toFixed(0)}x `
    + 'larger claim must not buy a proportionally larger amount of our work',
  );
});

test('sync: a log longer than any fetch window still completes, because the window SLIDES', async () => {
  // WRITTEN BEFORE THE WINDOW EXISTS, on purpose. It passes today for the trivial reason
  // that nothing is bounded, and its job is to fail the day a window is added without one.
  //
  // ARCHITECTURE R10 adopts a window W above linkedTo: never request, and never retain, more
  // than W blocks past the frontier. That bounds the scan, the allocation and the unlinked
  // bytes together — all three are sized by a head the PEER claims rather than one we hold.
  //
  // The thing it must not break is this: a log longer than W must still sync to completion,
  // because the window advances as linkedTo does. A window that is computed once, or from a
  // frontier that is read before the walk rather than after it, produces a joiner that
  // fetches exactly W blocks and then stops forever — with no error, no timeout and no
  // NOBLOCK, because from the scheduler's point of view there is simply nothing it wants.
  //
  // That failure is silent, which is why the guard is written now rather than after. The
  // product claim R10 says W trades against is parallel fetch DEPTH; this is the separate
  // claim that fetch LENGTH is unbounded, and the two are easy to conflate while choosing W.
  const author = identity();
  const LONG = 300; // longer than any window a sane person picks for a 400-block harness
  const blocks = chain(author, LONG, 'long');

  const seeder = spore(47800, { seedFrom: { id: author, blocks } });
  const joiner = spore(47801);
  await seeder.mgr.listen();
  await joiner.mgr.listen();
  seeder.sync.start();
  joiner.sync.start();

  const done = new Promise((res) => joiner.sync.once('complete', res));
  await joiner.mgr.dial({ sporeId: seeder.id.pub, addrs: ['127.0.0.1'], tcpPort: 47800 });
  await done;

  const rep = joiner.store.replica(author.logId.toString('hex'));
  assert.equal(rep.held, LONG, `every block arrived (held ${rep.held} of ${LONG})`);
  assert.equal(rep.linkedTo, LONG - 1, 'and the chain links end to end, not W blocks in');
  assert.equal(rep.get(LONG - 1).payload.toString(), `long ${LONG - 1}`);

  joiner.sync.stop(); seeder.sync.stop();
  await joiner.mgr.stop(); await seeder.mgr.stop();
});

test('sync: a block far above the frontier is still reachable when a peer has it', async () => {
  // The other half of the same guard, and the one that is genuinely in tension with R10.
  //
  // A window bounds how far above linkedTo we will look. This asserts the behaviour that
  // bound must preserve: a joiner that holds NOTHING of a log, meeting a peer that holds it
  // from seq 0, ends up with all of it. The window may make that take more rounds; it must
  // not make it impossible.
  //
  // Stated separately from the sliding test because the failure modes differ. The sliding
  // test catches a window that never advances. This one catches a window applied to the
  // wrong frontier — clamped against `head` or `total` rather than against `linkedTo` — in
  // which case a replica with nothing linked has a window of zero and wants no blocks at all.
  const author = identity();
  const blocks = chain(author, 120, 'far');

  const seeder = spore(47802, { seedFrom: { id: author, blocks } });
  const joiner = spore(47803);
  await seeder.mgr.listen();
  await joiner.mgr.listen();
  seeder.sync.start();
  joiner.sync.start();

  const before = joiner.store.replica(author.logId.toString('hex'));
  assert.equal(before, null, 'the joiner starts holding nothing of this log');

  const done = new Promise((res) => joiner.sync.once('complete', res));
  await joiner.mgr.dial({ sporeId: seeder.id.pub, addrs: ['127.0.0.1'], tcpPort: 47802 });
  await done;

  const rep = joiner.store.replica(author.logId.toString('hex'));
  assert.equal(rep.linkedTo, 119, 'a standing start must still reach the end');
  assert.ok(rep.get(119), 'including the block furthest from where we began');

  joiner.sync.stop(); seeder.sync.stop();
  await joiner.mgr.stop(); await seeder.mgr.stop();
});
