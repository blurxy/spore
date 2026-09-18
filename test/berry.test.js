// 🫐.txt claims to be the complete wire protocol. This checks that it still is.
//
// It drifted for a day: it published MAX_SEQ = 2^24 after the value changed, and worse, it
// published the REASONING that change disproved — that the check belongs in the decoder
// "because there is only one place to forget it", when BLOCK carries its seq inside a signed
// cert and never reaches the decoder at all.
//
// The structural cause was that the generator restated every constant by hand. It imports
// them now, so the spec cannot disagree with the code about a number. What it can still do is
// go stale in prose, and nothing here can catch that. This test covers the numbers only, and
// says so rather than implying more.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { selectorsToBytes } from '../src/app/invite.js';
import { MAX_SEQ, MSG } from '../src/sharding/wire.js';
import { MAX_LOGS, MAX_INFLIGHT_PER_PEER, FETCH_WINDOW } from '../src/sharding/sync.js';

/** The spec as it is actually published, decoded from the berry on disk. */
function published() {
  const berry = readFileSync(new URL('../🫐.txt', import.meta.url), 'utf8');
  return gunzipSync(selectorsToBytes(berry)).toString('utf8');
}

test('berry: the published spec carries the constants the code actually uses', () => {
  const spec = published();

  // Each of these was typed by hand in the generator until the drift was found.
  assert.ok(spec.includes(`MAX_SEQ = ${MAX_SEQ}`), `spec must carry MAX_SEQ = ${MAX_SEQ}`);
  assert.ok(spec.includes(`MAX_LOGS = ${MAX_LOGS}`), `spec must carry MAX_LOGS = ${MAX_LOGS}`);
  assert.ok(
    spec.includes(`FETCH_WINDOW = ${FETCH_WINDOW}`),
    `spec must carry FETCH_WINDOW = ${FETCH_WINDOW}`,
  );
  assert.ok(
    spec.includes(`${Object.keys(MSG).length} messages`),
    `spec must say there are ${Object.keys(MSG).length} messages`,
  );
  assert.ok(
    spec.includes(`${MAX_INFLIGHT_PER_PEER}\n  blocks outstanding per peer`)
    || spec.includes(`${MAX_INFLIGHT_PER_PEER} blocks outstanding per peer`),
    'spec must carry the in-flight depth',
  );
});

test('berry: the disproved reasoning is gone, and stays gone', () => {
  // The specific sentence, not a paraphrase. It asserted that a decoder check is sufficient
  // because there is "only one place to forget" it — and the bug that reasoning produced was
  // that BLOCK never passes through the decoder. A spec that teaches a disproved rule is
  // worse than one that is merely out of date, because a reader implements from it.
  const spec = published();
  assert.ok(!spec.includes('2^24'), 'the old MAX_SEQ value must not survive anywhere');
  assert.ok(
    !/enforced in the DECODER, because\s+there is nothing correct/.test(spec),
    'the disproved decoder-is-sufficient argument must not be published as spec',
  );
  // And the simulated scaling numbers, which R9 caveated in every other document.
  assert.ok(!spec.includes('3.59x'), 'modelled speedups belong in RESULTS, not in the spec');
});
