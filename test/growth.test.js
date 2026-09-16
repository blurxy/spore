// GROWTH.md §1 — the fixed-step integrator.
//
// "Fixed-step is non-negotiable: the TUI samples at 30fps and the canvas at 60fps, but
// identical substeps mean both renderers produce bit-comparable motion — a peer joining
// looks the same curve in a terminal and a browser, just sampled at a different rate."
//
// That is a claim about the code, so it gets a test. The code did not do it: Spring.step
// took whatever dt the frame happened to take and did ONE Euler step with it, clamped at
// 50 ms. Variable-dt Euler is frame-rate dependent by construction, and measured before
// the fix the two renderers disagreed by 5.6% of full travel a quarter-second in — which
// is not a rounding difference, it is a visibly different curve.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Spring, FIXED_DT, MAX_ACCUM, MAX_SUBSTEPS } from '../src/ui/mycelium.js';

/**
 * Run a spring for EXACTLY `secs` of wall time, delivered in frames of 1/fps.
 *
 * The exactness is the test. A first version used `Math.round(secs * fps)` frames, which
 * at 0.25s and 30fps is 8 frames — 0.267s, not 0.25s — so it compared unequal amounts of
 * time and then blamed the integrator for the difference. The last frame is short instead.
 */
function travel(fps, secs, { stiffness = 26 } = {}) {
  const s = new Spring(0, stiffness);
  s.to(1);
  const dt = 1 / fps;
  let prev = 0;
  for (let i = 1; ; i++) {
    const t = Math.min(secs, i * dt);
    s.step(t - prev);
    prev = t;
    if (t >= secs) break;
  }
  return s.x;
}

test('growth: the same wall time produces the same motion at any frame rate', () => {
  // The whole reason the integrator is fixed-step. Every rate below is one a real renderer
  // actually runs at: 30 the TUI, 60 the canvas, 8 the backpressure governor's floor
  // (§5), 120 the substep rate itself.
  for (const secs of [0.25, 0.5, 1, 2]) {
    const ref = travel(120, secs);
    for (const fps of [8, 24, 30, 60, 90]) {
      const got = travel(fps, secs);
      assert.ok(
        Math.abs(got - ref) < 1e-9,
        `${secs}s at ${fps}fps gave ${got}, at 120fps gave ${ref} — motion is frame-rate dependent`,
      );
    }
  }
});

test('growth: a stalled frame cannot eat time the integrator owes', () => {
  // §1: "accumulator clamp raised to 250 ms, max substeps raised to 30" — because §5 grafts
  // in a governor that can drop the TUI to 8fps, and 125 ms at dt=1/120 is ~15 substeps.
  // The original 33 ms clamp would have discarded 92 ms of every degraded frame and every
  // spring would have visibly run in slow motion.
  assert.equal(FIXED_DT, 1 / 120);
  assert.equal(MAX_ACCUM, 0.25);
  assert.ok(MAX_SUBSTEPS >= Math.ceil(0.125 / FIXED_DT),
    `${MAX_SUBSTEPS} substeps cannot cover a 125ms governor frame`);

  const governed = travel(8, 2);
  const smooth = travel(120, 2);
  assert.ok(Math.abs(governed - smooth) < 1e-9,
    `8fps gave ${governed}, 120fps gave ${smooth} — the governor loses time`);
});

test('growth: a frame longer than the clamp is truncated, not accumulated forever', () => {
  // A process suspended for a minute must not come back and integrate a minute of motion
  // in one frame. It resumes from where it stopped, having lost the gap — which is the
  // honest behaviour: nothing was measured during the gap either.
  const s = new Spring(0);
  s.to(1);
  s.step(60);
  assert.ok(s.x > 0, 'it must advance by the clamp');
  const reference = new Spring(0);
  reference.to(1);
  for (let i = 0; i < Math.round(MAX_ACCUM * 120); i++) reference.step(FIXED_DT);
  assert.ok(Math.abs(s.x - reference.x) < 1e-9,
    `a 60s frame advanced ${s.x}, ${MAX_ACCUM}s of substeps gives ${reference.x}`);
});

test('growth: a spring that has not been given a full substep does not move', () => {
  // Hold-last-value (§3.1), at the integrator level. Interpolating between substeps would
  // be fabricating motion that no measurement supports.
  const s = new Spring(0);
  s.to(1);
  s.step(FIXED_DT / 3);
  assert.equal(s.x, 0, 'a third of a substep is not a third of the motion');
  s.step(FIXED_DT / 3);
  assert.equal(s.x, 0);
  s.step(FIXED_DT / 3 + 1e-12);
  assert.ok(s.x > 0, 'the three thirds together are one substep, and it fires');
});

test('growth: a spring settles on its target and stays there', () => {
  const s = new Spring(0);
  s.to(1);
  for (let i = 0; i < 1200; i++) s.step(1 / 60);
  assert.ok(Math.abs(s.x - 1) < 1e-6, `settled at ${s.x}`);
  const settled = s.x;
  for (let i = 0; i < 600; i++) s.step(1 / 60);
  assert.ok(Math.abs(s.x - settled) < 1e-9, 'and it does not drift once settled');
});
