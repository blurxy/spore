// Wiring, and nothing more.
//
// Feed (telemetry over the stream) + MyceliumView (the one view, shared with the terminal)
// + WebCanvas (a pen). Every decision about what moves and how fast lives in mycelium.js,
// which is the file the TUI runs too.
//
// The frame loop here samples at whatever rate the device offers — 60Hz, 120Hz, whatever a
// phone decides under thermal load. That is safe precisely because the integrator is
// fixed-step (GROWTH.md §1): the view is handed elapsed wall time and takes 1/120 s
// substeps out of it, so the sampling rate changes how OFTEN you see the motion and never
// what the motion is.

import { MyceliumView, PAL } from '../mycelium.js';
import { css } from '../palette.js';
import { Feed } from './feed.js';
import { WebCanvas } from './paint.js';

const BG = css(PAL.substrate);
const AMBER = 0xffb020;

export function boot(root, { nick = 'spore', sporeId = '' } = {}) {
  const el = document.createElement('canvas');
  el.style.cssText = 'display:block;width:100%;height:100%;touch-action:none';
  root.appendChild(el);
  const ctx = el.getContext('2d', { alpha: false });

  const feed = new Feed();
  const view = new MyceliumView(feed, { nick, sporeId });
  const cv = new WebCanvas(ctx);

  // Cells are sized so a phone in portrait gets a readable grid rather than a wall of
  // 4px dots. Recomputed on resize because a phone rotating is the normal case here.
  const fit = () => {
    const ratio = Math.min(3, window.devicePixelRatio || 1);
    const pxW = Math.max(1, Math.round(root.clientWidth * ratio));
    const pxH = Math.max(1, Math.round(root.clientHeight * ratio));
    el.width = pxW;
    el.height = pxH;
    cv.cellPx = Math.max(6, Math.round(Math.min(pxW / 74, pxH / 40)));
    cv.fit(pxW, pxH);
  };
  fit();
  window.addEventListener('resize', fit);
  window.addEventListener('orientationchange', fit);

  feed.connect();

  let raf = 0;
  const frame = () => {
    view.step();
    cv.clear(BG);
    view.draw(cv);

    // FAIL-LOUD, on the phone. §3.3: a visual whose binding resolves to no telemetry row
    // renders U+2298 rather than a plausible default, and a dead stream is the loudest
    // version of that — everything on screen is then the last thing we actually knew.
    if (!feed.connected) {
      cv.write(1, 1, '⊘ stream down · holding last measured values', AMBER);
    }
    cv.flush();
    raf = requestAnimationFrame(frame);
  };
  raf = requestAnimationFrame(frame);

  return {
    view,
    feed,
    stop() {
      cancelAnimationFrame(raf);
      feed.source?.close();
      window.removeEventListener('resize', fit);
      window.removeEventListener('orientationchange', fit);
    },
  };
}
