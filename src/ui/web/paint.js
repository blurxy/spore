// A Canvas2D backend wearing the terminal canvas's interface.
//
// MyceliumView.draw(cv) speaks one language: `cv.w`/`cv.h` cells, and plot/line/write in a
// 2w x 4h subpixel space. canvas.js answers that with braille codepoints; this answers it
// with filled rectangles. The view does not know the difference, and that is the point —
// GROWTH.md §1 requires a peer joining to look like the same curve in a terminal and a
// browser, and the only way to be sure of that is for there to be one view, not two.
//
// So this file is deliberately dumb. It owns no state the view could disagree with: no
// springs, no easing, no interpolation between frames. It is a pen.
//
// It does keep the SUBPIXEL GRID rather than drawing smooth vectors, because the grid is
// where the two renderers agree. Smoothing here would mean the browser drawing a curve the
// terminal cannot, and then "the same motion" becomes a claim nobody can check.

const FONT_STACK = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

export class WebCanvas {
  /**
   * @param {CanvasRenderingContext2D} ctx
   * @param {number} cellPx  width of one terminal cell in CSS pixels
   */
  constructor(ctx, { cellPx = 8, ratio = 1 } = {}) {
    this.ctx = ctx;
    this.cellPx = cellPx;
    this.ratio = ratio;
    this.w = 1;
    this.h = 1;
    this.texts = [];
  }

  /** Fit the grid to the drawing surface. Cells are 1x2 like a terminal's, not square. */
  fit(pxW, pxH) {
    this.w = Math.max(20, Math.floor(pxW / this.cellPx));
    this.h = Math.max(10, Math.floor(pxH / (this.cellPx * 2)));
    this.dotW = pxW / (this.w * 2);
    this.dotH = pxH / (this.h * 4);
    return this;
  }

  clear(background) {
    const { ctx } = this;
    ctx.fillStyle = background;
    ctx.fillRect(0, 0, this.w * 2 * this.dotW, this.h * 4 * this.dotH);
    this.texts.length = 0;
  }

  /** One subpixel, in the same 2w x 4h space the braille canvas uses. */
  plot(x, y, colour) {
    const xi = Math.round(x);
    const yi = Math.round(y);
    if (xi < 0 || yi < 0 || xi >= this.w * 2 || yi >= this.h * 4) return;
    this.ctx.fillStyle = css(colour);
    // +0.6 so neighbouring dots close up instead of leaving a lattice of hairlines at
    // fractional device-pixel ratios. Overdraw, not a gap.
    this.ctx.fillRect(xi * this.dotW, yi * this.dotH, this.dotW + 0.6, this.dotH + 0.6);
  }

  line(x0, y0, x1, y1, c0, c1 = c0) {
    const steps = Math.max(1, Math.ceil(Math.hypot(x1 - x0, y1 - y0)));
    for (let s = 0; s <= steps; s++) {
      const t = s / steps;
      this.plot(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, c0 === c1 ? c0 : mixc(c0, c1, t));
    }
  }

  /**
   * Text at cell coordinates. Deferred to a second pass so glyphs are never buried under
   * subpixels plotted later in the same frame — the terminal canvas gets this for free
   * because text simply wins the cell.
   *
   * GROWTH.md §3 rides on this: a visual bound to no telemetry row renders U+2298 (⊘), and
   * a fail-loud marker that silently vanishes on the phone is worse than no marker at all.
   */
  write(cx, cy, str, colour) {
    if (cy < 0 || cy >= this.h) return;
    this.texts.push({ cx, cy, str, colour });
  }

  /** Second pass. Call once per frame, after the view has drawn. */
  flush() {
    const { ctx } = this;
    const cw = this.dotW * 2;
    const ch = this.dotH * 4;
    ctx.font = `${Math.round(ch * 0.82)}px ${FONT_STACK}`;
    ctx.textBaseline = 'middle';
    for (const t of this.texts) {
      ctx.fillStyle = css(t.colour);
      ctx.fillText(t.str, t.cx * cw, t.cy * ch + ch / 2);
    }
  }
}

const css = (c) => `#${(c & 0xffffff).toString(16).padStart(6, '0')}`;
const lerp = (a, b, t) => a + (b - a) * t;
const mixc = (c1, c2, t) => (
  (Math.round(lerp((c1 >> 16) & 255, (c2 >> 16) & 255, t)) << 16)
  | (Math.round(lerp((c1 >> 8) & 255, (c2 >> 8) & 255, t)) << 8)
  | Math.round(lerp(c1 & 255, c2 & 255, t))
);
