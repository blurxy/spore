// Braille subpixel canvas with differential rendering.
//
// A terminal cell is 1x1. A braille cell is 2x4. That is 8x the resolution for free,
// which is what makes real growth drawable in a text grid.
//
// Probe 3 (docs/probes/FINDINGS.md) measured the thing that dictates this file's shape:
// CPU is not the constraint, terminal write throughput is. Naive full repaint costs
// 576 KB/s at 60fps. Emitting only changed cells, coalescing runs that share a colour,
// and wrapping each frame in synchronized output brings that to 80 KB/s for 0.012ms.
// So differential rendering is not an optimization here, it is the design.

const DOT = [
  [0x01, 0x02, 0x04, 0x40],
  [0x08, 0x10, 0x20, 0x80],
];

export const SYNC_ON = '\x1b[?2026h';
export const SYNC_OFF = '\x1b[?2026l';
export const ALT_SCREEN_ON = '\x1b[?1049h';
export const ALT_SCREEN_OFF = '\x1b[?1049l';
export const HIDE_CURSOR = '\x1b[?25l';
export const SHOW_CURSOR = '\x1b[?25h';

// Colour lives in palette.js so the browser renderer can import it without a terminal
// attached. Re-exported here because every existing caller imports it from canvas.js.
export { rgb, lerp, mix, css } from './palette.js';
import { mix } from './palette.js';

export class Canvas {
  constructor(cols, rows) {
    this.resize(cols, rows);
  }

  resize(cols, rows) {
    this.w = Math.max(1, cols);
    this.h = Math.max(1, rows);
    const n = this.w * this.h;
    this.dots = new Uint8Array(n);
    this.col = new Uint32Array(n);
    this.text = new Array(n).fill(0); // codepoint overlay; 0 = use braille
    this.pDots = new Uint8Array(n);
    this.pCol = new Uint32Array(n);
    this.pText = new Array(n).fill(0);
    this.first = true;
  }

  clear() {
    this.dots.fill(0);
    this.col.fill(0);
    this.text.fill(0);
  }

  /** Plot one subpixel. Coordinates are in 2w x 4h space. */
  plot(x, y, colour) {
    const xi = Math.round(x);
    const yi = Math.round(y);
    if (xi < 0 || yi < 0 || xi >= this.w * 2 || yi >= this.h * 4) return;
    const i = (yi >> 2) * this.w + (xi >> 1);
    this.dots[i] |= DOT[xi & 1][yi & 3];
    this.col[i] = colour;
  }

  line(x0, y0, x1, y1, c0, c1 = c0) {
    const steps = Math.max(1, Math.ceil(Math.hypot(x1 - x0, y1 - y0)));
    for (let s = 0; s <= steps; s++) {
      const t = s / steps;
      this.plot(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, c0 === c1 ? c0 : mix(c0, c1, t));
    }
  }

  /** Write text at cell coordinates. Text always wins over braille in that cell. */
  write(cx, cy, str, colour) {
    for (let i = 0; i < str.length; i++) {
      const x = cx + i;
      if (x < 0 || x >= this.w || cy < 0 || cy >= this.h) continue;
      const idx = cy * this.w + x;
      this.text[idx] = str.codePointAt(i);
      this.col[idx] = colour;
    }
  }

  /**
   * Emit only what changed, coalescing runs that share a colour and repositioning the
   * cursor only when a run is discontinuous. Wrapped in synchronized output so the
   * terminal composites a whole frame rather than tearing mid-draw.
   */
  render() {
    let out = SYNC_ON;
    let lastCol = -1;
    let cx = -1;
    let cy = -1;

    for (let r = 0; r < this.h; r++) {
      for (let c = 0; c < this.w; c++) {
        const i = r * this.w + c;
        if (!this.first
          && this.dots[i] === this.pDots[i]
          && this.col[i] === this.pCol[i]
          && this.text[i] === this.pText[i]) continue;

        if (cy !== r || cx !== c) {
          out += `\x1b[${r + 1};${c + 1}H`;
          cy = r;
          cx = c;
        }

        const ch = this.text[i];
        const bits = this.dots[i];
        if (!ch && !bits) {
          if (lastCol !== -2) { out += '\x1b[0m'; lastCol = -2; }
          out += ' ';
        } else {
          const v = this.col[i];
          if (v !== lastCol) {
            out += `\x1b[38;2;${(v >> 16) & 255};${(v >> 8) & 255};${v & 255}m`;
            lastCol = v;
          }
          out += ch ? String.fromCodePoint(ch) : String.fromCharCode(0x2800 + bits);
        }
        cx++;
      }
    }

    this.pDots.set(this.dots);
    this.pCol.set(this.col);
    for (let i = 0; i < this.text.length; i++) this.pText[i] = this.text[i];
    this.first = false;
    return out + '\x1b[0m' + SYNC_OFF;
  }
}

/**
 * Drives frames against a real clock and measures itself, so the degradation ladder in
 * GROWTH.md has actual numbers to react to rather than vibes.
 */
export class Screen {
  constructor(stream = process.stdout) {
    this.stream = stream;
    this.canvas = new Canvas(stream.columns || 100, (stream.rows || 30) - 1);
    this.frames = 0;
    this.bytes = 0;
    this.drawMs = 0;
    this.running = false;
    this._onResize = () => this.canvas.resize(stream.columns || 100, (stream.rows || 30) - 1);
  }

  enter() {
    this.stream.write(ALT_SCREEN_ON + HIDE_CURSOR);
    this.stream.on?.('resize', this._onResize);
    this.running = true;
  }

  exit() {
    this.running = false;
    this.stream.off?.('resize', this._onResize);
    this.stream.write('\x1b[0m' + SHOW_CURSOR + ALT_SCREEN_OFF);
  }

  paint(drawFn) {
    if (!this.running) return;
    const t0 = process.hrtime.bigint();
    this.canvas.clear();
    drawFn(this.canvas);
    const out = this.canvas.render();
    this.stream.write(out);
    this.drawMs += Number(process.hrtime.bigint() - t0) / 1e6;
    this.bytes += out.length;
    this.frames++;
  }

  get stats() {
    return {
      frames: this.frames,
      msPerFrame: this.frames ? this.drawMs / this.frames : 0,
      bytesPerFrame: this.frames ? Math.round(this.bytes / this.frames) : 0,
    };
  }
}
