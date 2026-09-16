// Colour, and nothing else.
//
// Split out of canvas.js so the browser renderer can have the palette without dragging in
// a terminal: canvas.js is braille cells, ANSI escapes and process.hrtime, none of which
// mean anything in a page. canvas.js re-exports these, so every existing import still
// resolves to exactly the same functions and the TUI does not know this happened.

export const rgb = (r, g, b) => ((r & 255) << 16) | ((g & 255) << 8) | (b & 255);
export const lerp = (a, b, t) => a + (b - a) * t;
export const mix = (c1, c2, t) => rgb(
  Math.round(lerp((c1 >> 16) & 255, (c2 >> 16) & 255, t)),
  Math.round(lerp((c1 >> 8) & 255, (c2 >> 8) & 255, t)),
  Math.round(lerp(c1 & 255, c2 & 255, t)),
);

/** '#rrggbb', for a context that wants CSS rather than an ANSI triplet. */
export const css = (c) => `#${(c & 0xffffff).toString(16).padStart(6, '0')}`;
