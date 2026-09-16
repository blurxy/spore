// Entry point, as a FILE rather than an inline <script>.
//
// The page is served with `script-src 'self'`, which forbids inline script — so the first
// version of this, a `<script type="module">` in the HTML calling boot(), was silently
// refused by the browser's own policy. No console error the tooling surfaced, no failed
// request, a correct-looking page: just a black canvas and a title. Every test passed,
// because every test checked what the SERVER sent and none opened it.
//
// Keeping the entry point here is the better shape anyway. The CSP stays strict with no
// 'unsafe-inline' escape hatch, and the page becomes pure markup — which is also what
// makes "this UI has no control surface" something you can check by reading it.
//
// Configuration arrives as data attributes, because they are markup, not code.

import { boot } from './boot.js';

const root = document.getElementById('m');
if (root) {
  boot(root, {
    nick: root.dataset.nick || 'spore',
    sporeId: root.dataset.spore || '',
  });
}
