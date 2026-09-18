# How the bugs in this repo were found

Written 2026-09-17, after a session in which adversarial review found seven fatal bugs in a
substrate that had already passed one review round — three of them in the commit that review
had been asked to certify.

This is not a style guide. It is the set of procedures that actually produced findings, and the
ones that produced none, recorded because the difference was not obvious in advance.

---

## The failure this codebase produces

**A bound stated in a comment rather than enforced in code.** Six instances, and the last two
are in the *fixes* for the earlier ones:

| where | the comment said | the code did |
|---|---|---|
| `forks` | `// seq -> { kept, other } block hashes` | stored two full certs, ~520 B against the implied 64 |
| `KEEP_FOREVER` | "authority outlives the byte budget" | exempted by wire TYPE; `#rebuildAuth` counted far less |
| `MAX_SEQ` | 2 MB per log is tolerable | never multiplied by `MAX_LOGS` — 512 MB from one frame |
| `dep_count` | u16 on the wire | capped nowhere; a ~64 KB unevictable cert |
| `rarity()` | — | `Int32Array(total)` sized by the same number `MAX_SEQ` had just bounded |
| `MAX_SEQ`, again | "32 MB across the cap" | per *peer*; no hypha cap exists |

Refined, after all six: **the bound is placed on the number and never on the product.** Number
× multiplicity × per-unit cost is the quantity that matters, and it is the one nothing asserts.
The check is a test that multiplies — see `test/sync.test.js`, "the advertised-set allocation is
bounded across ALL logs".

The pattern is not carelessness. It is **stopping at the first multiplier you can see.**

---

## Procedures that found things

**Mutation testing, by hand, one line at a time.** Delete a line, run the suite, record which
tests die or `NONE`, restore, verify the tree is clean before the next. A line whose deletion
breaks nothing is either dead code or an uncovered invariant, and both are findings. This found
the revocation-enforcing line that no test defended — deleting it let revoked blocks deliver
and all 102 tests still passed.

Do it mechanically and record the whole table, including the lines where nothing was wrong. The
table is reusable; the conclusion is not.

**Falsify every regression test against the broken code before keeping it.** Three times this
session a test was wrong and the *code* corrected it:
- A test asserted a later grant would deliver a stalled block. It cannot: the block cites a
  grant pinned above its own seq, so once the owner speaks the citation fails outright.
- A divergence classifier reported delivery failures that were ordering failures. `linkedTo <=
  orderedTo` holds by construction, so an ordering divergence drags delivery with it, and a
  classifier checking delivery first reports one fault as two.
- A regression test allowed `clean + 40` over 40 inserts — exactly the effect size — so it
  admitted the entire bug and passed against the mutant.

**A test that cannot fail is indistinguishable from a test that passes.** Only running it
against the broken code tells them apart.

**Delete tests you cannot falsify; annotate the line instead.** One test here was removed for
this reason, and the redundant line it would have defended now says in its comment that no test
dies if it is removed, and why. That is more honest than coverage theatre.

**Ask an adversarial reviewer what the work is systematically AVOIDING**, not what is next.
"What should I do next" returns the list. "What am I not seeing" returned the finding that two
subsystems in this codebase assume opposite process lifetimes and no document ever chose one —
see R10. That question is worth asking directly and it is not the same question.

**Give a reviewer the session history as well as the code.** The blind spots are in the
reasoning, not the diff.

---

## The one that produced nothing, and why

**Convergence property testing could not find the bug it was built for.** Every property in
`test/property.test.js` asserted that replicas fed the same blocks in any order reach the same
state. The supersession bug was *deterministic*: every replica computed the identical wrong
verdict, agreed perfectly, and passed every seed.

**Agreement is not correctness.** No generator and no number of seeds could have found it,
because the property being checked was not the property being violated. The fix was an oracle —
a second, deliberately naive reading of the same rule list — which catches a *consumer*
diverging from the rule its *producer* built.

It is a regression oracle, not a discovery oracle: if the rule itself is wrong, both readings
are wrong together and it stays silent. Say which kind you have built.

The generator was separately blind in two ways worth knowing about, because both are easy to
reproduce elsewhere: it emitted control blocks in a fixed order, so two orderings that must be
allowed to disagree never did; and it could only cite the first grant ever issued, so the
supersession path was unreachable at any seed.

---

## Measurement discipline

From the first hardware run (`RESULTS-2026-09-17.md`), where three of six trials were
contaminated and the contamination looked exactly like a finding:

- **A smooth monotonic curve is a shape you should distrust first.** 11.14 → 8.77 → 5.17 MB/s
  was one, two and three of my own leftover seeder processes competing, not the mesh.
- **Record contaminated runs with their cause rather than deleting them.** The deleted version
  of that table is a clean-looking result that someone would later trust.
- **Check what the harness cannot see.** Wi-Fi power saving was parking the radio between
  packets — 86 ms ICMP at *zero packet loss* on a 5 GHz LAN. Nothing in the harness output
  would have revealed it, and the number would have been wrong with a plausible story attached.
- **A model and a measurement agreeing is not corroboration if they measure different
  quantities.** `bench/curve.js` models a 3 ms RTT, where the request-window ceiling is
  invisible. It agreed with hardware that may have been hitting that ceiling. See R9.
- **Several trials per point.** Variance was ~1.8× on a quiet device with the radio pinned and
  zero loss.

---

## Things that are true about this repo specifically

- `npm test` is the only version check that means anything on a new platform. It passed 119/119
  unmodified on aarch64 Android the first time it ran there.
- Commit messages here carry the reasoning, not just the change. They are long on purpose, and
  they are the reason a decision can be re-examined a week later.
- Corrections are written **as corrections**. R7 corrects its own reasoning, R8 corrects R7,
  `ENCRYPTION.md` strikes an argument rather than deleting it, and `RESULTS` withdraws a claim
  it made three commits earlier. The failed reasoning is the useful part.
- Documentation decays silently. Three published errors were found in one pass over a README
  and a decision record that had both been read many times: a stale test count, a headline
  resting on a model that could not exhibit what it claimed to measure, and a mandate
  contradicted by the same document's own correction. **Prefer a generated artefact that
  imports its constants over one that restates them.**
