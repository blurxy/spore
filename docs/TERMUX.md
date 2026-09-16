# Getting SPORE onto a phone

`docs/HARNESS.md` describes the experiment. This describes getting to the point where you
can run it, which is the part that has never been done and where all the friction is.

Everything below is meant to be pasted one line at a time, with what you should see after
each. If a step's output does not look like the one shown, stop there — the next step will
fail in a way that looks like a different problem.

**Two phones is the minimum for a real result.** One phone tells you the stack runs on
Android. Two tells you almost nothing about the curve. Four is where §3.1's prediction
becomes falsifiable, because the knee is claimed to be at N=4.

---

## 0. On the laptop: make the bundle

The repo has no git remote, so the code travels as a single file. A bundle is a whole
repository — full history, and `git pull` works against it later — in one blob you can move
by USB, Syncthing, or emailing yourself.

```sh
cd /c/Users/blizz/spore
git bundle create spore.bundle --all
git bundle verify spore.bundle
```

Expect:

```
The bundle records a complete history.
```

It is around 500 KB. Copy it to each phone — plugging in a USB cable and dropping it in
`Downloads` is the least fiddly way, and it is the one step 2 assumes.

**To send an update later**, re-run exactly the same command and copy the new file over. On
the phone, `git pull ~/storage/downloads/spore.bundle` — no re-clone.

---

## 1. On each phone: Termux

Install Termux **from F-Droid**, not the Play Store. The Play Store build was abandoned
years ago and its package repositories no longer resolve; it fails at step 1.2 in a way
that reads like a network problem.

<https://f-droid.org/packages/com.termux/>

**1.1 — update the package index.**

```sh
pkg update -y && pkg upgrade -y
```

**1.2 — install what is needed. All of it.**

```sh
pkg install -y nodejs-lts git termux-api
```

`termux-api` is not optional: step 3 uses `termux-wake-lock`, and without it Android
suspends the process mid-run and you measure the churn path instead of the sync. You also
need the companion **Termux:API** app from F-Droid alongside it — the `pkg` package is only
the command-line half.

**1.3 — check Node.**

```sh
node --version
```

Anything **20 or newer** is expected to work. This was written against 24 and the test
suite in step 4 is the real check — a version number is a claim, and the suite is evidence.

**1.4 — let Termux see the Downloads folder.**

```sh
termux-setup-storage
```

Android shows a permission dialog. Accept it. Afterwards `~/storage/downloads` is the
folder your file manager calls Downloads.

---

## 2. On each phone: the code

```sh
cd ~
git clone ~/storage/downloads/spore.bundle spore
cd spore
```

Expect `Cloning into 'spore'...` and a receiving-objects line. If it says
`does not look like a v2 bundle file`, the copy was truncated — recopy it.

There is no `npm install`. There is nothing to install. That is the point; `dependencies`
is `{}` and stays that way.

---

## 3. On each phone: hold the wakelock

```sh
termux-wake-lock
```

Nothing is printed. A notification appears saying Termux is holding a wakelock.

**Do this before every run.** Android's Doze will suspend Node otherwise, and a suspended
spore does not fail loudly — it stalls mid-fetch, resumes later, and reports a number that
is mostly Android's scheduler. Release it with `termux-wake-unlock` when you are done, or
the battery pays for it.

Keep the screen on as well. The wakelock keeps the CPU alive; it does not stop every
aggressive OEM battery manager, and Samsung and Xiaomi in particular are worse than stock.

---

## 4. On each phone: prove the stack runs here

```sh
npm test
```

Expect a few seconds of output ending in:

```
ℹ pass 96
ℹ fail 0
```

This is the version check that means something. If every test passes, the protocol,
BLAKE2b, ed25519, Noise, the substrate and the scheduler all work on this device's Node —
regardless of what `node --version` said.

If something fails here, **stop and send the output**. It is a real finding: nothing in
this repo is platform-specific by intent, so a failure on Android is a bug, not a setup
problem.

---

## 5. One phone, alone: see it

```sh
node bin/spore.js --glass
```

Expect:

```
GLASS http://127.0.0.1:7777/
SPORE 9c14467554d0a465 "spore-30828" on :7777
MESSAGES ARE NOT ENCRYPTED — SP1 has no content confidentiality.
```

Now open **Chrome on the phone** — not on the laptop; the address is loopback and means
*this device* — and go to `http://127.0.0.1:7777/`.

You should see the lone spore breathing, the shout counter climbing, and the log panel.
Every pulse is a real multicast announce going out into the room and getting no answer.

**This is the first time this has been seen on real hardware.** Screenshot it.

`Ctrl-C` to stop.

---

## 6. The network, before you measure anything

Everything must be on **one Wi-Fi access point**. Not a mesh system or an extender: those
bridge cells, and §3.1's whole prediction is about one shared cell's airtime.

**Turn AP isolation / client isolation OFF on the router.** It is on by default on most
guest networks and it blocks device-to-device traffic entirely — which looks exactly like
SPORE being broken, all the way down to the beacons appearing to send fine.

Check the phones can see each other at all before blaming the code:

```sh
# on phone A
node bin/spore.js --nick alpha
# on phone B
node bin/spore.js --nick beta
```

Within a few seconds each should log the other as `SPORE ... is out there`, then `FUSED`.
If they never see each other, it is the network, not the mesh. Go back and check isolation.

---

## 7. The measurement

Now `docs/HARNESS.md` takes over — it has the experiment, the predicted curve, and the one
line that matters most (the per-source attribution warning). In short:

```sh
# on each seeder
termux-wake-lock
node bench/mesh.js --seed --corpus alpha --blocks 400

# on the joiner, once the seeders are up
termux-wake-lock
node bench/mesh.js --join --corpus alpha --blocks 400 --sources 1
```

Repeat with `--sources 2`, `3`, `4`, `5`, adding a seeder each time, restarting the joiner
between runs.

Read `docs/HARNESS.md` § "The line that matters most" before reporting anything. If one
source supplied most of a run, the run measured one uplink no matter how many phones were
in the room, and the harness will say so.

---

## When it goes wrong

| What you see | What it is |
|---|---|
| `pkg: command not found` | Not Termux — probably a different terminal app |
| `Unable to locate package nodejs-lts` | Play Store Termux. Uninstall, get the F-Droid build |
| `termux-wake-lock: command not found` | `pkg install termux-api`, **and** install the Termux:API app |
| Phones never see each other | AP isolation is on, or they are on different APs/bands |
| A run stalls and resumes | The wakelock was not held, or an OEM battery manager killed it |
| `does not look like a v2 bundle file` | Truncated copy. Recopy the bundle |
| The glass page is blank | Wrong device — `127.0.0.1` means the phone running the spore |
| Numbers keep climbing past N=5 | **A result.** §3.1 predicts a knee at 4. Report it |

## What this does and does not prove

Termux is Node on Android. It proves the protocol runs on phone hardware over phone radios
and through a real shared cell — which is the thing no laptop can test and the thing every
number in §3.1 currently rests on.

It does not prove SPORE survives Android's background execution rules, Doze with the screen
off, or being swiped away. That needs the native bridge, which is SP3. The wakelock in step
3 exists precisely to take that variable *out* of the measurement, not to show it is solved.
