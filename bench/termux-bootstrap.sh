#!/data/data/com.termux/files/usr/bin/bash
#
# Everything in docs/TERMUX.md steps 1-4, in one paste.
#
# Read the runbook first, at least once. This script is for the SECOND phone and the ones
# after it — when it fails you get a wall of output, and knowing what it was trying to do
# is the difference between a ten-second fix and a confusing evening.
#
# Idempotent: safe to re-run. It will not re-clone over an existing checkout, and it will
# pull instead if a bundle is present.
#
#   bash bench/termux-bootstrap.sh              # expects the bundle in ~/storage/downloads
#   bash bench/termux-bootstrap.sh /path/to.bundle

set -euo pipefail

BUNDLE="${1:-$HOME/storage/downloads/spore.bundle}"
DEST="${SPORE_DIR:-$HOME/spore}"

say() { printf '\n\033[36m== %s\033[0m\n' "$*"; }
die() { printf '\n\033[31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# --- 0. are we actually in Termux ------------------------------------------------------
command -v pkg >/dev/null 2>&1 || die "no 'pkg' — this is not Termux. See docs/TERMUX.md step 1."

# --- 1. packages ------------------------------------------------------------------------
say "installing packages (nodejs-lts, git, termux-api)"
pkg update -y >/dev/null
# nodejs-lts is the pinned LTS; plain nodejs is current. Either satisfies >=20.
pkg install -y nodejs-lts git termux-api >/dev/null 2>&1 \
  || pkg install -y nodejs git termux-api >/dev/null 2>&1 \
  || die "package install failed. If this says 'Unable to locate package', you have the Play Store Termux — get the F-Droid build."

command -v node >/dev/null 2>&1 || die "node did not install"
NODE_V="$(node --version)"
say "node $NODE_V"
case "$NODE_V" in
  v1[0-9].*) die "node $NODE_V is too old; need 20 or newer" ;;
esac

# termux-api ships the CLI; the Termux:API *app* is a separate F-Droid install and there is
# no way to install it from here. Warn rather than fail — the harness runs without it, it
# just measures Android's scheduler instead of the network.
if ! command -v termux-wake-lock >/dev/null 2>&1; then
  printf '\n\033[33m~~ termux-wake-lock missing. Install the Termux:API APP from F-Droid.\n'
  printf '   Without it Android will suspend a run mid-fetch and the numbers are not the network.\033[0m\n'
fi

# --- 2. storage -------------------------------------------------------------------------
if [ ! -d "$HOME/storage" ]; then
  say "requesting storage access (accept the Android dialog)"
  termux-setup-storage || true
  sleep 2
fi

# --- 3. the code ------------------------------------------------------------------------
if [ -d "$DEST/.git" ]; then
  say "$DEST exists"
  if [ -f "$BUNDLE" ]; then
    say "pulling updates from $BUNDLE"
    git -C "$DEST" pull "$BUNDLE" || die "pull failed — is the bundle from the same repo?"
  fi
else
  [ -f "$BUNDLE" ] || die "no bundle at $BUNDLE. Make it on the laptop with: git bundle create spore.bundle --all"
  say "cloning from $BUNDLE"
  git clone "$BUNDLE" "$DEST" \
    || die "clone failed. 'not a v2 bundle file' means the copy was truncated — recopy it."
fi

cd "$DEST"

# --- 4. prove it runs HERE ---------------------------------------------------------------
# The version check that means something. If this passes, BLAKE2b, ed25519, Noise, the
# substrate and the scheduler all work on this device — whatever `node --version` claimed.
say "running the test suite (this is the real check)"
if npm test; then
  say "all tests passed on this device"
else
  die "tests failed on this device. That is a finding, not a setup problem — send the output."
fi

cat <<'DONE'

  Ready.

  See it, alone:
      termux-wake-lock
      node bin/spore.js --glass
    then open Chrome ON THIS PHONE at http://127.0.0.1:7777/

  Measure it, with the others (see docs/HARNESS.md):
      termux-wake-lock
      node bench/mesh.js --seed --corpus alpha --blocks 400     # on each seeder
      node bench/mesh.js --join --corpus alpha --blocks 400 --sources 1

  Before measuring anything: one AP, and AP/client isolation OFF on the router.
  Release the wakelock when you are done:  termux-wake-unlock

DONE
