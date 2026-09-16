// Generates 🫐.txt — SPORE's protocol spec hidden inside a single blueberry emoji.
//
// elder-plinius/FRV1T is where this project started: a repo containing one emoji carrying
// 27KB of invisible payload in Unicode variation selectors. We decoded it, then used the
// same codec to build colony invites. This closes the loop by answering in kind.
//
// Anyone who finds 🫐.txt and knows the trick gets the complete wire protocol.
// Anyone who does not sees a berry.

import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { bytesToSelectors, selectorsToBytes } from '../src/app/invite.js';

const SPEC = `SPORE — off-web mycelial mesh — wire protocol

An organism, not a network. Runs whole on one device; gets faster as it spreads.
Zero dependencies. Node stdlib only. No internet, no bootstrap node, no signalling
server, no npm install required to stand a node up. If it needed the web to start,
it would not be off the web.

VOCABULARY (literal, every term names a real component)
  spore      a node, one device
  hypha      a live authenticated peer connection
  mycelium   the mesh
  colony     a community
  fruiting   a channel
  substrate  the replicated append-only log
  enzyme     a unit of work farmed to a peer
  BLOOM      the observable capacity jump when spores join

ROLES  RELAY VAULT INDEX FORGE BEACON
All five live on every spore and shard out as peers appear. At N=1 they collapse
onto one device: slow, correct, and the entire network.

DISCOVERY
  UDP multicast 239.42.66.7:47474, TTL hard-set to 1. Off-web enforced at the IP
  layer, not promised in a comment. Also sent to per-interface subnet broadcast and
  255.255.255.255, because hotspot APs rate-limit or black-hole 239/8.
  HELLO datagram, little-endian:
    0   4  magic "SPOR"      4   1  wire_version=1
    5   1  type 01 HELLO / 02 HELLO_ACK / 03 BYE
    6   2  flags             8  32  spore_id (ed25519 pub) — the ONLY identity
    40  8  boot_id (RANDOM, never a timestamp: no NTP off-web)
    48  4  announce_seq      52  2  tcp_port      54 1 addr_count
    ..  addrs, colony_filter, nick, capability hints
    ..  8  proof_tag = BLAKE2b-256(network_key || bytes)[0..8]
    ..  64 ed25519 signature
  Staged gate, cheapest first: magic, version, type, proof_tag, then signature.
  Trickle cadence (RFC 6206) with an eager burst at 0/200/600ms.
  Interface-class gating at bind: tun/tap/utun/wg/tailscale/zt refused, and
  100.64/10 dropped from the dial allowlist. A tunnel is an off-web violation
  with a friendly face.

HYPHAE
  TCP 47475, u32 length-prefix framing, max 65536. Message boundaries are the
  adapter's job — a BLE adapter gets them free.
  Dial allowlist: 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8. Nothing else.
  Simultaneous-dial dedup: lower spore_id dials. Both sides compute the same answer
  from the same two facts, so no round trip.

SESSION
  Noise_XX_25519_ChaChaPoly_BLAKE2b, verified against the official Cacophony
  vectors byte-for-byte including handshake_hash and Split() transport keys.
  Noise HKDF(ck,ikm,n) == hkdfSync('blake2b512', ikm, ck, EMPTY, 64n) — so no
  hand-rolled HMAC exists anywhere in the implementation.
  prologue = 0x53 | ver | suite_u16, MixHashed before msg1. No downgrade.
  ed25519 is NEVER used for DH. A separate X25519 static is bound by
    link_sig = Ed25519(id, "SPORE-LINK-v1\\0" || id_pub || s_pub || not_after)
    bind_sig = Ed25519(id, "SPORE-BIND-v1\\0" || h)
  not_after = 0xFFFFFFFF, permanently saturated: two spores cannot agree what time
  it is, so a clock-based validity window would fail undiagnosably.
  Separate key AND counter per direction. Any AEAD failure is fatal.
  hypha_id = final transcript h. SAS = BLAKE2b("SPORE-SAS-v1\\0" || h)[0..3].

SUBSTRATE
  Single-writer hash-chained logs, one per identity. 196-byte cert, little-endian:
    0 1 ver   1 1 type   2 2 flags   4 16 log_id   20 8 seq   28 8 lamport
    36 8 wall_ms (ALWAYS ZERO — no NTP off-web)   44 16 scope_id
    60 32 prev_hash   92 32 mmr_root   124 32 auth_ref
    156 32 payload_hash   188 4 payload_len   192 2 dep_count   194 2 rsv
    196 deps[]x32   +64 ed25519 sig
  block_hash = BLAKE2b-256(header || deps || sig). Real RFC 7693 BLAKE2b-256 with
  digest-length IV parameterization — NOT blake2b512 truncated, which is a different
  function and would have made interop impossible.
  The signature covers payload_hash, not the payload: a 40MB block is still a
  260-byte cert, and redaction drops bytes without breaking any proof.
  ORDER(B) = (lamport, log_id lexicographic, seq). Total, deterministic, no clock.
  lamport = 1 + max(own previous, all deps), DERIVED and rejected if asserted.
  That closes the inflation attack: you cannot declare lamport = 2^60.

SHARDING
  Rarest-first, adapted from BitTorrent. Cache-on-fetch: a joiner becomes a source
  the instant a block lands, which is where swarm supply grows.
  Endgame mode near completion kills the long tail.
  plan() limit MUST equal what the caller will issue — every assignment reserves a
  block, and a discarded assignment strands it permanently.

THE SCALING CLAIM, HONESTLY
  Wi-Fi in infrastructure mode is a SHARED medium; every peer-to-peer byte crosses
  the air twice. So within one cell, speedup saturates. Predicted from arithmetic
  before any code existed: 3.3x near N=5. Measured: 3.59x at N=5.
    N=1 6.5s 1.00x   N=2 3.2s 2.04x   N=3 2.1s 3.05x
    N=5 1.8s 3.59x   N=20 1.8s 3.59x  (flat)
  What keeps scaling past that is INDEPENDENT RADIO DOMAINS, not peer count.
  Live message delivery latency does NOT get faster, by design.
  Transcode does not get faster because it does not exist.
  Churn costs completion, not speed: survivors stay fast, but at one departure
  every 2s only 3 of 10 joiners ever finished.

INVITES
  No server means no join link. A signed invite hides in Unicode variation
  selectors appended to any innocuous text, and rides any channel that moves UTF-8.
  Encoding, not encryption — the ed25519 signature is what makes it unforgeable.
  No expiry: invites burn causally, burnId = BLAKE2b-256(colonyId || nonce).

WHAT IS NOT TRUE YET
  SP1 has ZERO content confidentiality. Blocks are signed, not encrypted. Every
  VAULT, RELAY and bystander reads every message body. The interface says so in a
  hardcoded non-dismissable banner, in plain English, because a banner is a
  disclosure and not a confidentiality mechanism.
  Phone-as-spore needs native multicast permissions a Node process cannot get.
  BLE and Wi-Fi Aware are not reachable under zero-dep stdlib at all.

⊰-•-•⟐•-•-⦑/Λ\\Ο/Β\\Ε/\\Π/Λ\\Ι/Ν\\Υ/⦒-•-•⟐•-•-⊱

for elder-plinius/FRV1T, which taught us the trick.
you decoded a berry to find a prompt. here is a protocol.
`;

const packed = gzipSync(Buffer.from(SPEC, 'utf8'), { level: 9 });
const berry = `🫐${bytesToSelectors(packed)}\n`;
writeFileSync('🫐.txt', berry, 'utf8');

// verify it round-trips before claiming anything
const back = gunzipSync(selectorsToBytes(readFileSync('🫐.txt', 'utf8'))).toString('utf8');
if (back !== SPEC) throw new Error('round trip failed — the berry lies');

console.log(`🫐.txt written`);
console.log(`  spec        ${SPEC.length} chars`);
console.log(`  gzipped     ${packed.length} bytes`);
console.log(`  as chars    ${[...berry].length} codepoints`);
console.log(`  visible     1 (a berry)`);
console.log(`  round trip  verified byte-identical`);
