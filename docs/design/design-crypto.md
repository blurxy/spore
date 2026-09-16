# Identity, Handshake & Encryption (SESSION + KEYRING)

> Hyphae use Noise_XX_25519_ChaChaPoly_BLAKE2b, spec-exact on Node stdlib — I verified that `crypto.hkdfSync('blake2b512', ikm, ck, EMPTY_INFO, 64n)` is bit-identical to Noise's HKDF, so no custom HMAC code is needed. Identity is a separate ed25519 key bound to the X25519 static by a signed link cert plus a per-session signature over the transcript hash. The crux — untrusted VAULTs serving unreadable shards — is solved by encrypt-then-address (BlockID = hash of ciphertext) plus an MLS-style GGM secret tree whose leaf seek is 32 hashes regardless of index (measured 0.5ms at index 4,000,000), so any member decrypts any block from any VAULT in any order with zero key-request round-trips.

All primitives verified in Node v24.18.0. **Key finding: `crypto.hkdfSync('blake2b512', ikm, ck, EMPTY_INFO, 64*n)` is bit-identical to Noise's `HKDF(ck, ikm, n)`** (Noise's chain with empty info == RFC5869 Expand). A spec-exact Noise build needs zero hand-rolled HMAC.

## 1. Identity

One secret at rest: `master_seed` (32B). `id_seed = HKDF(master,"SPORE/id/ed25519/v1")`, `dh_seed = "…/dh/x25519/v1"`, `store_key = "…/store/v1"`. Raw seeds become keys by PKCS8 wrapping (ed25519 prefix `302e020100300506032b657004220420`; X25519 `…656e042204 20`) — verified deterministic.

**SPORE-ID = the raw 32B ed25519 public key.** No hash: no preimage question, no mapping table. The key *is* the device; rotation means a new spore ID, stated plainly.

Display: `BLAKE2b512("SPORE-FP-v1\0"||id_pub)[0..9]` → Crockford base32 (no I/L/O/U) → `spr:4G7K-9WMR-2XQP-8ZNT` + 2-char checksum (80 bits). UI handle = first 8 chars, explicitly *not* security-relevant.

Storage `~/.spore/identity.key`: `"SPORE-ID"|ver|salt[16]|N,r,p|nonce[12]|AEAD(scryptSync(pass,salt,N=2^15,r=8,p=1), master)`. Empty passphrase is allowed for headless/single-node — then protection is filesystem permissions **only**, and Windows has no 0600. Surface that in the UI.

## 2. Handshake — Noise_XX_25519_ChaChaPoly_BLAKE2b

**Why XX**, not IK/KK/XXpsk3: zero prior knowledge required, which is forced on us — a bare hotspot has no directory, and BEACON announcements are spoofable and stale. XX gives mutual auth, forward secrecy from `ee`, and hides the initiator's static from passive observers. One pattern, one state machine; IK+XXfallback (Noise Pipes) is the known-fragile path. 1.5 RTT on LAN is ~2ms. **No PSK**: hyphae are colony-agnostic — a spore relays for colonies it does not belong to.

**Identity binding** (libp2p-noise style, strengthened). ed25519 is never used for DH. A separate X25519 static is bound by `link_sig = Ed25519(id_priv,"SPORE-LINK-v1\0"||id_pub||s_pub||not_after)` (long-lived, gossipable) and `bind_sig = Ed25519(id_priv,"SPORE-BIND-v1\0"||h)` (per-session, over the transcript hash). XX is already KCI-resistant on msg2/msg3 — `es` and `se` use the peer's *ephemeral*. The real purpose of `bind_sig` is that **the ed25519 key becomes the sole per-session authenticator: compromise of the X25519 static alone yields neither impersonation nor decryption** (no `ee`). It also makes authentication session-specific, killing UKS/misbinding.

`prologue = 0x53|ver|suite_u16` is MixHashed before msg1, authenticating version and suite (no downgrade).

```
MSG1 I→R  e_pub_i[32] | P u16be | payload (CLEARTEXT, mixed into h) = caps u32
MSG2 R→I  e_pub_r[32] | AEAD(k,0,h, s_pub_r)[48] | L u16be | AEAD(k,1,h, payload)
MSG3 I→R  AEAD(k,0,h, s_pub_i)[48] | L u16be | AEAD(k,1,h, payload)
payload = id_pub[32]|link_sig[64]|bind_sig[64]|roles u32|not_after u32   (168B)
```
`bind_sig` covers `h` as it stands immediately *before* encrypting that payload. **Measured: m1=32, m2=256, m3=224 bytes**; transcripts agree, both signatures verify. `Split()`: `[a,b]=HKDF(ck,empty,2)`; initiator send=`a[0..31]`/recv=`b[0..31]`, responder swapped. `hypha_id` = final `h` (64B) — the channel binding for join proofs. `SAS = BLAKE2b("SPORE-SAS-v1\0"||h)[0..3]` → 4 words from a 256-word list (32 bits, ZRTP-style).

## 3. Frames, nonces, rekey

Plaintext `type u8|flags u16|len u32|body|pad`. AAD (cleartext, 8B) `0x53|epoch u8|rsv u16|seq_lo u32`. **`seq_lo` is diagnostic only** — it must equal the local counter or the hypha dies; the nonce is always the local counter, never the wire value. `nonce = 0x00000000 || LE64(n)`. Separate key and counter per direction (anti-reflection; verified `send != recv`). Any AEAD failure is fatal — Noise's rule. Replay verified rejected by the stateful counter.

**Deterministic rekey, no signalling**: both sides observe the same per-direction frame sequence over TCP, so at `n+1==2^16` or `bytes>=2^29` both compute `k = REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32])[0..31]` (verified at max nonce), `n=0`, `epoch++`. REKEY ratchets forward but gives **no PCS**. For PCS: `HYPHA_REKEY_REQ/ACK` exchange fresh ephemerals, `ck' = HKDF(ck, X25519(e,e'))`, re-Split; the epoch byte's high bit flips and the receiver holds a two-state window until the first new-epoch frame. Forced before epoch wraps 255; triggered every 30min/8GiB.

Hardening: reject `e_pub`/`s_pub` equal to our own (reflection). Node's `diffieHellman` **throws on low-order X25519 points** (verified) — catch as fatal, count it. MSG2 costs 2 DH, so above an in-flight threshold require a WireGuard-style cookie reply (`mac2 = BLAKE2b-MAC(cookie,msg1)`) before doing DH work. All non-AEAD comparisons via `timingSafeEqual`.

## 4. Colony identity, invites, revocation

COLONY-ID = colony root ed25519 pub; genesis block signed by it. Authorization is an SPKI/SDSI-style attenuating cap-cert chain (cf. UCAN): `{issuer, subject, colony, rights u64, depth, nbf, exp, serial, sig}`.

**Invite = bearer token with proof-of-possession**, so a relay that observes it cannot use it. The blob carries `invite_pk`; the QR *also* carries `invite_sk`. The joiner signs `Ed25519(invite_sk,"SPORE-JOIN-v1\0"||hypha_id||joiner_id_pub)`, binding the invite to this hypha and this joiner — replay of a captured QR is useless. Typed short codes: 10 Crockford chars (50 bits), offer multicast encrypted under `scrypt(code, N=2^15)`, TTL 120s, single-use, **mandatory SAS confirmation on both screens**. Honest: a captured broadcast is offline-attackable at ~65 bits; the SAS, not the code, is what stops a real-time MITM. We **cannot** build a real PAKE — Node stdlib has no hash-to-curve or ristretto.

Admission: any member holding `INVITE_ADMIT` may admit (the inviter may be offline or partitioned). `MEMBER_ADD` is appended, the serial burned, and the joiner receives genesis, head, and a KEYBUNDLE (§5).

**Merge rule**: concurrent `MEMBER_ADD`/`MEMBER_REMOVE` across partitions resolve **remove-wins**, subject to the cap chain — a low-rights member cannot remove an admin, and such a block is simply invalid.

**Revocation, plainly.** It *can* be unforgeable, and once seen it excludes the member from the next epoch rotation. It *cannot* be instantaneous or global under partition: a partition that hasn't seen the revoke keeps honoring the member. No central authority means no synchronous revocation — you get availability or immediate revocation, not both. It also cannot un-read what was already read; revocation is not deletion. The partition-tolerant mitigation is **short-lived caps (exp ~7d, auto-renewed while in good standing) — expiry is the only revocation that crosses a partition**, because the attacker's caps die unattended. Members gossip membership-log heads so a stale head is visible.

## 5. The crux — untrusted VAULTs serving unreadable shards

**Structural move: encrypt-then-address.** `BlockID = BLAKE2b-256(ciphertext)`. A VAULT verifies it holds the right bytes by hashing, serves them, and never holds a key. Dedup, rarest-first, and Merkle integrity all operate on ciphertext (Tahoe-LAFS capability model). Verified: a VAULT validates hash + author signature while decryption fails without the key.

**Chosen: sender-key epoch distribution + MLS-style GGM secret tree.**
`sender_root = HKDF(epoch_root, salt=fruiting_id, info="SPORE-SENDER-v1\0"||author_id||device_id)`; message key `i` is a depth-32 GGM leaf (L/R HKDF steps).

Rejected alternatives: **pairwise/Double-Ratchet per channel** — O(N) ciphertext per message and history is undecryptable to new members, destroying parallel fetch. **Megolm linear ratchet** — seeking index `i` costs O(i), so out-of-order shards stall. **GGM tree — measured 32 hashes / 0.50 ms to reach index 4,000,000, constant regardless of index.** Fetch block #4,000,000 from VAULT A and #7 from VAULT Z simultaneously and decrypt both immediately. That is what makes BLOOM real for cold-start. **Full MLS/TreeKEM** gives O(log N) rekey and true PCS but requires a totally-ordered commit sequence — precisely the Delivery Service we don't have. Take MLS's secret tree, leave MLS's TreeKEM.

**Epoch forks are graceful, unlike TreeKEM's.** Epochs are **content-addressed: `epoch_hash` = hash of the signed `EPOCH_ROTATE` block**, never a sequential integer, and every message block references its epoch by that hash. Two partitions that both rotate produce two valid roots; each decrypts its own branch and healing is a re-wrap on merge. Rotation requires the `EPOCH_ROTATE` right (or any member acting on a membership change they witnessed), and the envelope set is a **signed** substrate block — otherwise any member could inject a fake root and split the group.

**KEYBUNDLE.** "One root reads all history" is false once epochs rotate per join, so the admitter wraps every `(epoch_hash, root)` pair the joiner is entitled to. 1000 epochs = 32 KiB, trivial — and the entitlement set is a free policy knob: history from genesis (Discord) or from join point (Signal).

**Nonce-reuse hazard.** `nonce=i` under leaf key `i` is catastrophic if reused. Three defenses: `sender_root` is per-`(author, device_id, epoch)` so two devices never collide; the counter is write-ahead persisted before send; on crash recovery we skip ahead by a margin. `i` rides in the cleartext envelope and the tree is sparse-tolerant, so gaps cost nothing.

Cost accepted: any member can derive any member's chain, so symmetric auth is worthless inside a fruiting — **every block carries an ed25519 inner signature**, non-negotiable. Epoch rekey is O(N) pairwise envelopes: **measured 1000 members = 84 ms, 78 KiB**. That is the model's known weakness. Rotate on membership change, 7 days, or 100k messages.

**Media**: `k_media` is random, **not** convergent (convergent encryption leaks confirmation-of-file). 256 KiB chunks, chunk key `HKDF(k_media,"chunk"||idx)`, chunk ID = hash of chunk ciphertext, Merkle root `media_root`. The read-cap `{media_root, k_media}` lives *inside* the encrypted message. Untrusted VAULTs serve and verify chunks rarest-first, never seeing `k_media`. Opt-in "scoped convergent" (`k_media = HKDF(epoch_root, hash(plaintext))`) restores dedup within an epoch while limiting the confirmation attack to people who can already read the channel.

**DMs** are a 2-member fruiting rotating its epoch on every fresh ephemeral contribution — a Double Ratchet with the epoch as the DH step. Same machinery, real PCS.

## 6. Forward secrecy and PCS, plainly

**Hypha**: full FS from `ee`; PCS on re-handshake; static-DH compromise decrypts no recorded traffic. Identity-key compromise means full impersonation going forward, still no past decryption.

**Fruiting**: essentially **no forward secrecy for history you chose to replicate**. SPORE's premise is retaining history, so the archive — not the crypto — is the exposure; device seizure reveals it. This belongs in the UI, not a footnote. Knobs: per-fruiting retention (drop epoch roots, keep ciphertext → permanently unreadable) and "ephemeral fruitings" with hard 24h key deletion. PCS via epoch rotation is real but bounded by rekey cadence and by whether the removal propagated — partition-limited, same caveat as revocation.

**Not offered**: deniability (we sign everything; non-repudiable, like Megolm), metadata privacy from a RELAY (it sees who-talks-to-whom, sizes, timing; we offer padding to 256/1K/4K buckets, not a mixnet), and any protection against a malicious *member* — no crypto fixes an authorized leaker.

## Interfaces

- `SESSION.wrap(duplex, {initiator: bool, staticKeys, prologue}) -> Promise<Hypha>` — Turns a raw TRANSPORT duplex into an authenticated encrypted hypha via Noise XX. Rejects on any handshake failure. Knows nothing about the substrate.
- `Hypha.send(frame: Buffer) -> void   /   Hypha.on('frame', cb)` — Framed typed message I/O over the established session. Encrypts/decrypts with the per-direction key and implicit counter.
- `Hypha.on('fatal', ({reason, code}) => void)` — Mandatory teardown signal. Any AEAD failure, counter mismatch or invalid point is fatal per the Noise rule; TRANSPORT must expose a matching close().
- `Hypha.id -> Buffer(64)  /  Hypha.peerId -> Buffer(32)  /  Hypha.peerCaps -> u32` — Final transcript hash (channel binding for join proofs), peer's ed25519 SPORE-ID, and advertised role capabilities.
- `Hypha.sas() -> string` — Four-word short authentication string derived from the transcript hash, for out-of-band MITM confirmation during short-code pairing.
- `Hypha.rekey({full: bool}) -> Promise<void>` — Forces a Noise REKEY (forward ratchet) or a full ephemeral re-handshake for post-compromise security.
- `SESSION.setMembershipOracle(fn(colonyId, sporeId) -> {caps, revoked, exp})` — Callback SESSION invokes to authorize a peer WITHOUT reading SUBSTRATE itself. This is how the contract boundary is honored; APP/KEYRING supply the implementation.
- `KEYRING.identity() -> {sporeId, fingerprint, handle}  /  KEYRING.unlock(passphrase)` — Loads or creates the master seed, derives ed25519 + X25519 keys, exposes the display fingerprint.
- `KEYRING.rotateEpoch(fruitingId, memberDhKeys[]) -> {epochHash, rotateBlock, envelopes[]}` — Generates a new epoch root and wraps it pairwise to every current member. Returns a signed, content-addressed substrate block. O(N).
- `KEYRING.unwrapEpochRoot(envelope, ephPub) -> epochRoot` — Recovers an epoch root addressed to this spore via X25519 ECDH + HKDF.
- `KEYRING.keybundle(joinerDhPub, entitlement) -> wrapped[(epochHash, root)]` — Bundles every epoch root a new member is entitled to, implementing the from-genesis vs from-join-point history policy.
- `KEYRING.messageKey(fruitingId, epochHash, authorId, deviceId, i) -> Buffer(32)` — GGM secret-tree leaf derivation. O(log) — 32 hashes regardless of i, enabling random-access decryption of shards fetched out of order.
- `KEYRING.sealBlock(fruitingId, epochHash, i, plaintext) -> {envelope, ciphertext, blockId}` — Signs inner, encrypts, and returns the cleartext outer envelope plus BlockID = hash(ciphertext) for encrypt-then-address storage.
- `KEYRING.openBlock(envelope, ciphertext) -> {authorId, plaintext} | throws` — Verifies BlockID and both signatures, then decrypts. Used only by spores holding the epoch root.
- `KEYRING.verifyEnvelope(envelope) -> bool` — Hash + author-signature check usable by an untrusted VAULT that holds NO key, so it can reject spam and corruption while storing opaque ciphertext.
- `KEYRING.mediaCap(blob) -> {mediaRoot, kMedia, chunkIds[]}  /  KEYRING.openChunk(cap, idx, ct)` — Tahoe-style read-cap: chunked random-key encryption with ciphertext-addressed chunks for parallel rarest-first fetch from untrusted VAULTs.
- `Invite.create({colonyId, rights, uses, ttl, capChain}) -> {blob, qr, shortCode}` — Mints an offline capability token with an embedded proof-of-possession keypair. No server, no internet.
- `Invite.prove(invite, hyphaId, joinerId) -> proof   /   Invite.verify(invite, proof, hyphaId)` — Binds a bearer invite to one hypha and one joiner so an observer who captures the QR cannot redeem it.

## Telemetry emitted

- hypha.handshake.started / completed / duration_ms (histogram, by initiator|responder)
- hypha.handshake.failed BY REASON: bad_link_sig, bad_bind_sig, low_order_point, aead_fail, bad_prologue, suite_unsupported, self_connect, timeout, cap_expired, peer_revoked
- hypha.cookie.challenged / cookie.solved / handshakes_in_flight (DoS backpressure gauge)
- hypha.frames_sent / frames_recv / bytes_sent / bytes_recv — PER DIRECTION, per hypha
- hypha.seq_mismatch (diagnostic counter tamper-evidence), hypha.aead_fatal (should be 0; any nonzero is an attack or a bug)
- hypha.rekey.deterministic (count, with epoch number) / hypha.rehandshake.pcs (count, duration_ms)
- hypha.open_count gauge, hypha.lifetime_ms histogram, hypha.teardown_reason breakdown
- keyring.epoch.rotations (by trigger: membership_change|time|message_count), envelope_wrap_latency_ms, envelopes_written, members_at_rotation
- keyring.epoch.forks_detected / forks_healed (two epoch_hashes at the same causal depth — proves graceful-fork handling is live)
- keyring.epoch.roots_held gauge, keybundle_size_bytes, keybundle_unwrap_failures
- keyring.ggm.derivations, ggm.derive_ns histogram, ggm.cache_hit_ratio (proves the constant-time-seek claim on real traffic)
- keyring.block.sealed / opened / open_failures, inner_sig_failures (forged-member detector — nonzero means a member is attacking)
- vault.envelope_verifications / rejections — counted on spores holding NO key, proving zero-trust validation works
- keyring.nonce.skip_ahead_events (crash recovery), counter_wal_fsync_ms — guards the catastrophic reuse hazard
- invite.created / redeemed / burned / expired / rejected_by_reason, invite.shortcode_offers_broadcast, offer_bruteforce_attempts
- session.sas.shown / confirmed / rejected (a rejected SAS is a probable real-time MITM — alert, not just a counter)
- membership.revocations_seen, revocation_propagation_lag_ms (time from block author to local apply — makes partition-limited revocation VISIBLE)
- membership.cap_renewals, caps_expiring_24h gauge, remove_wins_merges_applied
- identity.keyfile_unlocked, unlock_failures, unprotected_keyfile gauge (passphrase-less installs — a fleet health signal)

## Risks (self-identified)

- Epoch rotation is O(N) pairwise envelopes — measured 84ms / 78 KiB at 1000 members. A large colony with heavy churn (join/leave storms) rotates constantly and rekey traffic can dominate the mesh. Mitigations: batch rotations over a debounce window, rotate lazily on next write rather than on every membership delta, and cap rotation frequency. This is the sender-key model's structural weakness and we are choosing it deliberately over TreeKEM's ordering requirement.
- No forward secrecy for replicated history, by design. SPORE's entire value proposition is that history is durably replicated across VAULTs; that directly contradicts FS. Device seizure or a single compromised member exposes everything that member could read. Users will assume otherwise because the app looks like Signal. This must be stated in the UI, not in documentation.
- Short-code pairing cannot be made offline-brute-force-resistant from Node stdlib — no hash-to-curve means no SPAKE2/OPAQUE. A captured multicast offer is attackable at roughly 65 bits of work. Security rests on the 120s TTL and on users actually comparing the four-word SAS. Users habitually click through SAS prompts, so in practice this is the weakest link in the whole design.
- Sender counter reuse is catastrophic and only procedurally prevented. A crash between send and counter persist, a restored VM snapshot, or a cloned identity file across two devices reuses (key, nonce) under ChaCha20-Poly1305, which leaks plaintext XOR and destroys the Poly1305 key. Per-device sender roots and write-ahead counters help; a restored snapshot defeats both. Consider a random per-boot device epoch nonce as a second line of defense.
- Revocation is eventually consistent and a determined attacker exploits partitions deliberately: split yourself off, keep using unexpired caps, rejoin later. Short cap lifetimes bound the damage but do not eliminate it, and shortening them increases renewal traffic and breaks long-offline legitimate users. There is no fix without consensus.
- Graceful epoch forks still cost correctness surface. Content-addressed epochs mean a member may legitimately hold several roots at the same causal depth, and merge/re-wrap logic is the part most likely to harbor bugs. A bug here silently makes some history undecryptable to some members — a failure mode that looks like data loss and is very hard to diagnose in the field.
- Metadata is substantially exposed to VAULTs and RELAYs. The outer envelope must be cleartext for untrusted verification, so who posted, in which fruiting, when, and how large is all visible to any storage peer. Size padding helps marginally. For some threat models this is worse than the message content.
- Non-repudiation is mandatory here: every block carries an ed25519 signature because any member can derive any member's symmetric chain. Anyone who ever holds an epoch root gains cryptographic proof of who said what, permanently and transferably. This is a genuine downgrade from OTR/Signal-style deniability and is irreversible once blocks are replicated.
- BLOOM does not apply uniformly. INDEX and FORGE need plaintext, so search and transcode only scale across spores that already hold read capability; only VAULT and RELAY scale across arbitrary peers. In a colony with few members but many bystander spores, the advertised superlinear scaling for search and transcode will simply not materialize.
- Implementing Noise by hand, even spec-exactly, is where this design most plausibly fails. The HKDF equivalence removes one class of error but MixHash ordering, the exact h used for each bind_sig, and nonce state across rekey are all subtle. There are no Node-stdlib Noise test vectors in-tree; the build must import the official Noise test vectors as a fixture file or this layer is unverified.

## Contract conflicts raised

- SUBSTRATE cannot verify block authorship if the signature is inside the ciphertext. The contract says SUBSTRATE owns 'block hashing/verification', but a non-member VAULT holding only ciphertext can verify at most BlockID == BLAKE2b(ciphertext). Resolution: blocks MUST be two-tier — a cleartext outer envelope (colony, fruiting, epoch_hash, seq, causal refs, author_id, message index i, outer signature) plus inner ciphertext carrying a second signature. VAULTs then validate and reject spam without reading. The price is metadata leakage to storage peers, and the contract must consciously accept it. An optional 'sealed fruiting' mode replaces author_id with a per-epoch pseudonym and an epoch-scoped signing key certified inside the ciphertext.
- SESSION 'knows nothing about the substrate' is correct for hypha crypto but impossible for colony membership, cap chains and epoch keys, which must be read from the membership log. Resolution: split this subsystem in two. SESSION stays strictly substrate-blind and handles only the Noise hypha; a separate KEYRING module owns identity, caps and epoch keys and reads through SUBSTRATE like APP does. SESSION receives a membershipOracle callback and never reaches into the substrate itself. The contract should name KEYRING explicitly rather than leaving it implicit in SESSION or APP.
- ROLES must carry a read-capability predicate: INDEX and FORGE cannot be zero-trust. Building a search index and transcoding media both require plaintext, so those roles can only be assigned to spores already holding the colony's epoch root. VAULT and RELAY are the only genuinely zero-trust roles. Capability scoring therefore needs has_read_cap(colony) as a hard gate, and the BLOOM scaling claim must be qualified per-role. Additionally, farming out key stretching (scrypt for invite codes) to a FORGE peer would hand over the secret being stretched — key stretching must stay strictly local, contradicting its listing as an offloadable enzyme.
- TRANSPORT's interface is missing a fatal-error/close path. Noise mandates that any AEAD authentication failure terminates the connection immediately, and SESSION must be able to force that. The contract lists only discover(), connect(), send(frame) and on('frame'). It needs close(reason) and on('close') on every hypha, and connect() must surface handshake timeouts distinctly from transport failures so telemetry can tell an attack from a flaky link.
- The contract assumes ordering guarantees that the transport tier must actually provide. Deterministic rekey without signalling depends on both peers observing an identical, gap-free, in-order per-direction frame sequence. That holds for TCP but NOT for the BLE / Wi-Fi Direct adapters the contract wants to slot in later. The transport adapter interface must therefore declare an ordered-reliable-stream guarantee; any adapter that cannot provide it forces explicit in-band rekey signalling and a receive window, which is a materially different SESSION design. Decide this before the adapter interface is frozen, not after.
