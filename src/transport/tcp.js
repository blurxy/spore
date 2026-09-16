// The TCP hypha adapter: raw socket in, authenticated encrypted hypha out.
//
// Transport is deliberately NOT a byte stream. The contract upper layers get is
// message-boundary-preserving: one send produces exactly zero or one whole datagram at
// the peer. TCP does not give that, so we restore it with a u32 length prefix. A future
// BLE GATT adapter gets boundaries for free and implements the same interface honestly.

import net from 'node:net';
import { EventEmitter } from 'node:events';
import { Handshake, NoiseError } from '../session/noise.js';
import { HYPHA_PORT } from './beacon.js';

export const MAX_FRAME = 65536;

/**
 * Hard address allowlist. Any destination outside it is refused and counted.
 * This turns "no internet dependency of any kind" into a testable invariant rather
 * than a design intention.
 *
 * 100.64/10 is deliberately ABSENT. It is carrier-grade NAT, but in practice on a
 * developer machine it is Tailscale, and ARCHITECTURE.md 1.3 chose closing the tunnel
 * loophole over supporting CGNAT mobile networks. Interface-class gating in beacon.js
 * is the primary defence; this is the second layer.
 */
const ALLOW = [
  [/^10\./, '10/8'],
  [/^172\.(1[6-9]|2\d|3[01])\./, '172.16/12'],
  [/^192\.168\./, '192.168/16'],
  [/^169\.254\./, '169.254/16'],
  [/^127\./, '127/8'],
];

export function dialAllowed(host) {
  for (const [re, label] of ALLOW) if (re.test(host)) return { ok: true, range: label };
  return { ok: false, range: null };
}

/**
 * Length-prefixed frame reader. Refuses oversize before allocating anything.
 *
 * `stop()` matters more than it looks. TCP coalesces, so the last handshake message and
 * the first application frame routinely arrive in ONE chunk. Without a way to halt
 * mid-chunk, this loop would hand that application frame to the handshake — which is
 * finished — and the bytes would be consumed and discarded. Everything after that
 * decrypts one counter out of step, which surfaces as an AEAD failure that looks like
 * a crypto bug and is really a buffer-handoff bug. `rest` is what a stopped reader
 * still holds, so the next owner of the socket can pick up exactly where this one left off.
 */
export class FrameReader {
  constructor(onFrame, onError) {
    this.buf = Buffer.alloc(0);
    this.onFrame = onFrame;
    this.onError = onError;
    this.stopped = false;
  }
  stop() { this.stopped = true; }
  get rest() { return this.buf; }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.stopped) return;
      if (this.buf.length < 4) return;
      const len = this.buf.readUInt32LE(0);
      if (len > MAX_FRAME) return this.onError(new Error(`oversize frame ${len}`));
      if (this.buf.length < 4 + len) return;
      const frame = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      this.onFrame(frame);
    }
  }
}

export function frame(payload) {
  const h = Buffer.alloc(4);
  h.writeUInt32LE(payload.length);
  return Buffer.concat([h, payload]);
}

/**
 * A live hypha. Wraps the socket; every application frame is AEAD-sealed with the
 * per-direction key and counter derived by the handshake.
 */
export class Hypha extends EventEmitter {
  constructor(socket, cipher, peerId, meta = {}, carryover = null) {
    super();
    this.socket = socket;
    this.cipher = cipher;
    this.peerId = peerId;
    this.meta = meta;
    // Bytes the handshake reader had already pulled off the socket but did not own.
    // Held, not replayed: replaying now would emit 'message' before anybody is listening.
    this.carryover = carryover && carryover.length ? Buffer.from(carryover) : null;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.framesIn = 0;
    this.framesOut = 0;
    this.closed = false;

    this.reader = new FrameReader(
      (f) => this.#onFrame(f),
      (e) => this.close(e.message),
    );
    socket.on('data', (c) => {
      this.bytesIn += c.length;
      this.reader.push(c);
    });
    socket.on('error', (e) => this.close(e.message));
    socket.on('close', () => this.close('socket_closed'));
  }

  get sas() { return this.cipher.sas; }
  get hyphaId() { return this.cipher.hyphaId; }

  /**
   * Start delivering. Called once, by the manager, after every listener is attached.
   *
   * The socket is handed over paused precisely so this can be ordered correctly: frames
   * that arrive between the end of the handshake and the manager wiring up its handlers
   * would otherwise be emitted to nobody and lost without trace.
   */
  resume() {
    const carry = this.carryover;
    this.carryover = null;
    if (carry) this.reader.push(carry);
    if (!this.closed) this.socket.resume();
  }

  #ad() {
    // cleartext associated data: 0x53 | epoch | reserved | seq_lo.
    // seq_lo is DIAGNOSTIC ONLY — the nonce is always the local counter, never the wire
    // value, so a lying peer cannot steer our nonce. A mismatch kills the hypha.
    const ad = Buffer.alloc(8);
    ad.writeUInt8(0x53, 0);
    ad.writeUInt8(0, 1);
    ad.writeUInt16LE(0, 2);
    ad.writeUInt32LE(Number(this.cipher.sendN & 0xffffffffn), 4);
    return ad;
  }

  send(payload) {
    if (this.closed) throw new Error('hypha closed');
    const ad = this.#ad();
    const ct = this.cipher.encrypt(ad, payload);
    const out = frame(Buffer.concat([ad, ct]));
    this.socket.write(out);
    this.bytesOut += out.length;
    this.framesOut++;
    this.emit('sent', { bytes: out.length });
  }

  #onFrame(f) {
    if (f.length < 8) return this.close('short_frame');
    const ad = f.subarray(0, 8);
    try {
      const pt = this.cipher.decrypt(ad, f.subarray(8));
      this.framesIn++;
      this.emit('message', pt);
    } catch (e) {
      // Noise's rule: any AEAD failure is fatal. No retries, no tolerance.
      this.close(e instanceof NoiseError ? e.code : 'aead_fail');
    }
  }

  close(reason = 'local') {
    if (this.closed) return;
    this.closed = true;
    try { this.socket.destroy(); } catch {}
    this.emit('close', { reason });
  }
}

/** Pump a Noise handshake over a socket, reporting real progress as it advances. */
function runHandshake(socket, hs, telemetry, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!err) {
        // Stop consuming, then stop the flow. Both are required: stop() keeps this reader
        // from eating an application frame that shared a TCP segment with the last
        // handshake message, and pause() keeps the socket from emitting to nobody during
        // the await between here and the hypha being wired up.
        reader.stop();
        socket.pause();
      }
      socket.removeListener('data', onData);
      err ? reject(err) : resolve(val);
    };
    const timer = setTimeout(() => {
      telemetry?.count('hypha.handshake.failed.timeout');
      finish(new NoiseError('timeout'));
    }, timeoutMs);

    const report = () => {
      // This is the number the UI grows a hypha on. It is the real state machine
      // position, not an animation clock.
      telemetry?.event('hypha.handshake.progress', {
        peer: socket.remoteAddress,
        progress: hs.progress,
        step: hs.step,
      });
    };

    const reader = new FrameReader(
      (f) => {
        try {
          hs.readMessage(f);
          report();
          if (hs.done) return finish(null, { cipher: hs.finish(), carryover: reader.rest });
          socket.write(frame(hs.writeMessage()));
          report();
          if (hs.done) return finish(null, { cipher: hs.finish(), carryover: reader.rest });
        } catch (e) {
          telemetry?.count(`hypha.handshake.failed.${e.code || 'error'}`);
          finish(e);
        }
      },
      (e) => finish(e),
    );
    const onData = (c) => reader.push(c);
    socket.on('data', onData);
    socket.once('error', (e) => finish(e));
    socket.once('close', () => finish(new NoiseError('closed_during_handshake')));

    if (hs.initiator) {
      try {
        socket.write(frame(hs.writeMessage()));
        report();
      } catch (e) {
        finish(e);
      }
    }
  });
}

/**
 * Listens for inbound hyphae and dials outbound ones.
 *
 * Simultaneous-dial dedup, decided with no round trip: both sides know both spore_ids
 * from the HELLO, so the side with the numerically lower id dials. If the race happens
 * anyway, both independently keep the link whose initiator has the lower id and close
 * the other. Same two facts, same answer, no negotiation.
 */
export class HyphaManager extends EventEmitter {
  constructor({ sporeId, staticKeys, idPublicRaw, idPrivate, telemetry = null, port = HYPHA_PORT }) {
    super();
    this.sporeId = sporeId;
    this.staticKeys = staticKeys;
    this.idPublicRaw = idPublicRaw;
    this.idPrivate = idPrivate;
    this.tel = telemetry;
    this.port = port;
    this.server = null;
    this.hyphae = new Map();
    this.dialing = new Set();
    // Every socket we own, including ones still mid-handshake and ones whose handshake
    // failed. `hyphae` holds only the connections that made it; shutdown has to account
    // for the ones that did not. See stop().
    this.sockets = new Set();
    this.stopping = false;
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this.#inbound(socket));
      this.server.on('error', reject);
      this.server.listen(this.port, () => {
        this.tel?.event('hypha.listening', { port: this.port });
        resolve(this.port);
      });
    });
  }

  /** We dial only if our spore_id sorts lower. Deterministic, no clock, no negotiation. */
  shouldDial(peerId) {
    return Buffer.compare(this.sporeId, peerId) < 0;
  }

  #track(socket) {
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
  }

  async #inbound(socket) {
    if (this.stopping) return socket.destroy();
    socket.setNoDelay(true);
    this.#track(socket);
    this.tel?.count('hypha.inbound');
    const hs = new Handshake({
      initiator: false,
      staticKeys: this.staticKeys,
      idPublicRaw: this.idPublicRaw,
      idPrivate: this.idPrivate,
    });
    try {
      const { cipher, carryover } = await runHandshake(socket, hs, this.tel);
      this.#adopt(new Hypha(socket, cipher, hs.peerId, { initiator: false }, carryover));
    } catch (e) {
      this.tel?.event('hypha.handshake.failed', { reason: e.code || e.message, initiator: false });
      try { socket.destroy(); } catch {}
    }
  }

  async dial(peer) {
    const key = peer.sporeId.toString('hex');
    if (this.hyphae.has(key) || this.dialing.has(key)) return null;

    const host = peer.addrs?.[0] || peer.from;
    const gate = dialAllowed(host);
    if (!gate.ok) {
      this.tel?.count('tp.dial_refused_public');
      this.tel?.event('hypha.dial_refused', { host, why: 'outside_lan_allowlist' });
      return null;
    }

    this.dialing.add(key);
    this.tel?.event('hypha.dialing', { host, port: peer.tcpPort, range: gate.range });
    try {
      const socket = await new Promise((res, rej) => {
        const s = net.connect({ host, port: peer.tcpPort || this.port }, () => res(s));
        s.once('error', rej);
        s.setTimeout(6000, () => rej(new Error('connect_timeout')));
      });
      socket.setNoDelay(true);
      socket.setTimeout(0);
      this.#track(socket);

      const hs = new Handshake({
        initiator: true,
        staticKeys: this.staticKeys,
        idPublicRaw: this.idPublicRaw,
        idPrivate: this.idPrivate,
      });
      const { cipher, carryover } = await runHandshake(socket, hs, this.tel);
      return this.#adopt(new Hypha(socket, cipher, hs.peerId, { initiator: true, host }, carryover));
    } catch (e) {
      this.tel?.event('hypha.dial_failed', { host, reason: e.code || e.message });
      return null;
    } finally {
      this.dialing.delete(key);
    }
  }

  #adopt(hypha) {
    const key = Buffer.from(hypha.peerId).toString('hex');
    const existing = this.hyphae.get(key);
    if (existing) {
      // The race happened. Both sides compute the same answer from the same two facts.
      const keepNew = Buffer.compare(
        hypha.meta.initiator ? this.sporeId : hypha.peerId,
        existing.meta.initiator ? this.sporeId : existing.peerId,
      ) < 0;
      this.tel?.count('hypha.dup_resolved');
      if (keepNew) existing.close('dup_hypha');
      else { hypha.close('dup_hypha'); return existing; }
    }

    this.hyphae.set(key, hypha);
    this.tel?.gauge('hypha.live', this.hyphae.size);
    this.tel?.event('hypha.established', {
      peerId: hypha.peerId,
      sas: hypha.sas,
      initiator: hypha.meta.initiator,
    });

    hypha.on('close', ({ reason }) => {
      if (this.hyphae.get(key) === hypha) {
        this.hyphae.delete(key);
        this.tel?.gauge('hypha.live', this.hyphae.size);
        this.tel?.event('hypha.withered', { peerId: hypha.peerId, reason });
      }
    });
    hypha.on('message', (m) => this.emit('message', { hypha, payload: m }));
    this.emit('hypha', hypha);
    hypha.resume(); // last: every listener above is attached, nothing can be dropped now
    return hypha;
  }

  broadcast(payload) {
    let n = 0;
    for (const h of this.hyphae.values()) {
      try { h.send(payload); n++; } catch {}
    }
    return n;
  }

  /**
   * Shut down deterministically.
   *
   * `server.close()` does NOT close connections — it stops accepting and then waits for
   * every existing one to end on its own. So closing the hyphae is not enough: a socket
   * that is still mid-handshake, or whose handshake failed, is not in `hyphae` and nothing
   * would ever close it, and the callback never fires. That is a process that will not
   * exit — on a laptop an annoyance, on a phone a background task the OS kills for you
   * later and blames you for.
   *
   * So: refuse new arrivals, close the hyphae, destroy whatever sockets remain, and only
   * then wait for the server. By that point there is nothing left to wait for.
   */
  async stop() {
    this.stopping = true;
    for (const h of this.hyphae.values()) h.close('shutdown');
    this.hyphae.clear();
    for (const s of this.sockets) {
      try { s.destroy(); } catch { /* already gone */ }
    }
    this.sockets.clear();
    if (this.server) await new Promise((r) => this.server.close(() => r()));
    this.server = null;
  }
}
