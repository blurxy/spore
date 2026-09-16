// BEACON — off-web peer discovery. No bootstrap nodes, no DHT, no signalling server.
//
// A spore shouts "SPOR" into a link-local multicast group and listens for shouts back.
// That is the entire discovery mechanism, and it is why a phone hotspot with no uplink
// is a complete SPORE network.
//
// Two findings from docs/probes/FINDINGS.md are load-bearing here:
//
//   1. On Windows, addMembership(group, ifaceAddr) throws EINVAL on some adapters while
//      the default-interface join succeeds and carries the traffic fine. A spore that
//      treats a per-interface join failure as fatal does not start. So: join the default
//      first, then attempt each interface, and tolerate failures.
//
//   2. A Tailscale adapter was present during probing and joined multicast happily.
//      That is an off-web violation with a friendly face — a tunnel interface will carry
//      a hypha over the public internet while every address-range check still passes.
//      ARCHITECTURE.md 1.3: gate by interface CLASS at bind time, not by address range.

import dgram from 'node:dgram';
import os from 'node:os';
import { createHash, randomBytes, sign as edSign, verify as edVerify } from 'node:crypto';
import { edPub } from '../session/noise.js';

export const GROUP = '239.42.66.7';
export const PORT = 47474;
export const HYPHA_PORT = 47475;
export const MAGIC = Buffer.from('SPOR', 'ascii');
export const WIRE_VERSION = 1;
export const MAX_HELLO = 1200; // never fragment on a 1280-byte-MTU path

export const TYPE = { HELLO: 0x01, HELLO_ACK: 0x02, BYE: 0x03 };
export const FLAG = {
  DIALABLE_LAN: 1 << 0,
  HAS_BLE: 1 << 1,
  HAS_AWARE: 1 << 2,
  RELAY_WILLING: 1 << 3,
  GRACEFUL_BYE: 1 << 4,
};

// Interfaces whose traffic may leave the local segment. Refusing to bind these is what
// makes "off-web" a property of the code rather than a promise in a comment.
const TUNNEL_RE = /^(tun|tap|utun|wg|tailscale|zt|ppp|nordlynx|proton|ipsec|gpd|awdl|llw)/i;

/** Classify an interface. Only 'lan' is ever bound or dialed. */
export function classify(name, addr) {
  if (TUNNEL_RE.test(name)) return 'tunnel';
  if (addr.internal) return 'loopback';
  // Tailscale hands out 100.64/10 (CGNAT). ARCHITECTURE 1.3 drops that range from the
  // allowlist outright: belt and braces alongside the name check above.
  if (addr.family === 'IPv4' && /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(addr.address)) {
    return 'tunnel';
  }
  return 'lan';
}

/** Every LAN-class IPv4 interface, tunnels and loopbacks excluded. */
export function lanInterfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4') continue;
      const cls = classify(name, a);
      if (cls === 'lan') out.push({ name, address: a.address, netmask: a.netmask, cls });
    }
  }
  return out;
}

/** Subnet-directed broadcast for an interface: rescues APs that black-hole 239/8. */
export function broadcastFor({ address, netmask }) {
  const a = address.split('.').map(Number);
  const m = netmask.split('.').map(Number);
  return a.map((o, i) => (o & m[i]) | (~m[i] & 255)).join('.');
}

const PROOF_LEN = 8;
const SIG_LEN = 64;

/**
 * Encode a HELLO datagram.
 *
 * boot_id is RANDOM, not milliseconds since epoch as the original transport design had
 * it. ARCHITECTURE.md 1.2: off-web means no NTP, so a wall-clock boot_id is both a
 * clock dependency and a gratuitous privacy leak of when the device started. Random
 * 8 bytes serves the only real purpose — distinguishing this boot from the last one.
 */
export function encodeHello({
  type = TYPE.HELLO, flags = FLAG.DIALABLE_LAN, sporeId, bootId, announceSeq = 0,
  tcpPort = HYPHA_PORT, addrs = [], colonyFilter = Buffer.alloc(0), nick = '',
  capabilities = 0, networkKey, idPrivate,
}) {
  const nickBuf = Buffer.from(String(nick).slice(0, 32), 'utf8');
  const addrBytes = [];
  for (const a of addrs) {
    const parts = a.split('.').map(Number);
    addrBytes.push(Buffer.from([4, 24, ...parts]));
  }
  const addrsBuf = Buffer.concat(addrBytes);

  const len = 55 + addrsBuf.length + 2 + colonyFilter.length + 1 + nickBuf.length + 2 + PROOF_LEN + SIG_LEN;
  if (len > MAX_HELLO) throw new Error(`HELLO ${len} exceeds ${MAX_HELLO}`);
  const b = Buffer.alloc(len);

  MAGIC.copy(b, 0);
  b.writeUInt8(WIRE_VERSION, 4);
  b.writeUInt8(type, 5);
  b.writeUInt16LE(flags, 6);
  sporeId.copy(b, 8);
  bootId.copy(b, 40);
  b.writeUInt32LE(announceSeq, 48);
  b.writeUInt16LE(tcpPort, 52);
  b.writeUInt8(addrs.length, 54);
  let o = 55;
  addrsBuf.copy(b, o);
  o += addrsBuf.length;
  b.writeUInt16LE(colonyFilter.length, o);
  o += 2;
  colonyFilter.copy(b, o);
  o += colonyFilter.length;
  b.writeUInt8(nickBuf.length, o);
  o += 1;
  nickBuf.copy(b, o);
  o += nickBuf.length;
  b.writeUInt16LE(capabilities, o);
  o += 2;

  // proof_tag: a cheap pre-signature gate so a flood of junk costs a hash, not a verify
  const proof = createHash('blake2b512')
    .update(networkKey)
    .update(b.subarray(0, o))
    .digest()
    .subarray(0, PROOF_LEN);
  proof.copy(b, o);
  o += PROOF_LEN;

  edSign(null, b.subarray(0, o), idPrivate).copy(b, o);
  return b;
}

/**
 * Staged validity gate, cheapest test first. A hostile LAN can send a lot of garbage;
 * we spend a signature verification only on datagrams that already look like ours.
 */
export function decodeHello(buf, networkKey) {
  if (buf.length < 55 + 2 + 1 + 2 + PROOF_LEN + SIG_LEN) return { ok: false, reason: 'too_short' };
  if (!buf.subarray(0, 4).equals(MAGIC)) return { ok: false, reason: 'bad_magic' };
  if (buf.readUInt8(4) !== WIRE_VERSION) return { ok: false, reason: 'bad_version' };

  const type = buf.readUInt8(5);
  if (type !== TYPE.HELLO && type !== TYPE.HELLO_ACK && type !== TYPE.BYE) {
    return { ok: false, reason: 'bad_type' };
  }

  const addrCount = buf.readUInt8(54);
  let o = 55;
  const addrs = [];
  for (let i = 0; i < addrCount; i++) {
    if (o + 2 > buf.length) return { ok: false, reason: 'truncated_addrs' };
    const fam = buf.readUInt8(o);
    const size = fam === 4 ? 4 : 16;
    if (o + 2 + size > buf.length) return { ok: false, reason: 'truncated_addrs' };
    if (fam === 4) addrs.push(Array.from(buf.subarray(o + 2, o + 6)).join('.'));
    o += 2 + size;
  }
  if (o + 2 > buf.length) return { ok: false, reason: 'truncated' };
  const cfLen = buf.readUInt16LE(o);
  o += 2;
  if (o + cfLen + 1 > buf.length) return { ok: false, reason: 'truncated' };
  const colonyFilter = buf.subarray(o, o + cfLen);
  o += cfLen;
  const nickLen = buf.readUInt8(o);
  o += 1;
  if (o + nickLen + 2 + PROOF_LEN + SIG_LEN > buf.length) return { ok: false, reason: 'truncated' };
  const nick = buf.subarray(o, o + nickLen).toString('utf8');
  o += nickLen;
  const capabilities = buf.readUInt16LE(o);
  o += 2;

  const proof = createHash('blake2b512')
    .update(networkKey)
    .update(buf.subarray(0, o))
    .digest()
    .subarray(0, PROOF_LEN);
  if (!proof.equals(buf.subarray(o, o + PROOF_LEN))) return { ok: false, reason: 'bad_proof_tag' };
  o += PROOF_LEN;

  if (o + SIG_LEN !== buf.length) return { ok: false, reason: 'length_mismatch' };
  const sporeId = buf.subarray(8, 40);
  let sigOk = false;
  try {
    sigOk = edVerify(null, buf.subarray(0, o), edPub(sporeId), buf.subarray(o));
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: 'bad_signature' };

  return {
    ok: true,
    hello: {
      type,
      flags: buf.readUInt16LE(6),
      sporeId,
      bootId: buf.subarray(40, 48),
      announceSeq: buf.readUInt32LE(48),
      tcpPort: buf.readUInt16LE(52),
      addrs,
      colonyFilter,
      nick,
      capabilities,
    },
  };
}

/**
 * The discovery loop. Emits 'peer' for each freshly-heard spore and 'bye' on departure.
 *
 * Eager burst at 0 / ~200ms / ~600ms mirrors mDNS announcing (RFC 6762 8.3) so cold
 * start feels instant, then settles to a slow Trickle so a room full of spores does not
 * become a packet storm.
 */
export class Beacon {
  constructor({ sporeId, idPrivate, networkKey, nick = '', telemetry = null, tcpPort = HYPHA_PORT }) {
    this.sporeId = sporeId;
    this.idPrivate = idPrivate;
    this.networkKey = networkKey;
    this.nick = nick;
    this.tel = telemetry;
    this.tcpPort = tcpPort;
    this.bootId = randomBytes(8); // random, never a timestamp — see encodeHello
    this.announceSeq = 0;
    this.peers = new Map();
    this.socket = null;
    this.joined = [];
    this.timers = [];
    this.handlers = { peer: [], bye: [], lost: [] };
    this.interval = 8000;
  }

  on(ev, fn) {
    (this.handlers[ev] ||= []).push(fn);
    return this;
  }

  #emit(ev, ...a) {
    for (const fn of this.handlers[ev] || []) fn(...a);
    if (this.tel) this.tel.event(`beacon.${ev}`, a[0]);
  }

  start() {
    const ifaces = lanInterfaces();
    this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    this.socket.on('message', (msg, rinfo) => this.#onMessage(msg, rinfo));
    this.socket.on('error', (e) => this.tel?.event('beacon.error', { message: e.message }));

    return new Promise((resolve) => {
      this.socket.bind(PORT, () => {
        this.socket.setMulticastTTL(1); // off-web enforced at the IP layer, not promised
        try { this.socket.setMulticastLoopback(true); } catch {}
        try { this.socket.setBroadcast(true); } catch {}

        // Default join first — probe finding 1: this is the one that reliably works.
        try {
          this.socket.addMembership(GROUP);
          this.joined.push('default');
        } catch (e) {
          this.tel?.event('beacon.join_failed', { iface: 'default', message: e.message });
        }
        // Then per-interface, tolerating failures rather than dying on them.
        for (const i of ifaces) {
          try {
            this.socket.addMembership(GROUP, i.address);
            this.joined.push(i.name);
          } catch (e) {
            this.tel?.event('beacon.join_failed', { iface: i.name, message: e.message });
          }
        }

        this.tel?.gauge('beacon.interfaces', ifaces.length);
        this.tel?.gauge('beacon.joined', this.joined.length);
        this.tel?.event('beacon.started', { joined: this.joined, interfaces: ifaces });

        for (const d of [0, 180 + Math.random() * 60, 540 + Math.random() * 120]) {
          this.timers.push(setTimeout(() => this.announce(), d));
        }
        this.timers.push(setInterval(() => this.announce(), this.interval));
        resolve(this);
      });
    });
  }

  announce(type = TYPE.HELLO, to = null) {
    if (!this.socket) return;
    const ifaces = lanInterfaces();
    const pkt = encodeHello({
      type,
      sporeId: this.sporeId,
      bootId: this.bootId,
      announceSeq: this.announceSeq++,
      tcpPort: this.tcpPort,
      addrs: ifaces.map((i) => i.address),
      nick: this.nick,
      networkKey: this.networkKey,
      idPrivate: this.idPrivate,
    });

    const send = (host, port = PORT) => this.socket.send(pkt, port, host, () => {});
    if (to) {
      send(to.address, to.port);
    } else {
      send(GROUP);
      // Hotspot APs rate-limit or black-hole multicast; broadcast rescues those cases.
      for (const i of ifaces) send(broadcastFor(i));
      send('255.255.255.255');
    }
    this.tel?.count('beacon.sent');
  }

  #onMessage(msg, rinfo) {
    this.tel?.count('beacon.rx');
    const r = decodeHello(msg, this.networkKey);
    if (!r.ok) {
      this.tel?.count(`beacon.reject.${r.reason}`);
      return;
    }
    const h = r.hello;
    if (h.sporeId.equals(this.sporeId)) return; // our own shout, echoed back

    const key = h.sporeId.toString('hex');
    if (h.type === TYPE.BYE) {
      if (this.peers.delete(key)) this.#emit('bye', { sporeId: h.sporeId, nick: h.nick });
      return;
    }

    const known = this.peers.get(key);
    const peer = {
      sporeId: h.sporeId,
      bootId: h.bootId,
      nick: h.nick,
      flags: h.flags,
      tcpPort: h.tcpPort,
      addrs: h.addrs.length ? h.addrs : [rinfo.address],
      from: rinfo.address,
      announceSeq: h.announceSeq,
      firstSeenMs: known?.firstSeenMs ?? (this.tel?.ms() ?? 0),
      lastSeenMs: this.tel?.ms() ?? 0,
    };
    const rebooted = known && !known.bootId.equals(h.bootId);
    this.peers.set(key, peer);
    this.tel?.gauge('beacon.peers', this.peers.size);

    if (!known || rebooted) {
      this.#emit('peer', peer);
      // mDNS known-answer trick: reply UNICAST after a short jitter, never multicast.
      // This is what stops N^2 storms when a group walks into a room together.
      if (h.type === TYPE.HELLO) {
        setTimeout(() => this.announce(TYPE.HELLO_ACK, rinfo), Math.random() * 100);
      }
    }
  }

  async stop() {
    for (const t of this.timers) { clearTimeout(t); clearInterval(t); }
    this.timers = [];
    if (this.socket) {
      try { this.announce(TYPE.BYE); } catch {}
      await new Promise((r) => setTimeout(r, 30));
      try { this.socket.close(); } catch {}
      this.socket = null;
    }
  }
}
