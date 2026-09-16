// PROBE: does zero-dep UDP multicast discovery actually work here?
// If this fails, SPORE's entire LAN discovery design needs rework.
import dgram from 'node:dgram';
import os from 'node:os';

const GROUP = '239.255.42.99', PORT = 47777;
const ifaces = Object.entries(os.networkInterfaces())
  .flatMap(([n, as]) => (as||[]).filter(a => a.family==='IPv4' && !a.internal).map(a => ({n, addr:a.address})));
console.log('candidate interfaces:', ifaces.map(i=>`${i.n}=${i.addr}`).join(' ') || '(none)');

const got = [];
const rx = dgram.createSocket({ type:'udp4', reuseAddr:true });
rx.on('message', (m, rinfo) => got.push({ msg:m.toString(), from:`${rinfo.address}:${rinfo.port}` }));
rx.bind(PORT, () => {
  try { rx.addMembership(GROUP); console.log('joined group on default iface'); } catch(e){ console.log('default join FAILED:', e.message); }
  for (const i of ifaces) { try { rx.addMembership(GROUP, i.addr); console.log('joined via', i.n); } catch(e){ console.log('join via',i.n,'failed:',e.message); } }

  const tx = dgram.createSocket({ type:'udp4', reuseAddr:true });
  tx.bind(() => {
    tx.setMulticastTTL(4);
    try { tx.setMulticastLoopback(true); } catch {}
    const beacon = JSON.stringify({ p:'SPORE', v:1, id:'probe0', roles:'RVIFB' });
    let n = 0;
    const t = setInterval(() => { tx.send(beacon, PORT, GROUP); if(++n>=3) clearInterval(t); }, 120);
  });

  setTimeout(() => {
    console.log('\nBEACONS RECEIVED:', got.length);
    got.slice(0,3).forEach(g => console.log(' <-', g.from, g.msg));
    console.log(got.length ? '\nRESULT: PASS — multicast discovery is viable, zero deps.' : '\nRESULT: FAIL — need unicast-sweep fallback.');
    process.exit(0);
  }, 1200);
});
