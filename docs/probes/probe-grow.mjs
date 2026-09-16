// PROBE: can a zero-dep ANSI terminal render real mycelial GROWTH at 60fps?
// Space colonization algorithm -> braille 2x4 subpixel canvas -> truecolour.
const W=100,H=26, SW=W*2, SH=H*4;           // subpixel resolution
const DOT=[[0x01,0x02,0x04,0x40],[0x08,0x10,0x20,0x80]];

class Braille{
  constructor(w,h){this.w=w;this.h=h;this.cells=new Uint8Array(w*h);this.col=new Uint32Array(w*h);}
  clear(){this.cells.fill(0);this.col.fill(0);}
  plot(x,y,c){ x=Math.round(x); y=Math.round(y);
    if(x<0||y<0||x>=this.w*2||y>=this.h*4)return;
    const i=(y>>2)*this.w+(x>>1);
    this.cells[i]|=DOT[x&1][y&3]; this.col[i]=c; }
  render(){ let out='',lastC=-1;
    for(let r=0;r<this.h;r++){ out+=`\x1b[${r+1};1H`;
      for(let c=0;c<this.w;c++){ const i=r*this.w+c,b=this.cells[i];
        if(!b){ if(lastC!==-2){out+='\x1b[0m';lastC=-2;} out+=' '; continue; }
        const col=this.col[i];
        if(col!==lastC){ out+=`\x1b[38;2;${(col>>16)&255};${(col>>8)&255};${col&255}m`; lastC=col; }
        out+=String.fromCharCode(0x2800+b); } }
    return out+'\x1b[0m'; }
}

// --- space colonization: hyphae growing toward nutrient attractors ---
const ATTRACT=140, KILL=6, INFLUENCE=34, STEP=2.2;
let attractors=[], nodes=[];
function seed(){
  attractors=[]; nodes=[];
  for(let i=0;i<ATTRACT;i++){ const a=(i*2.399963)%(Math.PI*2), r=18+ (i/ATTRACT)*Math.min(SW,SH)*0.46;
    attractors.push({x:SW/2+Math.cos(a)*r*1.9, y:SH/2+Math.sin(a)*r, dead:false}); }
  nodes.push({x:SW/2,y:SH/2,parent:-1,gen:0});
}
function grow(){
  const pull=new Map();
  for(const a of attractors){ if(a.dead)continue;
    let best=-1,bd=1e9;
    for(let i=0;i<nodes.length;i++){ const d=Math.hypot(nodes[i].x-a.x,nodes[i].y-a.y);
      if(d<KILL){a.dead=true;best=-1;break;} if(d<INFLUENCE&&d<bd){bd=d;best=i;} }
    if(best>=0){ const p=pull.get(best)||{x:0,y:0,n:0};
      const d=Math.hypot(nodes[best].x-a.x,nodes[best].y-a.y);
      p.x+=(a.x-nodes[best].x)/d; p.y+=(a.y-nodes[best].y)/d; p.n++; pull.set(best,p); } }
  let added=0;
  for(const [i,p] of pull){ const m=Math.hypot(p.x,p.y)||1;
    nodes.push({x:nodes[i].x+(p.x/m)*STEP, y:nodes[i].y+(p.y/m)*STEP, parent:i, gen:nodes[i].gen+1}); added++; }
  return added;
}
// bioluminescent ramp: deep cyan core -> magenta tips
const lerp=(a,b,t)=>Math.round(a+(b-a)*t);
function tipColor(t){ return (lerp(10,255,t)<<16)|(lerp(220,60,t)<<8)|lerp(200,230,t); }

const cv=new Braille(W,H);
function draw(){ cv.clear();
  const maxGen=nodes.reduce((m,n)=>Math.max(m,n.gen),1);
  for(const n of nodes){ if(n.parent<0)continue; const p=nodes[n.parent];
    const t=n.gen/maxGen, c=tipColor(t), steps=Math.ceil(Math.hypot(n.x-p.x,n.y-p.y));
    for(let s=0;s<=steps;s++) cv.plot(p.x+(n.x-p.x)*s/steps, p.y+(n.y-p.y)*s/steps, c); }
  return cv.render(); }

// ---- measure ----
seed();
let frames=0, totalGrow=0, totalDraw=0, bytes=0, alive=true;
const t0=process.hrtime.bigint();
while(alive && frames<220){
  const a=process.hrtime.bigint(); const added=grow(); const b=process.hrtime.bigint();
  const s=draw(); const c=process.hrtime.bigint();
  totalGrow+=Number(b-a)/1e6; totalDraw+=Number(c-b)/1e6; bytes+=s.length; frames++;
  if(added===0 && frames>10) alive=false;
}
const wall=Number(process.hrtime.bigint()-t0)/1e6;

// show the grown organism
console.log('\x1b[2J'+draw().replace(/\x1b\[\d+;1H/g,'\n')+'\x1b[0m');
console.log(`
nodes grown      ${nodes.length}
frames           ${frames}
grow  avg        ${(totalGrow/frames).toFixed(3)} ms/frame
draw  avg        ${(totalDraw/frames).toFixed(3)} ms/frame
total avg        ${((totalGrow+totalDraw)/frames).toFixed(3)} ms/frame   (budget 16.67)
bytes/frame      ${Math.round(bytes/frames)}  -> ${(bytes/frames*60/1024).toFixed(0)} KB/s at 60fps
headroom         ${(16.67/((totalGrow+totalDraw)/frames)).toFixed(1)}x
RESULT           ${((totalGrow+totalDraw)/frames)<16.67?'PASS':'FAIL'} - zero-dep braille growth at 60fps`);
