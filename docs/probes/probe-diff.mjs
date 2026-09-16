// PROBE: does differential dirty-cell rendering kill the 576 KB/s problem?
const W=100,H=26,SW=W*2,SH=H*4;
const DOT=[[0x01,0x02,0x04,0x40],[0x08,0x10,0x20,0x80]];

class Canvas{
  constructor(w,h){this.w=w;this.h=h;
    this.cells=new Uint8Array(w*h); this.col=new Uint32Array(w*h);
    this.pCells=new Uint8Array(w*h); this.pCol=new Uint32Array(w*h); this.first=true;}
  clear(){this.cells.fill(0);this.col.fill(0);}
  plot(x,y,c){x=Math.round(x);y=Math.round(y);
    if(x<0||y<0||x>=this.w*2||y>=this.h*4)return;
    const i=(y>>2)*this.w+(x>>1); this.cells[i]|=DOT[x&1][y&3]; this.col[i]=c;}

  full(){ let o='',lc=-1;
    for(let r=0;r<this.h;r++){ o+=`\x1b[${r+1};1H`;
      for(let c=0;c<this.w;c++){ const i=r*this.w+c,b=this.cells[i];
        if(!b){ if(lc!==-2){o+='\x1b[0m';lc=-2;} o+=' '; continue; }
        if(this.col[i]!==lc){ const v=this.col[i]; o+=`\x1b[38;2;${(v>>16)&255};${(v>>8)&255};${v&255}m`; lc=this.col[i]; }
        o+=String.fromCharCode(0x2800+b);}}
    return o+'\x1b[0m'; }

  // emit ONLY changed cells, coalescing adjacent runs and reusing the active SGR colour
  diff(){ let o='\x1b[?2026h', lc=-1, cx=-1, cy=-1;   // synchronized output on
    for(let r=0;r<this.h;r++){
      for(let c=0;c<this.w;c++){ const i=r*this.w+c;
        if(!this.first && this.cells[i]===this.pCells[i] && this.col[i]===this.pCol[i]) continue;
        if(cy!==r||cx!==c){ o+=`\x1b[${r+1};${c+1}H`; cy=r; cx=c; }
        const b=this.cells[i];
        if(!b){ if(lc!==-2){o+='\x1b[0m';lc=-2;} o+=' '; }
        else { if(this.col[i]!==lc){ const v=this.col[i]; o+=`\x1b[38;2;${(v>>16)&255};${(v>>8)&255};${v&255}m`; lc=this.col[i]; }
               o+=String.fromCharCode(0x2800+b); }
        cx++; } }
    this.pCells.set(this.cells); this.pCol.set(this.col); this.first=false;
    return o+'\x1b[0m\x1b[?2026l'; }
}

const ATTRACT=140,KILL=6,INFLUENCE=34,STEP=2.2;
let attractors=[],nodes=[];
function seed(){attractors=[];nodes=[];
  for(let i=0;i<ATTRACT;i++){const a=(i*2.399963)%(Math.PI*2),r=18+(i/ATTRACT)*Math.min(SW,SH)*0.46;
    attractors.push({x:SW/2+Math.cos(a)*r*1.9,y:SH/2+Math.sin(a)*r,dead:false});}
  nodes.push({x:SW/2,y:SH/2,parent:-1,gen:0});}
function grow(){const pull=new Map();
  for(const a of attractors){if(a.dead)continue;let best=-1,bd=1e9;
    for(let i=0;i<nodes.length;i++){const d=Math.hypot(nodes[i].x-a.x,nodes[i].y-a.y);
      if(d<KILL){a.dead=true;best=-1;break;} if(d<INFLUENCE&&d<bd){bd=d;best=i;}}
    if(best>=0){const p=pull.get(best)||{x:0,y:0,n:0};const d=Math.hypot(nodes[best].x-a.x,nodes[best].y-a.y);
      p.x+=(a.x-nodes[best].x)/d;p.y+=(a.y-nodes[best].y)/d;p.n++;pull.set(best,p);}}
  let added=0;
  for(const [i,p] of pull){const m=Math.hypot(p.x,p.y)||1;
    nodes.push({x:nodes[i].x+(p.x/m)*STEP,y:nodes[i].y+(p.y/m)*STEP,parent:i,gen:nodes[i].gen+1});added++;}
  return added;}
const lerp=(a,b,t)=>Math.round(a+(b-a)*t);
const tipColor=t=>(lerp(10,255,t)<<16)|(lerp(220,60,t)<<8)|lerp(200,230,t);

const cv=new Canvas(W,H);
function paint(){cv.clear();const mg=nodes.reduce((m,n)=>Math.max(m,n.gen),1);
  for(const n of nodes){if(n.parent<0)continue;const p=nodes[n.parent];
    const c=tipColor(n.gen/mg),s=Math.ceil(Math.hypot(n.x-p.x,n.y-p.y));
    for(let k=0;k<=s;k++)cv.plot(p.x+(n.x-p.x)*k/s,p.y+(n.y-p.y)*k/s,c);}}

seed();
let fullB=0,diffB=0,frames=0,tDiff=0,alive=true;
while(alive&&frames<220){
  const added=grow(); paint();
  fullB+=cv.full().length;
  const a=process.hrtime.bigint(); diffB+=cv.diff().length; tDiff+=Number(process.hrtime.bigint()-a)/1e6;
  frames++; if(added===0&&frames>10)alive=false;
}
const f=n=>n.toLocaleString();
console.log(`frames                ${frames}   nodes ${f(nodes.length)}
full  repaint         ${f(Math.round(fullB/frames))} B/frame -> ${(fullB/frames*60/1024).toFixed(0)} KB/s @60fps
diff  repaint         ${f(Math.round(diffB/frames))} B/frame -> ${(diffB/frames*60/1024).toFixed(0)} KB/s @60fps
reduction             ${(fullB/diffB).toFixed(1)}x smaller
diff cost             ${(tDiff/frames).toFixed(3)} ms/frame
VERDICT               ${(diffB/frames*60/1024)<100?'PASS - comfortably under 100 KB/s, works over SSH':'still heavy'}`);
