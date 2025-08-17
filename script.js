// Mobile drawer with scroll lock
const navToggle = document.querySelector('.nav-toggle');
const navDrawer = document.getElementById('nav-drawer');
if (navToggle && navDrawer) {
  navToggle.addEventListener('click', () => {
    const open = navDrawer.classList.toggle('open');
    navDrawer.setAttribute('aria-hidden', open ? 'false' : 'true');
    navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    document.body.classList.toggle('no-scroll', open);
  });
  navDrawer.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
    navDrawer.classList.remove('open');
    navDrawer.setAttribute('aria-hidden','true');
    navToggle.setAttribute('aria-expanded','false');
    document.body.classList.remove('no-scroll');
  }));
}

// Canvas sizing helper (covers full hero)
function fitCanvas(canvas){
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  const w = Math.floor(rect.width);
  const h = Math.floor(rect.height);
  if (!w || !h) return false;
  if (canvas.width !== w*dpr || canvas.height !== h*dpr){
    canvas.width = w*dpr; canvas.height = h*dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr,0,0,dpr,0,0);
  }
  return { width: w, height: h };
}

const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// Grain (static)
function setupGrain(){
  const canvas = document.getElementById('grain');
  if (!canvas) return;
  function draw(){
    const sized = fitCanvas(canvas); if (!sized){ requestAnimationFrame(draw); return; }
    const ctx = canvas.getContext('2d');
    const { width:w, height:h } = sized;
    ctx.clearRect(0,0,w,h);
    const count = Math.floor((w*h)/22000);
    for (let i=0;i<count;i++){
      const x = Math.random()*w, y = Math.random()*h, a = Math.random()*0.08;
      ctx.fillStyle = `rgba(255,255,255,${a})`;
      ctx.fillRect(x,y,1,1);
    }
  }
  draw();
  window.addEventListener('resize', () => requestAnimationFrame(draw));
}

// Waves (animated)
function setupWaves(){
  const canvas = document.getElementById('waves');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let t = 0, rafId = null;

  function line(y0, amp, freq, speed, alpha, w){
    ctx.beginPath();
    for(let x=0;x<=w;x+=6){
      const y = y0 + Math.sin((x*freq)+t*speed)*amp;
      x===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    }
    ctx.strokeStyle = `rgba(120,255,180,${alpha})`;
    ctx.lineWidth = 1; ctx.stroke();
  }

  function frame(){
    const sized = fitCanvas(canvas); if (!sized){ rafId = requestAnimationFrame(frame); return; }
    const { width:w, height:h } = sized;
    ctx.clearRect(0,0,w,h);
    ctx.globalCompositeOperation='lighter';
    const base = Math.min(h*0.78, h-40);
    const amp = Math.max(12, Math.min(28, h*0.05));
    line(base-10, amp*0.7, 0.015, 0.8, 0.14, w);
    line(base,     amp,     0.012, 0.7, 0.12, w);
    line(base+12,  amp*1.1, 0.010, 0.6, 0.10, w);
    ctx.globalCompositeOperation='source-over';
    t += 0.02;
    rafId = requestAnimationFrame(frame);
  }

  function start(){ if (!prefersReduced && !rafId){ frame(); } }
  function stop(){ if (rafId){ cancelAnimationFrame(rafId); rafId = null; } }

  start();
  document.addEventListener('visibilitychange', () => document.hidden ? stop() : start());
  window.addEventListener('resize', () => { /* next frame fits size */ });
}

window.addEventListener('load', () => {
  requestAnimationFrame(() => {
    setupGrain();
    setupWaves();
  });
});

// Copy command
const copyBtn = document.getElementById('copy-cmd');
const cmdEl = document.getElementById('cmd');
if (copyBtn && cmdEl) {
  copyBtn.addEventListener('click', async () => {
    const text = cmdEl.innerText.trim();
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => copyBtn.textContent = 'Copy', 1400);
    } catch {
      const r = document.createRange();
      r.selectNode(cmdEl);
      const s = window.getSelection();
      s.removeAllRanges(); s.addRange(r);
      document.execCommand('copy'); s.removeAllRanges();
      copyBtn.textContent = 'Copied!';
      setTimeout(() => copyBtn.textContent = 'Copy', 1400);
    }
  });
}

// Basic modals open/close
function byId(id){return document.getElementById(id)}
[['open-terms','terms-modal'],['open-privacy','privacy-modal'],['open-terms-inline','terms-modal'],['open-privacy-inline','privacy-modal']]
.forEach(([aId,mId])=>{
  const a = byId(aId), m = byId(mId);
  a?.addEventListener('click', e => { e.preventDefault(); m?.classList.add('show'); });
});
document.querySelectorAll('.modal-close').forEach(btn=>{
  btn.addEventListener('click', e=>{
    const id = e.currentTarget.getAttribute('data-close');
    byId(id)?.classList.remove('show');
  });
});
document.querySelectorAll('.modal').forEach(m=>{
  m.addEventListener('click', e => { if (e.target === m) m.classList.remove('show'); });
});
