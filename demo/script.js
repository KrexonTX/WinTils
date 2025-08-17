// ========= Helpers =========
function norm(s){ return (s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase(); }
function byId(id){ return document.getElementById(id); }
function openPanel(id){ document.querySelector(`.nl[data-panel="${id}"]`)?.click(); }

// ========= Left-nav routing =========
document.querySelectorAll('.nl').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    document.querySelectorAll('.nl').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    const id = btn.dataset.panel;
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    byId(`panel-${id}`)?.classList.add('active');
    document.querySelector('.main')?.scrollTo({top:0, behavior:'smooth'});
    resetSearchUI(); // clear search highlights when switching panels
  });
});

// ========= Category-aware Search (yellow underline + text highlight) =========
const search = byId('search');
const searchClear = byId('search-clear');
const railSearch = byId('rail-search');
const railSearchClear = byId('rail-search-clear');

function clearHighlights(){
  document.querySelectorAll('.__hit').forEach(el=> el.classList.remove('__hit'));
  document.querySelectorAll('mark.hit').forEach(m=>{
    const t = document.createTextNode(m.textContent);
    m.parentNode.replaceChild(t, m);
    m.parentNode.normalize?.();
  });
}
function resetSearchUI(){
  clearHighlights();
  document.querySelectorAll('.nl.__hit').forEach(n=> n.classList.remove('__hit'));
}
function wrapMatches(root, query){
  if (!query) return;
  const q = norm(query);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(node=>{
    const txt = node.nodeValue;
    if (!txt || !txt.trim()) return;
    const n = norm(txt);
    const idx = n.indexOf(q);
    if (idx === -1) return;
    const span = document.createElement('span');
    const before = document.createTextNode(txt.slice(0, idx));
    const mark = document.createElement('mark'); mark.className='hit'; mark.textContent = txt.slice(idx, idx+query.length);
    const after = document.createTextNode(txt.slice(idx+query.length));
    span.append(before, mark, after);
    node.parentNode.replaceChild(span, node);
  });
}
function collectSearchables(){
  const items = [];
  document.querySelectorAll('.panel').forEach(panel=>{
    const panelId = panel.id.replace('panel-','');
    const categoryName = panel.dataset.category || panelId;

    panel.querySelectorAll('.card').forEach(card=>{
      const title = card.querySelector('.card-h h3, .card-h h4')?.textContent?.trim() || '';
      if (title) items.push({el:card, text:title, type:'card', panel:panelId, categoryName});
    });
    panel.querySelectorAll('.tline').forEach(line=>{
      const label = line.querySelector('span')?.textContent?.trim() || '';
      if (label) items.push({el:line, text:label, type:'toggle', panel:panelId, categoryName});
    });
    panel.querySelectorAll('.btn').forEach(btn=>{
      const t = btn.textContent.trim();
      if (!t) return;
      if (/^(Apply|Open|Run)$/i.test(t)) return;
      items.push({el:btn, text:t, type:'button', panel:panelId, categoryName});
    });
  });
  return items;
}
function runGlobalSearch(q){
  resetSearchUI();
  const s = norm(q);
  if (!s){ return; }

  const items = collectSearchables().filter(x=> norm(x.text).includes(s));
  if (!items.length) return;

  const panels = [...new Set(items.map(i=>i.panel))];
  if (panels.length===1) openPanel(panels[0]);

  items.forEach(i=>{
    i.el.classList.add('__hit');
    wrapMatches(i.el, q);
  });

  const hitPanels = new Set(items.map(i=>i.panel));
  document.querySelectorAll('.nl').forEach(nl=>{
    if (hitPanels.has(nl.dataset.panel)) nl.classList.add('__hit'); // yellow underline via CSS
  });

  items[0].el.scrollIntoView({block:'center', behavior:'smooth'});
}
search?.addEventListener('input', e=>{
  const v = e.target.value;
  searchClear?.classList.toggle('show', !!v);
  runGlobalSearch(v);
});
searchClear?.addEventListener('click', ()=>{
  search.value=''; search.focus();
  searchClear.classList.remove('show');
  resetSearchUI();
});
railSearch?.addEventListener('input', e=>{
  const v = e.target.value;
  railSearchClear?.classList.toggle('show', !!v);
  const active = document.querySelector('.tag.active')?.dataset.tag || 'all';
  renderThread(active, norm(v));
});
railSearchClear?.addEventListener('click', ()=>{
  railSearch.value=''; railSearch.focus();
  railSearchClear.classList.remove('show');
  const active = document.querySelector('.tag.active')?.dataset.tag || 'all';
  renderThread(active, '');
});

// ========= Quick panel jump buttons =========
document.querySelectorAll('[data-nav]').forEach(b=> b.addEventListener('click', ()=> openPanel(b.dataset.nav)));
byId('panel-overview')?.querySelector('[data-action="open-backup"]')?.addEventListener('click', ()=> openPanel('backup'));

// ========= Ongoing Tasks (with progress bars) =========
const tasks = [
  { name:'Create Backup', status:'Queued', date:'Today', owner:'System', progress:0 },
  { name:'Apply Privacy Preset', status:'In progress', date:'—', owner:'Admin', progress:45 },
  { name:'Optimize Startup', status:'Scheduled', date:'Tomorrow', owner:'System', progress:0 }
];
(function renderTasks(){
  const body = byId('tasks-body');
  if (!body) return;
  body.innerHTML = '';
  tasks.forEach(t=>{
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <span>${t.name}</span>
      <span>${t.status}</span>
      <span>${t.date}</span>
      <span>${t.owner}</span>
      <span><div class="progress"><i style="width:${t.progress}%"></i></div></span>
    `;
    body.appendChild(row);
  });
})();
document.querySelector('[data-action="view-all-tasks"]')?.addEventListener('click', ()=>{
  byId('tasks-body')?.scrollIntoView({behavior:'smooth', block:'start'});
});

// ========= Overview metrics (placeholder values) =========
const m = { cpu:'~92%', ram:'~7.8GB', disk:'~120GB', startup:'6', proc:'~135', gpu:'~12%' };
['cpu','ram','disk','startup','proc','gpu'].forEach(k=>{
  const el = byId(`m-${k}`); if (el) el.textContent = m[k];
});

// ========= Safety Checks (incl. Boot Loader Backup row) =========
(function renderSafetyChecks(){
  const root = byId('safety-checks'); if (!root) return;
  const rows = [
    { name:'Restore Point', status:'idle' },
    { name:'Registry Backup', status:'idle' },
    { name:'Policy Backup', status:'idle' },
    { name:'Boot Loader Backup', status:'idle' },
  ];
  root.innerHTML = '';
  rows.forEach(r=>{
    const tagClass = r.status==='done' ? 'ok' : r.status==='pending' ? 'warn' : 'idle';
    const el = document.createElement('div');
    el.className = 'check-row';
    el.innerHTML = `
      <span>${r.name}</span>
      <span class="kit-tag ${tagClass}">${labelForStatus(r.status)}</span>
    `;
    root.appendChild(el);
  });
})();
function labelForStatus(s){ return s==='done'?'Completed': s==='pending'?'Pending':'Not started'; }
function markSafetyCheck(name, status){
  const root = byId('safety-checks'); if (!root) return;
  [...root.querySelectorAll('.check-row')].forEach(row=>{
    if (row.firstElementChild?.textContent.trim() === name){
      const tag = row.querySelector('.kit-tag');
      tag.classList.remove('ok','warn','idle');
      const cls = status==='done'?'ok':status==='pending'?'warn':'idle';
      tag.classList.add(cls);
      tag.textContent = labelForStatus(status);
    }
  });
}

// ========= Right rail logs with relative time and clear =========
function relTime(ts){
  const s = Math.max(0, Math.floor((Date.now()-ts)/1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s/60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m/60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h/24);
  return `${d}d ago`;
}
let logs = [
  { module:'Settings', text:'Imported profile', ts: Date.now()-5*1000, tag:'system' },
  { module:'Settings', text:'Exported profile "Default Profile"', ts: Date.now()-60*1000, tag:'system' },
  { module:'Ops', text:'Startup apps scan complete', ts: Date.now()-12*60*1000, tag:'ops' },
  { module:'Privacy', text:'Privacy preset applied', ts: Date.now()-60*60*1000, tag:'system' },
  { module:'Backup', text:'Restore point created', ts: Date.now()-2*60*1000, tag:'system' }
];
function renderThread(filter='all', q=''){
  const thread = byId('thread'); if (!thread) return;
  thread.innerHTML='';
  logs.filter(m=> (filter==='all'||m.tag===filter) && norm(`${m.module} ${m.text}`).includes(q||'')) 
      .forEach(m=> appendLog(m));
}
function appendLog(entry){
  const thread = byId('thread'); if (!thread) return;
  const el = document.createElement('div'); el.className='msg';
  el.innerHTML = `
    <div class="meta">
      <div class="who"><div class="avatar">${entry.module.slice(0,2)}</div><strong>${entry.module}</strong></div>
      <span class="time" data-ts="${entry.ts}">${relTime(entry.ts)}</span>
    </div>
    <div class="text">${entry.text}</div>
  `;
  thread.prepend(el);
}
function logToRail(module, text){
  const entry = { module, text, ts: Date.now(), tag:'system' };
  logs.unshift(entry);
  appendLog(entry);
}
renderThread();
document.querySelectorAll('.tag').forEach(t=>{
  t.addEventListener('click', ()=>{
    document.querySelectorAll('.tag').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    const q = norm(railSearch?.value||'');
    renderThread(t.dataset.tag, q);
  });
});
setInterval(()=>{
  document.querySelectorAll('.msg .time').forEach(t=>{
    const ts = +t.dataset.ts; if (!ts) return;
    t.textContent = relTime(ts);
  });
}, 5000);
byId('clear-logs')?.addEventListener('click', ()=>{
  logs = [];
  renderThread(document.querySelector('.tag.active')?.dataset.tag || 'all', norm(railSearch?.value||'')); 
});

// ========= Personalization: App Removal list =========
const appRemoval = [
  { id:'xbox', name:'Xbox App' },
  { id:'copilot', name:'Copilot Hub' },
  { id:'3dviewer', name:'3D Viewer' },
  { id:'edge', name:'Remove Microsoft Edge' },
  { id:'onedrive', name:'Remove OneDrive' },
  { id:'yourphone', name:'Your Phone' },
];

// ========= Winget categories & data =========
const appsByCategory = {
  browser: [
    { id:'zen', name:'Zen Browser (Firefox base)', winget:'Zen-Team.Zen-Browser' },
    { id:'brave-ms', name:'Brave (Chromium)', winget:'XP8C9QZMS2PC1T' },
    { id:'ungoogled', name:'Ungoogled Chromium', winget:'eloston.ungoogled-chromium' },
    { id:'arc', name:'Arc Browser (Chromium)', winget:'XPFMDW72VHTTX9' },
  ],
  archive: [
    { id:'nanazip', name:'NanaZip', winget:'9n8g7tscl18r' },
    { id:'7zip', name:'7‑Zip', winget:'7zip.7zip' },
    { id:'winrar', name:'WinRAR', winget:'RARLab.WinRAR' },
  ],
  editor: [
    { id:'sublime4', name:'Sublime Text 4', winget:'SublimeHQ.SublimeText.4' },
    { id:'vscode', name:'VS Code', winget:'Microsoft.VisualStudioCode' },
  ],
  alt: [
    { id:'screenbox', name:'Screenbox (Video Player)', winget:'9ntsnmsvcb5l' },
    { id:'nilesoft', name:'Nilesoft Shell (Windows 11 Shell)', winget:'Nilesoft.Shell' },
    { id:'fluentweather', name:'FluentWeather (Weather)', winget:'9pfd136m8457' },
    { id:'modernflyouts', name:'ModernFlyouts (Preview) (Volume Flyouts)', winget:'9mt60qv066rp' },
    { id:'eartrumpet', name:'EarTrumpet (Volume Mixer)', winget:'9nblggh516xp' },
    { id:'unigetui', name:'UniGetUI (Microsoft Store)', winget:'xpfftq032ptphf' },
  ],
  tools: [
    { id:'vcredist', name:'VCRedist (AIO) — external link', winget:'' },
    { id:'nvcleanstall', name:'NVCleanstall — external link (see guide)', winget:'' },
    { id:'directx', name:'DirectX End‑User Runtime — external link', winget:'' },
    { id:'revo', name:'Revo Uninstaller — external link', winget:'' },
    { id:'portmaster', name:'PortMaster (Advanced) — external link', winget:'' },
  ]
};

function renderCompactList(targetId, items, withWinget=false){
  const cont = byId(targetId);
  if (!cont) return;
  cont.innerHTML = '';
  items.forEach(a=>{
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <span class="name">${a.name}</span>
      <input type="checkbox" class="toggle pick-app" data-id="${a.id}" ${withWinget && a.winget ?`title="${a.winget}"`:''}>
    `;
    cont.appendChild(row);
  });
}

function initWingetCategories(){
  renderCompactList('apps-browser', appsByCategory.browser, true);
  renderCompactList('apps-archive', appsByCategory.archive, true);
  renderCompactList('apps-editor', appsByCategory.editor, true);
  renderCompactList('apps-alt', appsByCategory.alt, true);
  renderCompactList('apps-tools', appsByCategory.tools, false);

  const tabs = document.querySelectorAll('#app-tabs .tab');
  tabs.forEach(tab=>{
    tab.addEventListener('click', ()=>{
      tabs.forEach(t=> t.classList.remove('active'));
      tab.classList.add('active');
      const key = tab.dataset.tab;
      document.querySelectorAll('.apps-compact.cat').forEach(c=> c.classList.remove('active'));
      byId(`apps-${key}`)?.classList.add('active');
    });
  });
}

// Initial render lists (Removal + Winget categories)
(function initPersonalization(){
  const appRemovalCont = byId('app-removal');
  if (appRemovalCont){
    appRemovalCont.innerHTML = '';
    appRemoval.forEach(a=>{
      const row = document.createElement('div');
      row.className = 'row';
      row.innerHTML = `
        <span class="name">${a.name}</span>
        <input type="checkbox" class="toggle pick-remove" data-id="${a.id}">
      `;
      appRemovalCont.appendChild(row);
    });
  }
  initWingetCategories();
})();

// ========= Updates segmented control =========
let updMode = 'security';
document.querySelectorAll('.seg-btn').forEach(b=>{
  b.addEventListener('click', ()=>{
    document.querySelectorAll('.seg-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); updMode = b.dataset.upd;
    logToRail('System',`Update mode set: ${updMode}`);
  });
});
const updRange = byId('upd-bandwidth');
const updVal = byId('upd-bandwidth-val');
updRange?.addEventListener('input', ()=>{ if (updVal) updVal.textContent = `${updRange.value}%`; });

// ========= Memory Compression expander =========
document.querySelectorAll('[data-expand]').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    const key = btn.dataset.expand;
    const body = byId(`${key}-desc`);
    const expanded = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!expanded));
    if (body){
      if (expanded){ body.classList.remove('open'); }
      else { body.classList.add('open'); }
    }
  });
});

// ========= Guide modal (NVCleanstall) =========
function openGuideModal(title, url){
  document.getElementById('__guide_modal')?.remove();
  const wrap = document.createElement('div');
  wrap.id='__guide_modal';
  wrap.style.cssText = `
    position:fixed; inset:0; background:rgba(0,0,0,.55);
    display:grid; place-items:center; z-index:9999;
  `;
  wrap.innerHTML = `
    <div style="width:min(960px,94vw); height:min(80vh,860px); background:rgba(16,20,22,.98); border:1px solid rgba(255,255,255,.12); border-radius:12px; box-shadow:0 20px 80px rgba(0,0,0,.6); display:grid; grid-template-rows:auto 1fr auto;">
      <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);">
        <strong style="font:700 16px Inter,system-ui">Guide • ${title}</strong>
        <div style="display:flex; gap:8px; align-items:center">
          <a href="${url}" target="_blank" rel="noopener" style="padding:6px 10px; border:1px solid rgba(255,255,255,.18); border-radius:8px; color:#cfe; text-decoration:none; background:rgba(255,255,255,.06)">Open in new tab</a>
          <button id="__guide_close" style="padding:6px 10px; border:1px solid rgba(255,255,255,.18); border-radius:8px; color:#fff; background:rgba(255,255,255,.08); cursor:pointer">Close</button>
        </div>
      </div>
      <iframe src="${url}" style="width:100%; height:100%; border:0; background:#0b0f10"></iframe>
      <div style="padding:8px 12px; border-top:1px solid rgba(255,255,255,.08); color:#b7c8bf; font:500 12px/1.4 Inter,system-ui;">
        Disclaimer: You are viewing external content. Review steps carefully before proceeding.
      </div>
    </div>
  `;
  document.body.appendChild(wrap);
  document.getElementById('__guide_close')?.addEventListener('click', ()=> wrap.remove());
}
document.addEventListener('click', e=>{
  const a = e.target.closest('[data-open-guide="nvclean"]');
  if (!a) return;
  e.preventDefault();
  openGuideModal('NVCleanstall', 'https://www.techpowerup.com/download/techpowerup-nvcleanstall/');
});

// ========= Export / Import profile =========
document.querySelectorAll('[data-action="export-profile"]').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    const currentName = byId('profile-name')?.textContent || 'Default Profile';
    const name = prompt('Profile name:', currentName) || currentName;
    const data = collectState();
    data.meta = { name, version: 'v1.0' };
    downloadJSON(`${name.replace(/\s+/g,'_')}.wintils.json`, data);
    setActiveProfileName(name);
    logToRail('Settings',`Exported profile "${name}"`);
  });
});
document.querySelectorAll('[data-action="import-profile"]').forEach(btn=>{
  btn.addEventListener('click', ()=> byId('profile-file')?.click());
});
byId('profile-file')?.addEventListener('change', async e=>{
  const f = e.target.files?.[0]; if (!f) return;
  try{
    const s = JSON.parse(await f.text());
    applyState(s);
    const name = (s.meta && s.meta.name) ? String(s.meta.name) : 'Custom Profile';
    const version = (s.meta && s.meta.version) ? String(s.meta.version) : 'v1.0';
    setActiveProfileName(name);
    selectProfile('custom', true);
    setCustomPillLabel(`${name} (${version})`);
    logToRail('Settings','Imported profile');
  }catch{
    logToRail('Settings','Invalid profile file');
  }finally{
    e.target.value = '';
  }
});
function setActiveProfileName(name){
  byId('profile-name')?.replaceChildren(document.createTextNode(name));
  byId('dash-active-profile')?.replaceChildren(document.createTextNode(name));
}

// ========= Profiles pill logic =========
const pillContainer = byId('profile-pills');
pillContainer?.addEventListener('click', e=>{
  const btn = e.target.closest('.pill-row');
  if (!btn) return;
  selectProfile(btn.dataset.profile, false);
});
function selectProfile(key, fromImport){
  if (!pillContainer) return;
  pillContainer.querySelectorAll('.pill-row').forEach(p=> p.classList.remove('selected'));
  const target = pillContainer.querySelector(`.pill-row[data-profile="${key}"]`);
  if (target){
    target.classList.add('selected');
    if (key==='custom'){
      target.classList.remove('dimmed');
    }else{
      const customPill = pillContainer.querySelector('.pill-row[data-profile="custom"]');
      if (customPill){
        customPill.classList.add('dimmed');
        setCustomPillLabel('Custom (import)');
      }
      const label = target.querySelector('.label')?.textContent || 'Profile';
      setActiveProfileName(`${label} Profile`);
    }
  }
}
function setCustomPillLabel(text){
  const pill = document.querySelector('.pill-row[data-profile="custom"] .label');
  if (pill) pill.textContent = text;
}

// ========= Bind actions =========
bind({
  // Backup
  'create-restore-point':()=> {
    logToRail('Backup','Restore point created');
    markSafetyCheck('Restore Point','done');
    markSafetyCheck('Registry Backup','pending');
  },
  'snapshot-config':()=> logToRail('Backup','Snapshot configuration saved'),
  'export-reg':()=> { logToRail('Backup','Registry keys exported'); markSafetyCheck('Registry Backup','done'); },
  'export-policies':()=> { logToRail('Backup','Policies exported'); markSafetyCheck('Policy Backup','done'); },
  'boot-backup':()=> { logToRail('Backup','Boot Loader Backup: bcdedit /export BCD.bkp'); markSafetyCheck('Boot Loader Backup','done'); },
  'boot-restore':()=> logToRail('Backup','Boot Loader Restore: bcdedit /import BCD.bkp'),
  'open-system-restore':()=> logToRail('Backup','Opened System Restore UI'),
  'run-custom-backup':()=> {
    const out = byId('backup-path')?.value || '(not set)';
    const picks = [...document.querySelectorAll('[data-backup]:checked')].map(i=>i.dataset.backup).join(', ') || 'none';
    const line = `Folder: ${out} | Items: [${picks}]`;
    byId('backup-output')?.replaceChildren(document.createTextNode(`Output: ${line}`));
    logToRail('Backup',`Custom backup -> ${line}`);
  },
  'apply-backup':()=> logToRail('Backup','Backup actions applied'),
  'apply-restore':()=> logToRail('Backup','Restore actions applied'),

  // Personalization
  'remove-selected':()=> {
    const ids = [...document.querySelectorAll('.pick-remove:checked')].map(i=>i.dataset.id);
    logToRail('Personalization',`Removed apps: ${ids.join(', ') || 'none'}`);
  },
  'install-selected':()=> {
    // Collect ALL checked picks across all categories
    const pickedIds = [...document.querySelectorAll('.apps-compact.cat .pick-app:checked')].map(i=>i.dataset.id);
    const all = Object.values(appsByCategory).flat();
    const tokens = all.filter(a=> pickedIds.includes(a.id)).map(a=>a.winget).filter(Boolean);
    logToRail('Personalization',`Install apps: ${tokens.length ? tokens.join(', ') : 'none'}`);
  },
  'apply-personalization':()=> {
    const s = [...document.querySelectorAll('[data-per]')].reduce((a,i)=>{a[i.dataset.per]=i.checked;return a;}, {});
    logToRail('Personalization',`Applied: ${Object.keys(s).filter(k=>s[k]).join(', ')||'none'}`);
  },

  // Optimization
  'apply-optimizations':()=> {
    const s = [...document.querySelectorAll('[data-opt]')].reduce((a,i)=>{a[i.dataset.opt]=i.checked;return a;}, {});
    logToRail('Optimization',`Applied: ${Object.keys(s).filter(k=>s[k]).join(', ')||'none'}`);
  },
  'adobe-debloat':()=> logToRail('Optimization','Adobe debloat executed'),

  // Privacy
  'apply-privacy':()=> {
    const picks = [...document.querySelectorAll('[data-priv], [data-telemetry]')].filter(i=>i.checked).length;
    logToRail('Privacy',`Privacy changes applied (${picks} toggles)`);
  },

  // System
  'apply-updates':()=> {
    const bw = +byId('upd-bandwidth')?.value || 25;
    const driver = document.querySelector('[data-upd="disable-driver-updates"]')?.checked;
    const restart = document.querySelector('[data-upd="disable-auto-restart"]')?.checked;
    const reserved = document.querySelector('[data-upd="disable-reserved-storage"]')?.checked;
    logToRail('System',`Mode=${updMode}; BW=${bw}%; DriverUpd=${!!driver}; AutoRestart=${!!restart}; ReservedStorage=${!!reserved}`);
  },
  'dism-check':()=> logToRail('System','DISM /CheckHealth started'),
  'dism-scan':()=> logToRail('System','DISM /ScanHealth started'),
  'dism-restore':()=> logToRail('System','DISM /RestoreHealth started'),
  'run-sfc':()=> logToRail('System','SFC /scannow started'),
  'wsreset':()=> logToRail('System','WSReset executed'),
  'run-chkdsk':()=> logToRail('System','CHKDSK scheduled (reboot required)'),
  'apply-repair':()=> logToRail('System','Repair actions applied'),

  'add-ultimate-power':()=> logToRail('System','Ultimate Power Plan added & set'),
  'rebuild-counters':()=> logToRail('System','Performance counters rebuilt'),
  'registry-tweaks-bundle':()=> logToRail('System','Registry Tweaks (bundle) applied'),
  'set-ntp':()=> logToRail('System','NTP server set to pool.ntp.org'),
  'set-utc':()=> logToRail('System','Time set to UTC (Dual Boot)'),
  'apply-power-tools':()=> logToRail('System','Power tools changes applied'),

  'open-startup-taskmgr':()=> logToRail('System','Opened Task Manager (Startup tab)'),
  'apply-startup-shutdown':()=> {
    const v = document.querySelector('[data-sys="verbose-shutdown"]')?.checked;
    logToRail('System',`Verbose shutdown/login=${!!v}`);
  },

  'apply-security':()=> {
    const net = document.querySelector('[data-sec="improve-network"]')?.checked;
    const cam = document.querySelector('[data-sec="disable-camera-lock"]')?.checked;
    logToRail('System',`Security -> Network=${!!net}; CameraLock=${!!cam}`);
  },

  // Settings
  'apply-settings':()=> {
    const s = { 
      dryRun: byId('dry-run')?.checked, 
      fullBackup: byId('full-backup')?.checked, 
      confirmRisky: byId('confirm-risky')?.checked 
    };
    logToRail('Settings',`Applied: ${JSON.stringify(s)}`);
  },
  'open-discord':()=> logToRail('Settings','Open Discord (link)'),
  'open-github':()=> logToRail('Settings','Open GitHub (link)'),
  'view-changelog':()=> logToRail('Settings','Opened full changelog'),
});
function bind(map){
  Object.entries(map).forEach(([k,fn])=>{
    document.querySelectorAll(`[data-action="${k}"]`).forEach(b=> b.addEventListener('click', fn));
  });
}

// ========= Download helper =========
function downloadJSON(filename, obj){
  const blob = new Blob([JSON.stringify(obj,null,2)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}

// ========= Minimal state for export/import =========
function collectState(){
  return { meta:{ name: byId('profile-name')?.textContent || 'Default Profile', version: 'v1.0' } };
}
function applyState(s){
  if (s?.meta?.name){
    setActiveProfileName(s.meta.name);
  }
}
