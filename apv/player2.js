
  const params = new URLSearchParams(window.location.search);
 const batch_id   = params.get('batch_id');
const subject_id = params.get('subject_id');
const schedule_id = params.get('schedule_id');
const time = params.get('time');
const PW_HEADERS = {
    "Accept-Encoding": "gzip",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A707F Build/RP1A.200720.012)",
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODE3OTg1NTIuNjk5LCJkYXRhIjp7Il9pZCI6IjY1ZTA0MDBjYjllNmRjYjZhYTM0YjQxYSIsInVzZXJuYW1lIjoiOTM0MTc5Mzg5OSIsImZpcnN0TmFtZSI6IlByaXlhbnNodSIsImxhc3ROYW1lIjoiS3VtYXIgVXBhZGhheWF5Iiwib3JnYW5pemF0aW9uIjp7Il9pZCI6IjVlYjM5M2VlOTVmYWI3NDY4YTc5ZDE4OSIsIndlYnNpdGUiOiJwaHlzaWNzd2FsbGFoLmNvbSIsIm5hbWUiOiJQaHlzaWNzd2FsbGFoIn0sImVtYWlsIjoiYW51ai51cGFkaHlheTM2OUBnbWFpbC5jb20iLCJyb2xlcyI6WyI1YjI3YmQ5NjU4NDJmOTUwYTc3OGM2ZWYiXSwiY291bnRyeUdyb3VwIjoiSU4iLCJvbmVSb2xlcyI6W10sInR5cGUiOiJVU0VSIn0sImp0aSI6IlZTX01pdkdyUlZhdnBqUmZWV2pWUVFfNjVlMDQwMGNiOWU2ZGNiNmFhMzRiNDFhIiwiaWF0IjoxNzgxMTkzNzUyfQ.yCow88dcTVSa7vYyj3yyGRf8S22BKU5bVWiIj-I5fk4",
    "client-id": "ADMIN",
    "client-type": "MOBILE",
    "client-version": "538",
    "content-type": "application/json",
    "device-meta": "{\"APP_VERSION\":\"538\",\"APP_VERSION_NAME\":\"15.32.0\",\"DEVICE_MAKE\":\"Samsung\",\"DEVICE_MODEL\":\"SM-A707F\",\"OS_VERSION\":\"11\",\"PACKAGE_NAME\":\"xyz.penpencil.physicswala\",\"network\":\"wifi_data\",\"carrier\":\"UNDEFINED\"}",
    "randomid": "d054aefb-8a77-4ae1-bbf6-77c0e1931374",
    "referer": "https://android.pw.live"
};const VIDEO_DETAILS_URL = `https://learnbyakp.onrender.com/api/pw/video-url-details?batchId=${batch_id}&childId=${schedule_id}&subjectId=${subject_id}`;

let VIDEO_DATA = null;  // 🔹 global

async function fetchVideoData() {
  const res = await fetch(VIDEO_DETAILS_URL);

  if (!res.ok) {
    throw new Error(`video-url-details failed: ${res.status} ${res.statusText}`);
  }

  const json = await res.json();

  // Array check
  if (
    !json.success ||
    !json.data ||
    !Array.isArray(json.data) ||
    json.data.length === 0 ||
    !json.data[0].url
  ) {
    throw new Error("Invalid video-url-details response");
  }

  const { url, signedUrl } = json.data[0];

  // Yahan global `time` use ho raha hai
  const fullUrl =
    time !== null && time !== undefined
      ? `${url}\u0026start=${time}`
      : url;

  VIDEO_DATA = {
    drmType: "ClearKey",
    keys: [
      "f663a9dfeaf2fe5ce1BBbcdf4beaeb16:4c13c5314896911834e340c8f2f84c2a",
    ],
    url: fullUrl,
  };

  console.log("VIDEO_DATA:", VIDEO_DATA);
  return VIDEO_DATA;
}

// JavaScript code
document.getElementById('downloadBtn').addEventListener('click', () => {
  // VIDEO_DATA.url se finalUrl get karo
  const finalUrl = VIDEO_DATA?.url || '';
  
  if (!finalUrl) {
    console.error('No video URL available for download');
    return;
  }
  
  // Redirect to download endpoint
  window.location.href = `/download?url=${encodeURIComponent(finalUrl)}`;
});
const API_URL = `https://learnbyakp.onrender.com/slides?batch_id=${batch_id}&subject_id=${subject_id}&schedule_id=${schedule_id}&type=slides`;

let SLIDES = [];

async function initSlides() {
  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error(`API request failed: ${res.status} ${res.statusText}`);

    const response = await res.json();
    if (!response.success || !response.data || !Array.isArray(response.data.slides)) {
      throw new Error("Invalid API response structure");
    }

    SLIDES = response.data.slides.map((slide) => {
      const { img, serialNumber, timeStamp, name } = slide;

      const imageUrl =
        img && img.baseUrl && img.key
          ? img.baseUrl + img.key
          : "";

      const slideName = name || `Slide No. ${serialNumber}`;

      return {
        image: imageUrl,
        name: slideName,
        timestamp: Number(timeStamp) || 0,
      };
    });

    console.log("SLIDES:", SLIDES);

    // 👉 Slides load hone ke baad panel build/render karo
    const PANEL_HTML = buildPanelHTML();
    document.getElementById('panelInner').innerHTML    = PANEL_HTML;
    document.getElementById('panelInnerMob').innerHTML = PANEL_HTML;

    // Agar panel already open hai to current slide sync kar lo
    syncSlide(true);
  } catch (err) {
    console.error("Error loading slides:", err);
  }
}const API_URL1 = `https://learnbyakp.onrender.com/slides?batch_id=${batch_id}&subject_id=${subject_id}&schedule_id=${schedule_id}&type=schedule-details`;

let TOPIC_NAME = "";
let NOTES = [];
let DPP_NOTES = [];

async function initScheduleData() {
  try {
    const res = await fetch(API_URL1);
    if (!res.ok) throw new Error(`API request failed: ${res.status} ${res.statusText}`);

    const resp = await res.json();
    if (!resp.success || !resp.data) throw new Error("Invalid API response structure");

    const data = resp.data;

    // 1) TOPIC_NAME — bilkul const jaisa
    TOPIC_NAME = data.topic || "";

    const titleEl = document.getElementById("player-title");
    if (titleEl && TOPIC_NAME) {
      titleEl.textContent = TOPIC_NAME;
    }

    // 2) NOTES — const NOTES jaisa hi array
    NOTES = [];
    if (Array.isArray(data.homeworkIds)) {
      data.homeworkIds.forEach(hw => {
        const att = hw.attachmentIds && hw.attachmentIds[0];
        if (!att || !att.baseUrl || !att.key) return;

        NOTES.push({
          name: hw.topic || hw.note || "Notes",
          url: att.baseUrl + att.key
        });
      });
    }

    // 3) DPP_NOTES — dpp.homeworkIds se
    DPP_NOTES = [];
    if (data.dpp && Array.isArray(data.dpp.homeworkIds)) {
      data.dpp.homeworkIds.forEach(hw => {
        const att = hw.attachmentIds && hw.attachmentIds[0];
        if (!att || !att.baseUrl || !att.key) return;

        DPP_NOTES.push({
          name: hw.topic || hw.note || "DPP",
          url: att.baseUrl + att.key
        });
      });
    }

    console.log("TOPIC_NAME:", TOPIC_NAME);
    console.log("NOTES:", NOTES);
    console.log("DPP_NOTES:", DPP_NOTES);

    // 🔴 IMPORTANT: ab panel HTML ko dubara build karo
    const PANEL_HTML = buildPanelHTML();
    document.getElementById('panelInner').innerHTML    = PANEL_HTML;
    document.getElementById('panelInnerMob').innerHTML = PANEL_HTML;

  } catch (err) {
    console.error("Error loading schedule data:", err);
  }
}
// call once on load

if (TOPIC_NAME) document.getElementById('player-title').textContent = TOPIC_NAME;

function fmt(s) {
  s = Math.floor(s || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sc = s % 60;
  return h > 0 ? h+':'+(m<10?'0':'')+m+':'+(sc<10?'0':'')+sc : m+':'+(sc<10?'0':'')+sc;
}

function isDesktopLayout() {
  return !!(document.fullscreenElement || document.webkitFullscreenElement)
    || window.screen.width > window.screen.height || window.screen.width >= 768;
}

function applyLayout() {
  const shell = document.getElementById('shell');
  if (isDesktopLayout()) {
    shell.classList.replace('layout-mobile','layout-desktop') || shell.classList.add('layout-desktop');
  } else {
    shell.classList.replace('layout-desktop','layout-mobile') || shell.classList.add('layout-mobile');
  }
  if (panelOpen) openPanel(curTab);
 }
 window.addEventListener('resize', applyLayout);
 window.addEventListener('orientationchange', () => setTimeout(applyLayout, 100));
 if (screen.orientation) screen.orientation.addEventListener('change', () => setTimeout(applyLayout, 100));
 document.addEventListener('fullscreenchange',       () => setTimeout(applyLayout, 50));
 document.addEventListener('webkitfullscreenchange', () => setTimeout(applyLayout, 50));

 let panelOpen = false, curTab = 'tl';
 applyLayout();

 function previewPDF(url, name) {
  if (!url) { alert('No file URL available.'); return; }
  const pi = document.getElementById(isDesktopLayout() ? 'panelInner' : 'panelInnerMob');
  pi.querySelector('#mainPanelBody').style.display = 'none';
  pi.querySelector('#panelTabsArea').style.display = 'none';
  pi.querySelector('.panel-hdr-title').textContent = 'Preview';
  const previewWrap = pi.querySelector('#pdfPreviewWrap');
  previewWrap.style.cssText = 'display:flex;flex-direction:column;flex:1;min-height:0';
  pi.querySelector('#pdfPreviewTitle').textContent = name;
  const fc = pi.querySelector('#pdfFrameContainer');
  fc.innerHTML = '<div class="pdf-loading"><div class="spinner"></div><p>Loading PDF…</p></div>';
  function renderWithPDFjs() {
    const lib = window['pdfjs-dist/build/pdf'];
    lib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    lib.getDocument({ url, cMapUrl: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/cmaps/', cMapPacked: true })
      .promise.then(pdfDoc => {
        fc.innerHTML = '';
        const wrap = document.createElement('div'); wrap.className = 'pdf-canvas-wrap'; fc.appendChild(wrap);
        const dpr = window.devicePixelRatio || 1, containerW = fc.clientWidth || 360;
        function renderPage(n) {
          if (n > pdfDoc.numPages) return;
          pdfDoc.getPage(n).then(page => {
            const vp0 = page.getViewport({ scale: 1 });
            const vp  = page.getViewport({ scale: (containerW - 16) / vp0.width * dpr });
            const canvas = document.createElement('canvas'); canvas.className = 'pdf-page-canvas';
            canvas.width = vp.width; canvas.height = vp.height;
            canvas.style.width = (vp.width/dpr)+'px'; canvas.style.height = (vp.height/dpr)+'px';
            wrap.appendChild(canvas);
            page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise.then(() => renderPage(n+1));
          });
        }
        renderPage(1);
      }).catch(() => { fc.innerHTML = `<div class="pdf-err"><p>Could not load PDF.</p><a href="${url}" target="_blank" rel="noopener">Open PDF ↗</a></div>`; });
  }
  if (window['pdfjs-dist/build/pdf']) { renderWithPDFjs(); return; }
  const s = document.createElement('script');
  s.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
  s.onload = renderWithPDFjs;
  s.onerror = () => { fc.innerHTML = `<div class="pdf-err"><p>PDF viewer failed.</p><a href="${url}" target="_blank" rel="noopener">Open PDF ↗</a></div>`; };
  document.head.appendChild(s);
 }

 function closePDFPreview(pi) {
  pi.querySelector('#mainPanelBody').style.display = '';
  pi.querySelector('#panelTabsArea').style.display = '';
  pi.querySelector('#pdfPreviewWrap').style.display = 'none';
  pi.querySelector('#pdfFrameContainer').innerHTML = '';
  const activeTab = pi.querySelector('.ptab.active');
  if (activeTab) pi.querySelector('.panel-hdr-title').textContent = activeTab.dataset.tab === 'tl' ? 'Timeline' : 'Attachments';
 }

 function downloadPDF(url, name) {
  if (!url) { alert('No file URL available.'); return; }
  let fileName = (name.trim().toLowerCase().endsWith('.pdf') ? name.trim() : name.trim()+'.pdf')
    .replace(/:/g,' -').replace(/[/\\?%*|"<>]/g,'-').replace(/ {2,}/g,' ').trim();
  fetch(url).then(r => { if (!r.ok) throw 0; return r.blob(); })
    .then(blob => {
      const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: fileName });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    })
    .catch(() => {
      const a = Object.assign(document.createElement('a'), { href: url, download: fileName, target: '_blank', rel: 'noopener' });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    });
 }

 function buildPanelHTML() {
  let tlH = '<div class="tl-list">';
  if (SLIDES && SLIDES.length) {
    SLIDES.forEach((s, i) => {
      tlH += `<div class="tl-card" data-idx="${i}" onclick="seekSlide(${s.timestamp})">
        ${s.image ? `<img class="tl-img" src="${s.image}" alt="" loading="lazy" onerror="this.style.background='#1c1c27'">` : '<div class="tl-img"></div>'}
        <span class="tl-cur-badge">&#9654; Current</span>
        <div class="tl-ov"><span class="tl-name">${s.name||''}</span><span class="tl-ts">${fmt(s.timestamp)}</span></div>
      </div>`;
    });
  } else { tlH += '<div class="no-items">No slides available</div>'; }
  tlH += '</div>';

  function grpHTML(items, dot, ic, tc, cc, svg, label, pfx) {
    if (!items || !items.length) return '';
    let h = `<div class="acc open" id="acc-${pfx}"><div class="acc-hdr" onclick="this.closest('.acc').classList.toggle('open')"><div class="acc-hl"><div class="acc-ic ${ic}">${svg}</div><span class="acc-title ${tc}">${label}</span><span class="acc-cnt ${cc}">${items.length}</span></div><div class="acc-chev"><svg viewBox="0 0 24 24" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg></div></div><div class="acc-body"><div class="acc-inner">`;
    items.forEach((it, i) => {
      const nm = (it.name||label+' '+(i+1)).replace(/'/g,"\\'");
      const su = (it.url||'').replace(/'/g,"\\'");
      h += `<div class="att-item"><div class="att-dot ${dot}"></div><span class="att-name">${it.name||label+' '+(i+1)}</span><div class="att-actions">
        <button class="att-btn preview" onclick="previewPDF('${su}','${nm}')"><svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
        <button class="att-btn open-tab" onclick="window.open('${su}','_blank','noopener')"><svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></button>
        <button class="att-btn download" onclick="downloadPDF('${su}','${nm}')"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>
      </div></div>`;
    });
    h += '</div></div></div>'; return h;
  }
  const nSvg = '<svg viewBox="0 0 24 24"><path d="M9 12h6M9 16h6M9 8h6M5 4h14a1 1 0 011 1v14a1 1 0 01-1 1H5a1 1 0 01-1-1V5a1 1 0 011-1z"/></svg>';
  const dSvg = '<svg viewBox="0 0 24 24"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>';
  let attH = grpHTML(NOTES,'nd','ni','nt','nc',nSvg,'Notes','note') + grpHTML(DPP_NOTES,'dd','di','dt','dc',dSvg,'DPP','dpp');
  if (!attH) attH = '<div class="no-items">No attachments available</div>';

  return `
    <div class="panel-hdr"><span class="panel-hdr-title">Timeline</span><button class="panel-close" onclick="closePanel()"><svg viewBox="0 0 24 24" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg></button></div>
    <div class="panel-tabs" id="panelTabsArea">
      <button class="ptab active" data-tab="tl" onclick="swTab(this,'tl')"><svg viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="1.5" d="M3.167 5.583a.083.083 0 01.166 0v12.834a.083.083 0 01-.167 0V5.583zM5.667 17.333a1 1 0 001 1h10.666a1 1 0 001-1V6.667a1 1 0 00-1-1H6.667a1 1 0 00-1 1v10.666zm4.888-3.3V9.966L13.945 12l-3.39 2.034zM20.666 5.583a.083.083 0 11.167 0v12.834a.083.083 0 01-.166 0V5.583z"/></svg>Timeline</button>
      <button class="ptab" data-tab="att" onclick="swTab(this,'att')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>Attachments</button>
    </div>
    <div class="panel-body" id="mainPanelBody">
      <div class="ptab-panel active" data-p="tl">${tlH}</div>
      <div class="ptab-panel" data-p="att">${attH}</div>
    </div>
    <div class="pdf-preview-wrap" id="pdfPreviewWrap" style="display:none;flex:1;min-height:0">
      <div class="pdf-preview-topbar"><button class="pdf-back-btn" onclick="closePDFPreview(this.closest('.panel-inner'))"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back</button><span class="pdf-preview-title" id="pdfPreviewTitle"></span></div>
      <div class="pdf-frame-container" id="pdfFrameContainer"><div class="pdf-loading"><div class="spinner"></div><p>Loading PDF…</p></div></div>
    </div>`;
 }



 function swTab(btn, tab) {
  const pi = btn.closest('.panel-inner');
  pi.querySelectorAll('.ptab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  pi.querySelectorAll('.ptab-panel').forEach(p => p.classList.toggle('active', p.dataset.p === tab));
  pi.querySelector('.panel-hdr-title').textContent = tab === 'tl' ? 'Timeline' : 'Attachments';
  if (tab === 'tl') syncSlide(true);
 }

 function getActivePanelInner() {
  return document.getElementById(isDesktopLayout() ? 'panelInner' : 'panelInnerMob');
 }

 function activateTab(pi, tab) {
  pi.querySelectorAll('.ptab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  pi.querySelectorAll('.ptab-panel').forEach(p => p.classList.toggle('active', p.dataset.p === tab));
  pi.querySelector('.panel-hdr-title').textContent = tab === 'tl' ? 'Timeline' : 'Attachments';
 }

 function openPanel(tab) {
  curTab = tab || 'tl'; panelOpen = true;
  if (isDesktopLayout()) {
    document.getElementById('bottom-panel').classList.remove('open');
    const pi = document.getElementById('panelInner');
    const pw = pi.querySelector('#pdfPreviewWrap');
    if (pw && pw.style.display !== 'none') closePDFPreview(pi);
    activateTab(pi, curTab);
    document.getElementById('side-panel').classList.add('open');
  } else {
    document.getElementById('side-panel').classList.remove('open');
    const pi = document.getElementById('panelInnerMob');
    const pw = pi.querySelector('#pdfPreviewWrap');
    if (pw && pw.style.display !== 'none') closePDFPreview(pi);
    activateTab(pi, curTab);
    document.getElementById('bottom-panel').classList.add('open');
  }
  if (curTab === 'tl') setTimeout(() => syncSlide(true), 80);
 }

 function closePanel() {
  panelOpen = false;
  document.getElementById('bottom-panel').classList.remove('open');
  document.getElementById('side-panel').classList.remove('open');
 }

 let tdOpen = false;
 document.getElementById('tdBtn').addEventListener('click', e => { e.stopPropagation(); tdOpen = !tdOpen; document.getElementById('tdMenu').classList.toggle('on', tdOpen); });
 document.addEventListener('click', () => { tdOpen = false; document.getElementById('tdMenu').classList.remove('on'); });
 document.getElementById('tdTimeline').addEventListener('click', e => { e.stopPropagation(); openPanel('tl'); tdOpen = false; document.getElementById('tdMenu').classList.remove('on'); });
 document.getElementById('tdAttach').addEventListener('click',   e => { e.stopPropagation(); openPanel('att'); tdOpen = false; document.getElementById('tdMenu').classList.remove('on'); });
 document.getElementById('tlBtn').addEventListener('click', e => { e.stopPropagation(); (panelOpen && isDesktopLayout()) ? closePanel() : openPanel('tl'); });

 function seekSlide(ts) {
  const v = window.V;
  if (!v || !isFinite(v.duration) || v.duration <= 0) return;
  v.currentTime = ts; v.play().catch(() => {});
  syncSlide(false);
  if (!isDesktopLayout()) closePanel();
 }

 function syncSlide(doScroll) {
  if (!SLIDES || !SLIDES.length || !window.V) return;
  const ct = window.V.currentTime;
  let idx = 0;
  for (let i = 0; i < SLIDES.length; i++) { if (ct >= SLIDES[i].timestamp) idx = i; else break; }
  document.querySelectorAll('.tl-card').forEach(el => el.classList.toggle('cur', +el.dataset.idx === idx));
  if (doScroll) {
    const pi = getActivePanelInner();
    const cur = pi ? pi.querySelector('.tl-card.cur') : null;
    if (cur) cur.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

['contextmenu','selectstart','dragstart','copy'].forEach(ev => document.addEventListener(ev, e => e.preventDefault()));

(function () {
  'use strict';

  const vid       = document.getElementById('vid'); window.V = vid;
  const overlay   = document.getElementById('ctrl-overlay');
  const tapShield = document.getElementById('tap-shield');
  const playBtn   = document.getElementById('playBtn');
  const iPlay     = document.getElementById('iPlay');
  const iPause    = document.getElementById('iPause');
  const rwBtn     = document.getElementById('rwBtn');
  const fwBtn     = document.getElementById('fwBtn');
  const muteBtn   = document.getElementById('muteBtn');
  const volIcon   = document.getElementById('volIcon');
  const volBar    = document.getElementById('volBar');
  const seekBar   = document.getElementById('seekBar');
  const barFill   = document.getElementById('barFill');
  const barBuf    = document.getElementById('barBuf');
  const barThumb  = document.getElementById('barThumb');
  const curTime   = document.getElementById('curTime');
  const durTime   = document.getElementById('durTime');
  const spdBadge  = document.getElementById('spdBadge');
  const liveBadge = document.getElementById('liveBadge');
  const settBtn   = document.getElementById('settBtn');
  const settPanel = document.getElementById('settPanel');
  const settBd    = document.getElementById('settBd');
  const sMain     = document.getElementById('sMain');
  const sSpeedSub = document.getElementById('sSpeedSub');
  const sQualSub  = document.getElementById('sQualSub');
  const fsBtn     = document.getElementById('fsBtn');
  const iFs       = document.getElementById('iFs');
  const ovLoad    = document.getElementById('ovLoad');
  const loadMsg   = document.getElementById('loadMsg');
  const ovErr     = document.getElementById('ovErr');
  const errMsg    = document.getElementById('errMsg');
  const retryBtn  = document.getElementById('retryBtn');
  const bufSpin   = document.getElementById('bufSpin');

  let hlsPlayer = null, shakaPlayer = null, lastVideoData = null, initialized = false;
  let isSeeking = false, isLiveStream = false, settOpen = false;

  vid.volume = 1; vid.muted = false; volBar.value = 100;

  function updMuteIcon() {
    const muted = vid.muted || vid.volume === 0;
    if (muted) {
      volIcon.setAttribute('fill','none');
      volIcon.innerHTML = `<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM17.25 9.75l4.5 4.5m0-4.5-4.5 4.5" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>`;
    } else if (vid.volume < 0.5) {
      volIcon.setAttribute('fill','white');
      volIcon.innerHTML = `<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM15.932 7.757a.75.75 0 0 1 1.061 0 6 6 0 0 1 0 8.486.75.75 0 0 1-1.06-1.061 4.5 4.5 0 0 0 0-6.364.75.75 0 0 1 0-1.06Z" fill="white"/>`;
    } else {
      volIcon.setAttribute('fill','white');
      volIcon.innerHTML = `<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM18.584 5.106a.75.75 0 0 1 1.06 0c3.808 3.807 3.808 9.98 0 13.788a.75.75 0 0 1-1.06-1.06 8.25 8.25 0 0 0 0-11.668.75.75 0 0 1 0-1.06Z"/><path d="M15.932 7.757a.75.75 0 0 1 1.061 0 6 6 0 0 1 0 8.486.75.75 0 0 1-1.06-1.061 4.5 4.5 0 0 0 0-6.364.75.75 0 0 1 0-1.06Z" fill="white"/>`;
    }
  }

  let hideTimer = null;
  function scheduleHide() { clearTimeout(hideTimer); hideTimer = setTimeout(hideControls, 4000); }
  function showControls() { overlay.classList.remove('hidden'); overlay.classList.add('visible'); tapShield.classList.remove('on'); }
  function hideControls() { if (settOpen || tdOpen) return; overlay.classList.remove('visible'); overlay.classList.add('hidden'); tapShield.classList.add('on'); }
  function onInteraction() { showControls(); scheduleHide(); }

  tapShield.addEventListener('click',    e => { e.stopPropagation(); e.preventDefault(); onInteraction(); }, { passive: false });
  tapShield.addEventListener('touchend', e => { e.stopPropagation(); e.preventDefault(); onInteraction(); }, { passive: false });
  document.getElementById('ctrl-mid').addEventListener('click', e => { e.stopPropagation(); onInteraction(); });
  document.getElementById('video-col').addEventListener('mousemove', onInteraction);

  function setPlaying(p) { iPlay.style.display = p ? 'none' : 'block'; iPause.style.display = p ? 'block' : 'none'; showControls(); scheduleHide(); }
  function doToggle() { if (vid.paused) vid.play(); else vid.pause(); }

  playBtn.addEventListener('click', e => { e.stopPropagation(); doToggle(); onInteraction(); });
  vid.addEventListener('playing', () => { bufSpin.classList.remove('on'); setPlaying(true); });
  vid.addEventListener('pause',   () => setPlaying(false));
  vid.addEventListener('ended',   () => setPlaying(false));
  vid.addEventListener('waiting', () => bufSpin.classList.add('on'));
  vid.addEventListener('canplay', () => bufSpin.classList.remove('on'));

  function seekBy(s) { vid.currentTime = Math.max(0, Math.min(vid.duration || 0, vid.currentTime + s)); }
  function skAnim(b, c) { b.classList.remove('anim-l','anim-r'); void b.offsetWidth; b.classList.add(c); setTimeout(() => b.classList.remove(c), 360); }
  rwBtn.addEventListener('click', e => { e.stopPropagation(); seekBy(-10); skAnim(rwBtn,'anim-l'); onInteraction(); });
  fwBtn.addEventListener('click', e => { e.stopPropagation(); seekBy(10);  skAnim(fwBtn,'anim-r'); onInteraction(); });

  function updBar() {
    if (!vid.duration) return;
    const p = vid.currentTime / vid.duration * 100;
    barFill.style.width = p+'%'; barThumb.style.left = p+'%';
    seekBar.value = Math.round(vid.currentTime / vid.duration * 1000);
    curTime.textContent = fmt(vid.currentTime);
  }
  seekBar.addEventListener('input', () => {
    isSeeking = true; onInteraction();
    if (vid.duration && isFinite(vid.duration)) {
      const p = seekBar.value / 1000;
      vid.currentTime = p * vid.duration;
      barFill.style.width = (p*100)+'%'; barThumb.style.left = (p*100)+'%';
      curTime.textContent = fmt(vid.currentTime);
    }
  });
  seekBar.addEventListener('change', () => { isSeeking = false; });
  vid.addEventListener('timeupdate', () => { if (isSeeking) return; updBar(); if (isLiveStream && isFinite(vid.duration)) durTime.textContent = fmt(vid.duration); syncSlide(false); });
  vid.addEventListener('loadedmetadata', () => { if (isFinite(vid.duration) && vid.duration > 0) durTime.textContent = fmt(vid.duration); });
  vid.addEventListener('progress', () => { if (vid.buffered.length && vid.duration) barBuf.style.width = (vid.buffered.end(vid.buffered.length-1)/vid.duration*100)+'%'; });

  function markLive() { isLiveStream = true; liveBadge.classList.add('on'); }

  function updVol() { const v = volBar.value; volBar.style.background = `linear-gradient(to right,#fff ${v}%,rgba(255,255,255,.25) ${v}%)`; }
  volBar.addEventListener('input', () => { vid.volume = volBar.value/100; vid.muted = false; updVol(); updMuteIcon(); onInteraction(); });
  muteBtn.addEventListener('click', e => {
    e.stopPropagation();
    if (vid.muted || vid.volume === 0) { vid.muted = false; vid.volume = 1; volBar.value = 100; }
    else { vid.muted = true; volBar.value = 0; }
    updVol(); updMuteIcon(); onInteraction();
  });
  vid.addEventListener('volumechange', updMuteIcon);
  updVol(); updMuteIcon();

  function showSub(v) { sMain.classList.toggle('off', v!=='main'); sSpeedSub.classList.toggle('on', v==='speed'); sQualSub.classList.toggle('on', v==='quality'); }
  function openSett()  { settOpen = true;  showSub('main'); settPanel.classList.add('on'); settBd.classList.add('on'); clearTimeout(hideTimer); }
  function closeSett() { settOpen = false; settPanel.classList.remove('on'); settBd.classList.remove('on'); showSub('main'); scheduleHide(); }
  settBtn.addEventListener('click', e => { e.stopPropagation(); settOpen ? closeSett() : openSett(); });
  settBd.addEventListener('click', closeSett);
  document.getElementById('sSpeedRow').addEventListener('click', e => { e.stopPropagation(); showSub('speed'); });
  document.getElementById('sQualRow').addEventListener('click',  e => { e.stopPropagation(); showSub('quality'); });
  document.getElementById('sSpeedBack').addEventListener('click', e => { e.stopPropagation(); showSub('main'); });
  document.getElementById('sQualBack').addEventListener('click',  e => { e.stopPropagation(); showSub('main'); });

  function buildSpeed() {
    const c = document.getElementById('sSpeedOpts'); c.innerHTML = '';
    [0.25,0.5,0.75,1,1.25,1.5,1.75,2,2.25,2.5,2.75,3,3.25,3.5,3.75,4,4.25,4.5,4.75,5,5.25,5.5,5.75,6].forEach(sp => {
      const lbl = sp === 1 ? 'Normal' : sp+'x';
      const d = document.createElement('div');
      d.className = 'sopt'+(sp===1?' active':'');
      d.innerHTML = `<span>${lbl}</span><div class="radio"><div class="rdot"></div></div>`;
      d.onclick = e => { e.stopPropagation(); vid.playbackRate = sp; spdBadge.textContent = sp+'x'; document.getElementById('sSpeedVal').textContent = lbl; c.querySelectorAll('.sopt').forEach(o => o.classList.remove('active')); d.classList.add('active'); closeSett(); };
      c.appendChild(d);
    });
  }

  function buildQual(levels) {
    const c = document.getElementById('sQualOpts'); c.innerHTML = '';
    [{ label:'Auto', value:-1 }, ...levels].forEach(lv => {
      const d = document.createElement('div'); d.className = 'sopt'+(lv.value===-1?' active':'');
      d.innerHTML = `<span>${lv.label}</span><div class="radio"><div class="rdot"></div></div>`;
      d.onclick = e => {
        e.stopPropagation(); document.getElementById('sQualVal').textContent = lv.label;
        c.querySelectorAll('.sopt').forEach(o => o.classList.remove('active')); d.classList.add('active');
        if (hlsPlayer) { if (lv.value===-1) { hlsPlayer.autoLevelCapping=-1; hlsPlayer.nextLevel=-1; } else { hlsPlayer.autoLevelCapping=lv.value; hlsPlayer.nextLevel=lv.value; } }
        if (shakaPlayer) { try { if (lv.value===-1) shakaPlayer.configure({abr:{enabled:true}}); else { const t=shakaPlayer.getVariantTracks().find(t=>t.id===lv.value); if(t){shakaPlayer.configure({abr:{enabled:false}});shakaPlayer.selectVariantTrack(t,true);} } } catch {} }
        closeSett();
      };
      c.appendChild(d);
    });
  }
  buildSpeed(); buildQual([]);

  fsBtn.addEventListener('click', e => {
    e.stopPropagation();
    const fs = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (fs) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
    else { const el = document.getElementById('shell'); (el.requestFullscreen || el.webkitRequestFullscreen).call(el); }
  });

  function onFs() {
    const fs = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (fs) { iFs.setAttribute('viewBox','0 0 24 24'); iFs.setAttribute('fill','white'); iFs.removeAttribute('stroke'); iFs.removeAttribute('stroke-width'); iFs.removeAttribute('stroke-linecap'); iFs.innerHTML = '<path d="M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z"/>'; screen.orientation?.lock('landscape').catch(() => {}); }
    else { iFs.setAttribute('viewBox','0 0 24 24'); iFs.setAttribute('fill','none'); iFs.setAttribute('stroke','white'); iFs.setAttribute('stroke-width','2'); iFs.setAttribute('stroke-linecap','round'); iFs.innerHTML = '<path d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4"/>'; }
    setTimeout(applyLayout, 50);
  }
  document.addEventListener('fullscreenchange', onFs);
  document.addEventListener('webkitfullscreenchange', onFs);

  document.addEventListener('keydown', e => {
    if (['INPUT','TEXTAREA'].includes(e.target.tagName)) return;
    if      (e.code==='Space')      { e.preventDefault(); doToggle(); }
    else if (e.code==='ArrowLeft')  seekBy(-10);
    else if (e.code==='ArrowRight') seekBy(10);
    else if (e.code==='ArrowUp')    { vid.volume=Math.min(1,vid.volume+.1); volBar.value=Math.round(vid.volume*100); vid.muted=false; updVol(); updMuteIcon(); }
    else if (e.code==='ArrowDown')  { vid.volume=Math.max(0,vid.volume-.1); volBar.value=Math.round(vid.volume*100); if(!vid.volume) vid.muted=true; updVol(); updMuteIcon(); }
    onInteraction();
  });

  function showLoading(msg, stage) { ovLoad.classList.remove('off'); loadMsg.textContent = msg+(stage?' — '+stage:''); ovErr.classList.remove('on'); }
  function hideLoading()           { ovLoad.classList.add('off'); }
  function showError(msg)          { hideLoading(); errMsg.textContent = msg; ovErr.classList.add('on'); }

  function sigParams(url) {
    try { const u=new URL(url),p=new URLSearchParams(); u.searchParams.forEach((v,k)=>{if(k.toLowerCase()!=='start')p.append(k,v);}); return p.toString()?'?'+p:''; } catch { return ''; }
  }
  function appendSig(target, sig) {
    if (!sig) return target;
    try { const u=new URL(target); new URLSearchParams(sig.slice(1)).forEach((v,k)=>{if(!u.searchParams.has(k))u.searchParams.set(k,v);}); return u.toString(); } catch { return target; }
  }
  function parseKeys(keys) {
    const norm = s => String(s).replace(/-/g,'').toLowerCase().trim();
    const o = {};
    if (!keys) return o;
    const addPair = (k,v) => { k=norm(k); v=norm(v); if(k&&v) o[k]=v; };
    if (typeof keys==='object' && !Array.isArray(keys)) {
      Object.entries(keys).forEach(([k,v]) => addPair(k,v));
    } else {
      const lines = Array.isArray(keys) ? keys : String(keys).split(/[\n,]+/);
      lines.forEach(s => { s=String(s).trim(); if(!s) return; const i=s.indexOf(':'); if(i>0) addPair(s.slice(0,i),s.slice(i+1)); });
    }
    return o;
  }
  function isYouTube(u) { try { return ['youtube.com','youtube-nocookie.com','youtu.be'].includes(new URL(u).hostname.replace('www.','')); } catch { return false; } }
  function youTubeId(u) {
    try { const x=new URL(u); if(x.hostname.includes('youtu.be')) return x.pathname.slice(1).split('?')[0]; if(x.pathname.includes('/embed/')) return x.pathname.split('/embed/')[1].split(/[?/]/)[0]; if(x.searchParams.get('v')) return x.searchParams.get('v'); if(x.pathname.includes('/v/')) return x.pathname.split('/v/')[1].split(/[?/]/)[0]; } catch {}
    return '';
  }
  function dashToHlsUrl(url) {
    try { const u=new URL(url); u.pathname=u.pathname.replace(/master\.mpd$/i,'master.m3u8'); return u.toString(); }
    catch { return url.replace(/master\.mpd(\?|$)/i,'master.m3u8$1'); }
  }
  async function detectType(url) {
    if (isYouTube(url)) return 'youtube';
    const lo = url.toLowerCase().split('?')[0];
    if (lo.endsWith('.m3u8') || lo.includes('m3u8')) return 'hls';
    if (lo.endsWith('.mpd')  || lo.includes('.mpd'))  return 'dash';
    if (lo.endsWith('.mp4')  || lo.endsWith('.webm')  || lo.endsWith('.ogg')) return 'progressive';
    try { const r=await fetch(url,{method:'HEAD',mode:'no-cors'}); const ct=(r.headers?.get('Content-Type')||'').toLowerCase(); if(ct.includes('mpegurl')) return 'hls'; if(ct.includes('dash+xml')) return 'dash'; if(ct.includes('video/')) return 'progressive'; } catch {}
    return 'dash';
  }

  async function startVideo() {
    hideLoading();
    vid.volume=1; vid.muted=false; volBar.value=100; updVol(); updMuteIcon();
    try { await vid.play(); setPlaying(true); }
    catch { try { vid.muted=true; await vid.play(); vid.muted=false; vid.volume=1; volBar.value=100; updVol(); updMuteIcon(); setPlaying(true); } catch { updMuteIcon(); } }
  }

  function initYouTube(url) {
    showLoading('Loading…','YouTube');
    document.body.classList.add('yt-mode');
    vid.style.display='none'; overlay.style.display='none'; tapShield.style.display='none';
    let src;
    if (url.includes('/embed/')) { try { const u=new URL(url); u.searchParams.set('autoplay','1'); u.searchParams.set('playsinline','1'); src=u.toString(); } catch { src=url; } }
    else { const id=youTubeId(url); if(!id) throw new Error('Invalid YouTube URL'); src=`https://www.youtube.com/embed/${id}?autoplay=1&controls=1&rel=0&modestbranding=1&playsinline=1`; }
    const iframe=document.createElement('iframe');
    iframe.style.cssText='width:100%;height:100%;border:none;position:absolute;inset:0;z-index:5;';
    iframe.src=src; iframe.allow='accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture'; iframe.allowFullscreen=true;
    document.getElementById('vid-box').appendChild(iframe);
    iframe.onload=hideLoading; setTimeout(hideLoading,1500);
  }

  function initProgressive(url) {
    showLoading('Loading Video…','Preparing'); let started=false;
    vid.addEventListener('loadedmetadata',()=>{if(!isFinite(vid.duration)||vid.duration===0)markLive();},{once:true});
    vid.addEventListener('canplay',()=>{if(started)return;started=true;startVideo();},{once:true});
    vid.addEventListener('error',e=>{if(!started)showError(e.target.error?.message||'Playback failed');},{once:true});
    vid.src=url; vid.load();
  }

  function initHLS(url) {
    showLoading('Loading Video…','HLS stream');
    if (Hls.isSupported()) {
      if (hlsPlayer) { hlsPlayer.destroy(); hlsPlayer=null; }
      const sig = sigParams(url);
      hlsPlayer = new Hls({ enableWorker:true, lowLatencyMode:false, maxBufferLength:60, maxMaxBufferLength:120,
        xhrSetup(xhr, reqUrl) {
          xhr.open('GET', appendSig(reqUrl, sig), true);
          if (reqUrl.includes('.key') || reqUrl.includes('get-hls-key') || reqUrl.includes('enc.key')) {
            Object.entries(PW_HEADERS||{}).forEach(([k,v]) => { try { xhr.setRequestHeader(k,v); } catch {} });
          }
        }
      });
      hlsPlayer.on(Hls.Events.ERROR, (_,data) => {
        if (!data.fatal) return;
        if      (data.type===Hls.ErrorTypes.NETWORK_ERROR) hlsPlayer.startLoad();
        else if (data.type===Hls.ErrorTypes.MEDIA_ERROR)   hlsPlayer.recoverMediaError();
        else showError('HLS playback failed.');
      });
      hlsPlayer.on(Hls.Events.MANIFEST_PARSED, (_,data) => {
        if (data.levels?.some(l=>l.details?.live)) markLive();
        const seen=new Set();
        const levels=data.levels.map((l,i)=>({label:(l.height||parseInt(l.attrs?.RESOLUTION?.split('x')[1])||0)+'p',value:i,height:l.height||parseInt(l.attrs?.RESOLUTION?.split('x')[1])||0})).filter(l=>{if(!l.height||seen.has(l.height))return false;seen.add(l.height);return true;}).sort((a,b)=>b.height-a.height);
        if (levels.length) buildQual(levels);
      });
      hlsPlayer.on(Hls.Events.LEVEL_LOADED, (_,data) => { if(data.details?.live) markLive(); });
      let started=false;
      vid.addEventListener('canplay',()=>{if(started)return;started=true;startVideo();},{once:true});
      hlsPlayer.loadSource(url); hlsPlayer.attachMedia(vid);
      if (vid.readyState>=3 && !started) { started=true; startVideo(); }
      return;
    }
    if (!vid.canPlayType('application/vnd.apple.mpegurl')) throw new Error('HLS not supported in this browser');
    let started=false, errTimer=null;
    function doStart() { if(started)return; started=true; clearTimeout(errTimer); if(!isFinite(vid.duration)||vid.duration===0) markLive(); startVideo(); }
    vid.addEventListener('loadedmetadata',doStart,{once:true});
    vid.addEventListener('canplay',doStart,{once:true});
    vid.addEventListener('canplaythrough',doStart,{once:true});
    vid.addEventListener('error',()=>{ if(started)return; const code=vid.error?.code; if(code===1||code===4){clearTimeout(errTimer);showError(vid.error?.message||'HLS playback failed');} });
    errTimer=setTimeout(()=>{if(!started)showError('HLS stream did not start');},12000);
    vid.src=url; vid.load();
  }

  async function initShaka(data) {
    if (!shaka.Player.isBrowserSupported()) throw new Error('DASH (Shaka) not supported');
    showLoading('Loading Video…','DASH stream');
    shaka.polyfill.installAll();
    if (shakaPlayer) { try { await shakaPlayer.destroy(); } catch {} shakaPlayer=null; }
    shakaPlayer = new shaka.Player();
    await shakaPlayer.attach(vid);
    shakaPlayer.addEventListener('error', e => {
      if (e.detail?.severity===shaka.util.Error.Severity.RECOVERABLE && e.detail?.category!==6)
        shakaPlayer.retryStreaming().catch(()=>{});
    });
    if (data.keys) {
      const ck = parseKeys(data.keys);
      if (Object.keys(ck).length) shakaPlayer.configure({ drm: { clearKeys: ck } });
    }
    const sig = sigParams(data.url);
    if (sig) shakaPlayer.getNetworkingEngine().registerRequestFilter((type,req) => {
      const T = shaka.net.NetworkingEngine.RequestType;
      if (type===T.SEGMENT || type===T.MANIFEST) req.uris=req.uris.map(u=>appendSig(u,sig));
    });
    await shakaPlayer.load(data.url);
    if (shakaPlayer.isLive()) markLive();
    try {
      const seen=new Set();
      const levels=shakaPlayer.getVariantTracks().filter(t=>{if(!t.height||seen.has(t.height))return false;seen.add(t.height);return true;}).sort((a,b)=>b.height-a.height).map(t=>({label:t.height+'p',value:t.id}));
      if (levels.length) buildQual(levels);
    } catch {}
    let started=false;
    vid.addEventListener('canplay',()=>{if(started)return;started=true;startVideo();},{once:true});
    if (vid.readyState>=3 && !started) { started=true; startVideo(); }
  }

  function destroyPlayers() {
    document.body.classList.remove('yt-mode');
    if (hlsPlayer)   { hlsPlayer.destroy(); hlsPlayer=null; }
    if (shakaPlayer) { try { shakaPlayer.destroy(); } catch {} shakaPlayer=null; }
    vid.removeAttribute('src'); vid.load();
    const ifr=document.getElementById('vid-box').querySelector('iframe'); if(ifr) ifr.remove();
    vid.style.display='block'; overlay.style.display=''; tapShield.style.display='';
    isLiveStream=false; liveBadge.classList.remove('on');
    barFill.style.width='0%'; barBuf.style.width='0%'; barThumb.style.left='0%';
    seekBar.value=0; curTime.textContent='0:00'; durTime.textContent='0:00';
    vid.volume=1; vid.muted=false; volBar.value=100; updVol(); updMuteIcon();
    setPlaying(false);
  }

  const isIOS       = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  const isSafari    = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
  const isNativeOnly = isIOS || isSafari;

  async function initPlayer(data) {
    if (initialized) { destroyPlayers(); initialized=false; }
    initialized=true; lastVideoData=data;
    showLoading('Initializing…','Detecting stream type');
    try {
      if (isNativeOnly) {
        if (isYouTube(data.url)) { initYouTube(data.url); return; }
        const lo = data.url.toLowerCase().split('?')[0];
        const hlsUrl = (lo.endsWith('.m3u8') || lo.includes('m3u8')) ? data.url : dashToHlsUrl(data.url);
        initHLS(hlsUrl); return;
      }
      const type = await detectType(data.url);
      if      (type==='youtube')     initYouTube(data.url);
      else if (type==='hls')         initHLS(data.url);
      else if (type==='progressive') initProgressive(data.url);
      else {
        try { await initShaka(data); }
        catch (err) {
          if (shakaPlayer) { try { await shakaPlayer.destroy(); } catch {} shakaPlayer=null; }
          vid.removeAttribute('src'); vid.load();
          initHLS(dashToHlsUrl(data.url));
        }
      }
    } catch (err) { initialized=false; showError(err.message||'Failed to load video.'); }
  }

  retryBtn.addEventListener('click', () => { if (lastVideoData) initPlayer(lastVideoData); });
  window.addEventListener('beforeunload', () => { if(shakaPlayer){try{shakaPlayer.destroy();}catch{}} if(hlsPlayer) hlsPlayer.destroy(); });

  // ...
  showLoading('Loading…','');
  showControls();
  scheduleHide();

  (async () => {
    try {
      const data = await fetchVideoData();   // 🔹 API se lao

      if (!data?.url) throw new Error('Video URL not available.');
      if (isYouTube(data.url)) document.body.classList.add('yt-mode');
      initPlayer(data);
    } catch (err) {
      showError(err.message || 'Video not available.');
    }
  })();

})();
initScheduleData();
initSlides();


function escapeAttr(value){ return escapeHtml(value).replace(/`/g, "&#96;"); }
    const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";

const s = document.createElement("script");
s.src = SCRIPT_LINK;
s.async = true;
s.onload = () => {
  console.log("Script loaded successfully");
};
s.onerror = () => {
  console.log("Script load nahi hua");
};

document.head.appendChild(s);
