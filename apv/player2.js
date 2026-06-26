

const params = new URLSearchParams(window.location.search);

const batch_id = params.get('batch_id') || params.get('batchId') || '';
const subject_id = params.get('subject_id') || params.get('subjectId') || '';
const schedule_id = params.get('schedule_id') || params.get('scheduleId') || '';
const time = params.get('time');



const VIDEO_DETAILS_URL = `https://learnbyakp.onrender.com/api/get-video?batchId=${encodeURIComponent(batch_id)}&lectureId=${encodeURIComponent(schedule_id)}&subjectId=${encodeURIComponent(subject_id)}`;
const SLIDES_URL = `https://learnbyakp.onrender.com/slides?batch_id=${encodeURIComponent(batch_id)}&subject_id=${encodeURIComponent(subject_id)}&schedule_id=${encodeURIComponent(schedule_id)}&type=slides`;
const SCHEDULE_URL = `https://learnbyakp.onrender.com/slides?batch_id=${encodeURIComponent(batch_id)}&subject_id=${encodeURIComponent(subject_id)}&schedule_id=${encodeURIComponent(schedule_id)}&type=schedule-details`;

let VIDEO_DATA = null;
let SLIDES = [];
let TOPIC_NAME = '';
let NOTES = [];
let DPP_NOTES = [];

let hlsPlayer = null;
let shakaPlayer = null;
let initialized = false;
let lastVideoData = null;

let panelOpen = false;
let curTab = 'tl';
let tdOpen = false;
let isLiveStream = false;
let settOpen = false;
let hideTimer = null;
let isSeeking = false;

const vid = document.getElementById('vid');
const overlay = document.getElementById('ctrl-overlay');
const tapShield = document.getElementById('tap-shield');
const playBtn = document.getElementById('playBtn');
const iPlay = document.getElementById('iPlay');
const iPause = document.getElementById('iPause');
const rwBtn = document.getElementById('rwBtn');
const fwBtn = document.getElementById('fwBtn');
const muteBtn = document.getElementById('muteBtn');
const volIcon = document.getElementById('volIcon');
const volBar = document.getElementById('volBar');
const seekBar = document.getElementById('seekBar');
const barFill = document.getElementById('barFill');
const barBuf = document.getElementById('barBuf');
const barThumb = document.getElementById('barThumb');
const curTimeEl = document.getElementById('curTime');
const durTimeEl = document.getElementById('durTime');
const spdBadge = document.getElementById('spdBadge');
const liveBadge = document.getElementById('liveBadge');
const settBtn = document.getElementById('settBtn');
const settPanel = document.getElementById('settPanel');
const settBd = document.getElementById('settBd');
const sMain = document.getElementById('sMain');
const sSpeedSub = document.getElementById('sSpeedSub');
const sQualSub = document.getElementById('sQualSub');
const fsBtn = document.getElementById('fsBtn');
const iFs = document.getElementById('iFs');
const ovLoad = document.getElementById('ovLoad');
const loadMsg = document.getElementById('loadMsg');
const ovErr = document.getElementById('ovErr');
const errMsg = document.getElementById('errMsg');
const retryBtn = document.getElementById('retryBtn');
const bufSpin = document.getElementById('bufSpin');

function fmt(s) {
  s = Math.floor(s || 0);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sc = s % 60;
  return h > 0 ? `${h}:${m < 10 ? '0' : ''}${m}:${sc < 10 ? '0' : ''}${sc}` : `${m}:${sc < 10 ? '0' : ''}${sc}`;
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseKeys(keys) {
  const out = {};
  if (!keys) return out;

  if (Array.isArray(keys)) {
    keys.forEach(item => {
      const s = String(item || '').trim();
      const i = s.indexOf(':');
      if (i > 0) out[s.slice(0, i).trim()] = s.slice(i + 1).trim();
    });
    return out;
  }

  if (typeof keys === 'object') {
    Object.entries(keys).forEach(([k, v]) => {
      if (k && v) out[String(k).trim()] = String(v).trim();
    });
  }
  return out;
}

function isDesktopLayout() {
  return !!(document.fullscreenElement || document.webkitFullscreenElement) ||
    window.screen.width > window.screen.height ||
    window.screen.width >= 768;
}

function getActivePanelInner() {
  return document.getElementById(isDesktopLayout() ? 'panelInner' : 'panelInnerMob');
}

function applyLayout() {
  const shell = document.getElementById('shell');
  if (!shell) return;
  if (isDesktopLayout()) {
    shell.classList.remove('layout-mobile');
    shell.classList.add('layout-desktop');
  } else {
    shell.classList.remove('layout-desktop');
    shell.classList.add('layout-mobile');
  }
  if (panelOpen) openPanel(curTab);
}

function showLoading(msg, stage) {
  if (ovLoad) ovLoad.classList.remove('off');
  if (loadMsg) loadMsg.textContent = stage ? `${msg} · ${stage}` : msg;
  if (ovErr) ovErr.classList.remove('on');
}

function hideLoading() {
  if (ovLoad) ovLoad.classList.add('off');
}

function showError(msg) {
  hideLoading();
  if (errMsg) errMsg.textContent = msg || 'Playback failed';
  if (ovErr) ovErr.classList.add('on');
}

function setPlaying(p) {
  if (iPlay) iPlay.style.display = p ? 'none' : 'block';
  if (iPause) iPause.style.display = p ? 'block' : 'none';
}

function updMuteIcon() {
  if (!volIcon) return;
  const muted = vid.muted || vid.volume === 0;
  if (muted) {
    volIcon.innerHTML = '<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM17.25 9.75l4.5 4.5m0-4.5-4.5 4.5" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
  } else if (vid.volume <= 0.5) {
    volIcon.innerHTML = '<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM15.932 7.757a.75.75 0 0 1 1.061 0 6 6 0 0 1 0 8.486.75.75 0 0 1-1.06-1.061 4.5 4.5 0 0 0 0-6.364.75.75 0 0 1 0-1.06Z" fill="white"/>';
  } else {
    volIcon.innerHTML = '<path d="M13.5 4.06c0-1.336-1.616-2.005-2.56-1.06l-4.5 4.5H4.508c-1.141 0-2.318.664-2.66 1.905A9.76 9.76 0 0 0 1.5 12c0 .898.121 1.768.35 2.595.341 1.24 1.518 1.905 2.659 1.905h1.93l4.5 4.5c.945.945 2.561.276 2.561-1.06V4.06ZM18.584 5.106a.75.75 0 0 1 1.06 0c3.808 3.807 3.808 9.98 0 13.788a.75.75 0 0 1-1.06-1.06 8.25 8.25 0 0 0 0-11.668.75.75 0 0 1 0-1.06Z"/><path d="M15.932 7.757a.75.75 0 0 1 1.061 0 6 6 0 0 1 0 8.486.75.75 0 0 1-1.06-1.061 4.5 4.5 0 0 0 0-6.364.75.75 0 0 1 0-1.06Z" fill="white"/>';
  }
}

function updVol() {
  if (!volBar) return;
  const v = Number(volBar.value || 0);
  volBar.style.background = `linear-gradient(to right, #fff ${v}%, rgba(255,255,255,.25) ${v}%)`;
}

function onInteraction() {
  if (overlay) overlay.classList.remove('hidden');
  if (tapShield) tapShield.classList.remove('on');
  clearTimeout(hideTimer);
  hideTimer = setTimeout(hideControls, 4000);
}

function showControls() {
  if (overlay) {
    overlay.classList.remove('hidden');
    overlay.classList.add('visible');
  }
  if (tapShield) tapShield.classList.remove('on');
}

function hideControls() {
  if (settOpen || tdOpen) return;
  if (overlay) {
    overlay.classList.remove('visible');
    overlay.classList.add('hidden');
  }
  if (tapShield) tapShield.classList.add('on');
}

function startVideo() {
  hideLoading();
  vid.volume = 1;
  vid.muted = false;
  if (volBar) volBar.value = 100;
  updVol();
  updMuteIcon();
  vid.play().then(() => setPlaying(true)).catch(() => {});
}

function seekBy(s) {
  vid.currentTime = Math.max(0, Math.min(vid.duration || 0, vid.currentTime + s));
}

function isYouTube(url) {
  try {
    const u = new URL(url);
    return /youtube\.com|youtu\.be|youtube-nocookie\.com/.test(u.hostname);
  } catch {
    return false;
  }
}

function dashToHlsUrl(url) {
  try {
    const u = new URL(url);
    u.pathname = u.pathname.replace(/master\.mpd$/i, 'master.m3u8');
    return u.toString();
  } catch {
    return url.replace(/master\.mpd$/i, 'master.m3u8');
  }
}

function sigParams(url) {
  try {
    const u = new URL(url);
    const p = new URLSearchParams();
    u.searchParams.forEach((v, k) => {
      if (k.toLowerCase() !== 'start') p.append(k, v);
    });
    return p.toString();
  } catch {
    return '';
  }
}

function appendSig(target, sig) {
  if (!sig) return target;
  try {
    const u = new URL(target);
    new URLSearchParams(sig).forEach((v, k) => {
      if (!u.searchParams.has(k)) u.searchParams.set(k, v);
    });
    return u.toString();
  } catch {
    return target;
  }
}

function detectType(url) {
  const lo = url.toLowerCase().split('?')[0];
  if (isYouTube(url)) return 'youtube';
  if (lo.endsWith('.m3u8') || lo.includes('m3u8')) return 'hls';
  if (lo.endsWith('.mpd') || lo.includes('mpd')) return 'dash';
  if (lo.endsWith('.mp4') || lo.endsWith('.webm') || lo.endsWith('.ogg')) return 'progressive';
  return 'dash';
}

function destroyPlayers() {
  if (hlsPlayer) {
    try { hlsPlayer.destroy(); } catch {}
    hlsPlayer = null;
  }
  if (shakaPlayer) {
    try { shakaPlayer.destroy(); } catch {}
    shakaPlayer = null;
  }
  vid.removeAttribute('src');
  vid.load();
  isLiveStream = false;
  if (liveBadge) liveBadge.classList.remove('on');
}

function buildPanelHTML() {
  let tlH = '<div class="tl-list">';
  if (SLIDES.length) {
    SLIDES.forEach((s, i) => {
      tlH += `<div class="tl-card" data-idx="${i}" onclick="seekSlide(${s.timestamp})">
        ${s.image ? `<img class="tl-img" src="${escapeHtml(s.image)}" alt="" loading="lazy" onerror="this.style.background='#1c1c27'">` : '<div class="tl-img"></div>'}
        <span class="tl-cur-badge">&#9654; Current</span>
        <div class="tl-ov"><span class="tl-name">${escapeHtml(s.name || '')}</span><span class="tl-ts">${fmt(s.timestamp)}</span></div>
      </div>`;
    });
  } else {
    tlH += '<div class="no-items">No slides available</div>';
  }
  tlH += '</div>';

  let attH = '';
  const groupHTML = (items, label, pfx) => {
    if (!items.length) return '';
    let h = `<div class="acc open" id="acc-${pfx}">
      <div class="acc-hdr" onclick="this.closest('.acc').classList.toggle('open')">
        <div class="acc-hl"><span class="acc-title">${label}</span><span class="acc-cnt">${items.length}</span></div>
      </div>
      <div class="acc-body"><div class="acc-inner">`;
    items.forEach((it, i) => {
      const nm = escapeHtml(it.name || `${label} ${i + 1}`);
      const su = escapeHtml(it.url || '');
      h += `<div class="att-item">
        <div class="att-dot"></div>
        <span class="att-name">${nm}</span>
        <div class="att-actions">
          <button class="att-btn" onclick="previewPDF('${su}','${nm}')">Preview</button>
          <button class="att-btn" onclick="window.open('${su}','_blank','noopener')">Open</button>
          <button class="att-btn" onclick="downloadPDF('${su}','${nm}')">Download</button>
        </div>
      </div>`;
    });
    h += '</div></div></div>';
    return h;
  };

  attH += groupHTML(NOTES, 'Notes', 'note');
  attH += groupHTML(DPP_NOTES, 'DPP', 'dpp');
  if (!attH) attH = '<div class="no-items">No attachments available</div>';

  return `
    <div class="panel-hdr">
      <span class="panel-hdr-title">Timeline</span>
      <button class="panel-close" onclick="closePanel()">×</button>
    </div>
    <div class="panel-tabs" id="panelTabsArea">
      <button class="ptab active" data-tab="tl" onclick="swTab(this,'tl')">Timeline</button>
      <button class="ptab" data-tab="att" onclick="swTab(this,'att')">Attachments</button>
    </div>
    <div class="panel-body" id="mainPanelBody">
      <div class="ptab-panel active" data-p="tl">${tlH}</div>
      <div class="ptab-panel" data-p="att">${attH}</div>
    </div>
    <div class="pdf-preview-wrap" id="pdfPreviewWrap" style="display:none;flex:1;min-height:0">
      <div class="pdf-preview-topbar">
        <button class="pdf-back-btn" onclick="closePDFPreview(this.closest('.panel-inner'))">Back</button>
        <span class="pdf-preview-title" id="pdfPreviewTitle"></span>
      </div>
      <div class="pdf-frame-container" id="pdfFrameContainer"></div>
    </div>
  `;
}

function renderPanels() {
  const a = document.getElementById('panelInner');
  const b = document.getElementById('panelInnerMob');
  const html = buildPanelHTML();
  if (a) a.innerHTML = html;
  if (b) b.innerHTML = html;
}

function swTab(btn, tab) {
  const pi = btn.closest('.panel-inner');
  pi.querySelectorAll('.ptab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  pi.querySelectorAll('.ptab-panel').forEach(p => p.classList.toggle('active', p.dataset.p === tab));
  const title = pi.querySelector('.panel-hdr-title');
  if (title) title.textContent = tab === 'tl' ? 'Timeline' : 'Attachments';
  if (tab === 'tl') syncSlide(true);
}

function activateTab(pi, tab) {
  pi.querySelectorAll('.ptab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  pi.querySelectorAll('.ptab-panel').forEach(p => p.classList.toggle('active', p.dataset.p === tab));
  const title = pi.querySelector('.panel-hdr-title');
  if (title) title.textContent = tab === 'tl' ? 'Timeline' : 'Attachments';
}

function openPanel(tab) {
  curTab = tab || 'tl';
  panelOpen = true;
  const pid = isDesktopLayout() ? 'side-panel' : 'bottom-panel';
  const panel = document.getElementById(pid);
  if (panel) panel.classList.add('open');
  const pi = getActivePanelInner();
  if (pi) {
    const pw = pi.querySelector('#pdfPreviewWrap');
    if (pw) pw.style.display = 'none';
    activateTab(pi, curTab);
  }
  if (curTab === 'tl') setTimeout(() => syncSlide(true), 80);
}

function closePanel() {
  panelOpen = false;
  document.getElementById('bottom-panel')?.classList.remove('open');
  document.getElementById('side-panel')?.classList.remove('open');
}

function previewPDF(url, name) {
  if (!url) return alert('No file URL available.');
  const pi = getActivePanelInner();
  if (!pi) return;
  pi.querySelector('#mainPanelBody').style.display = 'none';
  pi.querySelector('#panelTabsArea').style.display = 'none';
  pi.querySelector('.panel-hdr-title').textContent = 'Preview';
  const previewWrap = pi.querySelector('#pdfPreviewWrap');
  previewWrap.style.display = 'flex';
  pi.querySelector('#pdfPreviewTitle').textContent = name;
  const fc = pi.querySelector('#pdfFrameContainer');
  fc.innerHTML = '<div class="pdf-loading"><div class="spinner"></div><p>Loading PDF…</p></div>';
  if (window['pdfjs-dist/build/pdf']) return renderPdf(window['pdfjs-dist/build/pdf'], url, fc);
  const s = document.createElement('script');
  s.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
  s.onload = () => renderPdf(window['pdfjs-dist/build/pdf'], url, fc);
  s.onerror = () => { fc.innerHTML = `<div class="pdf-err"><p>PDF viewer failed.</p><a href="${url}" target="_blank" rel="noopener">Open PDF ↗</a></div>`; };
  document.head.appendChild(s);
}

function renderPdf(lib, url, fc) {
  lib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  lib.getDocument({ url, cMapUrl: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/cmaps/', cMapPacked: true })
    .promise.then(pdfDoc => {
      fc.innerHTML = '';
      const wrap = document.createElement('div');
      wrap.className = 'pdf-canvas-wrap';
      fc.appendChild(wrap);
      const dpr = window.devicePixelRatio || 1;
      const containerW = fc.clientWidth || 360;
      const renderPage = n => {
        if (n > pdfDoc.numPages) return;
        pdfDoc.getPage(n).then(page => {
          const vp0 = page.getViewport({ scale: 1 });
          const vp = page.getViewport({ scale: ((containerW - 16) / vp0.width) * dpr });
          const canvas = document.createElement('canvas');
          canvas.className = 'pdf-page-canvas';
          canvas.width = vp.width;
          canvas.height = vp.height;
          canvas.style.width = `${vp.width / dpr}px`;
          canvas.style.height = `${vp.height / dpr}px`;
          wrap.appendChild(canvas);
          page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise.then(() => renderPage(n + 1));
        });
      };
      renderPage(1);
    })
    .catch(() => {
      fc.innerHTML = `<div class="pdf-err"><p>Could not load PDF.</p><a href="${url}" target="_blank" rel="noopener">Open PDF ↗</a></div>`;
    });
}

function closePDFPreview(pi) {
  pi.querySelector('#mainPanelBody').style.display = '';
  pi.querySelector('#panelTabsArea').style.display = '';
  pi.querySelector('#pdfPreviewWrap').style.display = 'none';
  pi.querySelector('#pdfFrameContainer').innerHTML = '';
  const activeTab = pi.querySelector('.ptab.active');
  if (activeTab) {
    pi.querySelector('.panel-hdr-title').textContent = activeTab.dataset.tab === 'tl' ? 'Timeline' : 'Attachments';
  }
}

function downloadPDF(url, name) {
  if (!url) return alert('No file URL available.');
  let fileName = (name.trim().toLowerCase().endsWith('.pdf') ? name.trim() : `${name.trim()}.pdf`)
    .replace(/:/g, ' -')
    .replace(/[\/\\?%*|"<>]/g, '-')
    .replace(/ {2,}/g, ' ')
    .trim();
  fetch(url)
    .then(r => {
      if (!r.ok) throw new Error('download failed');
      return r.blob();
    })
    .then(blob => {
      const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: fileName });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    })
    .catch(() => {
      const a = Object.assign(document.createElement('a'), { href: url, download: fileName, target: '_blank', rel: 'noopener' });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
}

function seekSlide(ts) {
  if (!vid || !isFinite(vid.duration) || vid.duration <= 0) return;
  vid.currentTime = ts;
  vid.play().catch(() => {});
  if (!isDesktopLayout()) closePanel();
}

function syncSlide(doScroll) {
  if (!SLIDES.length || !window.V) return;
  const ct = window.V.currentTime || 0;
  let idx = 0;
  for (let i = 0; i < SLIDES.length; i++) {
    if (ct >= SLIDES[i].timestamp) idx = i;
    else break;
  }
  document.querySelectorAll('.tl-card').forEach(el => el.classList.toggle('cur', Number(el.dataset.idx) === idx));
  if (doScroll) {
    const pi = getActivePanelInner();
    const cur = pi ? pi.querySelector('.tl-card.cur') : null;
    if (cur) cur.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

async function fetchVideoData() {
  const res = await fetch(VIDEO_DETAILS_URL);
  if (!res.ok) throw new Error(`video-url-details failed: ${res.status} ${res.statusText}`);

  const json = await res.json();
  if (!json || !json.success) throw new Error('Invalid video-url-details response');

  const obj = Array.isArray(json.data) ? json.data[0] : json.data;
  const url = obj?.url || json.url;
  if (!url) throw new Error('No video URL found');

  const clearKeys = obj?.drmKeys?.clearKeys || json?.drmKeys?.clearKeys || null;
  const fullUrl = time != null ? `${url}${url.includes('?') ? '&' : '?'}start=${encodeURIComponent(time)}` : url;

  VIDEO_DATA = {
    type: obj?.type || json.type || 'dash',
    title: obj?.title || json.title || '',
    source: obj?.source || json.source || '',
    url: fullUrl,
    drmKeys: { clearKeys }
  };

  return VIDEO_DATA;
}

async function initShaka(data) {
  if (!window.shaka) throw new Error('Shaka not loaded');
  shaka.polyfill.installAll();
  if (!shaka.Player.isBrowserSupported()) throw new Error('DASH not supported');

  showLoading('Loading Video', 'DASH stream');

  if (shakaPlayer) {
    try { await shakaPlayer.destroy(); } catch {}
    shakaPlayer = null;
  }

  shakaPlayer = new shaka.Player();
  await shakaPlayer.attach(vid);

  if (data?.drmKeys?.clearKeys && Object.keys(data.drmKeys.clearKeys).length) {
    shakaPlayer.configure({ drm: { clearKeys: data.drmKeys.clearKeys } });
  }

  const sig = sigParams(data.url);
  if (sig) {
    shakaPlayer.getNetworkingEngine().registerRequestFilter((type, req) => {
      const T = shaka.net.NetworkingEngine.RequestType;
      if (type === T.SEGMENT || type === T.MANIFEST) {
        req.uris = req.uris.map(u => appendSig(u, sig));
      }
    });
  }

  shakaPlayer.addEventListener('error', e => {
    console.error('Shaka error', e);
  });

  await shakaPlayer.load(data.url);
  if (shakaPlayer.isLive()) {
    isLiveStream = true;
    liveBadge?.classList.add('on');
  }

  let started = false;
  vid.addEventListener('canplay', () => {
    if (started) return;
    started = true;
    startVideo();
  }, { once: true });

  if (vid.readyState >= 3 && !started) {
    started = true;
    startVideo();
  }
}

async function initPlayer(data) {
  lastVideoData = data;
  showLoading('Initializing', 'Detecting stream type');

  try {
    const type = detectType(data.url);
    if (type === 'dash') {
      await initShaka(data);
    } else {
      vid.src = data.url;
      vid.load();
      startVideo();
    }
  } catch (err) {
    showError(err.message || 'Failed to load video');
  }
}

function initControls() {
  if (playBtn) playBtn.addEventListener('click', e => { e.stopPropagation(); if (vid.paused) vid.play(); else vid.pause(); onInteraction(); });
  if (rwBtn) rwBtn.addEventListener('click', e => { e.stopPropagation(); seekBy(-10); onInteraction(); });
  if (fwBtn) fwBtn.addEventListener('click', e => { e.stopPropagation(); seekBy(10); onInteraction(); });
  if (muteBtn) muteBtn.addEventListener('click', e => {
    e.stopPropagation();
    if (vid.muted || vid.volume === 0) {
      vid.muted = false;
      vid.volume = 1;
      if (volBar) volBar.value = 100;
    } else {
      vid.muted = true;
      if (volBar) volBar.value = 0;
    }
    updVol();
    updMuteIcon();
    onInteraction();
  });

  if (volBar) volBar.addEventListener('input', () => {
    vid.volume = Number(volBar.value) / 100;
    vid.muted = false;
    updVol();
    updMuteIcon();
    onInteraction();
  });

  if (seekBar) seekBar.addEventListener('input', () => {
    isSeeking = true;
    if (vid.duration && isFinite(vid.duration)) {
      const p = Number(seekBar.value) / 1000;
      vid.currentTime = p * vid.duration;
    }
  });

  if (seekBar) seekBar.addEventListener('change', () => { isSeeking = false; });

  vid.addEventListener('play', () => { setPlaying(true); });
  vid.addEventListener('pause', () => { setPlaying(false); });
  vid.addEventListener('waiting', () => { bufSpin?.classList.add('on'); });
  vid.addEventListener('canplay', () => { bufSpin?.classList.remove('on'); });
  vid.addEventListener('timeupdate', () => {
    if (!isSeeking) {
      if (vid.duration && isFinite(vid.duration)) {
        const p = (vid.currentTime / vid.duration) * 1000;
        if (seekBar) seekBar.value = String(Math.round(p));
        if (barFill) barFill.style.width = `${p / 10}%`;
        if (barThumb) barThumb.style.left = `${p / 10}%`;
      }
      if (curTimeEl) curTimeEl.textContent = fmt(vid.currentTime);
      syncSlide(false);
    }
  });

  vid.addEventListener('loadedmetadata', () => {
    if (durTimeEl && vid.duration && isFinite(vid.duration)) durTimeEl.textContent = fmt(vid.duration);
  });

  vid.addEventListener('progress', () => {
    if (vid.buffered.length && vid.duration) {
      const end = vid.buffered.end(vid.buffered.length - 1);
      if (barBuf) barBuf.style.width = `${(end / vid.duration) * 100}%`;
    }
  });

  if (settBtn) settBtn.addEventListener('click', e => {
    e.stopPropagation();
    settOpen = !settOpen;
    if (settPanel) settPanel.classList.toggle('on', settOpen);
    if (settBd) settBd.classList.toggle('on', settOpen);
  });

  if (settBd) settBd.addEventListener('click', () => {
    settOpen = false;
    if (settPanel) settPanel.classList.remove('on');
    settBd.classList.remove('on');
  });

  if (fsBtn) fsBtn.addEventListener('click', e => {
    e.stopPropagation();
    const el = document.getElementById('shell');
    const fs = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (fs) {
      (document.exitFullscreen || document.webkitExitFullscreen)?.call(document);
    } else if (el?.requestFullscreen) {
      el.requestFullscreen();
    } else if (el?.webkitRequestFullscreen) {
      el.webkitRequestFullscreen();
    }
  });

  window.addEventListener('resize', applyLayout);
  window.addEventListener('orientationchange', () => setTimeout(applyLayout, 100));
  document.addEventListener('fullscreenchange', () => setTimeout(applyLayout, 50));
  document.addEventListener('webkitfullscreenchange', () => setTimeout(applyLayout, 50));

  document.getElementById('tdBtn')?.addEventListener('click', e => {
    e.stopPropagation();
    tdOpen = !tdOpen;
    document.getElementById('tdMenu')?.classList.toggle('on', tdOpen);
  });

  document.getElementById('tdTimeline')?.addEventListener('click', e => {
    e.stopPropagation();
    openPanel('tl');
    tdOpen = false;
    document.getElementById('tdMenu')?.classList.remove('on');
  });

  document.getElementById('tdAttach')?.addEventListener('click', e => {
    e.stopPropagation();
    openPanel('att');
    tdOpen = false;
    document.getElementById('tdMenu')?.classList.remove('on');
  });

  document.getElementById('tlBtn')?.addEventListener('click', e => {
    e.stopPropagation();
    panelOpen ? closePanel() : openPanel('tl');
  });

  document.addEventListener('click', () => {
    tdOpen = false;
    document.getElementById('tdMenu')?.classList.remove('on');
  });

  retryBtn?.addEventListener('click', () => {
    if (lastVideoData) initPlayer(lastVideoData);
  });
}

document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('selectstart', e => e.preventDefault());
document.addEventListener('dragstart', e => e.preventDefault());
document.addEventListener('copy', e => e.preventDefault());

document.addEventListener('keydown', e => {
  if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
  if (e.code === 'Space') { e.preventDefault(); vid.paused ? vid.play() : vid.pause(); }
  if (e.code === 'ArrowLeft') seekBy(-10);
  if (e.code === 'ArrowRight') seekBy(10);
  if (e.code === 'ArrowUp') {
    vid.volume = Math.min(1, vid.volume + 0.1);
    vid.muted = false;
    if (volBar) volBar.value = Math.round(vid.volume * 100);
    updVol();
    updMuteIcon();
  }
  if (e.code === 'ArrowDown') {
    vid.volume = Math.max(0, vid.volume - 0.1);
    if (volBar) volBar.value = Math.round(vid.volume * 100);
    if (!vid.volume) vid.muted = true;
    updVol();
    updMuteIcon();
  }
});

async function initSlides() {
  try {
    const res = await fetch(SLIDES_URL);
    if (!res.ok) throw new Error(`Slides API failed: ${res.status}`);
    const response = await res.json();
    const slides = response?.data?.slides || [];
    SLIDES = slides.map(slide => {
      const img = slide.img || {};
      return {
        image: img.baseUrl && img.key ? img.baseUrl + img.key : '',
        name: slide.name || `Slide No. ${slide.serialNumber || ''}`,
        timestamp: Number(slide.timeStamp) || 0
      };
    });
    renderPanels();
    syncSlide(true);
  } catch (err) {
    console.error(err);
    renderPanels();
  }
}

async function initScheduleData() {
  try {
    const res = await fetch(SCHEDULE_URL);
    if (!res.ok) throw new Error(`Schedule API failed: ${res.status}`);
    const resp = await res.json();
    const data = resp?.data || {};

    TOPIC_NAME = data.topic || '';
    const titleEl = document.getElementById('player-title');
    if (titleEl && TOPIC_NAME) titleEl.textContent = TOPIC_NAME;

    NOTES = [];
    if (Array.isArray(data.homeworkIds)) {
      data.homeworkIds.forEach(hw => {
        const att = hw?.attachmentIds?.[0];
        if (att?.baseUrl && att?.key) {
          NOTES.push({ name: hw.topic || hw.note || 'Notes', url: att.baseUrl + att.key });
        }
      });
    }

    DPP_NOTES = [];
    if (data.dpp && Array.isArray(data.dpp.homeworkIds)) {
      data.dpp.homeworkIds.forEach(hw => {
        const att = hw?.attachmentIds?.[0];
        if (att?.baseUrl && att?.key) {
          DPP_NOTES.push({ name: hw.topic || hw.note || 'DPP', url: att.baseUrl + att.key });
        }
      });
    }

    renderPanels();
  } catch (err) {
    console.error(err);
  }
}

document.getElementById('downloadBtn')?.addEventListener('click', () => {
  const finalUrl = VIDEO_DATA?.url || '';
  if (!finalUrl) return;
  window.location.href = `/download?url=${encodeURIComponent(finalUrl)}`;
});

(async function boot() {
  initControls();
  applyLayout();
  showLoading('Loading', 'Preparing player');

  try {
    const data = await fetchVideoData();
    renderPanels();
    await initPlayer(data);
  } catch (err) {
    showError(err.message || 'Video not available');
  }

  initScheduleData();
  initSlides();
})();

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
