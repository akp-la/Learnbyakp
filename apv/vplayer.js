lucide.createIcons();

const API = "https://vibrant-drab.vercel.app";
const params = new URLSearchParams(location.search);

const directVideoUrl = params.get('videourl');
const courseId = params.get('course_id') || params.get('course');
const videoId = params.get('video_id') || params.get('video');
const videoTitle = params.get('title') || 'Untitled Lesson';

let hls = null;
let qualities = [];
let currentQualityIdx = 0;

let isDragging = false;
let hideControlsTimer = null;
const vpRoot = document.querySelector('.vp-root') || document.getElementById('vpRoot');
const video = document.getElementById('video-player');
const videoShell = document.getElementById('videoShell');
const playPauseBtn = document.getElementById('playPauseBtn');
const centerPlayBtn = document.getElementById('centerPlayBtn');
const progressBar = document.getElementById('progressBar');
const progressFill = document.getElementById('progressFill');
const progressHandle = document.getElementById('progressHandle');
const currentTimeEl = document.getElementById('currentTime');
const durationEl = document.getElementById('duration');
const volumeSlider = document.getElementById('volumeSlider');
const speedSelect = document.getElementById('speedSelect');
const fullscreenBtn = document.getElementById('fullscreenBtn');
const moreBtn = document.getElementById('moreBtn');
const moreMenu = document.getElementById('moreMenu');
const qualitySelect = document.querySelector('#qualitySelect');

// Constants
const CONTROLS_HIDE_TIMEOUT = 3000;
const DOUBLE_TAP_DELAY = 300;
const SEEK_OFFSET = 5;

let lastTapTime = 0;
let lastTapSide = "";

// Inject loader + fixed controls CSS
injectLoaderUI();
addFixedControlsCSS();

document.getElementById('video-title').textContent = videoTitle;
document.title = 'LearnByAKP | ' + videoTitle;

// Flow decide: videourl vs API
if (directVideoUrl) {
  const proxied = 'https://learnbyakp.onrender.com/api/vibrant/play?url=' + encodeURIComponent(directVideoUrl);
  initHlsPlayback(proxied, true);
} else if (!courseId || !videoId) {
  hideLoader();
  showError('Invalid Authorization. Please launch from the dashboard.');
} else {
  loadVideo(courseId, videoId);
}

// ---------------- Loader UI ----------------

function injectLoaderUI() {
  const style = document.createElement('style');
  style.textContent = `
    #jsVideoLoader {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.78);
      z-index: 99999;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.25s ease, visibility 0.25s ease;
    }
    #jsVideoLoader.visible {
      display: flex;
      opacity: 1;
      visibility: visible;
    }
    .js-loader-box {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
      color: #fff;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .js-loader-spinner {
      width: 52px;
      height: 52px;
      border: 5px solid rgba(255,255,255,0.18);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: jsSpin 0.9s linear infinite;
    }
    .js-loader-text {
      font-size: 14px;
      letter-spacing: 0.3px;
      opacity: 0.9;
    }
    @keyframes jsSpin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    /* Controls visibility */
    #videoShell #vpControls {
      opacity: 1;
      pointer-events: auto;
      transition: opacity 0.25s ease;
    }
    #videoShell.user-active #vpControls {
      opacity: 1;
      pointer-events: auto;
    }
    #videoShell:not(.user-active) #vpControls {
      opacity: 0;
      pointer-events: none;
    }
  `;
  document.head.appendChild(style);

  const loader = document.createElement('div');
  loader.id = 'jsVideoLoader';
  loader.innerHTML = `
    <div class="js-loader-box">
      <div class="js-loader-spinner"></div>
      <div class="js-loader-text" id="jsVideoLoaderText">Decrypting stream...</div>
    </div>
  `;
  document.body.appendChild(loader);
}

function showLoader(text = 'Decrypting stream...') {
  const loader = document.getElementById('jsVideoLoader');
  const loaderText = document.getElementById('jsVideoLoaderText');
  if (loaderText) loaderText.textContent = text;
  if (loader) loader.classList.add('visible');
}

function hideLoader() {
  const loader = document.getElementById('jsVideoLoader');
  if (loader) loader.classList.remove('visible');
}

// ------------- Helper: proxy URL -------------

function buildProxyUrl(rawUrl) {
  return 'https://learnbyakp.onrender.com/api/vibrant/play?url=' + encodeURIComponent(rawUrl);
}

// ------------- Player destroy -------------

function destroyPlayer() {
  if (hls) {
    try { hls.destroy(); } catch (e) {}
    hls = null;
  }
  if (video) {
    video.removeAttribute('src');
    video.innerHTML = '';
  }
}

// ------------- Toast / Error -------------

function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.style.opacity = '1';
  toast.style.transform = 'translateX(-50%) translateY(0)';
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(-50%) translateY(20px)';
  }, 2500);
}

function showError(msg) {
  hideLoader();
  const errorPopup = document.getElementById('errorPopup');
  if (!errorPopup) return;
  errorPopup.textContent = msg;
  errorPopup.classList.add('show');
  setTimeout(() => errorPopup.classList.remove('show'), 4000);
}

// ------------- Controls show/hide (FIXED: hides even when mouse is inside videoShell) -------------

function showControls() {
  if (!videoShell) return;
  
  // Show controls
  videoShell.classList.add('user-active');
  
  // Clear existing timer
  if (hideControlsTimer) {
    clearTimeout(hideControlsTimer);
    hideControlsTimer = null;
  }
  
  // Start NEW timer: if video is playing and no interaction for 3 sec, hide controls
  hideControlsTimer = setTimeout(() => {
    // Only hide if video is playing (not paused)
    if (video && !video.paused) {
      hideControls();
    }
  }, CONTROLS_HIDE_TIMEOUT);
}

function hideControls() {
  if (!videoShell) return;
  
  // Clear timer
  if (hideControlsTimer) {
    clearTimeout(hideControlsTimer);
    hideControlsTimer = null;
  }
  
  // Hide controls (removes user-active class)
  videoShell.classList.remove('user-active');
}

// Force hide controls
function forceHideControls() {
  if (hideControlsTimer) {
    clearTimeout(hideControlsTimer);
    hideControlsTimer = null;
  }
  if (videoShell) {
    videoShell.classList.remove('user-active');
  }
}

// ------------- seek from pointer -------------

function seekFromPointer(clientX) {
  if (!progressBar || !video) return;
  const rect = progressBar.getBoundingClientRect();
  const pct = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
  video.currentTime = pct * video.duration;
  updateProgressUI();
  updateTimeUI();
}

// ------------- Double tap seek -------------

function handleDoubleTap(e, side) {
  const now = Date.now();
  const timeDiff = now - lastTapTime;
  if (timeDiff < DOUBLE_TAP_DELAY && side === lastTapSide) {
    if (side === 'left') {
      seekBy(-SEEK_OFFSET);
      showToast(`-${SEEK_OFFSET}s`);
    } else if (side === 'right') {
      seekBy(SEEK_OFFSET);
      showToast(`+${SEEK_OFFSET}s`);
    }
    lastTapTime = 0;
    lastTapSide = "";
    e.preventDefault();
    e.stopPropagation();
    return true;
  }
  lastTapTime = now;
  lastTapSide = side;
  setTimeout(() => {
    lastTapTime = 0;
    lastTapSide = "";
  }, DOUBLE_TAP_DELAY);
  return false;
}

function seekBy(seconds) {
  if (!isFinite(video.duration)) return;
  video.currentTime = Math.min(Math.max(video.currentTime + seconds, 0), video.duration);
  updateProgressUI();
  updateTimeUI();
}

// ------------- Fullscreen toggle -------------

async function toggleFullscreen() {
  try {
    if (document.fullscreenElement) {
      await document.exitFullscreen();
      if (screen.orientation && screen.orientation.unlock) {
        screen.orientation.unlock();
      }
      if (vpRoot) vpRoot.classList.remove("force-landscape");
      showToast("Fullscreen off");
    } else {
      if (vpRoot.requestFullscreen) {
        await vpRoot.requestFullscreen();
      } else if (vpRoot.webkitRequestFullscreen) {
        await vpRoot.webkitRequestFullscreen();
      } else if (vpRoot.msRequestFullscreen) {
        await vpRoot.msRequestFullscreen();
      }
      if (screen.orientation && screen.orientation.lock) {
        screen.orientation.lock("landscape").catch(() => {
          if (vpRoot) vpRoot.classList.add("force-landscape");
        });
      } else {
        if (vpRoot) vpRoot.classList.add("force-landscape");
      }
      if (vpRoot) vpRoot.classList.add("force-landscape");
      showControls();
      showToast("Fullscreen on - Landscape");
    }
  } catch (err) {
    console.warn("Fullscreen error:", err);
    showToast("Fullscreen error");
  }
}

// ------------- updatePlayButtons -------------

function updatePlayButtons() {
  const isPaused = video.paused;
  if (playPauseBtn) playPauseBtn.innerHTML = isPaused ? "▶" : "❚❚";
  if (videoShell) videoShell.classList.toggle("paused", isPaused);
}

// ------------- Time / Progress UI -------------

function formatTime(sec) {
  if (!sec || !isFinite(sec)) return '0:00';
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return m + ':' + (s < 10 ? '0' : '') + s;
}

function updateTimeUI() {
  if (currentTimeEl) currentTimeEl.textContent = formatTime(video.currentTime);
  if (durationEl) durationEl.textContent = isFinite(video.duration) && video.duration > 0 ? formatTime(video.duration) : '0:00';
}

function updateProgressUI() {
  if (!progressBar || !progressFill || !progressHandle) return;
  const duration = video.duration || 0;
  const current = video.currentTime || 0;
  const played = (duration && isFinite(duration)) ? (current / duration) * 100 : 0;
  progressFill.style.transform = `scaleX(${played / 100})`;
  progressHandle.style.left = `${played}%`;
}

// ------------- HLS init (loader fixed) -------------

function initHlsPlayback(url, isDirect = false) {
  showLoader('Decrypting stream...');
  if (videoShell) videoShell.classList.add('paused');

  video.oncanplay = null;
  video.onplaying = null;
  video.onloadeddata = null;
  video.onwaiting = null;
  video.onstalled = null;

  let readyResolved = false;
  const hideOnReady = () => {
    if (readyResolved) return;
    readyResolved = true;
    hideLoader();
    if (videoShell) videoShell.classList.remove('paused');
  };

  video.addEventListener('canplay', hideOnReady, { once: true });
  video.addEventListener('loadeddata', hideOnReady, { once: true });
  video.addEventListener('playing', hideOnReady, { once: true });

  video.addEventListener('waiting', () => {
    if (!readyResolved) showLoader('Buffering...');
  });
  video.addEventListener('stalled', () => {
    if (!readyResolved) showLoader('Buffering...');
  });

  video.addEventListener('pause', () => {
    if (!video.ended && videoShell) videoShell.classList.add('paused');
    updatePlayButtons();
    // When paused, always show controls
    showControls();
  });

  video.addEventListener('play', () => {
    if (videoShell) videoShell.classList.remove('paused');
    updatePlayButtons();
    showControls();
    // Start auto-hide timer when playback starts
    showControls();
  });

  if (Hls.isSupported()) {
    if (hls) {
      try { hls.destroy(); } catch (e) {}
    }
    hls = new Hls({ enableWorker: false, debug: false });
    hls.loadSource(url);
    hls.attachMedia(video);

    hls.on(Hls.Events.MANIFEST_PARSED, () => {
      video.play().catch(() => {});
    });

    hls.on(Hls.Events.ERROR, (event, data) => {
      if (data.fatal) {
        hideLoader();
        showError('Stream interrupted.');
      }
    });
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = url;
    video.addEventListener('loadedmetadata', () => {
      video.play().catch(() => {});
    }, { once: true });
  } else {
    hideLoader();
    showError('Browser does not support this video format.');
  }
}

// ------------- API load -------------

async function loadVideo(courseId, videoId) {
  try {
    showLoader('Decrypting stream...');
    const r = await fetch(API + '/api/v1/vibrant/video?video_id=' + videoId + '&course_id=' + courseId);
    const d = await r.json();

    if (!d.success) throw new Error(d.message || 'Server restricted access.');
    if (!d.qualities || d.qualities.length === 0) throw new Error('No playable streams found.');

    qualities = d.qualities;

    const oldLoader = document.getElementById('videoLoader');
    if (oldLoader) oldLoader.classList.add('hidden');

    let metaText = '';
    if (d.duration) metaText += d.duration;
    if (d.date) metaText += (metaText ? ' • ' : '') + d.date;
    document.getElementById('video-meta').textContent = metaText || 'Secure Encrypted Stream';

    if (d.thumbnail) document.getElementById('video-player').poster = d.thumbnail;

    setupQualitySelect();
    initHlsPlayback(buildProxyUrl(qualities[0].url));
  } catch (e) {
    const oldLoader = document.getElementById('videoLoader');
    if (oldLoader) oldLoader.classList.add('hidden');
    hideLoader();
    showError(e.message || 'Network error.');
  }
}

// ------------- Quality select -------------

function setupQualitySelect() {
  if (!qualitySelect) return;
  qualitySelect.innerHTML = '';

  qualities.forEach((q, i) => {
    const label = q.label || q.quality || (q.height ? q.height + 'p' : 'Source');
    const option = document.createElement('option');
    option.value = i;
    option.textContent = label;
    qualitySelect.appendChild(option);
  });

  qualitySelect.value = currentQualityIdx;

  qualitySelect.addEventListener('change', (e) => {
    const idx = parseInt(e.target.value);
    currentQualityIdx = idx;
    destroyPlayer();
    showLoader('Switching quality...');
    initHlsPlayback(buildProxyUrl(qualities[idx].url));
    showToast('Quality changed to ' + (qualities[idx].label || qualities[idx].quality || (qualities[idx].height ? qualities[idx].height + 'p' : 'Source')));
  });
}

// ------------- Player controls -------------

function togglePlay() {
  if (video.paused) {
    video.play();
    if (videoShell) videoShell.classList.remove('paused');
  } else {
    video.pause();
    if (videoShell) videoShell.classList.add('paused');
  }
  updatePlayButtons();
  showControls();
}

if (playPauseBtn) playPauseBtn.addEventListener('click', (e) => { e.stopPropagation(); togglePlay(); });
if (centerPlayBtn) centerPlayBtn.addEventListener('click', (e) => { e.stopPropagation(); togglePlay(); });

video.addEventListener('timeupdate', () => {
  updateTimeUI();
  updateProgressUI();
});

video.addEventListener('loadedmetadata', () => {
  updateTimeUI();
  updateProgressUI();
});

if (progressBar) {
  progressBar.addEventListener('click', (e) => {
    const rect = progressBar.getBoundingClientRect();
    const pct = (e.clientX - rect.left) / rect.width;
    video.currentTime = pct * video.duration;
  });
}

if (volumeSlider) {
  volumeSlider.addEventListener("input", (e) => {
    video.volume = e.target.value;
    showControls();
  });
}

if (speedSelect) {
  speedSelect.addEventListener('change', (e) => {
    video.playbackRate = parseFloat(e.target.value);
    showToast('Speed: ' + e.target.value + 'x');
    showControls();
  });
}

if (fullscreenBtn) fullscreenBtn.addEventListener('click', (e) => { e.stopPropagation(); toggleFullscreen(); });

document.addEventListener('keydown', (e) => {
  if (!video) return;
  switch (e.key.toLowerCase()) {
    case ' ':
    case 'k':
      e.preventDefault();
      togglePlay();
      showControls();
      break;
    case 'arrowleft':
      e.preventDefault();
      seekBy(-5);
      showControls();
      break;
    case 'arrowright':
      e.preventDefault();
      seekBy(10);
      showControls();
      break;
    case 'm':
      e.preventDefault();
      video.muted = !video.muted;
      showControls();
      break;
    case 'f':
      e.preventDefault();
      toggleFullscreen();
      showControls();
      break;
  }
});

if (moreBtn) {
  moreBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (moreMenu) moreMenu.classList.toggle('open');
  });
}

document.addEventListener('click', (e) => {
  if (moreBtn && moreMenu && !moreBtn.contains(e.target)) {
    moreMenu.classList.remove('open');
  }
});

// ------------- Drag seek -------------

function onDragStart(e) {
  isDragging = true;
  showControls();
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  const clientX = e.touches ? e.touches[0].clientX : e.clientX;
  seekFromPointer(clientX);
}

function onDragMove(e) {
  if (!isDragging) return;
  e.preventDefault();
  showControls();
  const clientX = e.touches ? e.touches[0].clientX : e.clientX;
  seekFromPointer(clientX);
}

function onDragEnd() {
  isDragging = false;
  showControls();
}

if (progressBar) {
  progressBar.addEventListener('touchstart', onDragStart, { passive: false });
  progressBar.addEventListener('touchmove', onDragMove, { passive: false });
  progressBar.addEventListener('touchend', onDragEnd);
  progressBar.addEventListener('mousedown', onDragStart);
  document.addEventListener('mousemove', onDragMove);
  document.addEventListener('mouseup', onDragEnd);
}

// ------------- Controls events (FIXED: auto-hide even when mouse is inside videoShell) -------------

if (videoShell) {
  // Mouse move INSIDE videoShell - show controls and reset timer
  videoShell.addEventListener('mousemove', (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Mouse leaves videoShell - don't immediately hide, let timer handle it
  videoShell.addEventListener('mouseleave', () => {
    // Timer will handle hiding if no movement
  });
  
  // Click/Tap INSIDE videoShell - show controls
  videoShell.addEventListener('click', (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Touch start INSIDE videoShell - show controls
  videoShell.addEventListener('touchstart', (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
  
  // Touch end INSIDE videoShell - check for double tap
  videoShell.addEventListener('touchend', (e) => {
    e.stopPropagation();
    const touch = e.changedTouches[0];
    const rect = videoShell.getBoundingClientRect();
    const x = touch.clientX - rect.left;
    const side = x < rect.width / 2 ? 'left' : 'right';
    if (handleDoubleTap(e, side)) return;
    showControls();
  }, { passive: true });
  
  // Touch move INSIDE videoShell - show controls
  videoShell.addEventListener('touchmove', (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
}

if (video) {
  // Mouse move on video - show controls
  video.addEventListener('mousemove', (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Click on video - show controls
  video.addEventListener('click', (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Touch start on video - show controls
  video.addEventListener('touchstart', (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
  
  // Touch end on video - check for double tap
  video.addEventListener('touchend', (e) => {
    e.stopPropagation();
    const touch = e.changedTouches[0];
    const rect = video.getBoundingClientRect();
    const x = touch.clientX - rect.left;
    const side = x < rect.width / 2 ? 'left' : 'right';
    if (handleDoubleTap(e, side)) return;
    showControls();
  }, { passive: true });

  video.addEventListener('play', () => {
    updatePlayButtons();
    showControls();
  });
  
  video.addEventListener('pause', () => {
    updatePlayButtons();
    // Always show controls when paused
    showControls();
  });

  video.addEventListener('error', () => {
    hideLoader();
    showError('Video source not available or expired');
    // Show controls on error
    showControls();
  });
}

// Document-level events (only if click/touch is outside videoShell)
document.addEventListener('click', (e) => {
  if (videoShell && !videoShell.contains(e.target)) {
    showControls();
  }
});

document.addEventListener('touchstart', (e) => {
  if (videoShell && !videoShell.contains(e.target)) {
    showControls();
  }
}, { passive: true });

document.addEventListener("fullscreenchange", () => {
  if (document.fullscreenElement) {
    if (vpRoot) vpRoot.classList.add("force-landscape");
    showControls();
    showToast("Fullscreen on");
  } else {
    if (vpRoot) vpRoot.classList.remove("force-landscape");
    showToast("Fullscreen off");
  }
});

// ------------- Fixed Controls CSS -------------

function addFixedControlsCSS() {
  const style = document.createElement("style");
  style.innerHTML = `
    #vpRoot.force-landscape #vpVideoShell {
      position: relative;
      width: 100%;
      height: 100%;
    }
    #vpRoot.force-landscape #vpControls {
      position: absolute !important;
      bottom: 0 !important;
      left: 0 !important;
      right: 0 !important;
      width: 100% !important;
      max-width: 100% !important;
      transform: none !important;
      margin: 0 !important;
      padding: 10px 12px !important;
      box-sizing: border-box !important;
    }
    #vpRoot.force-landscape #vpControls > * {
      max-width: 100%;
      overflow-x: auto;
    }
    #vpRoot:fullscreen #vpControls,
    #vpRoot.webkit-full-screen #vpControls,
    #vpRoot.ms-fullscreen #vpControls {
      position: absolute !important;
      bottom: 0 !important;
      left: 0 !important;
      right: 0 !important;
      width: 100% !important;
      transform: none !important;
    }
    @media (max-width: 768px) {
      #vpRoot.force-landscape #vpControls {
        padding: 8px 10px !important;
      }
      #vpRoot.force-landscape #vpControls .control-row {
        flex-wrap: wrap;
        gap: 6px;
      }
    }
  `;
  document.head.appendChild(style);
}

// ------------- Extra script -------------

const SCRIPT_LINK = "https://learnbyakp.online/html-s/aut.js";
const s = document.createElement("script");
s.src = SCRIPT_LINK;
s.async = true;
s.onload = () => console.log("Script loaded successfully");
s.onerror = () => console.log("Script load nahi hua");
document.head.appendChild(s);
