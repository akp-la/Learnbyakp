// =========================
// CUSTOM VIDEO PLAYER JS - FIXED CONTROLS HIDE/SHOW LOGIC
// =========================


const $ = (id) => document.getElementById(id);


const video = $("video");
const vpRoot = $("vpRoot");
const videoShell = $("vpVideoShell");
const vpControls = $("vpControls");


const playPauseBtn = $("playPauseBtn");
const centerPlayBtn = $("centerPlayBtn");
const backwardBtn = $("backwardBtn");
const forwardBtn = $("forwardBtn");
const muteBtn = $("muteBtn");
const volumeSlider = $("volumeSlider");
const fullscreenBtn = $("fullscreenBtn");
const fullscreenBtn2 = $("fullscreenBtn2");
const pipBtn = $("pipBtn");
const redirectBtn = $("redirectBtn");


const progressBar = $("vpProgressBar");
const progressFill = $("vpProgressFill");
const progressHandle = $("vpProgressHandle");
const bufferBar = $("vpBuffer");
const progressTooltip = $("vpProgressTooltip");


const currentTimeEl = $("vpCurrentTime");
const durationEl = $("vpDuration");
const toastEl = $("vpToast");


const liveBadge = $("vpLiveBadge");
const vodBadge = $("vpVodBadge");
const screenshotBtn = $("screenshotBtn");
const speedSelect = $("vpSpeedSelect");
const titleEl = $("videoTitleTxt");
const metaEl = $("vpMeta");


const videoLoader = $("videoLoader");
const loaderImg = $("loaderImg");
const loadText = $("loadText");


const moreBtn = $("moreBtn");
const moreMenu = $("moreMenu");
const qualitySelect = $("qualitySelect");


let hlsInstance = null;
let hideControlsTimer = null;
let isDragging = false;
let isLive = false;
let lastVolume = 1;
let currentSource = "";
let errorShown = false;


let errorBox = null;
let errorTitle = null;
let errorMsg = null;
let errorCloseBtn = null;

// Controls visibility timeout: 3 seconds
const CONTROLS_HIDE_TIMEOUT = 3000;


function showToast(message) {
  if (!toastEl) return;
  toastEl.textContent = message;
  toastEl.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toastEl.classList.remove("show"), 1800);
}


function showLoader(message = "Loading video...") {
  if (!videoLoader) return;
  videoLoader.style.display = "flex";
  const textEl = videoLoader.querySelector(".load-text");
  if (textEl) textEl.textContent = message;
}


function hideLoader() {
  if (!videoLoader) return;
  videoLoader.style.display = "none";
}


function formatTime(seconds) {
  if (!isFinite(seconds) || seconds < 0) return "00:00";
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  if (hrs > 0) {
    return `${String(hrs).padStart(2, "0")}:${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  }
  return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}


function clamp(num, min, max) {
  return Math.min(Math.max(num, min), max);
}


function updatePlayButtons() {
  const isPaused = video.paused;
  if (playPauseBtn) playPauseBtn.innerHTML = isPaused ? "▶" : "❚❚";
  if (videoShell) videoShell.classList.toggle("paused", isPaused);
}


function updateMuteUI() {
  if (!muteBtn || !volumeSlider) return;
  const muted = video.muted || video.volume === 0;
  muteBtn.innerHTML = muted ? "🔇" : "🔊";
  volumeSlider.value = muted ? 0 : video.volume;
}


function updateTimeUI() {
  if (currentTimeEl) currentTimeEl.textContent = formatTime(video.currentTime);
  if (durationEl) {
    durationEl.textContent = (isFinite(video.duration) && video.duration > 0) ? formatTime(video.duration) : "00:00";
  }
}


function updateProgressUI() {
  if (!progressBar || !progressFill || !progressHandle) return;

  const duration = video.duration || 0;
  const current = video.currentTime || 0;
  const played = (duration && isFinite(duration)) ? (current / duration) * 100 : 0;

  progressFill.style.transform = `scaleX(${played / 100})`;
  progressHandle.style.left = `${played}%`;

  try {
    if (video.buffered && video.buffered.length && bufferBar) {
      const bufferedEnd = video.buffered.end(video.buffered.length - 1);
      const buffered = (duration && isFinite(duration)) ? (bufferedEnd / duration) * 100 : 0;
      bufferBar.style.transform = `scaleX(${buffered / 100})`;
    }
  } catch (e) {}
}


// ✅ Show controls and START auto-hide timer
function showControls() {
  if (!videoShell) return;
  
  // Show controls
  videoShell.classList.add("user-active");
  
  // Clear existing timer
  if (hideControlsTimer) {
    clearTimeout(hideControlsTimer);
    hideControlsTimer = null;
  }
  
  // Start NEW timer to hide after 3 seconds of NO interaction
  hideControlsTimer = setTimeout(() => {
    hideControls();
  }, CONTROLS_HIDE_TIMEOUT);
}


// ✅ Hide controls and CLEAR timer
function hideControls() {
  if (!videoShell) return;
  
  // Clear timer
  if (hideControlsTimer) {
    clearTimeout(hideControlsTimer);
    hideControlsTimer = null;
  }
  
  // Hide controls
  videoShell.classList.remove("user-active");
}


// ✅ Toggle controls visibility
function toggleControls() {
  if (!videoShell) return;
  
  if (videoShell.classList.contains("user-active")) {
    hideControls();
  } else {
    showControls();
  }
}


function createErrorBox() {
  if (errorBox) return;

  const style = document.createElement("style");
  style.innerHTML = `
    #vpErrorBox {
      position: absolute;
      inset: 0;
      z-index: 200;
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
      font-family: system-ui, -apple-system, sans-serif;
    }
    #vpErrorBox.show {
      opacity: 1;
      pointer-events: auto;
    }
    .error-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(4, 7, 20, 0.75);
      backdrop-filter: blur(10px);
    }
    .error-card {
      position: relative;
      background: linear-gradient(145deg, rgba(20, 26, 45, 0.95), rgba(9, 13, 26, 0.98));
      border: 1px solid rgba(255, 75, 129, 0.35);
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8), 0 0 25px rgba(255, 75, 129, 0.15);
      border-radius: 22px;
      padding: 40px 30px;
      width: 90%;
      max-width: 340px;
      text-align: center;
      transform: translateY(20px) scale(0.95);
      transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    #vpErrorBox.show .error-card {
      transform: translateY(0) scale(1);
    }
    .error-close {
      position: absolute;
      top: 14px;
      right: 14px;
      background: rgba(255, 255, 255, 0.05);
      border: none;
      color: rgba(255, 255, 255, 0.6);
      width: 32px;
      height: 32px;
      border-radius: 50%;
      font-size: 18px;
      line-height: 1;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.25s ease;
    }
    .error-close:hover {
      background: rgba(255, 75, 129, 0.2);
      color: #ff4b81;
      transform: rotate(90deg);
    }
    .error-icon-wrap {
      margin: 0 auto 20px;
      width: 72px;
      height: 72px;
      border-radius: 50%;
      background: rgba(255, 75, 129, 0.08);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 2px solid rgba(255, 75, 129, 0.5);
      box-shadow: 0 0 25px rgba(255, 75, 129, 0.2);
      animation: vpPulseError 2s infinite ease-in-out;
    }
    .error-icon {
      font-size: 32px;
      color: #ff4b81;
      text-shadow: 0 0 15px rgba(255, 75, 129, 0.5);
    }
    @keyframes vpPulseError {
      0% { box-shadow: 0 0 0 0 rgba(255, 75, 129, 0.4); }
      70% { box-shadow: 0 0 0 15px rgba(255, 75, 129, 0); }
      100% { box-shadow: 0 0 0 0 rgba(255, 75, 129, 0); }
    }
    #vpErrorTitle {
      margin: 0 0 8px;
      color: #ffffff;
      font-size: 20px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }
    #vpErrorMsg {
      margin: 0;
      color: #9aa3d8;
      font-size: 14px;
      line-height: 1.5;
    }
  `;
  document.head.appendChild(style);

  errorBox = document.createElement("div");
  errorBox.id = "vpErrorBox";
  errorBox.className = "error-box";

  errorBox.innerHTML = `
    <div class="error-backdrop"></div>
    <div class="error-card">
      <button id="vpErrorClose" class="error-close" aria-label="Close error">✖</button>
      <div class="error-icon-wrap">
        <div class="error-icon">✕</div>
      </div>
      <h3 id="vpErrorTitle">Video Not Found</h3>
      <p id="vpErrorMsg">Video source not available or expired.</p>
    </div>
  `;

  (vpRoot || document.body).appendChild(errorBox);

  errorTitle = errorBox.querySelector("#vpErrorTitle");
  errorMsg = errorBox.querySelector("#vpErrorMsg");
  errorCloseBtn = errorBox.querySelector("#vpErrorClose");

  errorCloseBtn.addEventListener("click", hideSourceError);
  errorBox.addEventListener("click", (e) => {
    if (e.target === errorBox || e.target.classList.contains("error-backdrop")) hideSourceError();
  });
}


function showSourceError(message = "Video source not available or expired") {
  if (!errorBox) createErrorBox();
  errorShown = true;
  hideLoader();
  if (errorTitle) errorTitle.textContent = "Video Not Found";
  if (errorMsg) errorMsg.textContent = message;
  
  requestAnimationFrame(() => errorBox.classList.add("show"));
}


function hideSourceError() {
  errorShown = false;
  if (errorBox) {
    errorBox.classList.remove("show");
  }
}


function handlePlayerError(message) {
  showSourceError(message);
}


function handleTooltip(e) {
  if (!progressBar || !progressTooltip || !isFinite(video.duration)) return;
  const rect = progressBar.getBoundingClientRect();
  const ratio = clamp((e.clientX - rect.left) / rect.width, 0, 1);
  const hoverTime = ratio * video.duration;
  progressTooltip.textContent = formatTime(hoverTime);
  progressTooltip.style.left = `${ratio * 100}%`;
}


function updateBadges() {
  isLive = isLive || video.duration === Infinity;

  if (liveBadge && vodBadge) {
    if (isLive) {
      liveBadge.style.display = "inline-flex";
      vodBadge.style.display = "none";
    } else {
      liveBadge.style.display = "none";
      vodBadge.style.display = "inline-flex";
    }
  }
}


function getLevelLabel(level) {
  if (!level) return "";
  if (level.height) return String(level.height);
  if (level.bitrate) return String(Math.round(level.bitrate / 1000));
  return "";
}


function initQualitySelect() {
  if (!qualitySelect) return;

  if (!window.hlsInstance || !hlsInstance?.levels?.length) {
    qualitySelect.value = "auto";
    if (qualitySelect.parentElement) qualitySelect.parentElement.style.display = "none";
    return;
  }

  if (qualitySelect.parentElement) qualitySelect.parentElement.style.display = "flex";

  const currentLevel = hlsInstance.currentLevel;
  if (currentLevel === -1) {
    qualitySelect.value = "auto";
  } else {
    const current = hlsInstance.levels[currentLevel];
    const label = getLevelLabel(current);
    qualitySelect.value = qualitySelect.querySelector(`option[value="${label}"]`) ? label : "auto";
  }

  qualitySelect.onchange = () => {
    if (!window.hlsInstance || !hlsInstance.levels?.length) return;
    const value = qualitySelect.value;

    if (value === "auto") {
      hlsInstance.currentLevel = -1;
      showToast("Quality: Auto");
      return;
    }

    const targetLevel = hlsInstance.levels.findIndex((lvl) => getLevelLabel(lvl) === value);
    if (targetLevel >= 0) {
      hlsInstance.currentLevel = targetLevel;
      showToast(`Quality: ${value}p`);
    } else {
      hlsInstance.currentLevel = -1;
      qualitySelect.value = "auto";
      showToast("Quality: Auto");
    }
  };
}


async function togglePlay() {
  try {
    if (video.paused) {
      await video.play();
    } else {
      video.pause();
    }
  } catch (err) {
    console.error("Play/Pause error:", err);
    handlePlayerError("Unable to play this video");
  }
}


function seekBy(seconds) {
  if (!isFinite(video.duration)) return;
  video.currentTime = clamp(video.currentTime + seconds, 0, video.duration);
}


function setPlaybackRate(rate) {
  video.playbackRate = Number(rate) || 1;
  showToast(`Speed: ${video.playbackRate}x`);
}


function seekFromPointer(clientX) {
  if (!progressBar || !isFinite(video.duration)) return;
  const rect = progressBar.getBoundingClientRect();
  const ratio = clamp((clientX - rect.left) / rect.width, 0, 1);
  video.currentTime = ratio * video.duration;
  updateProgressUI();
  updateTimeUI();
}


function onDragStart(e) {
  isDragging = true;
  showControls();
  
  // Exit fullscreen on drag
  if (document.fullscreenElement) {
    document.exitFullscreen().catch(() => {});
  }
  
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


function toggleMute() {
  if (video.muted || video.volume === 0) {
    video.muted = false;
    video.volume = lastVolume > 0 ? lastVolume : 1;
  } else {
    lastVolume = video.volume;
    video.muted = true;
  }
  updateMuteUI();
}


function setVolume(value) {
  const vol = clamp(Number(value), 0, 1);
  video.volume = vol;
  video.muted = vol === 0;
  if (vol > 0) lastVolume = vol;
  updateMuteUI();
}


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


async function togglePip() {
  try {
    if (!document.pictureInPictureEnabled) {
      showToast("PiP not supported");
      return;
    }
    if (document.pictureInPictureElement) {
      await document.exitPictureInPicture();
    } else {
      await video.requestPictureInPicture();
    }
  } catch (err) {
    console.error("PiP error:", err);
  }
}


function takeScreenshot() {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth || video.clientWidth;
    canvas.height = video.videoHeight || video.clientHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    canvas.toBlob((blob) => {
      if (!blob) return;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `Learnbyakp-screenshot-${Date.now()}.png`;
      a.click();
      URL.revokeObjectURL(a.href);
    }, "image/png");

    showToast("Screenshot saved");
  } catch (err) {
    console.error("Screenshot error:", err);
    showToast("Screenshot failed");
  }
}


function getFileUrlFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get("file_url") || params.get("src") || params.get("fileurl");
}


function getTitleFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get("title");
}


function downloadOrRedirect() {
  const fileUrl = getFileUrlFromQuery();
  const title = getTitleFromQuery();

  if (!fileUrl) {
    alert("URL me ?file_url= nahi mila.");
    return;
  }

  const encodedFile = encodeURIComponent(fileUrl);
  const encodedTitle = title ? encodeURIComponent(title) : "";
  let target = `dow?file_url=${encodedFile}`;
  if (encodedTitle) {
    target += `&title=${encodedTitle}`;
  }
  window.location.href = target;
}


function toggleMoreMenu(e) {
  e?.stopPropagation();
  if (!moreMenu) return;
  moreMenu.classList.toggle("open");
  showControls();
}


function closeMoreMenu(e) {
  if (!moreMenu || !moreBtn) return;
  if (moreMenu.contains(e.target) || moreBtn.contains(e.target)) return;
  moreMenu.classList.remove("open");
}


function isHlsSource(src) {
  const s = (src || "").toLowerCase();
  return s.includes(".m3u8") || s.includes("application/vnd.apple.mpegurl");
}


function setupNativeFallback(src) {
  hideSourceError();
  video.src = src;

  video.addEventListener("loadedmetadata", () => {
    hideLoader();
    hideSourceError();
    updateTimeUI();
    updateProgressUI();
    updateBadges();
  }, { once: true });

  video.addEventListener("canplay", () => {
    hideLoader();
    hideSourceError();
    video.play().catch(() => {});
  }, { once: true });

  video.addEventListener("error", () => {
    hideLoader();
    showSourceError("Video source not available or expired");
  }, { once: true });

  setTimeout(() => {
    if (!video.videoWidth && video.error && !errorShown) {
      showSourceError("Video source not available or expired");
    }
  }, 1200);
}


function initHls(src) {
  hideSourceError();

  if (window.Hls && Hls.isSupported()) {
    hlsInstance = new Hls({
      enableWorker: true,
      lowLatencyMode: false,
      backBufferLength: 90,
      maxBufferLength: 20,
      maxMaxBufferLength: 300,
      startLevel: -1
    });
    window.hlsInstance = hlsInstance;

    hlsInstance.loadSource(src);
    hlsInstance.attachMedia(video);

    hlsInstance.on(Hls.Events.MANIFEST_PARSED, (event, data) => {
      hideLoader();
      updateTimeUI();
      updateProgressUI();
      initQualitySelect();
      updateBadges();
      video.play().catch(() => {});
    });

    hlsInstance.on(Hls.Events.LEVEL_SWITCHED, initQualitySelect);

    hlsInstance.on(Hls.Events.ERROR, (event, data) => {
      if (!data?.fatal) return;
      hideLoader();

      switch (data.type) {
        case Hls.ErrorTypes.NETWORK_ERROR:
          showSourceError("Network error while loading stream");
          try { hlsInstance.startLoad(); } catch (e) {}
          break;
        case Hls.ErrorTypes.MEDIA_ERROR:
          showSourceError("Media error while playing stream");
          try { hlsInstance.recoverMediaError(); } catch (e) {}
          break;
        default:
          showSourceError("Video source not available or expired");
          try { hlsInstance.destroy(); } catch (e) {}
          break;
      }
    });
  } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
    video.src = src;
    video.addEventListener("loadedmetadata", () => {
      hideLoader();
      hideSourceError();
      updateTimeUI();
      updateProgressUI();
      updateBadges();
      video.play().catch(() => {});
    }, { once: true });

    video.addEventListener("error", () => {
      hideLoader();
      showSourceError("Video source not available or expired");
    }, { once: true });
  } else {
    hideLoader();
    showSourceError("HLS playback is not supported");
  }
}


function initPlayer() {
  if (!video) return;

  createErrorBox();

  const urlParams = new URLSearchParams(window.location.search);
  const paramSrc = urlParams.get("src") || urlParams.get("file_url") || urlParams.get("fileurl");
  const paramTitle = urlParams.get("title");
  const paramMeta = urlParams.get("meta");

  if (urlParams.get("live") === "true" || video.dataset.live === "true") {
    isLive = true;
  }

  if (titleEl) titleEl.textContent = paramTitle || video.dataset.title || "Video";
  if (metaEl) metaEl.textContent = paramMeta || "Learn By AKP";

  const src = paramSrc || video.getAttribute("data-src") || video.dataset.src || video.getAttribute("src");
  currentSource = src || "";

  if (!currentSource) {
    showSourceError("Video source missing");
    hideLoader();
    return;
  }

  showLoader("Loading video...");

  if (isHlsSource(currentSource)) {
    initHls(currentSource);
  } else {
    setupNativeFallback(currentSource);
  }
}


// ================= EVENT LISTENERS - FIXED: vpVideoShell INSIDE/OUTSIDE HANDLING =================


// ✅ LEVEL 1: vpVideoShell DIV - Mouse/touch INSIDE the shell
if (videoShell) {
  // Mouse enters vpVideoShell - show controls
  videoShell.addEventListener("mouseenter", () => {
    showControls();
  });
  
  // Mouse leaves vpVideoShell - don't immediately hide, let timer handle it
  
  // Mouse move INSIDE vpVideoShell - show controls and reset timer
  videoShell.addEventListener("mousemove", (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Click/Tap INSIDE vpVideoShell - toggle controls
  videoShell.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleControls();
  });
  
  // Touch start INSIDE vpVideoShell - show controls
  videoShell.addEventListener("touchstart", (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
  
  // Touch move INSIDE vpVideoShell - show controls
  videoShell.addEventListener("touchmove", (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
  
  // Touch end INSIDE vpVideoShell - let timer handle hiding
  videoShell.addEventListener("touchend", (e) => {
    e.stopPropagation();
  });
}


// ✅ LEVEL 2: Video element - Mouse/touch on video itself
if (video) {
  // Mouse move on video - show controls
  video.addEventListener("mousemove", (e) => {
    e.stopPropagation();
    showControls();
  });
  
  // Click on video - toggle controls (NOT play/pause)
  video.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleControls();
  });
  
  // Touch on video - show controls
  video.addEventListener("touchstart", (e) => {
    e.stopPropagation();
    showControls();
  }, { passive: true });
  
  video.addEventListener("play", () => {
    updatePlayButtons();
    showControls();
  });
  
  video.addEventListener("pause", () => {
    updatePlayButtons();
  });
  
  video.addEventListener("timeupdate", () => {
    updateTimeUI();
    updateProgressUI();
  });
  
  video.addEventListener("loadedmetadata", () => {
    updateTimeUI();
    updateProgressUI();
    updateBadges();
  });
  
  video.addEventListener("canplay", hideLoader);
  
  video.addEventListener("playing", () => {
    hideLoader();
    updatePlayButtons();
    hideSourceError();
    showControls();
  });
  
  video.addEventListener("waiting", () => showLoader("Loading..."));
  video.addEventListener("progress", updateProgressUI);
  video.addEventListener("volumechange", updateMuteUI);
  
  video.addEventListener("error", () => {
    hideLoader();
    showSourceError("Video source not available or expired");
  });
}


// ✅ LEVEL 3: Document-level - Mouse/touch OUTSIDE vpVideoShell
// Mouse move anywhere on document - show controls
document.addEventListener("mousemove", (e) => {
  // Only show if not inside videoShell (to avoid duplicates)
  if (!videoShell || !videoShell.contains(e.target)) {
    showControls();
  }
});

// Click anywhere on document
document.addEventListener("click", (e) => {
  // If click is outside videoShell, toggle controls
  if (videoShell && !videoShell.contains(e.target)) {
    toggleControls();
  }
});

// Touch start anywhere on document
document.addEventListener("touchstart", (e) => {
  // If touch is outside videoShell, show controls
  if (videoShell && !videoShell.contains(e.target)) {
    showControls();
  }
}, { passive: true });


if (playPauseBtn) playPauseBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  togglePlay();
  showControls();
});

if (centerPlayBtn) centerPlayBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  togglePlay();
  showControls();
});

if (backwardBtn) backwardBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  seekBy(-10);
  showControls();
});

if (forwardBtn) forwardBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  seekBy(10);
  showControls();
});

if (muteBtn) muteBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleMute();
  showControls();
});

if (pipBtn) pipBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  togglePip();
  showControls();
});

if (screenshotBtn) screenshotBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  takeScreenshot();
  showControls();
});

if (redirectBtn) redirectBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  downloadOrRedirect();
});

if (moreBtn) moreBtn.addEventListener("click", toggleMoreMenu);


if (fullscreenBtn2) {
  fullscreenBtn2.onclick = async (e) => {
    e.stopPropagation();
    await toggleFullscreen();
    showControls();
  };
}

if (fullscreenBtn) {
  fullscreenBtn.onclick = async (e) => {
    e.stopPropagation();
    await toggleFullscreen();
    showControls();
  };
}

if (volumeSlider) {
  volumeSlider.addEventListener("input", (e) => {
    setVolume(e.target.value);
    showControls();
  });
}

if (speedSelect) {
  speedSelect.addEventListener("change", (e) => {
    setPlaybackRate(e.target.value);
    showControls();
  });
}

if (progressBar) {
  progressBar.addEventListener("mousedown", onDragStart);
  progressBar.addEventListener("touchstart", onDragStart, { passive: false });
  progressBar.addEventListener("mousemove", (e) => {
    progressTooltip?.classList.add("show");
    handleTooltip(e);
  });
  progressBar.addEventListener("mouseleave", () => {
    progressTooltip?.classList.remove("show");
  });
}

document.addEventListener("mousemove", onDragMove);
document.addEventListener("touchmove", onDragMove, { passive: false });
document.addEventListener("mouseup", onDragEnd);
document.addEventListener("touchend", onDragEnd);
document.addEventListener("click", closeMoreMenu);


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

document.addEventListener("keydown", (e) => {
  if (!video) return;

  switch (e.key.toLowerCase()) {
    case " ":
    case "k":
      e.preventDefault();
      togglePlay();
      showControls();
      break;
    case "arrowleft":
      e.preventDefault();
      seekBy(-5);
      showControls();
      break;
    case "arrowright":
      e.preventDefault();
      seekBy(10);
      showControls();
      break;
    case "m":
      e.preventDefault();
      toggleMute();
      showControls();
      break;
    case "f":
      e.preventDefault();
      toggleFullscreen();
      showControls();
      break;
    case "p":
      e.preventDefault();
      togglePip();
      showControls();
      break;
  }
});

document.addEventListener("DOMContentLoaded", () => {
  createErrorBox();
  initPlayer();
  updatePlayButtons();
  updateMuteUI();
  updateTimeUI();
  updateProgressUI();
  showControls();
});

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
