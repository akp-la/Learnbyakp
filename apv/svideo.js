const API_SERVER = "https://learnbyakp.onrender.com";

const urlParams = new URLSearchParams(window.location.search);
const courseId = urlParams.get('course_id');
const videoId = urlParams.get('video_id');
const isLive = urlParams.get('isLive') === 'true';

// Global Elements Selection (No Duplicate Declarations)
const video = document.getElementById('video');
const vpRoot = document.getElementById('vpRoot');
const vpVideoShell = document.getElementById('vpVideoShell');
const vpControls = document.getElementById('vpControls');
const vpLoading = document.getElementById('vpLoading');
const vpErrorOverlay = document.getElementById('vpErrorOverlay');
const vpErrorMsg = document.getElementById('vpErrorMsg');
const vpRetryBtn = document.getElementById('vpRetryBtn');
const vpQualityModal = document.getElementById('vpQualityModal');
const vpQualityList = document.getElementById('vpQualityList');
const vpCloseQuality = document.getElementById('vpCloseQuality');
const videoTitleTxt = document.getElementById('videoTitleTxt');
const vpMeta = document.getElementById('vpMeta');
const vpLiveBadge = document.getElementById('vpLiveBadge');
const vpVodBadge = document.getElementById('vpVodBadge');
const centerPlayBtn = document.getElementById('centerPlayBtn');

const backwardBtn = document.getElementById('backwardBtn');
const playPauseBtn = document.getElementById('playPauseBtn');
const forwardBtn = document.getElementById('forwardBtn');
const muteBtn = document.getElementById('muteBtn');
const volumeSlider = document.getElementById('volumeSlider');
const vpSpeedSelect = document.getElementById('vpSpeedSelect');
const fullscreenBtn = document.getElementById('fullscreenBtn');
const pipBtn = document.getElementById('pipBtn');
const screenshotBtn = document.getElementById('screenshotBtn');

const moreBtn = document.getElementById('moreBtn');
const moreMenu = document.getElementById('moreMenu');
const vpToast = document.getElementById('vpToast');

const vpProgressBar = document.getElementById('vpProgressBar');
const vpProgressFill = document.getElementById('vpProgressFill');
const vpBuffer = document.getElementById('vpBuffer');
const vpProgressHandle = document.getElementById('vpProgressHandle');
const vpProgressTooltip = document.getElementById('vpProgressTooltip');
const vpCurrentTime = document.getElementById('vpCurrentTime');
const vpDuration = document.getElementById('vpDuration');

let hls = null;
let videoData = null;
let isKeyValid = false;
let isScrubbing = false;
let controlsTimeout;

// ================= 1. AUTO-HIDE & CLICK TOGGLE SYSTEM =================

function showControls() {
  vpVideoShell.classList.add('user-active');
  clearTimeout(controlsTimeout);
  
  // Timer tabhi chalega jab video PLAY ho rhi ho aur Settings Menu BAND ho
  if (!video.paused && !moreMenu.classList.contains('open')) {
    controlsTimeout = setTimeout(hideControls, 4000); // 3 Seconds automatic hide
  }
}

function hideControls() {
  // Agar video pause hai ya settings menu open hai, toh controls mat chupao
  if (video.paused || moreMenu.classList.contains('open')) return;
  vpVideoShell.classList.remove('user-active');
}

// Mouse movements handlers
vpVideoShell.addEventListener('mousemove', showControls);
vpVideoShell.addEventListener('mouseenter', showControls);

vpVideoShell.addEventListener('mouseleave', () => {
  if (!video.paused) {
    clearTimeout(controlsTimeout);
    controlsTimeout = setTimeout(hideControls, 1000); // Bahar jaane par 1 sec mein hide
  }
});

// Controls bar par mouse hone par hide nahi hoga
vpControls.addEventListener('mousemove', (e) => {
  e.stopPropagation();
  vpVideoShell.classList.add('user-active');
  clearTimeout(controlsTimeout);
});

// Video screen click toggle
video.addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  if (vpVideoShell.classList.contains('user-active')) {
    hideControls();
  } else {
    showControls();
  }
});

// ================= 2. KEYBOARD SHORTCUTS SYSTEM =================
document.addEventListener('keydown', (e) => {
  if (document.activeElement.tagName === 'SELECT' || document.activeElement.tagName === 'INPUT') {
    return;
  }

  const keyCode = e.code;
  switch (keyCode) {
    case 'Space':
    case 'KeyK':
      e.preventDefault();
      showControls();
      if (video.paused) video.play(); else video.pause();
      break;
    case 'ArrowRight':
    case 'KeyL':
      e.preventDefault();
      showControls();
      video.currentTime = Math.min(video.duration, video.currentTime + 10);
      break;
    case 'ArrowLeft':
    case 'KeyJ':
      e.preventDefault();
      showControls();
      video.currentTime = Math.max(0, video.currentTime - 10);
      break;
    case 'ArrowUp':
      e.preventDefault();
      showControls();
      video.volume = Math.min(1, video.volume + 0.1);
      break;
    case 'ArrowDown':
      e.preventDefault();
      showControls();
      video.volume = Math.max(0, video.volume - 0.1);
      break;
    case 'KeyM':
      e.preventDefault();
      showControls();
      video.muted = !video.muted;
      break;
    case 'KeyF':
      e.preventDefault();
      showControls();
      if (!document.fullscreenElement) {
        vpRoot.requestFullscreen().catch(err => console.log("Error entering fullscreen:", err));
      } else {
        document.exitFullscreen();
      }
      break;
  }
});

// ================= 3. CORE VIDEO PLAYER LOGIC =================

function showLoading(show) {
  vpLoading.style.display = show ? 'flex' : 'none';
}

function showError(msg) {
  vpErrorMsg.textContent = msg;
  vpErrorOverlay.style.display = 'flex';
}

function hideError() {
  vpErrorOverlay.style.display = 'none';
}

function showToast(msg) {
  vpToast.textContent = msg;
  vpToast.classList.add('show');
  setTimeout(() => vpToast.classList.remove('show'), 2000);
}

function checkKeyValidity() {
  const accessKey = localStorage.getItem('delta-access-key');
  const expiration = localStorage.getItem('delta-key-expiration');
  if (accessKey && expiration) {
    const now = Date.now();
    if (now < parseInt(expiration, 10)) {
      isKeyValid = true;
      return;
    }
    localStorage.removeItem('delta-access-key');
    localStorage.removeItem('delta-key-expiration');
  }
  isKeyValid = false;
}

async function decryptLiveUrl(encPath) {
  const key = new TextEncoder().encode("638udh3829162018");
  const iv = new TextEncoder().encode("fedcba9876543210");
  const encodedBuffer = window.atob(encPath).split("").map(c => c.charCodeAt(0));
  const buffer = new Uint8Array(encodedBuffer).buffer;
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-CBC", length: 128 }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, cryptoKey, buffer);
  let result = new TextDecoder().decode(decrypted);
  const padding = result.charCodeAt(result.length - 1);
  if (padding > 0 && padding <= 16) {
    const isValid = result.slice(-padding).split("").every(c => c.charCodeAt(0) === padding);
    if (isValid) result = result.slice(0, -padding);
  }
  return result;
}

async function decryptVideoUrl(encPath, encKey = "") {
  const res = await fetch(`${API_SERVER}/api/science/url?url=${encodeURIComponent(encPath)}&key=${encodeURIComponent(encKey)}`);
  if (!res.ok) throw new Error('Decrypt API error');
  const data = await res.json();
  if (!data.success) throw new Error(data.error || 'Decryption failed');
  const { url, key } = data.data;
  return `${API_SERVER}/api/science/play?url=${encodeURIComponent(url)}&key=${encodeURIComponent(key)}`;
}

function destroyHls() {
  if (hls) {
    hls.destroy();
    hls = null;
  }
}

function loadFileSource(fileUrl) {
  showLoading(true);
  hideError();
  destroyHls();

  video.pause();
  video.removeAttribute('src');
  video.load();

  video.src = fileUrl;
  video.muted = false;
  video.playsInline = true;

  const onLoaded = async () => {
    showLoading(false);
    try { await video.play(); } catch (err) { console.warn('Autoplay blocked:', err); }
    video.removeEventListener('loadedmetadata', onLoaded);
  };
  const onError = () => {
    showLoading(false);
    showError('Video load error (file source)');
    video.removeEventListener('error', onError);
  };

  video.addEventListener('loadedmetadata', onLoaded);
  video.addEventListener('error', onError);
}

function loadHlsSource(m3u8Url) {
  showLoading(true);
  hideError();
  destroyHls();

  video.pause();
  video.removeAttribute('src');
  video.load();

  if (Hls.isSupported()) {
    hls = new Hls({ enableWorker: true, lowLatencyMode: false });
    hls.attachMedia(video);
    hls.on(Hls.Events.MEDIA_ATTACHED, () => {
      hls.loadSource(m3u8Url);
    });
    hls.on(Hls.Events.MANIFEST_PARSED, async () => {
      showLoading(false);
      try { await video.play(); } catch (e) { console.warn('Autoplay blocked', e); }
    });
    hls.on(Hls.Events.ERROR, (event, data) => {
      console.error('HLS error:', data);
      if (data.fatal) {
        showLoading(false);
        showError("Video playback failed: " + data.type);
      }
    });
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = m3u8Url;
    video.addEventListener('loadedmetadata', async () => {
      showLoading(false);
      try { await video.play(); } catch (e) { console.warn(e); }
    }, { once: true });
  } else {
    showLoading(false);
    showError("Your browser does not support HLS playback");
  }
}

async function fetchVideoDetails() {
  if (!courseId || !videoId) {
    showError("Course ID or Video ID is missing");
    return;
  }
  showLoading(true);
  hideError();

  try {
    const response = await fetch(`${API_SERVER}/api/science/video-details?video_id=${videoId}&course_id=${courseId}`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || "Failed to fetch video details");
    }
    const result = await response.json();
    if (result.status !== 200 || !result.data) {
      throw new Error(result.message || "Invalid video details response");
    }

    videoData = result.data;
    videoTitleTxt.textContent = videoData.title || "Video";
    vpMeta.textContent = `${videoData.course_name || ''} • ${videoData.duration || ''}`;

    if (isLive) {
      vpLiveBadge.style.display = 'inline';
      vpVodBadge.style.display = 'none';

      if (videoData.livestream_links && videoData.livestream_links.length > 0) {
        showQualityModal(videoData.livestream_links, true);
        return;
      } else if (videoData.recording_schedule) {
        const recordingUrl = `https://liveclasses.cloud-front.in/live/${videoData.recording_schedule}_appxabr.m3u8`;
        loadHlsSource(recordingUrl);
        return;
      } else {
        throw new Error("No playable live stream or recording found");
      }
    } else {
      vpLiveBadge.style.display = 'none';
      vpVodBadge.style.display = 'inline';

      if (videoData.encrypted_links && videoData.encrypted_links.length > 0) {
        showQualityModal(videoData.encrypted_links, false);
        return;
      } else {
        throw new Error("No playable sources found");
      }
    }
  } catch (e) {
    console.error(e);
    showError(e.message);
  } finally {
    showLoading(false);
  }
}

function showQualityModal(sources, isLiveSource) {
  vpQualityList.innerHTML = '';
  sources.forEach(source => {
    const btn = document.createElement('button');
    btn.className = 'vp-quality-item';
    btn.innerHTML = `
      <span>
        <svg style="display: inline-block; margin-right: 0.5rem; width: 1.25rem; height: 1.25rem;" viewBox="0 0 24 24" fill="none" stroke="var(--vp-accent)" stroke-width="2">
          <rect width="20" height="15" x="2" y="7" rx="2" ry="2"/>
          <polyline points="17 2 12 7 7 2"/>
        </svg>
        ${source.quality}
      </span>
      <svg style="width: 1.5rem; height: 1.5rem; color: var(--vp-accent);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="m9 18 6-6-6-6"/>
      </svg>
    `;
    btn.onclick = () => selectQuality(source, isLiveSource);
    vpQualityList.appendChild(btn);
  });
  vpQualityModal.classList.add('open');
}

async function selectQuality(source, isLiveSource) {
  vpQualityModal.classList.remove('open');
  showLoading(true);
  hideError();

  try {
    if (isLiveSource) {
      const liveUrl = await decryptLiveUrl(source.path);
      loadHlsSource(liveUrl);
    } else {
      const playUrl = await decryptVideoUrl(source.path, source.key || "");
      loadFileSource(playUrl);
    }
  } catch (e) {
    console.error(e);
    showError("Failed to load video: " + e.message);
    showLoading(false);
  }
}

vpCloseQuality.onclick = () => { vpQualityModal.classList.remove('open'); };
vpRetryBtn.onclick = () => { hideError(); fetchVideoDetails(); };

function formatTime(sec) {
  if (isNaN(sec)) return "00:00:00";
  sec = Math.floor(sec);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function updatePlayState() {
  if (video.paused) {
    playPauseBtn.textContent = '▶';
    centerPlayBtn.style.display = 'block';
    vpVideoShell.classList.add('paused');
  } else {
    playPauseBtn.textContent = '⏸';
    centerPlayBtn.style.display = 'none';
    vpVideoShell.classList.remove('paused');
  }
}

playPauseBtn.addEventListener('click', async () => {
  if (video.paused) { try { await video.play(); } catch(e) { console.warn(e); } }
  else video.pause();
  updatePlayState();
});

centerPlayBtn.addEventListener('click', async () => {
  if (video.paused) { try { await video.play(); } catch(e) { console.warn(e); } }
  else video.pause();
  updatePlayState();
});

backwardBtn.addEventListener('click', () => { video.currentTime = Math.max(0, video.currentTime - 10); showControls(); });
forwardBtn.addEventListener('click', () => { video.currentTime = Math.min(video.duration || Infinity, video.currentTime + 10); showControls(); });

muteBtn.addEventListener('click', () => {
  video.muted = !video.muted;
  muteBtn.textContent = video.muted ? '🔊' : '🔇';
  volumeSlider.value = video.muted ? 0 : video.volume;
});

volumeSlider.addEventListener('input', () => {
  const val = parseFloat(volumeSlider.value);
  video.volume = val;
  video.muted = val === 0;
  muteBtn.textContent = video.muted ? '🔊' : '🔇';
});

vpSpeedSelect.addEventListener('change', () => { video.playbackRate = parseFloat(vpSpeedSelect.value); });
fullscreenBtn.addEventListener('click', () => {
  if (!document.fullscreenElement) vpRoot.requestFullscreen().catch(console.error);
  else document.exitFullscreen().catch(console.error);
});

pipBtn.addEventListener('click', async () => {
  try {
    if (document.pictureInPictureElement) { await document.exitPictureInPicture(); }
    else if (document.pictureInPictureEnabled) { await video.requestPictureInPicture(); }
    else { showToast("PiP not supported"); }
  } catch (e) { console.error(e); }
});

screenshotBtn.addEventListener('click', () => {
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const dataUrl = canvas.toDataURL('image/png');
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = (videoData?.title || 'screenshot') + '.png';
  a.click();
  showToast("Screenshot saved");
});

moreBtn.addEventListener('click', (e) => { e.stopPropagation(); moreMenu.classList.toggle('open'); showControls(); });
moreMenu.addEventListener('click', (e) => { e.stopPropagation(); });

document.addEventListener('click', (e) => {
  if (!moreMenu.contains(e.target) && e.target !== moreBtn) {
    moreMenu.classList.remove('open');
  }
});

video.addEventListener('waiting', () => showLoading(true));
video.addEventListener('stalled', () => showLoading(true));
video.addEventListener('seeking', () => showLoading(true));
video.addEventListener('playing', () => showLoading(false));
video.addEventListener('canplay', () => showLoading(false));
video.addEventListener('seeked', () => showLoading(false));

video.addEventListener('play', () => { updatePlayState(); showControls(); });
video.addEventListener('pause', () => { updatePlayState(); showControls(); });

video.addEventListener('loadedmetadata', () => { vpDuration.textContent = formatTime(video.duration); });

video.addEventListener('timeupdate', () => {
  if (!isScrubbing) {
    const current = video.currentTime || 0;
    const duration = video.duration || 0;
    vpCurrentTime.textContent = formatTime(current);
    vpDuration.textContent = duration ? formatTime(duration) : '00:00:00';
    if (duration > 0) {
      const progressPercent = (current / duration) * 100;
      vpProgressFill.style.width = progressPercent + '%';
      vpProgressHandle.style.left = progressPercent + '%';
    }
  }
  
  const buffered = video.buffered;
  if (buffered.length) {
    const end = buffered.end(buffered.length - 1);
    const duration = video.duration || 0;
    if (duration > 0) {
      const bufPercent = (end / duration) * 100;
      vpBuffer.style.width = bufPercent + '%';
    }
  }
});

function updateScrub(e) {
  const rect = vpProgressBar.getBoundingClientRect();
  const pos = Math.min(Math.max(e.clientX - rect.left, 0), rect.width);
  const ratio = rect.width ? pos / rect.width : 0;
  const duration = video.duration || 0;
  const time = ratio * duration;
  
  const percent = ratio * 100;
  vpProgressFill.style.width = percent + '%';
  vpProgressHandle.style.left = percent + '%';
  vpProgressTooltip.style.left = percent + '%';
  vpProgressTooltip.textContent = formatTime(time);
  vpCurrentTime.textContent = formatTime(time);
  
  return time;
}

vpProgressBar.addEventListener('mousemove', (e) => {
  if (!video.duration) return;
  const rect = vpProgressBar.getBoundingClientRect();
  const pos = Math.min(Math.max(e.clientX - rect.left, 0), rect.width);
  const ratio = rect.width ? pos / rect.width : 0;
  vpProgressTooltip.style.left = (ratio * 100) + '%';
  vpProgressTooltip.textContent = formatTime(ratio * video.duration);
  vpProgressTooltip.classList.add('show');
});

vpProgressBar.addEventListener('mouseleave', () => { if (!isScrubbing) vpProgressTooltip.classList.remove('show'); });

vpProgressBar.addEventListener('mousedown', (e) => {
  if (!video.duration) return;
  isScrubbing = true;
  vpProgressTooltip.classList.add('show');
  const startTime = updateScrub(e);
  video.pause();

  const move = (ev) => updateScrub(ev);
  const up = (ev) => {
    document.removeEventListener('mousemove', move);
    document.removeEventListener('mouseup', up);
    const finalTime = updateScrub(ev);
    video.currentTime = finalTime;
    isScrubbing = false;
    vpProgressTooltip.classList.remove('show');
    video.play().catch(()=>{});
  };
  document.addEventListener('mousemove', move);
  document.addEventListener('mouseup', up);
});

checkKeyValidity();
if (isKeyValid) { fetchVideoDetails(); } 
else { window.location.replace("/delta-auth"); }
