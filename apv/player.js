/*****************************************************************
 * LearnByAKP Custom Player JS
 * Fixed for signed CloudFront live .m3u8 links
 *
 * Query params supported:
 * ?file_url=
 * ?url=
 * ?video_id=&subject_slug=&batch_id=&schedule_id=&subject_id=&topicSlug=
 *****************************************************************/

const CONFIG = {
  BASE_API: "https://learnbyakp.onrender.com",

  REQUIRE_DELTA_KEY: false,
  DELTA_ACCESS_KEY: "delta-access-key",
  DELTA_KEY_EXPIRATION: "delta-key-expiration",

  LOGO: "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png"
};

const $ = (id) => document.getElementById(id);

const state = {
  loading: true,
  loadingText: "Initializing...",
  loadingProgress: 0,

  videoUrl: null,
  youtubeId: null,

  playing: false,
  duration: 0,
  currentTime: 0,
  loadedTime: 0,

  seeking: false,
  buffering: false,
  controlsVisible: true,

  playbackSpeed: 1,

  qualities: [],
  selectedQuality: null,
  manualQuality: false,
  preferredHeight: null,

  lectures: [],
  attachments: [],
  currentScheduleId: null,

  volume: 1,
  muted: false
};

const refs = {
  video: $("video"),
  root: $("rootPlayer"),
  player: $("player"),

  youtubeLayer: $("youtubeLayer"),
  ytContainer: $("ytContainer"),

  loader: $("loader"),
  loaderText: $("loaderText"),
  loaderBar: $("loaderBar"),
  loaderPercent: $("loaderPercent"),

  buffering: $("buffering"),

  settingsPanel: $("settingsPanel"),
  settingsMain: $("settingsMain"),
  speedSub: $("speedSub"),
  qualitySub: $("qualitySub"),
  qualityRow: $("qualityRow"),
  speedValue: $("speedValue"),
  qualityValue: $("qualityValue"),

  progressBar: $("progressBar"),
  progressLoaded: $("progressLoaded"),
  progressPlayed: $("progressPlayed"),
  progressThumb: $("progressThumb"),
  currentTime: $("currentTime"),
  durationTime: $("durationTime"),

  playIcon: $("playIcon"),
  centerPlay: $("centerPlay"),

  errorState: $("errorState"),
  errorTitle: $("errorTitle"),
  errorText: $("errorText"),

  volumeFill: $("volumeFill"),
  volumeThumb: $("volumeThumb"),

  lecturePanel: $("lecturePanel"),
  attachmentPanel: $("attachmentPanel"),
  lectureList: $("lectureList"),
  attachmentList: $("attachmentList")
};

let shakaPlayer = null;
let ytPlayer = null;
let controlsTimer = null;
let ytProgressTimer = null;

const params = new URLSearchParams(location.search);

const qp = {
  videoId: params.get("video_id") || params.get("video") || params.get("id"),
  subjectSlug: params.get("subject_slug"),
  batchId: params.get("batch_id"),
  scheduleId: params.get("schedule_id"),
  subjectId: params.get("subject_id"),
  topicSlug: params.get("topicSlug")
};

state.currentScheduleId = qp.scheduleId;

/* -------------------------------------------------------
   BASIC HELPERS
------------------------------------------------------- */

function isKeyValid() {
  if (!CONFIG.REQUIRE_DELTA_KEY) return true;

  const key = localStorage.getItem(CONFIG.DELTA_ACCESS_KEY);
  const exp = localStorage.getItem(CONFIG.DELTA_KEY_EXPIRATION);

  if (!key || !exp) return false;

  const expMs = parseInt(exp, 10);

  if (Date.now() < expMs) return true;

  localStorage.removeItem(CONFIG.DELTA_ACCESS_KEY);
  localStorage.removeItem(CONFIG.DELTA_KEY_EXPIRATION);

  return false;
}

function setLoading(show, text = state.loadingText, progress = state.loadingProgress) {
  state.loading = show;
  state.loadingText = text;
  state.loadingProgress = Math.max(0, Math.min(100, Number(progress || 0)));

  if (!refs.loader) return;

  refs.loader.classList.toggle("show", show);

  if (refs.loaderText) refs.loaderText.textContent = text;
  if (refs.loaderBar) refs.loaderBar.style.width = state.loadingProgress + "%";
  if (refs.loaderPercent) refs.loaderPercent.textContent = Math.round(state.loadingProgress) + "%";
}

function setBuffering(show) {
  state.buffering = !!show;

  if (refs.buffering) {
    refs.buffering.style.display = show ? "block" : "none";
  }
}

function showError(title, message) {
  setLoading(false);

  if (refs.errorTitle) refs.errorTitle.textContent = title || "Video Not Available";
  if (refs.errorText) refs.errorText.textContent = message || "This video is not available right now.";
  if (refs.errorState) refs.errorState.classList.add("show");
}

function formatTime(value) {
  value = Number(value || 0);

  if (!isFinite(value)) return "00:00";

  const h = Math.floor(value / 3600);
  const m = Math.floor((value % 3600) / 60);
  const s = Math.floor(value % 60);

  if (h > 0) {
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }

  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function escapeHtml(text) {
  return String(text ?? "").replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

async function fetchJSON(url) {
  const res = await fetch(url);

  if (!res.ok) {
    throw new Error("Request failed " + res.status);
  }

  return res.json();
}

function extractYouTubeId(input) {
  if (!input) return null;

  try {
    const url = new URL(input);

    if (url.hostname.includes("youtu.be")) {
      return url.pathname.slice(1).split("?")[0];
    }

    if (url.hostname.includes("youtube.com")) {
      const v = url.searchParams.get("v");

      if (v) return v;

      const m = url.pathname.match(/(?:embed|shorts|v)\/([^/?&]+)/);

      if (m) return m[1];
    }
  } catch (e) {}

  return /^[a-zA-Z0-9_-]{11}$/.test(input) ? input : null;
}

/* -------------------------------------------------------
   DECRYPT HELPER
------------------------------------------------------- */

async function decryptPayload(payload) {
  if (!payload) return payload;
  if (typeof payload !== "string") return payload;

  try {
    return JSON.parse(payload);
  } catch (e) {}

  if (!payload.includes(":")) return payload;

  const secret =
    "maggikhalo" ||
    localStorage.getItem("maggikhalo") ||
    "";

  if (!secret) {
    console.warn("DECRYPT_SECRET_KEY missing. Returning encrypted payload.");
    return payload;
  }

  function hexToBytes(hex) {
    const clean = hex.trim();

    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error("Invalid hex");
    }

    return new Uint8Array(clean.match(/.{1,2}/g).map((x) => parseInt(x, 16)));
  }

  function secretToKeyBytes(secretText) {
    const enc = new TextEncoder().encode(secretText);
    const key = new Uint8Array(32);

    for (let i = 0; i < 32; i++) {
      key[i] = i < enc.length ? enc[i] : 0;
    }

    return key;
  }

  try {
    const [ivHex, dataHex] = payload.split(":");

    const key = await crypto.subtle.importKey(
      "raw",
      secretToKeyBytes(secret),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(ivHex) },
      key,
      hexToBytes(dataHex)
    );

    const text = new TextDecoder().decode(plain);

    return JSON.parse(text);
  } catch (err) {
    console.warn("Payload decrypt failed:", err);
    return payload;
  }
}

/* -------------------------------------------------------
   DRM / KEY HELPERS
------------------------------------------------------- */

async function extractKID(mpdUrl) {
  const url = `${CONFIG.BASE_API}/api/pw/kid?mpdUrl=${encodeURIComponent(mpdUrl)}`;
  const data = await fetchJSON(url);

  if (!data.success || !data.kid) {
    throw new Error(data.error || data.details || "Failed to extract KID");
  }

  return data.kid;
}

async function getClearKey(kid) {
  const url = `${CONFIG.BASE_API}/api/pw/otp?kid=${encodeURIComponent(kid)}`;
  const data = await fetchJSON(url);

  if (!data.success || !data.key) {
    throw new Error(data.error || "Invalid key data received from API.");
  }

  return data.key;
}

/* -------------------------------------------------------
   IMPORTANT LIVE HLS FIX
   Signed CloudFront m3u8 ke child segment me query add karega
------------------------------------------------------- */

function addManifestQueryFilter(manifestUrl) {
  if (!shakaPlayer || !manifestUrl) return;

  const queryIndex = manifestUrl.indexOf("?");

  if (queryIndex === -1) return;

  const signedQuery = manifestUrl.slice(queryIndex + 1);
  const manifestBase = manifestUrl.slice(0, queryIndex);

  let manifestOrigin = "";

  try {
    manifestOrigin = new URL(manifestBase).origin;
  } catch (error) {}

  const net = shakaPlayer.getNetworkingEngine && shakaPlayer.getNetworkingEngine();

  if (!net) return;

  net.registerRequestFilter((type, request) => {
    const isManifestOrSegment =
      type === shaka.net.NetworkingEngine.RequestType.MANIFEST ||
      type === shaka.net.NetworkingEngine.RequestType.SEGMENT;

    if (!isManifestOrSegment) return;
    if (!request.uris || !request.uris[0]) return;

    try {
      const u = new URL(request.uris[0], manifestBase);

      if (manifestOrigin && u.origin !== manifestOrigin) return;

      const alreadySigned =
        u.searchParams.has("Signature") ||
        u.searchParams.has("Policy") ||
        u.searchParams.has("Key-Pair-Id") ||
        u.searchParams.has("Expires");

      if (!alreadySigned) {
        const joiner = u.search ? "&" : "?";
        request.uris[0] = u.href + joiner + signedQuery;
      } else {
        request.uris[0] = u.href;
      }
    } catch (error) {
      const reqUrl = request.uris[0];

      const alreadySigned =
        reqUrl.includes("Signature=") ||
        reqUrl.includes("Policy=") ||
        reqUrl.includes("Key-Pair-Id=") ||
        reqUrl.includes("Expires=");

      if (!alreadySigned) {
        request.uris[0] = reqUrl + (reqUrl.includes("?") ? "&" : "?") + signedQuery;
      }
    }
  });
}

/* -------------------------------------------------------
   PLAYER UI
------------------------------------------------------- */

function updateControlsVisibility(show = true) {
  state.controlsVisible = show;

  if (refs.player) refs.player.classList.toggle("controls-visible", show);
  if (refs.root) refs.root.classList.toggle("controls-visible", show);

  if (controlsTimer) clearTimeout(controlsTimer);

  if (
    show &&
    !state.seeking &&
    refs.settingsPanel &&
    !refs.settingsPanel.classList.contains("show")
  ) {
    controlsTimer = setTimeout(() => {
      updateControlsVisibility(false);
    }, 3000);
  }
}

function updatePlayUI() {
  const playSvg = `<path d="M8 5v14l11-7z"/>`;
  const pauseSvg = `<path d="M7 5h4v14H7zM13 5h4v14h-4z"/>`;

  const svg = state.playing ? pauseSvg : playSvg;

  if (refs.playIcon) refs.playIcon.innerHTML = svg;

  if (refs.centerPlay) {
    refs.centerPlay.innerHTML = `<svg viewBox="0 0 24 24" fill="currentColor">${svg}</svg>`;
    refs.centerPlay.classList.toggle("pause", state.playing);
  }

  if (refs.player) refs.player.classList.toggle("playing", state.playing);
  if (refs.root) refs.root.classList.toggle("playing", state.playing);
}

function updateProgressUI() {
  const duration = state.duration || 0;
  const current = state.currentTime || 0;
  const loaded = state.loadedTime || 0;

  const playedPercent = duration ? Math.max(0, Math.min(100, current / duration * 100)) : 0;
  const loadedPercent = duration ? Math.max(0, Math.min(100, loaded / duration * 100)) : 0;

  if (refs.currentTime) refs.currentTime.textContent = formatTime(current);
  if (refs.durationTime) refs.durationTime.textContent = formatTime(duration);

  if (refs.progressPlayed) refs.progressPlayed.style.width = playedPercent + "%";
  if (refs.progressLoaded) refs.progressLoaded.style.width = loadedPercent + "%";
  if (refs.progressThumb) refs.progressThumb.style.left = playedPercent + "%";
}

function updateVolumeUI() {
  const percent = state.muted ? 0 : state.volume * 100;

  if (refs.volumeFill) refs.volumeFill.style.width = percent + "%";
  if (refs.volumeThumb) refs.volumeThumb.style.left = percent + "%";

  const volumeIcon = $("volumeIcon");

  if (volumeIcon) {
    volumeIcon.innerHTML = percent === 0
      ? `<path d="M3 9v6h4l5 4V5L7 9H3zm13 0l5 5m0-5l-5 5"/>`
      : `<path d="M3 9v6h4l5 4V5L7 9H3zm13.5 3A4.5 4.5 0 0014 8v8a4.5 4.5 0 002.5-4z"/>`;
  }
}

/* -------------------------------------------------------
   PLAY / SEEK / VOLUME
------------------------------------------------------- */

function getYTState() {
  if (!ytPlayer || !ytPlayer.getPlayerState) return -1;
  return ytPlayer.getPlayerState();
}

function togglePlay() {
  if (state.youtubeId && ytPlayer) {
    if (getYTState() === 1) {
      ytPlayer.pauseVideo();
      state.playing = false;
    } else {
      ytPlayer.playVideo();
      state.playing = true;
    }

    updatePlayUI();
    updateControlsVisibility(true);
    return;
  }

  const v = refs.video;

  if (!v) return;

  if (v.paused) {
    v.play()
      .then(() => {
        state.playing = true;
        updatePlayUI();
        updateControlsVisibility(true);
      })
      .catch((err) => {
        console.warn(err);
        showError("Playback Blocked", "Browser ne autoplay block kiya. Play button dobara dabao.");
      });
  } else {
    v.pause();
    state.playing = false;
    updatePlayUI();
    updateControlsVisibility(true);
  }
}

function seekBy(seconds) {
  if (state.youtubeId && ytPlayer) {
    const current = ytPlayer.getCurrentTime ? ytPlayer.getCurrentTime() : 0;
    const target = Math.max(0, Math.min(current + seconds, state.duration || 0));

    ytPlayer.seekTo(target, true);

    state.currentTime = target;
    updateProgressUI();
    return;
  }

  if (refs.video && state.duration > 0) {
    refs.video.currentTime = Math.max(0, Math.min(refs.video.currentTime + seconds, state.duration));
  }
}

function seekToPosition(clientX) {
  if (!refs.progressBar) return;

  const rect = refs.progressBar.getBoundingClientRect();
  const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
  const time = ratio * (state.duration || 0);

  if (state.youtubeId && ytPlayer) {
    ytPlayer.seekTo(time, true);
  } else if (refs.video) {
    refs.video.currentTime = time;
  }

  state.currentTime = time;
  updateProgressUI();
}

function setVolume(value) {
  state.volume = Math.max(0, Math.min(1, Number(value)));
  state.muted = state.volume <= 0;

  if (state.youtubeId && ytPlayer) {
    ytPlayer.setVolume(Math.round(state.volume * 100));

    if (state.muted) ytPlayer.mute();
    else ytPlayer.unMute();
  } else if (refs.video) {
    refs.video.volume = state.volume;
    refs.video.muted = state.muted;
  }

  updateVolumeUI();
}

function setPlaybackSpeed(speed) {
  state.playbackSpeed = speed;

  if (refs.speedValue) {
    refs.speedValue.textContent = speed === 1 ? "1" : String(speed);
  }

  if (state.youtubeId && ytPlayer) {
    ytPlayer.setPlaybackRate(speed);
  } else if (refs.video) {
    refs.video.playbackRate = speed;
  }

  closeSettings();
}

/* -------------------------------------------------------
   QUALITY SETTINGS
------------------------------------------------------- */

function getUniqueTracks(tracks) {
  const out = [];

  tracks
    .filter((t) => t.height)
    .sort((a, b) => b.height - a.height)
    .forEach((t) => {
      if (!out.find((x) => x.height === t.height)) {
        out.push(t);
      }
    });

  return out;
}

function refreshQualities() {
  if (!shakaPlayer || !shakaPlayer.getVariantTracks) return;

  const tracks = shakaPlayer.getVariantTracks();

  state.qualities = getUniqueTracks(tracks);

  const active = tracks.find((t) => t.active);

  if (active) {
    state.selectedQuality = active;
  }

  if (refs.qualityRow) {
    refs.qualityRow.style.display = state.qualities.length ? "flex" : "none";
  }

  updateQualityText();

  const pref = parseInt(localStorage.getItem("videoQualityPreference") || "", 10);

  if (pref && !state.manualQuality) {
    const found = tracks.find((t) => t.height === pref);

    if (found) {
      selectQuality(found.id, false);
    }
  }
}

function updateQualityText() {
  if (!refs.qualityValue) return;

  refs.qualityValue.textContent = state.selectedQuality
    ? `${state.selectedQuality.height}p`
    : "Auto";
}

function selectQuality(id, userAction = true) {
  if (!shakaPlayer) return;

  const track = shakaPlayer.getVariantTracks().find((t) => t.id === id);

  if (!track) return;

  shakaPlayer.configure({
    abr: {
      enabled: false
    }
  });

  shakaPlayer.selectVariantTrack(track, true);

  state.selectedQuality = track;
  state.manualQuality = true;
  state.preferredHeight = track.height;

  localStorage.setItem("videoQualityPreference", String(track.height));

  updateQualityText();

  if (userAction) {
    closeSettings();
  }
}

function autoQuality() {
  if (!shakaPlayer) return;

  shakaPlayer.configure({
    abr: {
      enabled: true
    }
  });

  state.selectedQuality = null;
  state.manualQuality = false;
  state.preferredHeight = null;

  localStorage.removeItem("videoQualityPreference");

  updateQualityText();
  closeSettings();
}

/* -------------------------------------------------------
   SETTINGS PANEL
------------------------------------------------------- */

function openSettingsPanel(type) {
  if (!refs.settingsMain || !refs.speedSub || !refs.qualitySub) return;

  refs.settingsMain.style.display = "none";
  refs.speedSub.style.display = type === "speed" ? "block" : "none";
  refs.qualitySub.style.display = type === "quality" ? "block" : "none";

  if (type === "speed") renderSpeedPanel();
  if (type === "quality") renderQualityPanel();
}

function closeSettings() {
  if (!refs.settingsPanel) return;

  refs.settingsPanel.classList.remove("show");

  if (refs.settingsMain) refs.settingsMain.style.display = "block";
  if (refs.speedSub) refs.speedSub.style.display = "none";
  if (refs.qualitySub) refs.qualitySub.style.display = "none";

  updateControlsVisibility(true);
}

function renderSpeedPanel() {
  if (!refs.speedSub) return;

  refs.speedSub.innerHTML = `
    <div class="settings-head">
      <button class="back-small" onclick="backToSettingsMain()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M15 18L9 12L15 6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
      <h3>Speed</h3>
    </div>
  `;

  [0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2].forEach((speed) => {
    const div = document.createElement("div");
    const active = state.playbackSpeed === speed;

    div.className = "option" + (active ? " active" : "");
    div.innerHTML = `<span>${speed === 1 ? "Normal (1x)" : speed + "x"}</span><span class="radio"></span>`;
    div.onclick = () => setPlaybackSpeed(speed);

    refs.speedSub.appendChild(div);
  });
}

function renderQualityPanel() {
  if (!refs.qualitySub) return;

  refs.qualitySub.innerHTML = `
    <div class="settings-head">
      <button class="back-small" onclick="backToSettingsMain()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M15 18L9 12L15 6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
      <h3>Quality</h3>
    </div>
  `;

  const auto = document.createElement("div");

  auto.className = "option" + (!state.selectedQuality ? " active" : "");
  auto.innerHTML = `<span>Auto (recommended)</span><span class="radio"></span>`;
  auto.onclick = autoQuality;

  refs.qualitySub.appendChild(auto);

  state.qualities.forEach((q) => {
    const active = state.selectedQuality && state.selectedQuality.height === q.height;

    const div = document.createElement("div");

    div.className = "option" + (active ? " active" : "");
    div.innerHTML = `<span>${q.height}p</span><span class="radio"></span>`;
    div.onclick = () => selectQuality(q.id);

    refs.qualitySub.appendChild(div);
  });
}

window.backToSettingsMain = function () {
  if (refs.settingsMain) refs.settingsMain.style.display = "block";
  if (refs.speedSub) refs.speedSub.style.display = "none";
  if (refs.qualitySub) refs.qualitySub.style.display = "none";
};

/* -------------------------------------------------------
   YOUTUBE SETUP
------------------------------------------------------- */

function loadYouTubeAPI() {
  return new Promise((resolve) => {
    if (window.YT && window.YT.Player) return resolve();

    if (!document.getElementById("yt-iframe-api-script")) {
      const script = document.createElement("script");
      script.id = "yt-iframe-api-script";
      script.src = "https://www.youtube.com/iframe_api";
      document.head.appendChild(script);
    }

    window.onYouTubeIframeAPIReady = resolve;
  });
}

async function setupYouTube(videoId) {
  state.youtubeId = videoId;
  state.videoUrl = null;

  if (refs.video) refs.video.style.display = "none";
  if (refs.youtubeLayer) refs.youtubeLayer.style.display = "block";
  if (refs.ytContainer) refs.ytContainer.innerHTML = "";

  await loadYouTubeAPI();

  const div = document.createElement("div");
  div.id = "yt-player-div";

  if (refs.ytContainer) refs.ytContainer.appendChild(div);

  ytPlayer = new YT.Player("yt-player-div", {
    videoId,
    width: "100%",
    height: "100%",
    playerVars: {
      autoplay: 0,
      controls: 0,
      disablekb: 1,
      fs: 0,
      iv_load_policy: 3,
      modestbranding: 1,
      rel: 0,
      showinfo: 0,
      playsinline: 1,
      end: 0,
      origin: window.location.origin
    },
    events: {
      onReady: (event) => onYouTubeReady(event.target),
      onStateChange: (event) => onYouTubeStateChange(event.data)
    }
  });

  const downloadBtn = $("downloadBtn");

  if (downloadBtn) downloadBtn.style.display = "none";
}

function onYouTubeReady(player) {
  setLoading(false);

  state.duration = player.getDuration ? player.getDuration() : 0;
  state.currentTime = 0;
  state.loadedTime = 0;

  updateProgressUI();
  updatePlayUI();

  if (ytProgressTimer) clearInterval(ytProgressTimer);

  ytProgressTimer = setInterval(() => {
    if (!ytPlayer) return;

    state.currentTime = ytPlayer.getCurrentTime ? ytPlayer.getCurrentTime() : 0;
    state.duration = ytPlayer.getDuration ? ytPlayer.getDuration() : state.duration;
    state.loadedTime = (ytPlayer.getVideoLoadedFraction ? ytPlayer.getVideoLoadedFraction() : 0) * (state.duration || 0);

    updateProgressUI();
  }, 250);
}

function onYouTubeStateChange(code) {
  if (code === 1) {
    state.playing = true;
    setBuffering(false);
    updateControlsVisibility(true);
  } else if (code === 2 || code === 0) {
    state.playing = false;
    updateControlsVisibility(true);
  } else if (code === 3) {
    setBuffering(true);
  }

  updatePlayUI();
}

/* -------------------------------------------------------
   SHAKA SETUP
------------------------------------------------------- */

async function setupShaka(url) {
  state.youtubeId = null;
  state.videoUrl = url;

  if (refs.video) refs.video.style.display = "block";
  if (refs.youtubeLayer) refs.youtubeLayer.style.display = "none";

  const downloadBtn = $("downloadBtn");

  if (downloadBtn) downloadBtn.style.display = "grid";

  if (!window.shaka) {
    throw new Error("Shaka Player not loaded");
  }

  if (shaka.Player.isBrowserSupported && !shaka.Player.isBrowserSupported()) {
    throw new Error("Browser does not support Shaka Player");
  }

  if (shakaPlayer) {
    try {
      await shakaPlayer.destroy();
    } catch (e) {}
  }

  const player = new shaka.Player();
  shakaPlayer = player;

  await player.attach(refs.video);

  player.configure({
    streaming: {
      lowLatencyMode: true,
      rebufferingGoal: 2,
      bufferingGoal: 10,
      retryParameters: {
        maxAttempts: 5,
        baseDelay: 1000,
        backoffFactor: 2,
        fuzzFactor: 0.5,
        timeout: 30000
      }
    },
    manifest: {
      retryParameters: {
        maxAttempts: 5,
        baseDelay: 1000,
        backoffFactor: 2,
        fuzzFactor: 0.5,
        timeout: 30000
      }
    }
  });

  player.addEventListener("error", (e) => {
    console.error("Shaka Player Error:", e.detail);
  });

  player.addEventListener("buffering", (e) => {
    setBuffering(e.buffering);
  });

  player.addEventListener("trackschanged", refreshQualities);

  player.addEventListener("adaptation", () => {
    if (state.manualQuality && state.preferredHeight) {
      const tracks = shakaPlayer.getVariantTracks();
      const active = tracks.find((t) => t.active);

      if (!active || active.height !== state.preferredHeight) {
        const target = tracks.find((t) => t.height === state.preferredHeight);

        if (target) {
          shakaPlayer.selectVariantTrack(target, true);
        }
      }
    }
  });

  if (url.includes("/drm/")) {
    addManifestQueryFilter(url);
  } else if (url.includes(".mpd") && !url.includes("/drm/")) {
    setLoading(true, "Fetching decryption keys.", 88);

    const mpdUrl = url.replace(/\.m3u8/i, ".mpd");
    const kid = await extractKID(mpdUrl);
    const key = await getClearKey(kid);

    player.configure({
      drm: {
        clearKeys: {
          [kid]: key
        }
      }
    });

    addManifestQueryFilter(url);
  } else {
    addManifestQueryFilter(url);
  }

  await player.load(url);

  state.duration = refs.video.duration || 0;

  refreshQualities();

  const pref = localStorage.getItem("videoQualityPreference");

  if (pref) {
    const height = parseInt(pref, 10);
    const target = player.getVariantTracks().find((t) => t.height === height);

    if (target) {
      selectQuality(target.id, false);
    }
  }

  if (downloadBtn) {
    downloadBtn.onclick = () => openDownload(url);
  }
}

function openDownload(url) {
  if (!url) {
    alert("Video manifest not available for download.");
    return;
  }

  const finalUrl = url.replace(/\.mpd/i, ".m3u8");

  location.href = `/download?url=${encodeURIComponent(finalUrl)}`;
}

/* -------------------------------------------------------
   VIDEO RESOLVE
------------------------------------------------------- */

async function resolveVideoUrl() {
  if (!qp.videoId || !qp.batchId || !qp.subjectId) {
    throw new Error("Missing video parameters.");
  }

  let url = null;
  let isYT = false;

  setLoading(true, "Fetching video details.", 5);

  try {
    const data = await fetchJSON(
      `${CONFIG.BASE_API}/api/pw/video-url-details?batchId=${encodeURIComponent(qp.batchId)}&childId=${encodeURIComponent(qp.videoId)}&subjectId=${encodeURIComponent(qp.subjectId)}`
    );

    if (data.success && Array.isArray(data.data) && data.data[0]?.url) {
      if (data.data[0].type === "youtube") isYT = true;
      url = data.data[0].url;
    }
  } catch (e) {
    console.warn("video-url-details failed:", e);
  }

  setLoading(true, "Fetching video details.", 25);

  if (!url) {
    try {
      const data = await fetchJSON(
        `${CONFIG.BASE_API}/api/pw/get-url?batchId=${encodeURIComponent(qp.batchId)}&childId=${encodeURIComponent(qp.videoId)}&subjectId=${encodeURIComponent(qp.subjectId)}`
      );

      if (data.success && Array.isArray(data.data) && data.data[0]?.url) {
        if (data.data[0].type === "youtube") isYT = true;
        url = data.data[0].url;
      }
    } catch (e) {
      console.warn("get-url failed:", e);
    }
  }

  setLoading(true, "Fetching video details.", 35);

  if (!url && qp.subjectSlug) {
    try {
      const data = await fetchJSON(
        `${CONFIG.BASE_API}/api/pw/video?batchId=${encodeURIComponent(qp.batchId)}&subjectId=${encodeURIComponent(qp.subjectSlug)}&childId=${encodeURIComponent(qp.videoId)}`
      );

      if (data.data) {
        const decrypted = await decryptPayload(data.data);

        if (decrypted?.success && decrypted?.data?.url) {
          url = decrypted.data.signedUrl
            ? decrypted.data.url + decrypted.data.signedUrl
            : decrypted.data.url;
        }
      }
    } catch (e) {
      console.warn("video subjectSlug failed:", e);
    }
  }

  setLoading(true, "Fetching video details.", 50);

  if (!url) {
    try {
      const data = await fetchJSON(
        `${CONFIG.BASE_API}/api/pw/video?batchId=${encodeURIComponent(qp.batchId)}&childId=${encodeURIComponent(qp.videoId)}&subjectId=${encodeURIComponent(qp.subjectId)}`
      );

      if (data.success && Array.isArray(data.data) && data.data[0]?.url) {
        if (data.data[0].type === "youtube") isYT = true;
        url = data.data[0].url;
      }
    } catch (e) {
      console.warn("video fallback failed:", e);
    }
  }

  setLoading(true, "Fetching video details.", 75);

  if (!url) {
    return {
      notAvailable: true
    };
  }

  if (!isYT) {
    const yt = extractYouTubeId(url);

    if (yt) {
      isYT = true;
      url = yt;
    }
  }

  return {
    url,
    isYouTube: isYT
  };
}

async function loadMainVideo() {
  if (!isKeyValid()) {
    location.href = "/delta-auth";
    return;
  }

  try {
    const directUrl = params.get("file_url") || params.get("url");
    const directYoutube = directUrl ? extractYouTubeId(directUrl) : null;

    if (directUrl) {
      if (directYoutube) {
        setLoading(true, "Loading YouTube video.", 85);
        await setupYouTube(directYoutube);
      } else {
        setLoading(true, "Loading video.", 85);
        await setupShaka(directUrl);
        setLoading(false);
      }

      return;
    }

    const result = await resolveVideoUrl();

    if (result.notAvailable) {
      showError("Batch Not Available", "This batch isn't available on our site yet.");
      return;
    }

    if (result.isYouTube) {
      setLoading(true, "Loading YouTube video.", 90);
      await setupYouTube(extractYouTubeId(result.url) || result.url);
      return;
    }

    setLoading(true, "Loading video.", 90);
    await setupShaka(result.url);
    setLoading(false);
  } catch (err) {
    console.error("Failed to load video:", err);
    showError("Failed to load video", err.message || "Something went wrong.");
  }
}

/* -------------------------------------------------------
   LECTURES
------------------------------------------------------- */

function normalizeLecture(item) {
  return {
    _id: item._id,
    topic: item.topic || "Lecture",
    findKey: item.videoDetails?.findKey || item._id,
    thumbnail: item.videoDetails?.image || item.previewImage || CONFIG.LOGO,
    date: item.date,
    duration: item.videoDetails?.duration || item.duration || "N/A"
  };
}

async function loadLectures() {
  if (!qp.batchId || !qp.subjectSlug || !qp.topicSlug) return;

  try {
    const contentType = "videos";
    let lectures = [];

    if (qp.topicSlug === "all-contents") {
      const topicsRes = await fetchJSON(
        `${CONFIG.BASE_API}/api/pw/topics?BatchId=${encodeURIComponent(qp.batchId)}&SubjectId=${encodeURIComponent(qp.subjectSlug)}`
      );

      const topicsData = await decryptPayload(topicsRes.data);
      const topics = topicsData?.success && Array.isArray(topicsData.data) ? topicsData.data : [];

      for (const topic of topics) {
        try {
          const dataRes = await fetchJSON(
            `${CONFIG.BASE_API}/api/pw/datacontent?batchId=${encodeURIComponent(qp.batchId)}&subjectSlug=${encodeURIComponent(qp.subjectSlug)}&topicSlug=${encodeURIComponent(topic.slug)}&contentType=${contentType}`
          );

          const data = await decryptPayload(dataRes.data);

          if (data?.success && Array.isArray(data.data)) {
            lectures.push(...data.data.map(normalizeLecture));
          }
        } catch (e) {
          console.warn("topic lectures failed:", e);
        }
      }
    } else {
      const dataRes = await fetchJSON(
        `${CONFIG.BASE_API}/api/pw/datacontent?batchId=${encodeURIComponent(qp.batchId)}&subjectSlug=${encodeURIComponent(qp.subjectSlug)}&topicSlug=${encodeURIComponent(qp.topicSlug)}&contentType=${contentType}`
      );

      const data = await decryptPayload(dataRes.data);

      if (data?.success && Array.isArray(data.data)) {
        lectures = data.data.map(normalizeLecture);
      }
    }

    state.lectures = lectures;
    renderLectures();
  } catch (err) {
    console.warn("Failed to fetch lectures:", err);
  }
}

function renderLectures() {
  if (!refs.lectureList) return;

  if (!state.lectures.length) {
    refs.lectureList.innerHTML = `<div class="empty">No lectures loaded.</div>`;
    return;
  }

  refs.lectureList.innerHTML = "";

  state.lectures.forEach((lecture) => {
    const div = document.createElement("div");

    div.className = "lecture-card" + (state.currentScheduleId === lecture._id ? " active" : "");

    div.innerHTML = `
      <img src="${escapeHtml(lecture.thumbnail)}" alt="">
      <div>
        <div class="lecture-title">${escapeHtml(lecture.topic)}</div>
        <div class="lecture-duration">${escapeHtml(lecture.duration || "")}</div>
      </div>
    `;

    div.onclick = () => {
      const url =
        `/study-v2/player?video_id=${encodeURIComponent(lecture.findKey)}` +
        `&subject_slug=${encodeURIComponent(qp.subjectSlug || "")}` +
        `&batch_id=${encodeURIComponent(qp.batchId || "")}` +
        `&schedule_id=${encodeURIComponent(lecture._id)}` +
        `&subject_id=${encodeURIComponent(qp.subjectId || "")}` +
        `&topicSlug=${encodeURIComponent(qp.topicSlug || "")}`;

      location.href = url;
    };

    refs.lectureList.appendChild(div);
  });
}

/* -------------------------------------------------------
   ATTACHMENTS
------------------------------------------------------- */

async function loadAttachments() {
  if (!qp.batchId || !qp.subjectId || !qp.scheduleId) return;

  try {
    const url =
      `${CONFIG.BASE_API}/api/pw/attachment-url?BatchId=${encodeURIComponent(qp.batchId)}` +
      `&SubjectId=${encodeURIComponent(qp.subjectId)}` +
      `&ContentId=${encodeURIComponent(qp.scheduleId)}`;

    const res = await fetchJSON(url);

    if (res.success && Array.isArray(res.data)) {
      state.attachments = res.data
        .map((item, index) => ({
          _id: item.url || item.key || String(index),
          name: item.topic || item.name || "Attachment",
          url: item.url
        }))
        .filter((x) => x.url);
    } else {
      state.attachments = [];
    }

    renderAttachments();
  } catch (err) {
    console.warn("Failed to fetch attachments:", err);
  }
}

function renderAttachments() {
  if (!refs.attachmentList) return;

  if (!state.attachments.length) {
    refs.attachmentList.innerHTML = `<div class="empty">No attachments available.</div>`;
    return;
  }

  refs.attachmentList.innerHTML = "";

  state.attachments.forEach((file) => {
    const a = document.createElement("a");

    a.className = "attachment-card";
    a.href = file.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";

    a.innerHTML = `
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M4 4h16v16H4V4z" stroke="#B3B3BC" stroke-width="1.5"/>
        <path d="M8 9h8M8 13h8M8 17h5" stroke="#B3B3BC" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <span>${escapeHtml(file.name)}</span>
      <svg width="20" height="20" viewBox="0 0 17 17" fill="none">
        <path d="M14.8 10.5v2.7c0 .35-.14.69-.39.94-.25.25-.59.36-.94.36h-10c-.35 0-.69-.11-.94-.36-.25-.25-.36-.59-.36-.94v-2.7" stroke="#B3B3BC" stroke-width="1.5" stroke-linecap="round"/>
        <path d="M5.2 7.2l3.3 3.3 3.3-3.3M8.5 10.5v-8" stroke="#B3B3BC" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
    `;

    refs.attachmentList.appendChild(a);
  });
}

/* -------------------------------------------------------
   PANELS
------------------------------------------------------- */

function togglePanel(panel) {
  if (refs.lecturePanel) {
    refs.lecturePanel.classList.toggle(
      "show",
      panel === "lectures" && !refs.lecturePanel.classList.contains("show")
    );
  }

  if (refs.attachmentPanel) {
    refs.attachmentPanel.classList.toggle(
      "show",
      panel === "attachments" && !refs.attachmentPanel.classList.contains("show")
    );
  }
}

/* -------------------------------------------------------
   EVENTS
------------------------------------------------------- */

function bindEvents() {
  const backBtn = $("backBtn");
  const playBtn = $("playBtn");
  const ytClickLayer = $("ytClickLayer");
  const rewindBtn = $("rewindBtn");
  const forwardBtn = $("forwardBtn");
  const settingsBtn = $("settingsBtn");
  const fullscreenBtn = $("fullscreenBtn");
  const fullscreenBtn2 = $("fullscreenBtn2");
  const muteBtn = $("muteBtn");
  const volumeRange = $("volumeRange");
  const lecturesBtn = $("lecturesBtn");
  const attachmentsBtn = $("attachmentsBtn");
  const closeLectures = $("closeLectures");
  const closeAttachments = $("closeAttachments");

  if (backBtn) {
    backBtn.onclick = (e) => {
      e.stopPropagation();
      history.back();
    };
  }

  if (playBtn) {
    playBtn.onclick = (e) => {
      e.stopPropagation();
      togglePlay();
    };
  }

  if (refs.centerPlay) {
    refs.centerPlay.onclick = (e) => {
      e.stopPropagation();
      togglePlay();
    };
  }

  if (ytClickLayer) {
    ytClickLayer.onclick = (e) => {
      e.stopPropagation();
      togglePlay();
    };
  }

  if (rewindBtn) {
    rewindBtn.onclick = (e) => {
      e.stopPropagation();
      seekBy(-10);
    };
  }

  if (forwardBtn) {
    forwardBtn.onclick = (e) => {
      e.stopPropagation();
      seekBy(10);
    };
  }

  if (refs.player) {
    refs.player.addEventListener("mousemove", () => {
      updateControlsVisibility(true);
    });

    refs.player.addEventListener("touchstart", (e) => {
      const touchedInsideControls =
        e.target.closest(".controls") ||
        e.target.closest(".top-bar") ||
        e.target.closest(".bottom-bar") ||
        e.target.closest(".center-play") ||
        e.target.closest(".settings-panel") ||
        e.target.closest("button");

      if (touchedInsideControls) return;

      if (refs.settingsPanel && refs.settingsPanel.classList.contains("show")) {
        updateControlsVisibility(true);
        return;
      }

      updateControlsVisibility(!state.controlsVisible);
    }, { passive: true });

    refs.player.addEventListener("mouseleave", () => {
      if (state.playing && refs.settingsPanel && !refs.settingsPanel.classList.contains("show")) {
        updateControlsVisibility(false);
      }
    });
  }

  if (refs.progressBar) {
    refs.progressBar.addEventListener("mousedown", (e) => {
      e.stopPropagation();

      state.seeking = true;
      seekToPosition(e.clientX);

      const move = (ev) => seekToPosition(ev.clientX);

      const up = () => {
        state.seeking = false;
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
        updateControlsVisibility(true);
      };

      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    });

    refs.progressBar.addEventListener("touchstart", (e) => {
      e.stopPropagation();

      state.seeking = true;

      if (e.touches[0]) {
        seekToPosition(e.touches[0].clientX);
      }
    }, { passive: true });

    refs.progressBar.addEventListener("touchmove", (e) => {
      if (state.seeking && e.touches[0]) {
        e.preventDefault();
        seekToPosition(e.touches[0].clientX);
      }
    }, { passive: false });

    refs.progressBar.addEventListener("touchend", (e) => {
      e.stopPropagation();
      state.seeking = false;
      updateControlsVisibility(true);
    });
  }

  if (settingsBtn) {
    settingsBtn.onclick = (e) => {
      e.stopPropagation();

      if (!refs.settingsPanel) return;

      refs.settingsPanel.classList.toggle("show");
      backToSettingsMain();
      updateControlsVisibility(true);
    };
  }

  if (refs.settingsPanel) {
    refs.settingsPanel.addEventListener("click", (e) => {
      e.stopPropagation();

      const row = e.target.closest("[data-open]");

      if (row) {
        openSettingsPanel(row.dataset.open);
      }
    });
  }

  document.addEventListener("mousedown", (e) => {
    if (
      refs.settingsPanel &&
      settingsBtn &&
      !refs.settingsPanel.contains(e.target) &&
      e.target !== settingsBtn
    ) {
      closeSettings();
    }
  });

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();

        if (screen.orientation && screen.orientation.unlock) {
          screen.orientation.unlock();
        }
      } else {
        await refs.root.requestFullscreen();

        if (screen.orientation && screen.orientation.lock) {
          screen.orientation.lock("landscape").catch(() => {});
        }
      }
    } catch (err) {
      console.warn("Fullscreen/orientation error:", err);
    }
  }

  if (fullscreenBtn2) {
    fullscreenBtn2.onclick = async (e) => {
      e.stopPropagation();
      await toggleFullscreen();
    };
  }

  if (fullscreenBtn) {
    fullscreenBtn.onclick = async (e) => {
      e.stopPropagation();
      await toggleFullscreen();
    };
  }

  document.addEventListener("fullscreenchange", () => {
    updateControlsVisibility(true);
  });

  if (muteBtn) {
    muteBtn.onclick = (e) => {
      e.stopPropagation();

      if (state.muted || state.volume === 0) {
        setVolume(1);
      } else {
        setVolume(0);
      }
    };
  }

  if (volumeRange) {
    volumeRange.addEventListener("mousedown", (e) => {
      e.stopPropagation();

      const update = (clientX) => {
        const rect = volumeRange.getBoundingClientRect();
        setVolume((clientX - rect.left) / rect.width);
      };

      update(e.clientX);

      const move = (ev) => update(ev.clientX);

      const up = () => {
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
      };

      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    });
  }

  if (lecturesBtn) {
    lecturesBtn.onclick = (e) => {
      e.stopPropagation();
      togglePanel("lectures");
    };
  }

  if (attachmentsBtn) {
    attachmentsBtn.onclick = (e) => {
      e.stopPropagation();
      togglePanel("attachments");
    };
  }

  if (closeLectures && refs.lecturePanel) {
    closeLectures.onclick = () => {
      refs.lecturePanel.classList.remove("show");
    };
  }

  if (closeAttachments && refs.attachmentPanel) {
    closeAttachments.onclick = () => {
      refs.attachmentPanel.classList.remove("show");
    };
  }

  if (refs.video) {
    refs.video.addEventListener("timeupdate", () => {
      if (!refs.video.seeking) {
        state.currentTime = refs.video.currentTime || 0;
      }

      updateProgressUI();
    });

    refs.video.addEventListener("durationchange", () => {
      if (refs.video.duration && refs.video.duration !== Infinity) {
        state.duration = refs.video.duration;
      }

      updateProgressUI();
    });

    refs.video.addEventListener("progress", () => {
      try {
        if (refs.video.buffered.length > 0) {
          state.loadedTime = refs.video.buffered.end(refs.video.buffered.length - 1);
        }
      } catch (e) {}

      updateProgressUI();
    });

    refs.video.addEventListener("play", () => {
      state.playing = true;
      setBuffering(false);
      updatePlayUI();
      updateControlsVisibility(true);
    });

    refs.video.addEventListener("pause", () => {
      state.playing = false;
      updatePlayUI();
      updateControlsVisibility(true);
    });

    refs.video.addEventListener("waiting", () => {
      setBuffering(true);
    });

    refs.video.addEventListener("canplay", () => {
      setBuffering(false);
    });

    refs.video.addEventListener("playing", () => {
      setBuffering(false);
    });
  }

  document.addEventListener("keydown", (e) => {
    if (
      document.activeElement &&
      ["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)
    ) {
      return;
    }

    if (e.code === "Space") {
      e.preventDefault();
      togglePlay();
    }

    if (e.code === "ArrowLeft") {
      seekBy(-10);
    }

    if (e.code === "ArrowRight") {
      seekBy(10);
    }

    if (e.key.toLowerCase() === "f" && fullscreenBtn) {
      fullscreenBtn.click();
    }

    if (e.key.toLowerCase() === "m" && muteBtn) {
      muteBtn.click();
    }
  });
}

/* -------------------------------------------------------
   INIT
------------------------------------------------------- */

async function init() {
  bindEvents();

  updateVolumeUI();
  updatePlayUI();
  updateProgressUI();

  await Promise.allSettled([
    loadLectures(),
    loadAttachments()
  ]);

  await loadMainVideo();
}

init();