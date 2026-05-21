
    const API_BASE = "https://learnbyakp.onrender.com";
    // NOTE: /api/vibrant/resolve-url hata diya gaya hai. Ab encrypted path isi page me decrypt hoga.

    const qs = new URLSearchParams(location.search);
    const courseId = qs.get("course_id");
    const videoId = qs.get("video_id");
    const isLive = qs.get("isLive") === "true";

    const refs = {
      playerWrap: document.getElementById("playerWrap"),
      video: document.getElementById("video"),
      loader: document.getElementById("loader"),
      loadingText: document.getElementById("loadingText"),
      loadingFill: document.getElementById("loadingFill"),
      errorBox: document.getElementById("errorBox"),
      errorText: document.getElementById("errorText"),
      titleText: document.getElementById("titleText"),

      backBtn: document.getElementById("backBtn"),
      qualityTopBtn: document.getElementById("qualityTopBtn"),
      qualityBtn: document.getElementById("qualityBtn"),
      qualityModal: document.getElementById("qualityModal"),
      closeQuality: document.getElementById("closeQuality"),
      qualityList: document.getElementById("qualityList"),

      bigPlay: document.getElementById("bigPlay"),
      playBtn: document.getElementById("playBtn"),
      back10: document.getElementById("back10"),
      for10: document.getElementById("for10"),
      fullBtn: document.getElementById("fullBtn"),
      muteBtn: document.getElementById("muteBtn"),
      progressArea: document.getElementById("progressArea"),
      progressFill: document.getElementById("progressFill"),
      timeText: document.getElementById("timeText")
    };

    let player = null;
    let videoData = null;
    let selectedUrl = "";
    let hideTimer = null;

    function setLoading(show, text = "Loading...", progress = 0) {
      refs.loader.classList.toggle("show", show);
      refs.loadingText.textContent = text;
      refs.loadingFill.style.width = progress + "%";
    }

    function showError(message) {
      setLoading(false);
      refs.errorText.textContent = message || "Something went wrong.";
      refs.errorBox.classList.add("show");
    }

    function hideError() {
      refs.errorBox.classList.remove("show");
    }

    async function fetchVideoDetails() {
      if (!courseId || !videoId) {
        throw new Error("URL me course_id ya video_id missing hai.");
      }

      setLoading(true, "Fetching video details...", 25);

      const url =
        `${API_BASE}/api/vibrant/video-details?video_id=${encodeURIComponent(videoId)}&course_id=${encodeURIComponent(courseId)}`;

      const res = await fetch(url);

      if (!res.ok) {
        let msg = `Video details fetch failed. Status: ${res.status}`;
        try {
          const err = await res.json();
          msg = err.error || err.message || msg;
        } catch (_) {}
        throw new Error(msg);
      }

      const json = await res.json();

      if (json.status !== 200 || !json.data) {
        throw new Error(json.message || "Invalid video details response.");
      }

      videoData = json.data;

      refs.video.poster = videoData.thumbnail || "";
      refs.titleText.textContent =
        videoData.title ||
        videoData.video_title ||
        videoData.name ||
        "LearnByAKP Player";

      return videoData;
    }


    const AES_KEY_TEXT = "638udh3829162018";
    const AES_IV_TEXT = "fedcba9876543210";

    function looksLikeDirectUrl(value = "") {
      return /^https?:\/\//i.test(String(value));
    }

    async function decryptVibrantLink(encryptedText) {
      const raw = String(encryptedText || "").trim();
      if (!raw) throw new Error("Selected quality ka path empty hai.");

      // Agar API direct URL de rahi hai to decrypt ki zarurat nahi.
      if (looksLikeDirectUrl(raw)) return raw;

      try {
        const firstPart = raw.split(":")[0];
        const encryptedBinary = atob(firstPart);
        const encryptedBytes = new Uint8Array(encryptedBinary.length);

        for (let i = 0; i < encryptedBinary.length; i++) {
          encryptedBytes[i] = encryptedBinary.charCodeAt(i);
        }

        const keyBytes = new TextEncoder().encode(AES_KEY_TEXT);
        const ivBytes = new TextEncoder().encode(AES_IV_TEXT);

        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          keyBytes,
          { name: "AES-CBC", length: 128 },
          false,
          ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-CBC", iv: ivBytes },
          cryptoKey,
          encryptedBytes.buffer
        );

        let text = new TextDecoder().decode(decrypted);

        // Kuch responses me PKCS padding text ke end me aa sakti hai, isliye safe trim.
        const padding = text.charCodeAt(text.length - 1);
        if (padding > 0 && padding <= 16) {
          const paddingText = text.slice(-padding);
          const validPadding = Array.from(paddingText).every(ch => ch.charCodeAt(0) === padding);
          if (validPadding) text = text.slice(0, -padding);
        }

        text = text.trim();
        if (!looksLikeDirectUrl(text)) {
          throw new Error("Decrypt hua, lekin valid video URL nahi mila.");
        }
        return text;
      } catch (error) {
        console.error("Decrypt failed:", error);
        throw new Error("Video URL decrypt nahi ho paya. AES key/IV ya encrypted path check karo.");
      }
    }

    function getSources() {
      if (!videoData) return [];

      if (isLive) {
        if (Array.isArray(videoData.livestream_links) && videoData.livestream_links.length) {
          return videoData.livestream_links;
        }

        if (videoData.recording_schedule) {
          return [
            {
              quality: "Live",
              path: `https://liveclasses.cloud-front.in/live/${videoData.recording_schedule}_appxabr.m3u8`
            }
          ];
        }

        return [];
      }

      if (Array.isArray(videoData.download_links) && videoData.download_links.length) {
        return videoData.download_links;
      }

      if (videoData.file_link) {
        return [
          {
            quality: "Default",
            path: videoData.file_link
          }
        ];
      }

      return [];
    }

    function openQualityModal() {
      const sources = getSources();
      refs.qualityList.innerHTML = "";

      if (!sources.length) {
        refs.qualityList.innerHTML = `
          <button class="quality-item" type="button">
            <span>No source found</span>
            <span>×</span>
          </button>
        `;
      } else {
        sources.forEach((item, index) => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "quality-item";
          btn.innerHTML = `
            <span>🎬 ${item.quality || "Quality " + (index + 1)}</span>
            <span>›</span>
          `;

          btn.onclick = () => selectQuality(item);
          refs.qualityList.appendChild(btn);
        });
      }

      refs.qualityModal.classList.add("show");
    }

    function closeQualityModal() {
      refs.qualityModal.classList.remove("show");
    }

    async function resolveVideoUrl(item) {
      const encryptedOrDirectPath = item.path || item.url || item.file_link || "";
      return decryptVibrantLink(encryptedOrDirectPath);
    }

    async function selectQuality(item) {
      closeQualityModal();
      hideError();

      try {
        setLoading(true, "Decrypting URL...", 60);

        const finalUrl = await resolveVideoUrl(item);
        selectedUrl = finalUrl;

        if (isLive) {
          setLoading(true, "Initializing live player...", 75);
          await loadVideo(finalUrl);
          setLoading(false);
          showControls();
        } else {
          setLoading(true, "Redirecting to player...", 90);

          const redirectUrl =
            "https://appx-play.akamai.net.in/video-player?url=" +
            encodeURIComponent(finalUrl);

          window.location.href = redirectUrl;
        }

      } catch (err) {
        console.error(err);
        showError(err.message || "Failed to resolve selected quality URL.");
      }
    }

    async function loadVideo(url) {
      destroyPlayer();

      if (!window.shaka) {
        throw new Error("Shaka Player load nahi hua.");
      }

      shaka.polyfill.installAll();

      if (!shaka.Player.isBrowserSupported()) {
        throw new Error("Ye browser Shaka Player support nahi karta.");
      }

      player = new shaka.Player(refs.video);

      player.addEventListener("error", function (event) {
        console.error("Shaka Error:", event.detail);
        showError("Player error. Dusri quality try karo.");
      });

      await player.load(url);

      try {
        await refs.video.play();
      } catch (_) {}

      updatePlayState();
    }

    function destroyPlayer() {
      if (player) {
        try {
          player.destroy();
        } catch (_) {}
        player = null;
      }
    }

    function formatTime(sec) {
      if (!Number.isFinite(sec) || sec < 0) return "00:00";

      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);

      if (h > 0) {
        return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
      }

      return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }

    function updateProgress() {
      const v = refs.video;

      if (isLive || !Number.isFinite(v.duration)) {
        refs.timeText.textContent = isLive ? "LIVE" : "00:00 / 00:00";
        return;
      }

      const percent = (v.currentTime / v.duration) * 100;
      refs.progressFill.style.width = percent + "%";
      refs.timeText.textContent = `${formatTime(v.currentTime)} / ${formatTime(v.duration)}`;
    }

    function togglePlay() {
      if (!selectedUrl) {
        openQualityModal();
        return;
      }

      if (refs.video.paused) {
        refs.video.play().catch(() => {});
      } else {
        refs.video.pause();
      }
    }

    function updatePlayState() {
      const paused = refs.video.paused;
      refs.playerWrap.classList.toggle("paused", paused);
      refs.playBtn.textContent = paused ? "▶" : "⏸";
      refs.bigPlay.textContent = paused ? "▶" : "⏸";
    }

    function showControls() {
      refs.playerWrap.classList.add("show-controls");

      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => {
        refs.playerWrap.classList.remove("show-controls");
      }, 3000);
    }

    function seekBy(sec) {
      if (!Number.isFinite(refs.video.duration)) return;

      refs.video.currentTime = Math.max(
        0,
        Math.min(refs.video.duration, refs.video.currentTime + sec)
      );
    }

    function toggleFullscreen() {
      if (!document.fullscreenElement) {
        refs.playerWrap.requestFullscreen?.();
      } else {
        document.exitFullscreen?.();
      }
    }

    function toggleMute() {
      refs.video.muted = !refs.video.muted;
      refs.muteBtn.textContent = refs.video.muted ? "🔇" : "🔊";
    }

    function bindEvents() {
      refs.backBtn.onclick = () => {
        if (history.length > 1) history.back();
        else location.href = "/";
      };

      refs.qualityTopBtn.onclick = openQualityModal;
      refs.qualityBtn.onclick = openQualityModal;
      refs.closeQuality.onclick = closeQualityModal;

      refs.qualityModal.onclick = e => {
        if (e.target === refs.qualityModal) closeQualityModal();
      };

      refs.playBtn.onclick = togglePlay;
      refs.bigPlay.onclick = togglePlay;
      refs.video.onclick = togglePlay;

      refs.back10.onclick = () => seekBy(-10);
      refs.for10.onclick = () => seekBy(10);
      refs.fullBtn.onclick = toggleFullscreen;
      refs.muteBtn.onclick = toggleMute;

      refs.video.addEventListener("play", updatePlayState);
      refs.video.addEventListener("pause", updatePlayState);
      refs.video.addEventListener("timeupdate", updateProgress);
      refs.video.addEventListener("loadedmetadata", updateProgress);

      refs.progressArea.onclick = e => {
        if (!Number.isFinite(refs.video.duration)) return;

        const rect = refs.progressArea.getBoundingClientRect();
        const percent = (e.clientX - rect.left) / rect.width;
        refs.video.currentTime = refs.video.duration * Math.max(0, Math.min(1, percent));
      };

      ["mousemove", "touchstart", "click"].forEach(eventName => {
        refs.playerWrap.addEventListener(eventName, showControls, { passive: true });
      });

      document.addEventListener("keydown", e => {
        if (e.code === "Space") {
          e.preventDefault();
          togglePlay();
        }

        if (e.code === "ArrowRight") seekBy(10);
        if (e.code === "ArrowLeft") seekBy(-10);
        if (e.code === "KeyF") toggleFullscreen();
        if (e.code === "KeyM") toggleMute();
      });
    }

    async function init() {
      bindEvents();

      try {
        setLoading(true, "Initializing...", 10);

        await fetchVideoDetails();

        setLoading(true, "Awaiting quality selection...", 50);

        const sources = getSources();

        if (!sources.length) {
          throw new Error("No playable source found.");
        }

        setLoading(false);

        if (sources.length === 1) {
          await selectQuality(sources[0]);
        } else {
          openQualityModal();
        }

      } catch (err) {
        console.error(err);
        showError(err.message || "Player initialize failed.");
      }
    }

    window.addEventListener("beforeunload", destroyPlayer);

    init();

    
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
 