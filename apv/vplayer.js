lucide.createIcons();

const API = "https://vibrant-gloryfuel.onrender.com";
const params = new URLSearchParams(location.search);

const directVideoUrl = params.get('videourl');
const courseId = params.get('course_id') || params.get('course');
const videoId = params.get('video_id') || params.get('video');
const videoTitle = params.get('title') || 'Untitled Lesson';

let hls = null;
let qualities = [];
let currentQualityIdx = 0;

// Inject loader HTML + CSS
injectLoaderUI();

document.getElementById('video-title').textContent = videoTitle;
document.title = 'LearnByAKP | ' + videoTitle;

// Flow decide: videourl vs API
if (directVideoUrl) {
    const proxied = API + '/proxy-video?url=' + encodeURIComponent(directVideoUrl);
    initHlsPlayback(proxied); // loader yahi handle hoga
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
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(0, 0, 0, 0.78);
            z-index: 99999;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.25s ease, visibility 0.25s ease;
        }
        #jsVideoLoader.visible {
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
    return API + '/proxy-video?url=' + encodeURIComponent(rawUrl);
}

// ------------- Player destroy -------------

function destroyPlayer() {
    if (hls) {
        try { hls.destroy(); } catch (e) {}
        hls = null;
    }
    const video = document.getElementById('video-player');
    video.removeAttribute('src');
    video.innerHTML = '';
}

// ------------- Toast / Error -------------

function showToast(msg) {
    const toast = document.getElementById('toast');
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
    errorPopup.textContent = msg;
    errorPopup.classList.add('show');
    setTimeout(() => errorPopup.classList.remove('show'), 4000);
}

// ------------- HLS init (loader logic yahi hai) -------------

function initHlsPlayback(url) {
    const video = document.getElementById('video-player');
    const videoShell = document.getElementById('videoShell');

    // Har naya stream load hone pe loader dikhana
    showLoader('Decrypting stream...');
    videoShell.classList.add('paused');

    // Purane listeners clean karo (taaki duplicate na bane)
    video.oncanplay = null;
    video.onplaying = null;
    video.onloadeddata = null;
    video.onwaiting = null;
    video.onstalled = null;

    const hideOnReady = () => {
        hideLoader();
        videoShell.classList.remove('paused');
    };

    // Ye events actual playback-ready state ko pakadte hain [web:49][web:50][web:51]
    video.addEventListener('canplay', hideOnReady, { once: true });
    video.addEventListener('loadeddata', hideOnReady, { once: true });
    video.addEventListener('playing', hideOnReady, { once: true });

    // Buffering ke time loader wapas show
    video.addEventListener('waiting', () => showLoader('Buffering...'));
    video.addEventListener('stalled', () => showLoader('Buffering...'));

    video.addEventListener('pause', () => {
        if (!video.ended) {
            videoShell.classList.add('paused');
        }
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

// ------------- API load (no videourl) -------------

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
    const qualitySelect = document.querySelector('#qualitySelect');
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

function togglePlay() {
    if (video.paused) {
        video.play();
        videoShell.classList.remove('paused');
    } else {
        video.pause();
        videoShell.classList.add('paused');
    }
}

playPauseBtn.addEventListener('click', togglePlay);
centerPlayBtn.addEventListener('click', togglePlay);

video.addEventListener('play', () => videoShell.classList.remove('paused'));
video.addEventListener('pause', () => videoShell.classList.add('paused'));

video.addEventListener('timeupdate', () => {
    const pct = (video.currentTime / video.duration) * 100 || 0;
    progressFill.style.transform = `scaleX(${pct / 100})`;
    progressHandle.style.left = `${pct}%`;
    currentTimeEl.textContent = formatTime(video.currentTime);
});

video.addEventListener('loadedmetadata', () => {
    durationEl.textContent = formatTime(video.duration);
});

progressBar.addEventListener('click', (e) => {
    const rect = progressBar.getBoundingClientRect();
    const pct = (e.clientX - rect.left) / rect.width;
    video.currentTime = pct * video.duration;
});

volumeSlider.addEventListener('input', (e) => {
    video.volume = e.target.value;
});

speedSelect.addEventListener('change', (e) => {
    video.playbackRate = parseFloat(e.target.value);
    showToast('Speed: ' + e.target.value + 'x');
});

fullscreenBtn.addEventListener('click', () => {
    const root = document.querySelector('.vp-root');
    if (!document.fullscreenElement) {
        root.requestFullscreen?.();
    } else {
        document.exitFullscreen?.();
    }
});

moreBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    moreMenu.classList.toggle('open');
});

document.addEventListener('click', (e) => {
    if (!moreBtn.contains(e.target)) {
        moreMenu.classList.remove('open');
    }
});

function formatTime(sec) {
    if (!sec || !isFinite(sec)) return '0:00';
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return m + ':' + (s < 10 ? '0' : '') + s;
}

// ------------- Extra script -------------

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
