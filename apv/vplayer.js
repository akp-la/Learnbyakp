
        lucide.createIcons();

        const API = "https://vibrant-gloryfuel.onrender.com";
        const params = new URLSearchParams(location.search);
        const courseId = params.get('course');
        const videoId = params.get('video');
        const videoTitle = params.get('title') || 'Untitled Lesson';

        let hls = null;
        let qualities = [];
        let currentQualityIdx = 0;

        document.getElementById('video-title').textContent = videoTitle;
        document.title = 'LearnByAKP | ' + videoTitle;

        if (!courseId || !videoId) {
            showError('Invalid Authorization. Please launch from the dashboard.');
        } else {
            loadVideo(courseId, videoId);
        }

        function buildProxyUrl(rawUrl) {
            return API + '/proxy-video?url=' + encodeURIComponent(rawUrl);
        }

        function destroyPlayer() {
            if (hls) { try { hls.destroy(); } catch(e) {} hls = null; }
            const video = document.getElementById('video-player');
            video.removeAttribute('src');
            video.innerHTML = '';
        }

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
            const errorPopup = document.getElementById('errorPopup');
            errorPopup.textContent = msg;
            errorPopup.classList.add('show');
            setTimeout(() => errorPopup.classList.remove('show'), 4000);
        }

        function initHlsPlayback(url) {
            const video = document.getElementById('video-player');
            const videoShell = document.getElementById('videoShell');

            if (Hls.isSupported()) {
                hls = new Hls({ enableWorker: false, debug: false });
                hls.loadSource(url);
                hls.attachMedia(video);
                hls.on(Hls.Events.MANIFEST_PARSED, () => {
                    video.play().catch(() => {});
                    videoShell.classList.remove('paused');
                });
                hls.on(Hls.Events.ERROR, (event, data) => {
                    if (data.fatal) showError('Stream interrupted.');
                });
            } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                video.src = url;
                video.addEventListener('loadedmetadata', () => {
                    video.play().catch(() => {});
                    videoShell.classList.remove('paused');
                });
            } else {
                showError('Browser does not support this video format.');
            }
        }

        async function loadVideo(courseId, videoId) {
            try {
                const r = await fetch(API + '/api/v1/vibrant/video?video_id=' + videoId + '&course_id=' + courseId);
                const d = await r.json();

                if (!d.success) throw new Error(d.message || 'Server restricted access.');
                if (!d.qualities || d.qualities.length === 0) throw new Error('No playable streams found.');

                qualities = d.qualities;

                document.getElementById('videoLoader').classList.add('hidden');

                let metaText = '';
                if (d.duration) metaText += d.duration;
                if (d.date) metaText += (metaText ? ' • ' : '') + d.date;
                document.getElementById('video-meta').textContent = metaText || 'Secure Encrypted Stream';

                if (d.thumbnail) document.getElementById('video-player').poster = d.thumbnail;

                setupQualitySelect();
                initHlsPlayback(buildProxyUrl(qualities[0].url));

            } catch (e) {
                document.getElementById('videoLoader').classList.add('hidden');
                showError(e.message || 'Network error.');
            }
        }

        function setupQualitySelect() {
            const qualitySelect = document.querySelector('#qualitySelect');
            qualitySelect.innerHTML = '';

            qualities.forEach((q, i) => {
                const label = q.label || q.quality || q.height + 'p' || 'Source';
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
                initHlsPlayback(buildProxyUrl(qualities[idx].url));
                showToast('Quality changed to ' + (qualities[idx].label || qualities[idx].quality || qualities[idx].height + 'p'));
            });
        }

        // Player Controls
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

