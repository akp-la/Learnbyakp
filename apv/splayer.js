
        // Configuration
        const API_BASE = "https://learnbyakp.onrender.com";
        let videoPlayer = null;
        let currentVideoUrl = null;
        let videoData = null;
        let isLive = false;
        let selectedQuality = null;
        
        // Get URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const courseId = urlParams.get('course_id');
        const videoId = urlParams.get('video_id');
        isLive = urlParams.get('isLive') === 'true';
        
        // Toast notification
        function showToast(message, type = 'success') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `<span class="toast-message">${message}</span>`;
            container.appendChild(toast);
            
            setTimeout(() => {
                toast.style.animation = 'slideIn 0.3s ease reverse';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }
        
        // AES-128-CBC Decryption (same as original)
        async function decryptVideoPath(encryptedPath) {
            const KEY = new TextEncoder().encode("638udh3829162018");
            const IV = new TextEncoder().encode("fedcba9876543210");
            
            try {
                const parts = encryptedPath.split(':');
                const base64Data = parts[0];
                
                const encryptedBytes = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
                
                const cryptoKey = await crypto.subtle.importKey(
                    "raw",
                    KEY,
                    { name: "AES-CBC", length: 128 },
                    false,
                    ["decrypt"]
                );
                
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-CBC", iv: IV },
                    cryptoKey,
                    encryptedBytes
                );
                
                let decryptedText = new TextDecoder().decode(decryptedBuffer);
                
                // Remove PKCS7 padding
                const padding = decryptedText.charCodeAt(decryptedText.length - 1);
                if (padding > 0 && padding <= 16) {
                    let isValid = true;
                    for (let i = 0; i < padding; i++) {
                        if (decryptedText.charCodeAt(decryptedText.length - 1 - i) !== padding) {
                            isValid = false;
                            break;
                        }
                    }
                    if (isValid) {
                        decryptedText = decryptedText.slice(0, -padding);
                    }
                }
                
                return decryptedText;
            } catch (error) {
                console.error("Decryption failed:", error);
                throw new Error("Failed to decrypt video URL");
            }
        }
        
        // Fetch video details from API
        async function fetchVideoDetails() {
            if (!courseId || !videoId) {
                showError("Course ID or Video ID is missing. Please check the URL parameters.");
                return false;
            }
            
            try {
                const response = await fetch(
                    `${API_BASE}/api/science/video-details?video_id=${encodeURIComponent(videoId)}&course_id=${encodeURIComponent(courseId)}`
                );
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                
                if (result.status !== 200 || !result.data) {
                    throw new Error(result.message || "Invalid video details response");
                }
                
                videoData = result.data;
                return true;
                
            } catch (error) {
                console.error("Failed to fetch video details:", error);
                showError(error.message);
                return false;
            }
        }
        
        // Handle video data and determine playback source
        async function handleVideoData() {
            if (!videoData) return;
            
            try {
                if (isLive) {
                    // Live class handling
                    if (videoData.livestream_links && videoData.livestream_links.length > 0) {
                        showQualityModal(videoData.livestream_links);
                    } else if (videoData.recording_schedule) {
                        const recordingUrl = `https://liveclasses.cloud-front.in/live/${encodeURIComponent(videoData.recording_schedule)}_appxabr.m3u8`;
                        currentVideoUrl = recordingUrl;
                        await loadVideo(recordingUrl);
                    } else {
                        showError("No playable live stream or recording found for this class.");
                    }
                } else {
                    // Recorded video handling
                    if (videoData.video_player_url && videoData.video_player_token) {
                        let url = videoData.video_player_url
                            .replace(/\\?isMobile=true&/, "")
                            .replace(/&isMobile=true/, "");
                        window.location.href = url + videoData.video_player_token;
                        return;
                    }
                    
                    if (videoData.encrypted_links && videoData.encrypted_links.length > 0) {
                        showQualityModal(videoData.encrypted_links);
                    } else if (videoData.file_link) {
                        selectedQuality = { quality: "Default", path: videoData.file_link, bitrate: "" };
                        await selectQuality(selectedQuality);
                    } else {
                        showError("No video source found. Please contact support.");
                    }
                }
            } catch (error) {
                console.error("Error handling video data:", error);
                showError(error.message);
            }
        }
        
        // Show quality selection modal
        function showQualityModal(qualities) {
            const modal = document.getElementById('qualityModal');
            const qualityList = document.getElementById('qualityList');
            
            qualityList.innerHTML = qualities.map((q, index) => `
                <button class="quality-btn" onclick="selectQuality(${index})">
                    <span class="quality-label">
                        <svg class="quality-icon" viewBox="0 0 24 24">
                            <rect width="20" height="15" x="2" y="7" rx="2" ry="2"/>
                            <polyline points="17 2 12 7 7 2"/>
                        </svg>
                        ${q.quality || 'Default'}
                    </span>
                    <svg viewBox="0 0 24 24">
                        <path d="m9 18 6-6-6-6"/>
                    </svg>
                </button>
            `).join('');
            
            modal.classList.add('active');
        }
        
        // Select quality and decrypt video URL
        async function selectQuality(index) {
            const qualities = isLive 
                ? videoData.livestream_links 
                : videoData.encrypted_links;
            
            if (!qualities || !qualities[index]) return;
            
            const quality = qualities[index];
            document.getElementById('qualityModal').classList.remove('active');
            
            showToast(`Loading ${quality.quality || 'Default'} quality...`);
            
            try {
                const decryptedUrl = await decryptVideoPath(quality.path);
                selectedQuality = quality;
                currentVideoUrl = decryptedUrl;
                
                if (isLive) {
                    await loadVideo(decryptedUrl);
                } else {
                    const playUrl = `${API_BASE}/api/vibrant/play?url=${encodeURIComponent(decryptedUrl)}`;
                    await loadVideo(playUrl);
                }
                
                showToast(`Playing ${quality.quality || 'Default'} quality`);
            } catch (error) {
                console.error("Failed to decrypt video:", error);
                showError("Failed to decrypt the selected video quality. Please try another quality.");
            }
        }
        
        // Load video using Shaka Player
        async function loadVideo(url) {
            const video = document.getElementById('video');
            
            // Initialize Shaka Player
            if (!shaka.Player.isBrowserSupported()) {
                showError("This browser is not supported. Please try Chrome, Firefox, or Edge.");
                return;
            }
            
            videoPlayer = new shaka.Player(video);
            
            // Error handling
            videoPlayer.addEventListener('error', (event) => {
                console.error('Shaka Player error:', event.detail);
                if (event.detail.code) {
                    showError(`Video playback error (Code: ${event.detail.code})`);
                }
            });
            
            // Loading progress
            video.addEventListener('waiting', () => {
                showToast('Loading video...', 'success');
            });
            
            video.addEventListener('playing', () => {
                document.getElementById('playOverlay').classList.add('hidden');
            });
            
            try {
                await videoPlayer.load(url);
                console.log('Video loaded successfully!');
                document.getElementById('playOverlay').classList.add('hidden');
            } catch (error) {
                console.error('Failed to load video:', error);
                showError(`Failed to load video: ${error.message}`);
            }
        }
        
        // Show error
        function showError(message) {
            document.getElementById('loadingScreen').style.display = 'none';
            document.getElementById('playerWrapper').classList.remove('active');
            document.getElementById('errorOverlay').classList.add('active');
            document.getElementById('errorMessage').textContent = message;
        }
        
        // Toggle UI elements
        function toggleQualityModal() {
            document.getElementById('qualityModal').classList.toggle('active');
        }
        
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('active');
            document.getElementById('sidebarOverlay').classList.toggle('active');
        }
        
        // Navigation
        function goBack() {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = '/';
            }
        }
        
        function reloadPage() {
            window.location.reload();
        }
        
        // Download video using 1DM
        function downloadVideo() {
            if (!currentVideoUrl) {
                showToast("Please select a video quality first", "error");
                return;
            }
            
            const playUrl = `${API_BASE}/api/vibrant/play?url=${encodeURIComponent(currentVideoUrl)}`;
            
            // Create 1DM intent URL
            const intentUrl = `intent://${playUrl.replace(/^https?:\/\//, '')}#Intent;scheme=https;package=idm.internet.download.manager;S.browser_fallback_url=${encodeURIComponent('https://play.google.com/store/apps/details?id=idm.internet.download.manager')};end;`;
            
            window.location.href = intentUrl;
            showToast("Opening 1DM downloader...", "success");
        }
        
        // Check authentication (simplified)
        function checkAuth() {
            const accessToken = localStorage.getItem('delta-access-key');
            const expiration = localStorage.getItem('delta-key-expiration');
            
            if (!accessToken || !expiration) {
                window.location.href = '/delta-auth';
                return false;
            }
            
            const expiresAt = parseInt(expiration, 10);
            const now = new Date().getTime();
            
            if (now > expiresAt) {
                localStorage.removeItem('delta-access-key');
                localStorage.removeItem('delta-key-expiration');
                window.location.href = '/delta-auth';
                return false;
            }
            
            return true;
        }
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (videoPlayer) {
                videoPlayer.destroy();
            }
        });
        
        // Initialize app
        async function init() {
            try {
                // Check authentication
                if (!checkAuth()) {
                    return;
                }
                
                // Fetch video details
                const success = await fetchVideoDetails();
                
                if (!success) {
                    return;
                }
                
                // Handle video data
                await handleVideoData();
                
                // Hide loading, show player
                document.getElementById('loadingScreen').style.display = 'none';
                document.getElementById('playerWrapper').classList.add('active');
                
            } catch (error) {
                console.error('Initialization error:', error);
                showError("Failed to initialize video player. Please refresh the page.");
            }
        }
        
        // Start the app
        init();
    const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";

if(!isMobileDevice){
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
}