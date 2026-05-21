
    document.addEventListener("keydown", function (e) {
  if (
    e.key === "F12" ||
    (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key)) ||
    (e.ctrlKey && e.key === "U")
  ) {
    e.preventDefault();
    debugger; // pause
  }
});  



    const BASE_URL = "https://learnbyakp.onrender.com";

    const urlParts = window.location.pathname.split("/").filter(Boolean);
    const searchParams = new URLSearchParams(window.location.search);

    // expected path style:
    // /something/:batchId/:subjectSlug/:topicSlug?topicName=...&subjectId=...&topicId=...
    const batchId = searchParams.get("BatchId") || "";
    const subjectSlug = searchParams.get("Subjectslug") || "";
    const topicSlug = searchParams.get("topicslug")

    const topicName = searchParams.get("topicName") || "Chapter";
    const subjectId = searchParams.get("SubjectId") || "";
    const topicId = searchParams.get("topicId") || "";

    const pageTitle = document.getElementById("pageTitle");
    const topicHeading = document.getElementById("topicHeading");
    const topicSub = document.getElementById("topicSub");
    const sectionTitle = document.getElementById("sectionTitle");
    const sectionCount = document.getElementById("sectionCount");
    const contentArea = document.getElementById("contentArea");
    const themeBtn = document.getElementById("themeBtn");

    const pdfSheetBackdrop = document.getElementById("pdfSheetBackdrop");
    const pdfSheetTitle = document.getElementById("pdfSheetTitle");
    const pdfOpenBtn = document.getElementById("pdfOpenBtn");
    const pdfViewBtn = document.getElementById("pdfViewBtn");
    const pdfDownloadBtn = document.getElementById("pdfDownloadBtn");
    const pdfCloseBtn = document.getElementById("pdfCloseBtn");

    const videoSheetBackdrop = document.getElementById("videoSheetBackdrop");
    const videoSheetTitle = document.getElementById("videoSheetTitle");
    const playAppleBtn = document.getElementById("playAppleBtn");
    const playAndroidBtn = document.getElementById("playAndroidBtn");
    const downloadVideoBtn = document.getElementById("downloadVideoBtn");
    const videoCloseBtn = document.getElementById("videoCloseBtn");

    let activeTab = "lectures";
    let loading = false;

    let lectures = [];
    let notes = [];
    let dpps = [];

    let currentPdf = null;
    let currentVideo = null;

    function escapeHtml(str) {
      return String(str || "").replace(/[&<>"']/g, function (m) {
        return ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;"
        })[m];
      });
    }

    function applyTheme(mode) {
      const dark = mode === "dark";
      document.body.classList.toggle("dark", dark);
      themeBtn.textContent = dark ? "☀️ Day Mode" : "🌙 Night Mode";
      localStorage.setItem("topic-theme", dark ? "dark" : "light");
    }

    themeBtn.addEventListener("click", () => {
      applyTheme(document.body.classList.contains("dark") ? "light" : "dark");
    });

    applyTheme(localStorage.getItem("topic-theme") || "light");

    pageTitle.textContent = topicName;
    topicHeading.textContent = topicName;
    topicSub.textContent = topicSlug === "all-contents"
      ? "Showing content from all topics"
      : `Topic code: ${topicSlug || "N/A"}`;

    function setTab(tab) {
      activeTab = tab;
      document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.tab === tab);
      });

      if (tab === "lectures") sectionTitle.textContent = "Video Lectures";
      if (tab === "notes") sectionTitle.textContent = "Study Notes";
      if (tab === "dpp") sectionTitle.textContent = "Daily Practice Problems";

      renderCurrentTab();
      fetchContent(tab);
    }

    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => setTab(btn.dataset.tab));
    });

    function showLoading() {
      contentArea.innerHTML = `
        <div class="loading">
          <h3>Loading...</h3>
          <p>Please wait while content is being fetched.</p>
        </div>
      `;
    }

    function showError(msg) {
      contentArea.innerHTML = `
        <div class="error">
          <h3>Something went wrong</h3>
          <p>${escapeHtml(msg || "Failed to load content.")}</p>
        </div>
      `;
    }

    function showEmpty(message) {
      contentArea.innerHTML = `
        <div class="empty">
          <h3>No content available</h3>
          <p>${escapeHtml(message || "Nothing found yet.")}</p>
        </div>
      `;
    }

    async function importAesKey(keyText) {
      const input = new TextEncoder().encode(keyText);
      const fixed = new Uint8Array(32);

      for (let i = 0; i < 32; i++) {
        fixed[i] = i < input.length ? input[i] : 0;
      }

      return crypto.subtle.importKey(
        "raw",
        fixed,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
    }

    function hexToBytes(hex) {
      return new Uint8Array(hex.match(/.{1,2}/g).map(x => parseInt(x, 16)));
    }

    async function decryptPayload(payload) {
      try {
        const [ivHex, dataHex] = String(payload).split(":");
        if (!ivHex || !dataHex) throw new Error("Invalid encrypted payload format.");

        const iv = hexToBytes(ivHex);
        const encrypted = hexToBytes(dataHex);
        const key = await importAesKey("maggikhalo");

        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          encrypted
        );

        const decoded = new TextDecoder().decode(decrypted);
        return JSON.parse(decoded);
      } catch (err) {
        console.error("Decryption failed:", err);
        return { success: false, error: "Decryption failed: " + err.message };
      }
    }

    async function fetchJson(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    }

    async function fetchAndDecrypt(url) {
      const json = await fetchJson(url);
      if (!json.data) return null;
      const decrypted = await decryptPayload(json.data);
      return decrypted.success ? decrypted.data : null;
    }

    function formatDate(value) {
      if (!value) return "Date not available";
      try {
        return new Date(value).toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "numeric"
        });
      } catch {
        return "Date not available";
      }
    }

    function getCurrentItems() {
      if (activeTab === "lectures") return lectures;
      if (activeTab === "notes") return notes;
      return dpps;
    }

    function updateCount() {
      const items = getCurrentItems();
      sectionCount.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
    }

    function renderCurrentTab() {
      const items = getCurrentItems();
      updateCount();

      if (loading) {
        showLoading();
        return;
      }

      if (!items.length) {
        let msg = "No content available yet";
        if (activeTab === "lectures") msg = "No lectures available yet";
        if (activeTab === "notes") msg = "No notes available yet";
        if (activeTab === "dpp") msg = "No DPPs available yet";
        showEmpty(msg);
        return;
      }

      if (activeTab === "lectures") {
        contentArea.innerHTML = `
          <div class="grid lecture-grid">
            ${items.map(item => `
              <div class="card">
                <div class="lecture-thumb">
                  <img src="${escapeHtml(item.thumbnail)}" alt="${escapeHtml(item.topic)}" />
                  <div class="badge">Lecture</div>
                </div>
                <div class="card-body">
                  <div class="meta-line">📅 ${escapeHtml(formatDate(item.date))}</div>
                  <div class="title">${escapeHtml(item.topic)}</div>
                  <div class="info-row">
                    <div>⏱ ${escapeHtml(item.duration || "N/A")}</div>
                  </div>
                  <div class="actions">
                    <button class="btn primary" onclick="openVideoSheet('${escapeHtml(item._id)}')">Play Now</button>
                  </div>
                </div>
              </div>
            `).join("")}
          </div>
        `;
        return;
      }

      contentArea.innerHTML = `
        <div class="grid doc-grid">
          ${items.map(item => `
            <div class="card">
              <div class="doc-item">
                <div class="doc-left">
                  <div class="doc-icon">📄</div>
                  <div>
                    <div class="doc-title">${escapeHtml(item.topic)}</div>
                    <div class="doc-sub">${activeTab === "notes" ? "Study Note" : "Practice PDF"}</div>
                  </div>
                </div>
                <div class="actions" style="min-width:160px; justify-content:flex-end;">
                  <button class="btn" onclick="openPdfSheet('${escapeHtml(item._id)}')">Open</button>
                </div>
              </div>
            </div>
          `).join("")}
        </div>
      `;
    }

    async function fetchContent(tab) {
      if (!batchId || !subjectSlug || !topicSlug) {
        loading = false;
        showError("Missing route params. Path should include batchId / subjectSlug / topicSlug.");
        return;
      }

      loading = true;
      renderCurrentTab();

      const contentType =
        tab === "lectures" ? "videos" :
        tab === "dpp" ? "dpp" : "notes";

      try {
        if (topicSlug === "all-contents") {
          await fetchAllContents(tab, contentType);
        } else {
          await fetchSingleTopic(tab, contentType);
        }
      } catch (err) {
        console.error(err);
        if (tab === activeTab) showError(err.message || "Failed to load content.");
      } finally {
        loading = false;
        renderCurrentTab();
      }
    }

    async function fetchAllContents(tab, contentType) {
      const topicsUrl = `${BASE_URL}/api/pw/topics?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectSlug)}`;
      const topicJson = await fetchJson(topicsUrl);
      const topicList = await decryptPayload(topicJson.data);

      if (!topicList.success || !Array.isArray(topicList.data)) {
        setItems(tab, []);
        return;
      }

      let allItems = [];

      for (const topic of topicList.data) {
        const dataUrl = `${BASE_URL}/api/pw/datacontent?batchId=${encodeURIComponent(batchId)}&subjectSlug=${encodeURIComponent(subjectSlug)}&topicSlug=${encodeURIComponent(topic.slug)}&contentType=${encodeURIComponent(contentType)}`;

        try {
          const data = await fetchAndDecrypt(dataUrl);
          if (!data || !data.length) continue;

          const mapped = mapItems(data, contentType);
          allItems = allItems.concat(mapped);
        } catch (err) {
          console.warn("Topic fetch failed:", topic.slug, err);
        }
      }

      setItems(tab, allItems);
    }

    async function fetchSingleTopic(tab, contentType) {
      const dataUrl = `${BASE_URL}/api/pw/datacontent?batchId=${encodeURIComponent(batchId)}&subjectSlug=${encodeURIComponent(subjectSlug)}&topicSlug=${encodeURIComponent(topicSlug)}&contentType=${encodeURIComponent(contentType)}`;

      const data = await fetchAndDecrypt(dataUrl);
      if (!data || !data.length) {
        setItems(tab, []);
        return;
      }

      setItems(tab, mapItems(data, contentType));
    }

    function mapItems(data, contentType) {
      if (contentType === "videos") {
        return data.map(item => ({
          _id: item._id,
          topic: item.topic,
          thumbnail:
            item?.videoDetails?.image ||
            item.previewImage ||
            "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png",
          date: item.date,
          duration: item?.videoDetails?.duration || item.duration || "N/A",
          findKey: item.findKey || item?.videoDetails?.findKey || item._id
        }));
      }

      return data.flatMap(schedule =>
        (schedule.homeworkIds || []).map(hw => ({
          _id: hw._id,
          topic: hw.topic,
          pdf_url:
            hw.attachmentIds &&
            hw.attachmentIds[0] &&
            hw.attachmentIds[0].key
              ? `${hw.attachmentIds[0].baseUrl}${hw.attachmentIds[0].key}`
              : undefined,
          needs_fetching: !(
            hw.attachmentIds &&
            hw.attachmentIds[0] &&
            hw.attachmentIds[0].key
          ),
          original_schedule_id: schedule._id,
          subject: schedule.subject
        }))
      );
    }

    function setItems(tab, items) {
      if (tab === "lectures") lectures = items;
      if (tab === "notes") notes = items;
      if (tab === "dpp") dpps = items;
    }

    function getLectureById(id) {
      return lectures.find(x => String(x._id) === String(id));
    }

    function getDocById(id) {
      const all = activeTab === "notes" ? notes : dpps;
      return all.find(x => String(x._id) === String(id));
    }

    function openVideoSheet(id) {
      const item = getLectureById(id);
      if (!item?.findKey) {
        alert("Video processing is not complete. Please try again later.");
        return;
      }
      currentVideo = item;
      videoSheetTitle.textContent = item.topic || "Choose Player";
      videoSheetBackdrop.classList.add("show");
    }

    function closeVideoSheet() {
      currentVideo = null;
      videoSheetBackdrop.classList.remove("show");
    }

    function openPdfSheet(id) {
      const item = getDocById(id);
      if (!item) return;
      currentPdf = item;
      pdfSheetTitle.textContent = item.topic || "Choose Action";
      pdfSheetBackdrop.classList.add("show");
    }

    function closePdfSheet() {
      currentPdf = null;
      pdfSheetBackdrop.classList.remove("show");
    }

    async function resolvePdfUrl(item) {
      if (item.pdf_url && !item.needs_fetching) return item.pdf_url;

      if (!item.original_schedule_id || !batchId) {
        throw new Error("Cannot fetch PDF: missing necessary IDs.");
      }

      let finalUrl = null;
      let errorText = "Could not process attachment link.";

      try {
        const subjectVal = item?.subject?._id || subjectId;
        const url1 = `${BASE_URL}/api/pw/attachment-url?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId)}&ContentId=${encodeURIComponent(item.original_schedule_id)}`;
        const res1 = await fetch(url1);

        if (res1.ok) {
          const json1 = await res1.json();
          if (json1.success && Array.isArray(json1.data) && json1.data.length) {
            const match = json1.data.find(x => String(x.topic || "").includes(item.topic));
            if (match?.url) finalUrl = match.url;
            else if (json1.data[0]?.url) finalUrl = json1.data[0].url;
          }
        }
      } catch (e) {
        console.warn("Primary attachment API failed.");
      }

      if (!finalUrl) {
        try {
          const url2 = `${BASE_URL}/api/pw/attachment-link?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId)}&ContentId=${encodeURIComponent(item.original_schedule_id)}`;
          const res2 = await fetch(url2);

          if (res2.ok) {
            const json2 = await res2.json();
            if (json2.data) {
              const dec = await decryptPayload(json2.data);
              if (dec.success && dec.data) {
                if (Array.isArray(dec.data) && dec.data[0]?.url) finalUrl = dec.data[0].url;
                else if (typeof dec.data === "object" && dec.data.url) finalUrl = dec.data.url;
              } else if (dec.error) {
                errorText = dec.error;
              }
            }
          }
        } catch (e) {
          console.warn("Fallback attachment API failed.");
        }
      }

      if (!finalUrl) throw new Error(errorText);

      item.pdf_url = finalUrl;
      item.needs_fetching = false;
      return finalUrl;
    }

    async function handlePdfOpen(type) {
      if (!currentPdf) return;

      try {
        const url = await resolvePdfUrl(currentPdf);

        if (type === "open") {
          window.open(url, "_blank");
        } else if (type === "view") {
          window.open(`${BASE_URL}/api/pw/view?url=${encodeURIComponent(url)}&filename=${encodeURIComponent(currentPdf.topic)}`, "_blank");
        } else if (type === "download") {
          window.location.href = `${BASE_URL}/api/pw/download?url=${encodeURIComponent(url)}&filename=${encodeURIComponent(currentPdf.topic)}`;
        }

        closePdfSheet();
      } catch (err) {
        console.error(err);
        alert("Error fetching download link: " + err.message);
      }
    }

    function playVideo(mode) {
      if (!currentVideo) return;

      const videoId = currentVideo.findKey;
      const target =
        mode === "apple"
          ? `/study-v2/player?video_id=${encodeURIComponent(videoId)}&subject_slug=${encodeURIComponent(subjectSlug)}&batch_id=${encodeURIComponent(batchId)}&schedule_id=${encodeURIComponent(currentVideo._id)}&subject_id=${encodeURIComponent(subjectId)}&topicSlug=${encodeURIComponent(topicSlug)}`
          : `/study-v2/player?video_id=${encodeURIComponent(videoId)}&subject_slug=${encodeURIComponent(subjectSlug)}&batch_id=${encodeURIComponent(batchId)}&schedule_id=${encodeURIComponent(currentVideo._id)}&subject_id=${encodeURIComponent(subjectId)}&topicSlug=${encodeURIComponent(topicSlug)}`;

      closeVideoSheet();
      window.location.href = target;
    }

    async function downloadCurrentVideo() {
      if (!currentVideo?.findKey) {
        alert("Missing required info to start download.");
        return;
      }

      const key = currentVideo.findKey;
      closeVideoSheet();

      try {
        let finalUrl = null;

        try {
          const res1 = await fetch(`${BASE_URL}/api/pw/videonew?batchId=${encodeURIComponent(batchId)}&subjectId=${encodeURIComponent(subjectId)}&childId=${encodeURIComponent(key)}`);
          if (res1.ok) {
            const j1 = await res1.json();
            if (j1.data) {
              const d1 = await decryptPayload(j1.data);
              if (d1.success && d1.data?.url) {
                finalUrl = d1.data.signedUrl ? d1.data.url + d1.data.signedUrl : d1.data.url;
              }
            }
          }
        } catch (e) {
          console.warn("videonew failed", e);
        }

        if (!finalUrl) {
          try {
            const res2 = await fetch(`${BASE_URL}/api/pw/video?batchId=${encodeURIComponent(batchId)}&subjectId=${encodeURIComponent(subjectSlug)}&childId=${encodeURIComponent(key)}`);
            if (res2.ok) {
              const j2 = await res2.json();
              if (j2.data) {
                const d2 = await decryptPayload(j2.data);
                if (d2.success && d2.data?.url) {
                  finalUrl = d2.data.signedUrl ? d2.data.url + d2.data.signedUrl : d2.data.url;
                }
              }
            }
          } catch (e) {
            console.warn("video failed", e);
          }
        }

        if (!finalUrl) {
          try {
            const res3 = await fetch(`${BASE_URL}/api/pw/videosuper?batchId=${encodeURIComponent(batchId)}&childId=${encodeURIComponent(key)}`);
            if (res3.ok) {
              const j3 = await res3.json();
              if (j3.success && j3.data?.video_url) {
                finalUrl = j3.data.video_url;
              }
            }
          } catch (e) {
            console.warn("videosuper failed", e);
          }
        }

        if (!finalUrl) {
          try {
            const res4 = await fetch(`${BASE_URL}/api/pw/videoplay?batchId=${encodeURIComponent(batchId)}&childId=${encodeURIComponent(key)}`);
            if (res4.ok) {
              const j4 = await res4.json();
              if (j4.success && j4.data?.video_url) {
                finalUrl = j4.data.video_url;
              }
            }
          } catch (e) {
            console.warn("videoplay failed", e);
          }
        }

        if (!finalUrl) throw new Error("Could not retrieve a valid video URL from any source.");

        const m3u8 = finalUrl.replace(/\.mpd/i, ".m3u8");
        window.location.href = `/download?url=${encodeURIComponent(m3u8)}`;
      } catch (err) {
        alert("Failed to get download link: " + err.message);
      }
    }

    pdfOpenBtn.addEventListener("click", () => handlePdfOpen("open"));
    pdfViewBtn.addEventListener("click", () => handlePdfOpen("view"));
    pdfDownloadBtn.addEventListener("click", () => handlePdfOpen("download"));
    pdfCloseBtn.addEventListener("click", closePdfSheet);

    playAppleBtn.addEventListener("click", () => playVideo("apple"));
    playAndroidBtn.addEventListener("click", () => playVideo("android"));
    downloadVideoBtn.addEventListener("click", downloadCurrentVideo);
    videoCloseBtn.addEventListener("click", closeVideoSheet);

    pdfSheetBackdrop.addEventListener("click", (e) => {
      if (e.target === pdfSheetBackdrop) closePdfSheet();
    });

    videoSheetBackdrop.addEventListener("click", (e) => {
      if (e.target === videoSheetBackdrop) closeVideoSheet();
    });

    window.openPdfSheet = openPdfSheet;
    window.openVideoSheet = openVideoSheet;

    setTab("lectures");



let devtoolsOpen = false;

setInterval(() => {
  const start = performance.now();
  debugger;
  const end = performance.now();

  if (end - start > 100) {
    if (!devtoolsOpen) {
      devtoolsOpen = true;
      debugger; // pause again
    }
  } else {
    devtoolsOpen = false;
  }
}, 1000);

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